// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use crate::metadata::{
    OciBundleRecord, OciManifestRecord, OciMissingObjectRecord, OciObjectRecord, OciTagRecord,
    OciUploadState, SharedMetadataStore,
};
use crate::object_store::SharedObjectStore;
use axum::body::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub const DOCKER_DISTRIBUTION_API_VERSION: &str = "registry/2.0";
static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct OciRegistry {
    metadata: SharedMetadataStore,
    objects: SharedObjectStore,
    write_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone)]
pub struct OciBlob {
    pub content: Vec<u8>,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct OciManifest {
    pub content: Vec<u8>,
    pub digest: String,
    pub media_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OciMetadataMigrationReport {
    pub converted: usize,
    pub failed: usize,
    pub remaining: usize,
    pub incomplete: usize,
    pub errors: Vec<OciMetadataMigrationError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OciMetadataMigrationError {
    pub repository: String,
    pub digest: String,
    pub error: String,
}

impl OciRegistry {
    pub fn new(metadata: SharedMetadataStore, objects: SharedObjectStore) -> Self {
        Self {
            metadata,
            objects,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn start_upload(&self, repository: &str) -> Result<OciUploadState, AppError> {
        validate_repository_name(repository)?;
        let uuid = uuid_v4();
        let state = OciUploadState {
            repository: repository.to_string(),
            uuid,
            size: 0,
            sha256: None,
        };
        let _guard = self.write_lock.lock().await;
        self.metadata.create_oci_upload(state.clone()).await?;
        Ok(state)
    }

    pub async fn append_upload(
        &self,
        repository: &str,
        uuid: &str,
        chunk: Bytes,
    ) -> Result<OciUploadState, AppError> {
        let mut state = self.read_upload_state(repository, uuid).await?;
        let _guard = self.write_lock.lock().await;
        let mut content = self.read_upload_content(&state).await?;
        content.extend_from_slice(&chunk);
        state.size += chunk.len() as u64;
        state.sha256 = Some(hex::encode(self.store_content_object(&content).await?));
        self.metadata.update_oci_upload(state.clone()).await?;
        Ok(state)
    }

    pub async fn finish_upload(
        &self,
        repository: &str,
        uuid: &str,
        digest: &str,
        final_chunk: Bytes,
    ) -> Result<OciBlob, AppError> {
        validate_digest(digest)?;
        let state = self.read_upload_state(repository, uuid).await?;
        let mut content = self.read_upload_content(&state).await?;
        content.extend_from_slice(&final_chunk);
        let calculated = sha256_digest(&content);
        if calculated != digest {
            return Err(AppError::BadRequest(format!(
                "digest mismatch: calculated '{calculated}' but request specified '{digest}'"
            )));
        }

        let _guard = self.write_lock.lock().await;
        self.store_content_object(&content).await?;
        self.metadata
            .store_oci_object(oci_object(
                digest,
                content.len() as u64,
                "application/octet-stream",
                "blob",
            ))
            .await?;
        self.metadata
            .delete_oci_upload(repository, &state.uuid)
            .await?;
        Ok(OciBlob {
            content,
            digest: digest.to_string(),
        })
    }

    pub async fn store_blob(
        &self,
        repository: &str,
        digest: &str,
        content: Bytes,
    ) -> Result<OciBlob, AppError> {
        validate_repository_name(repository)?;
        validate_digest(digest)?;
        let calculated = sha256_digest(&content);
        if calculated != digest {
            return Err(AppError::BadRequest(format!(
                "digest mismatch: calculated '{calculated}' but request specified '{digest}'"
            )));
        }
        let _guard = self.write_lock.lock().await;
        self.store_content_object(&content).await?;
        self.metadata
            .store_oci_object(oci_object(
                digest,
                content.len() as u64,
                "application/octet-stream",
                "blob",
            ))
            .await?;
        Ok(OciBlob {
            content: content.to_vec(),
            digest: digest.to_string(),
        })
    }

    pub async fn read_blob(&self, repository: &str, digest: &str) -> Result<OciBlob, AppError> {
        validate_repository_name(repository)?;
        validate_digest(digest)?;
        let content = self
            .objects
            .read(&digest_sha256_bytes(digest)?)
            .await
            .map_err(|error| {
                if matches!(error, AppError::NotFound(_)) {
                    AppError::NotFound(format!("unknown OCI blob '{digest}'"))
                } else {
                    error
                }
            })?;
        Ok(OciBlob {
            content,
            digest: digest.to_string(),
        })
    }

    pub async fn store_manifest(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        content: Bytes,
    ) -> Result<OciManifest, AppError> {
        validate_repository_name(repository)?;
        validate_reference(reference)?;
        let digest = sha256_digest(&content);
        if is_digest(reference) && reference != digest {
            return Err(AppError::BadRequest(format!(
                "digest mismatch: calculated '{digest}' but request specified '{reference}'"
            )));
        }
        let media_type = if media_type.is_empty() {
            "application/vnd.oci.image.manifest.v1+json"
        } else {
            media_type
        };
        let _guard = self.write_lock.lock().await;
        self.store_content_object(&content).await?;
        self.metadata
            .store_oci_object(oci_object(
                &digest,
                content.len() as u64,
                media_type,
                kind_for_media_type(media_type),
            ))
            .await?;
        let bundle = self
            .materialize_bundle(&digest, media_type, &content)
            .await?;
        for object in &bundle.objects {
            self.metadata.store_oci_object(object.clone()).await?;
        }
        self.metadata.store_oci_bundle(bundle).await?;
        self.metadata
            .store_oci_manifest(OciManifestRecord {
                repository: repository.to_string(),
                digest: digest.clone(),
                media_type: media_type.to_string(),
            })
            .await?;

        if !is_digest(reference) {
            self.metadata
                .store_oci_tag(OciTagRecord {
                    repository: repository.to_string(),
                    tag: reference.to_string(),
                    digest: digest.clone(),
                })
                .await?;
        }

        Ok(OciManifest {
            content: content.to_vec(),
            digest,
            media_type: media_type.to_string(),
        })
    }

    pub async fn read_manifest(
        &self,
        repository: &str,
        reference: &str,
    ) -> Result<OciManifest, AppError> {
        validate_repository_name(repository)?;
        validate_reference(reference)?;
        let digest = if is_digest(reference) {
            reference.to_string()
        } else {
            self.metadata.oci_tag(repository, reference).await?.digest
        };
        validate_digest(&digest)?;
        let manifest = self.metadata.oci_manifest(repository, &digest).await?;
        let content = self
            .objects
            .read(&digest_sha256_bytes(&digest)?)
            .await
            .map_err(|error| {
                if matches!(error, AppError::NotFound(_)) {
                    AppError::NotFound(format!("unknown OCI manifest '{repository}@{digest}'"))
                } else {
                    error
                }
            })?;
        Ok(OciManifest {
            content,
            digest,
            media_type: manifest.media_type,
        })
    }

    pub async fn list_tags(&self, repository: &str) -> Result<Vec<String>, AppError> {
        validate_repository_name(repository)?;
        self.metadata.list_oci_tags(repository).await
    }

    pub async fn migrate_metadata(
        &self,
        limit: usize,
    ) -> Result<OciMetadataMigrationReport, AppError> {
        let existing_bundles = self
            .metadata
            .list_oci_bundles()
            .await?
            .into_iter()
            .map(|bundle| bundle.digest)
            .collect::<BTreeSet<_>>();
        let tags_by_digest = self
            .metadata
            .list_oci_tag_records()
            .await?
            .into_iter()
            .fold(BTreeMap::<String, Vec<String>>::new(), |mut tags, tag| {
                tags.entry(tag.digest)
                    .or_default()
                    .push(format!("{}:{}", tag.repository, tag.tag));
                tags
            });
        let mut pending = self
            .metadata
            .list_oci_manifests()
            .await?
            .into_iter()
            .filter(|manifest| !existing_bundles.contains(&manifest.digest))
            .fold(BTreeMap::new(), |mut manifests, manifest| {
                manifests.entry(manifest.digest.clone()).or_insert(manifest);
                manifests
            })
            .into_values()
            .collect::<Vec<_>>();
        pending.sort_by(|left, right| {
            left.repository
                .cmp(&right.repository)
                .then_with(|| left.digest.cmp(&right.digest))
        });
        let initial_pending = pending.len();
        debug!(
            limit,
            pending = initial_pending,
            existing_bundles = existing_bundles.len(),
            "starting OCI metadata migration batch"
        );

        let mut converted = 0;
        let mut failed = 0;
        let mut incomplete = 0;
        let mut errors = Vec::new();
        for manifest in pending.into_iter().take(limit) {
            match self.migrate_manifest_metadata(&manifest).await {
                Ok(bundle) => {
                    converted += 1;
                    let tags = tags_by_digest
                        .get(&manifest.digest)
                        .cloned()
                        .unwrap_or_default();
                    if bundle.status == "incomplete" {
                        incomplete += 1;
                    }
                    info!(
                        repository = %manifest.repository,
                        digest = %bundle.digest,
                        created = ?bundle.created,
                        status = %bundle.status,
                        object_count = bundle.objects.len(),
                        missing_object_count = bundle.missing_objects.len(),
                        tag_count = tags.len(),
                        tags = ?tags,
                        "converted OCI metadata for manifest"
                    );
                }
                Err(error) => {
                    failed += 1;
                    let tags = tags_by_digest
                        .get(&manifest.digest)
                        .cloned()
                        .unwrap_or_default();
                    warn!(
                        repository = %manifest.repository,
                        digest = %manifest.digest,
                        tag_count = tags.len(),
                        tags = ?tags,
                        error = %error,
                        "failed to convert OCI metadata for manifest"
                    );
                    errors.push(OciMetadataMigrationError {
                        repository: manifest.repository,
                        digest: manifest.digest,
                        error: error.to_string(),
                    });
                }
            }
        }
        let report = OciMetadataMigrationReport {
            converted,
            failed,
            remaining: initial_pending.saturating_sub(converted),
            incomplete,
            errors,
        };
        info!(
            converted = report.converted,
            failed = report.failed,
            remaining = report.remaining,
            incomplete = report.incomplete,
            "finished OCI metadata migration batch"
        );
        Ok(report)
    }

    async fn read_upload_state(
        &self,
        repository: &str,
        uuid: &str,
    ) -> Result<OciUploadState, AppError> {
        validate_repository_name(repository)?;
        validate_uuid(uuid)?;
        self.metadata.oci_upload(repository, uuid).await
    }

    async fn read_upload_content(&self, state: &OciUploadState) -> Result<Vec<u8>, AppError> {
        let Some(sha256) = state.sha256.as_deref() else {
            return Ok(Vec::new());
        };
        self.objects.read(&sha256_bytes(sha256)?).await
    }

    async fn store_content_object(&self, content: &[u8]) -> Result<[u8; 32], AppError> {
        let mut writer = self.objects.create_writer().await?;
        if let Err(error) = writer.write_chunk(content).await {
            writer.abort().await?;
            return Err(error);
        }
        writer.commit().await
    }

    async fn migrate_manifest_metadata(
        &self,
        manifest: &OciManifestRecord,
    ) -> Result<OciBundleRecord, AppError> {
        let sha256 = digest_sha256_bytes(&manifest.digest)?;
        let content = self.objects.read(&sha256).await.map_err(|error| {
            if matches!(error, AppError::NotFound(_)) {
                AppError::NotFound(format!(
                    "root OCI manifest '{}' is missing from object storage",
                    manifest.digest
                ))
            } else {
                error
            }
        })?;
        let bundle = self
            .materialize_bundle(&manifest.digest, &manifest.media_type, &content)
            .await?;
        for object in &bundle.objects {
            self.metadata.store_oci_object(object.clone()).await?;
        }
        self.metadata.store_oci_bundle(bundle.clone()).await?;
        Ok(bundle)
    }

    async fn materialize_bundle(
        &self,
        digest: &str,
        media_type: &str,
        content: &[u8],
    ) -> Result<OciBundleRecord, AppError> {
        let mut objects = BTreeMap::from([(
            digest.to_string(),
            oci_object(
                digest,
                content.len() as u64,
                media_type,
                kind_for_media_type(media_type),
            ),
        )]);
        let mut missing_objects = BTreeMap::new();
        let mut created = None;
        self.collect_manifest_objects(content, &mut objects, &mut missing_objects, &mut created)
            .await?;
        Ok(OciBundleRecord {
            digest: digest.to_string(),
            root_manifest_digest: digest.to_string(),
            root_media_type: media_type.to_string(),
            created,
            status: if missing_objects.is_empty() {
                "complete".to_string()
            } else {
                "incomplete".to_string()
            },
            objects: objects.into_values().collect(),
            missing_objects: missing_objects.into_values().collect(),
        })
    }

    async fn collect_manifest_objects(
        &self,
        content: &[u8],
        objects: &mut BTreeMap<String, OciObjectRecord>,
        missing_objects: &mut BTreeMap<String, OciMissingObjectRecord>,
        created: &mut Option<DateTime<Utc>>,
    ) -> Result<(), AppError> {
        let manifest: OciManifestDocument = serde_json::from_slice(content).map_err(|error| {
            AppError::BadRequest(format!(
                "failed to decode OCI manifest descriptors: {error}"
            ))
        })?;
        for descriptor in manifest.descriptors() {
            let media_type = descriptor
                .media_type
                .as_deref()
                .unwrap_or("application/octet-stream");
            let kind = kind_for_media_type(media_type);
            let already_seen = objects.contains_key(&descriptor.digest);
            objects.entry(descriptor.digest.clone()).or_insert_with(|| {
                oci_object(&descriptor.digest, descriptor.size, media_type, kind)
            });
            if kind == "config" {
                let sha256 = digest_sha256_bytes(&descriptor.digest)?;
                match self.objects.read(&sha256).await {
                    Ok(config_content) => update_created_from_config(created, &config_content),
                    Err(AppError::NotFound(_)) => {}
                    Err(error) => return Err(error),
                }
            } else if matches!(kind, "manifest" | "index") {
                if already_seen {
                    continue;
                }
                let sha256 = digest_sha256_bytes(&descriptor.digest)?;
                match self.objects.read(&sha256).await {
                    Ok(child_content) => {
                        Box::pin(self.collect_manifest_objects(
                            &child_content,
                            objects,
                            missing_objects,
                            created,
                        ))
                        .await?;
                    }
                    Err(AppError::NotFound(_)) => {
                        missing_objects.insert(
                            descriptor.digest.clone(),
                            OciMissingObjectRecord {
                                digest: descriptor.digest.clone(),
                                media_type: media_type.to_string(),
                                kind: kind.to_string(),
                            },
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }
}

fn oci_object(digest: &str, size: u64, media_type: &str, kind: &str) -> OciObjectRecord {
    OciObjectRecord {
        digest: digest.to_string(),
        size,
        media_type: media_type.to_string(),
        kind: kind.to_string(),
    }
}

fn kind_for_media_type(media_type: &str) -> &'static str {
    if media_type.contains("image.index") || media_type.contains("manifest.list") {
        "index"
    } else if media_type.contains("manifest") {
        "manifest"
    } else if media_type.contains("config") {
        "config"
    } else if media_type.contains("layer") {
        "layer"
    } else {
        "object"
    }
}

#[derive(Deserialize)]
struct OciManifestDocument {
    config: Option<OciDescriptor>,
    #[serde(default)]
    layers: Vec<OciDescriptor>,
    #[serde(default)]
    manifests: Vec<OciDescriptor>,
}

impl OciManifestDocument {
    fn descriptors(self) -> impl Iterator<Item = OciDescriptor> {
        self.config
            .into_iter()
            .chain(self.layers)
            .chain(self.manifests)
    }
}

#[derive(Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
    size: u64,
}

#[derive(Deserialize)]
struct OciImageConfigDocument {
    created: Option<DateTime<Utc>>,
}

fn update_created_from_config(latest: &mut Option<DateTime<Utc>>, content: &[u8]) {
    let Ok(config) = serde_json::from_slice::<OciImageConfigDocument>(content) else {
        return;
    };
    let Some(created) = config.created else {
        return;
    };
    if latest.as_ref().is_none_or(|current| current < &created) {
        *latest = Some(created);
    }
}

pub fn validate_repository_name(repository: &str) -> Result<(), AppError> {
    if is_valid_repository_name(repository) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "'{repository}' is not a valid OCI repository name"
        )))
    }
}

pub fn is_valid_repository_name(repository: &str) -> bool {
    !repository.is_empty()
        && repository.len() <= 255
        && repository
            .split('/')
            .all(|component| !component.is_empty() && is_valid_repository_component(component))
}

fn is_valid_repository_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_reference(reference: &str) -> Result<(), AppError> {
    if is_digest(reference) {
        validate_digest(reference)
    } else {
        validate_tag(reference)
    }
}

fn validate_tag(tag: &str) -> Result<(), AppError> {
    let bytes = tag.as_bytes();
    if tag.is_empty()
        || tag.len() > 128
        || matches!(bytes.first(), Some(b'.' | b'-'))
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest(format!(
            "'{tag}' is not a valid OCI tag"
        )));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), AppError> {
    split_digest(digest).map(|_| ())
}

fn split_digest(digest: &str) -> Result<(&str, &str), AppError> {
    let Some((algorithm, encoded)) = digest.split_once(':') else {
        return Err(AppError::BadRequest(format!(
            "'{digest}' is not a valid OCI digest"
        )));
    };
    if algorithm != "sha256"
        || encoded.len() != 64
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AppError::BadRequest(format!(
            "'{digest}' is not a supported OCI digest"
        )));
    }
    Ok((algorithm, encoded))
}

fn is_digest(reference: &str) -> bool {
    reference.starts_with("sha256:")
}

fn sha256_digest(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn sha256_bytes(hex_digest: &str) -> Result<[u8; 32], AppError> {
    let bytes = hex::decode(hex_digest).map_err(|error| {
        AppError::Internal(format!(
            "failed to decode OCI upload digest '{hex_digest}': {error}"
        ))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::Internal(format!(
            "invalid OCI upload digest '{hex_digest}': expected 32 bytes, got {}",
            bytes.len()
        ))
    })
}

fn uuid_v4() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = UPLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(now.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(
        std::thread::current()
            .name()
            .unwrap_or("reposnake")
            .as_bytes(),
    );
    let mut bytes = hasher.finalize()[..16].to_vec();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn validate_uuid(uuid: &str) -> Result<(), AppError> {
    if !uuid.is_empty()
        && uuid
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        Ok(())
    } else {
        Err(AppError::BadRequest("invalid OCI upload UUID".to_string()))
    }
}

fn digest_sha256_bytes(digest: &str) -> Result<[u8; 32], AppError> {
    let (_algorithm, encoded) = split_digest(digest)?;
    let bytes = hex::decode(encoded).map_err(|error| {
        AppError::Internal(format!("failed to decode OCI digest '{digest}': {error}"))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::Internal(format!(
            "invalid OCI digest '{digest}': expected 32 bytes, got {}",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{OciRegistry, is_valid_repository_name};
    use crate::metadata::FilesystemMetadataStore;
    #[cfg(feature = "surrealdb")]
    use crate::metadata::SurrealMetadataStore;
    use crate::object_store::FilesystemObjectStore;
    use crate::package::UploadPackage;
    use crate::repository::PackageRepository;
    use sha2::{Digest as _, Sha256};
    use std::sync::Arc;

    #[test]
    fn validates_repository_names() {
        assert!(is_valid_repository_name("library/alpine"));
        assert!(is_valid_repository_name("team/image.name"));
        assert!(!is_valid_repository_name("Team/Image"));
        assert!(!is_valid_repository_name("../image"));
        assert!(!is_valid_repository_name("team//image"));
    }

    #[cfg(feature = "surrealdb")]
    #[tokio::test]
    async fn stores_blob_and_manifest() {
        let tempdir = tempfile::tempdir().unwrap();
        let metadata = Arc::new(SurrealMetadataStore::in_memory().await.unwrap());
        let objects = Arc::new(FilesystemObjectStore::new(tempdir.path().join("objects")));
        let registry = OciRegistry::new(metadata, objects);
        let blob = registry
            .store_blob(
                "team/image",
                "sha256:dac1d7cfa95021764849fd102524e141488c5e3a90f861dbb5a12d9ac8584f85",
                "layer".into(),
            )
            .await
            .unwrap();
        assert_eq!(blob.content, b"layer");

        let manifest = registry
            .store_manifest(
                "team/image",
                "latest",
                "application/vnd.oci.image.manifest.v1+json",
                "{}".into(),
            )
            .await
            .unwrap();
        let read = registry
            .read_manifest("team/image", "latest")
            .await
            .unwrap();
        assert_eq!(read.digest, manifest.digest);
        assert_eq!(read.content, b"{}");
    }

    #[tokio::test]
    async fn filesystem_metadata_persists_manifest_references() {
        let tempdir = tempfile::tempdir().unwrap();
        let metadata = Arc::new(FilesystemMetadataStore::new(
            tempdir.path().join("metadata"),
        ));
        let objects = Arc::new(FilesystemObjectStore::new(tempdir.path().join("objects")));
        let registry = OciRegistry::new(metadata, objects.clone());

        let manifest = registry
            .store_manifest(
                "team/image",
                "latest",
                "application/vnd.oci.image.manifest.v1+json",
                "{}".into(),
            )
            .await
            .unwrap();

        let reopened_metadata = Arc::new(FilesystemMetadataStore::new(
            tempdir.path().join("metadata"),
        ));
        let reopened = OciRegistry::new(reopened_metadata, objects);
        let read = reopened
            .read_manifest("team/image", "latest")
            .await
            .unwrap();

        assert_eq!(read.digest, manifest.digest);
        assert_eq!(read.content, b"{}");
        assert_eq!(
            read.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
    }

    #[tokio::test]
    async fn python_packages_and_oci_blobs_share_content_addressed_objects() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let object_root = tempdir.path().join("objects");
        let metadata = Arc::new(FilesystemMetadataStore::new(
            tempdir.path().join("metadata"),
        ));
        let objects = Arc::new(FilesystemObjectStore::new(&object_root));
        let repository = PackageRepository::from_stores(metadata.clone(), objects.clone());
        let registry = OciRegistry::new(metadata, objects);
        let content = b"shared-content".to_vec();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&content)));

        repository
            .store_upload(UploadPackage {
                name: "reposnake-demo".to_string(),
                version: "0.1.0".to_string(),
                filename: "reposnake_demo-0.1.0.tar.gz".to_string(),
                content: content.clone(),
                provided_sha256: None,
                has_any_digest: true,
                requires_python: None,
            })
            .await?;
        registry
            .store_blob("team/image", &digest, content.clone().into())
            .await?;

        let mut entries = tokio::fs::read_dir(&object_root).await?;
        let mut object_count = 0;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                object_count += 1;
                assert_eq!(tokio::fs::read(entry.path()).await?, content);
            }
        }

        assert_eq!(object_count, 1);
        Ok(())
    }
}
