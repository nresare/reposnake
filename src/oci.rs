// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use crate::metadata::{OciManifestRecord, OciTagRecord, OciUploadState, SharedMetadataStore};
use crate::object_store::SharedObjectStore;
use axum::body::Bytes;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

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
            content: Vec::new(),
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
        state.content.extend_from_slice(&chunk);
        state.size += chunk.len() as u64;
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
        let state = self.append_upload(repository, uuid, final_chunk).await?;
        let content = state.content;
        let calculated = sha256_digest(&content);
        if calculated != digest {
            return Err(AppError::BadRequest(format!(
                "digest mismatch: calculated '{calculated}' but request specified '{digest}'"
            )));
        }

        let _guard = self.write_lock.lock().await;
        self.store_content_object(&content).await?;
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

    async fn read_upload_state(
        &self,
        repository: &str,
        uuid: &str,
    ) -> Result<OciUploadState, AppError> {
        validate_repository_name(repository)?;
        validate_uuid(uuid)?;
        self.metadata.oci_upload(repository, uuid).await
    }

    async fn store_content_object(&self, content: &[u8]) -> Result<[u8; 32], AppError> {
        let mut writer = self.objects.create_writer().await?;
        if let Err(error) = writer.write_chunk(content).await {
            writer.abort().await?;
            return Err(error);
        }
        writer.commit().await
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
}
