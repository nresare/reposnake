// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use axum::body::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub const DOCKER_DISTRIBUTION_API_VERSION: &str = "registry/2.0";
static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct OciRegistry {
    root: Arc<PathBuf>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadState {
    pub repository: String,
    pub uuid: String,
    pub size: u64,
}

impl OciRegistry {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Arc::new(root.into()),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn start_upload(&self, repository: &str) -> Result<UploadState, AppError> {
        validate_repository_name(repository)?;
        let uuid = uuid_v4();
        let state = UploadState {
            repository: repository.to_string(),
            uuid,
            size: 0,
        };
        let _guard = self.write_lock.lock().await;
        tokio::fs::create_dir_all(self.uploads_dir())
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to create OCI upload storage: {error}"))
            })?;
        tokio::fs::write(
            self.upload_state_path(&state.uuid),
            serialize_state(&state)?,
        )
        .await
        .map_err(|error| {
            AppError::Internal(format!("failed to create OCI upload state: {error}"))
        })?;
        tokio::fs::write(self.upload_content_path(&state.uuid), [])
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to create OCI upload content: {error}"))
            })?;
        Ok(state)
    }

    pub async fn append_upload(
        &self,
        repository: &str,
        uuid: &str,
        chunk: Bytes,
    ) -> Result<UploadState, AppError> {
        let mut state = self.read_upload_state(repository, uuid).await?;
        let _guard = self.write_lock.lock().await;
        let path = self.upload_content_path(uuid);
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to open OCI upload '{}': {error}",
                    path.display()
                ))
            })?;
        file.write_all(&chunk).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to append OCI upload '{}': {error}",
                path.display()
            ))
        })?;
        file.flush().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to flush OCI upload '{}': {error}",
                path.display()
            ))
        })?;
        state.size += chunk.len() as u64;
        tokio::fs::write(self.upload_state_path(uuid), serialize_state(&state)?)
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to update OCI upload state: {error}"))
            })?;
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
        let content = tokio::fs::read(self.upload_content_path(&state.uuid))
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to read OCI upload content: {error}"))
            })?;
        let calculated = sha256_digest(&content);
        if calculated != digest {
            return Err(AppError::BadRequest(format!(
                "digest mismatch: calculated '{calculated}' but request specified '{digest}'"
            )));
        }

        let _guard = self.write_lock.lock().await;
        let blob_path = self.blob_path(digest)?;
        if let Some(parent) = blob_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                AppError::Internal(format!("failed to create OCI blob storage: {error}"))
            })?;
        }
        if !path_exists(&blob_path).await? {
            tokio::fs::write(&blob_path, &content)
                .await
                .map_err(|error| {
                    AppError::Internal(format!(
                        "failed to write OCI blob '{}': {error}",
                        blob_path.display()
                    ))
                })?;
        }
        remove_if_exists(self.upload_state_path(&state.uuid)).await?;
        remove_if_exists(self.upload_content_path(&state.uuid)).await?;
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
        let blob_path = self.blob_path(digest)?;
        if let Some(parent) = blob_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                AppError::Internal(format!("failed to create OCI blob storage: {error}"))
            })?;
        }
        tokio::fs::write(&blob_path, &content)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to write OCI blob '{}': {error}",
                    blob_path.display()
                ))
            })?;
        Ok(OciBlob {
            content: content.to_vec(),
            digest: digest.to_string(),
        })
    }

    pub async fn read_blob(&self, repository: &str, digest: &str) -> Result<OciBlob, AppError> {
        validate_repository_name(repository)?;
        validate_digest(digest)?;
        let path = self.blob_path(digest)?;
        let content = tokio::fs::read(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("unknown OCI blob '{digest}'"))
            } else {
                AppError::Internal(format!(
                    "failed to read OCI blob '{}': {error}",
                    path.display()
                ))
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
        let manifest_path = self.manifest_path(repository, &digest)?;
        if let Some(parent) = manifest_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                AppError::Internal(format!("failed to create OCI manifest storage: {error}"))
            })?;
        }
        tokio::fs::write(&manifest_path, &content)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to write OCI manifest '{}': {error}",
                    manifest_path.display()
                ))
            })?;
        let media_type_path = self.manifest_media_type_path(repository, &digest)?;
        if let Some(parent) = media_type_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to create OCI manifest media type storage: {error}"
                ))
            })?;
        }
        tokio::fs::write(media_type_path, media_type)
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to write OCI manifest media type: {error}"))
            })?;

        if !is_digest(reference) {
            let tag_path = self.tag_path(repository, reference)?;
            if let Some(parent) = tag_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|error| {
                    AppError::Internal(format!("failed to create OCI tag storage: {error}"))
                })?;
            }
            tokio::fs::write(tag_path, &digest)
                .await
                .map_err(|error| AppError::Internal(format!("failed to write OCI tag: {error}")))?;
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
            let tag_path = self.tag_path(repository, reference)?;
            tokio::fs::read_to_string(&tag_path)
                .await
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        AppError::NotFound(format!("unknown OCI tag '{repository}:{reference}'"))
                    } else {
                        AppError::Internal(format!(
                            "failed to read OCI tag '{}': {error}",
                            tag_path.display()
                        ))
                    }
                })?
        };
        validate_digest(&digest)?;
        let path = self.manifest_path(repository, &digest)?;
        let content = tokio::fs::read(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("unknown OCI manifest '{repository}@{digest}'"))
            } else {
                AppError::Internal(format!(
                    "failed to read OCI manifest '{}': {error}",
                    path.display()
                ))
            }
        })?;
        let media_type =
            tokio::fs::read_to_string(self.manifest_media_type_path(repository, &digest)?)
                .await
                .unwrap_or_else(|_| "application/vnd.oci.image.manifest.v1+json".to_string());
        Ok(OciManifest {
            content,
            digest,
            media_type,
        })
    }

    async fn read_upload_state(
        &self,
        repository: &str,
        uuid: &str,
    ) -> Result<UploadState, AppError> {
        validate_repository_name(repository)?;
        validate_uuid(uuid)?;
        let path = self.upload_state_path(uuid);
        let content = tokio::fs::read_to_string(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("unknown OCI upload '{uuid}'"))
            } else {
                AppError::Internal(format!(
                    "failed to read OCI upload state '{}': {error}",
                    path.display()
                ))
            }
        })?;
        let state: UploadState = serde_json::from_str(&content).map_err(|error| {
            AppError::Internal(format!("failed to parse OCI upload state: {error}"))
        })?;
        if state.repository != repository {
            return Err(AppError::NotFound(format!("unknown OCI upload '{uuid}'")));
        }
        Ok(state)
    }

    fn uploads_dir(&self) -> PathBuf {
        self.root.join("oci").join("uploads")
    }

    fn upload_state_path(&self, uuid: &str) -> PathBuf {
        self.uploads_dir().join(format!("{uuid}.json"))
    }

    fn upload_content_path(&self, uuid: &str) -> PathBuf {
        self.uploads_dir().join(format!("{uuid}.bin"))
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("oci").join("blobs")
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf, AppError> {
        let (_algorithm, encoded) = split_digest(digest)?;
        Ok(self.blobs_dir().join("sha256").join(encoded))
    }

    fn repository_dir(&self, repository: &str) -> Result<PathBuf, AppError> {
        validate_repository_name(repository)?;
        Ok(self
            .root
            .join("oci")
            .join("repositories")
            .join(repository.replace('/', "__")))
    }

    fn manifest_path(&self, repository: &str, digest: &str) -> Result<PathBuf, AppError> {
        let (_algorithm, encoded) = split_digest(digest)?;
        Ok(self
            .repository_dir(repository)?
            .join("manifests")
            .join(encoded))
    }

    fn manifest_media_type_path(
        &self,
        repository: &str,
        digest: &str,
    ) -> Result<PathBuf, AppError> {
        let (_algorithm, encoded) = split_digest(digest)?;
        Ok(self
            .repository_dir(repository)?
            .join("manifest-media-types")
            .join(encoded))
    }

    fn tag_path(&self, repository: &str, tag: &str) -> Result<PathBuf, AppError> {
        validate_tag(tag)?;
        Ok(self.repository_dir(repository)?.join("tags").join(tag))
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

fn serialize_state(state: &UploadState) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(state).map_err(|error| {
        AppError::Internal(format!("failed to serialize OCI upload state: {error}"))
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

async fn path_exists(path: &Path) -> Result<bool, AppError> {
    tokio::fs::try_exists(path).await.map_err(|error| {
        AppError::Internal(format!(
            "failed to check path '{}': {error}",
            path.display()
        ))
    })
}

async fn remove_if_exists(path: PathBuf) -> Result<(), AppError> {
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::Internal(format!(
            "failed to remove '{}': {error}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{OciRegistry, is_valid_repository_name};

    #[test]
    fn validates_repository_names() {
        assert!(is_valid_repository_name("library/alpine"));
        assert!(is_valid_repository_name("team/image.name"));
        assert!(!is_valid_repository_name("Team/Image"));
        assert!(!is_valid_repository_name("../image"));
        assert!(!is_valid_repository_name("team//image"));
    }

    #[tokio::test]
    async fn stores_blob_and_manifest() {
        let tempdir = tempfile::tempdir().unwrap();
        let registry = OciRegistry::new(tempdir.path());
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
}
