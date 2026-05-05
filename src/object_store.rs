// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

pub type SharedObjectStore = Arc<dyn ObjectStore>;
static TEMP_OBJECT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[async_trait]
pub trait ObjectStore: fmt::Debug + Send + Sync {
    async fn read(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, AppError>;
    async fn create_writer(&self) -> Result<Box<dyn ObjectWriter>, AppError>;
    async fn delete_if_exists(&self, sha256: &[u8; 32]) -> Result<(), AppError>;
}

#[async_trait]
pub trait ObjectWriter: Send {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AppError>;
    async fn commit(self: Box<Self>) -> Result<[u8; 32], AppError>;
    async fn abort(self: Box<Self>) -> Result<(), AppError>;
}

#[derive(Debug)]
pub struct FilesystemObjectStore {
    root: PathBuf,
}

impl FilesystemObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn object_path(&self, sha256: &[u8; 32]) -> PathBuf {
        self.root.join(hex::encode(sha256))
    }

    fn temp_path(&self) -> PathBuf {
        self.root
            .join(format!(".reposnake-tmp-{}", next_temp_object_id()))
    }
}

#[async_trait]
impl ObjectStore for FilesystemObjectStore {
    async fn read(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        let path = self.object_path(sha256);
        tokio::fs::read(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("object '{}' not found", hex::encode(sha256)))
            } else {
                AppError::Internal(format!(
                    "failed to read object '{}': {error}",
                    path.display()
                ))
            }
        })
    }

    async fn create_writer(&self) -> Result<Box<dyn ObjectWriter>, AppError> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to create object directory '{}': {error}",
                    self.root.display()
                ))
            })?;

        let temp_path = self.temp_path();
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to create temporary object '{}': {error}",
                    temp_path.display()
                ))
            })?;
        Ok(Box::new(FilesystemObjectWriter {
            root: self.root.clone(),
            temp_path,
            file: Some(file),
            hasher: Sha256::new(),
        }))
    }

    async fn delete_if_exists(&self, sha256: &[u8; 32]) -> Result<(), AppError> {
        let path = self.object_path(sha256);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::Internal(format!(
                "failed to remove object '{}': {error}",
                path.display()
            ))),
        }
    }
}

struct FilesystemObjectWriter {
    root: PathBuf,
    temp_path: PathBuf,
    file: Option<tokio::fs::File>,
    hasher: Sha256,
}

#[async_trait]
impl ObjectWriter for FilesystemObjectWriter {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| AppError::Internal("object writer is already closed".to_string()))?;
        self.hasher.update(chunk);
        file.write_all(chunk).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to write temporary object '{}': {error}",
                self.temp_path.display()
            ))
        })
    }

    async fn commit(mut self: Box<Self>) -> Result<[u8; 32], AppError> {
        if let Some(mut file) = self.file.take() {
            file.flush().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to flush temporary object '{}': {error}",
                    self.temp_path.display()
                ))
            })?;
            file.sync_all().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to sync temporary object '{}': {error}",
                    self.temp_path.display()
                ))
            })?;
        }

        let sha256 = self.hasher.clone().finalize().into();
        let path = self.root.join(hex::encode(sha256));
        if tokio::fs::try_exists(&path).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to check object '{}': {error}",
                path.display()
            ))
        })? {
            self.abort().await?;
            return Ok(sha256);
        }

        match tokio::fs::rename(&self.temp_path, &path).await {
            Ok(()) => Ok(sha256),
            Err(error) => {
                let temp_path = self.temp_path.clone();
                self.abort().await?;
                Err(AppError::Internal(format!(
                    "failed to commit object '{}': {error}",
                    temp_path.display()
                )))
            }
        }
    }

    async fn abort(mut self: Box<Self>) -> Result<(), AppError> {
        self.file.take();
        match tokio::fs::remove_file(&self.temp_path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::Internal(format!(
                "failed to remove temporary object '{}': {error}",
                self.temp_path.display()
            ))),
        }
    }
}

fn next_temp_object_id() -> u64 {
    TEMP_OBJECT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{FilesystemObjectStore, ObjectStore};
    use sha2::{Digest as _, Sha256};

    #[tokio::test]
    async fn writer_commits_by_content_digest_and_deduplicates() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemObjectStore::new(tempdir.path());
        let content = b"package-content";
        let expected: [u8; 32] = Sha256::digest(content).into();

        let mut writer = store.create_writer().await?;
        writer.write_chunk(b"package-").await?;
        writer.write_chunk(b"content").await?;
        let digest = writer.commit().await?;

        assert_eq!(digest, expected);
        assert_eq!(
            tokio::fs::read(tempdir.path().join(hex::encode(expected))).await?,
            content
        );

        let mut duplicate = store.create_writer().await?;
        duplicate.write_chunk(content).await?;
        let duplicate_digest = duplicate.commit().await?;

        assert_eq!(duplicate_digest, expected);
        let mut entries = tokio::fs::read_dir(tempdir.path()).await?;
        let mut object_count = 0;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                object_count += 1;
            }
        }
        assert_eq!(object_count, 1);
        Ok(())
    }
}
