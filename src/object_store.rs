// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::{ObjectCacheConfig, ObjectStoreBackend, ObjectStoreConfig};
use crate::error::AppError;
use anyhow::Context;
use async_trait::async_trait;
use filetime::FileTime;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

pub type SharedObjectStore = Arc<dyn ObjectStore>;
static TEMP_OBJECT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMigrationStats {
    pub copied: usize,
    pub skipped: usize,
}

pub async fn build_object_store(config: &ObjectStoreConfig) -> anyhow::Result<SharedObjectStore> {
    build_object_store_with_cache(config, &ObjectCacheConfig::default()).await
}

pub async fn build_object_store_with_cache(
    config: &ObjectStoreConfig,
    cache: &ObjectCacheConfig,
) -> anyhow::Result<SharedObjectStore> {
    match config.backend {
        ObjectStoreBackend::Filesystem => {
            let directory = config.directory.as_ref().ok_or_else(|| {
                anyhow::anyhow!("object-store.directory is required when backend is filesystem")
            })?;
            Ok(Arc::new(FilesystemObjectStore::new(
                directory.join("objects"),
            )))
        }
        ObjectStoreBackend::S3 => build_s3_object_store(config, cache).await,
    }
}

pub async fn migrate_filesystem_objects_to_store(
    storage_root: impl Into<PathBuf>,
    destination: &dyn ObjectStore,
) -> anyhow::Result<ObjectMigrationStats> {
    let object_root = storage_root.into().join("objects");
    let mut entries = match tokio::fs::read_dir(&object_root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!(
                object_directory = %object_root.display(),
                "no filesystem objects to migrate"
            );
            return Ok(ObjectMigrationStats::default());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read filesystem object directory '{}'",
                    object_root.display()
                )
            });
        }
    };

    let mut stats = ObjectMigrationStats::default();
    while let Some(entry) = entries.next_entry().await.with_context(|| {
        format!(
            "failed to read filesystem object directory '{}'",
            object_root.display()
        )
    })? {
        if !entry
            .file_type()
            .await
            .with_context(|| format!("failed to inspect '{}'", entry.path().display()))?
            .is_file()
        {
            stats.skipped += 1;
            continue;
        }

        let Some(expected_sha256) = object_digest_from_filename(&entry.file_name()) else {
            stats.skipped += 1;
            warn!(
                path = %entry.path().display(),
                "skipping filesystem object with invalid digest filename"
            );
            continue;
        };

        let content = tokio::fs::read(entry.path()).await.with_context(|| {
            format!(
                "failed to read filesystem object '{}'",
                entry.path().display()
            )
        })?;
        let actual_sha256: [u8; 32] = Sha256::digest(&content).into();
        if actual_sha256 != expected_sha256 {
            stats.skipped += 1;
            warn!(
                path = %entry.path().display(),
                expected = %hex::encode(expected_sha256),
                actual = %hex::encode(actual_sha256),
                "skipping filesystem object whose content digest does not match its filename"
            );
            continue;
        }

        let mut writer = destination
            .create_writer()
            .await
            .map_err(|error| anyhow::anyhow!("failed to create migrated object writer: {error}"))?;
        writer
            .write_chunk(&content)
            .await
            .map_err(|error| anyhow::anyhow!("failed to write migrated object: {error}"))?;
        let stored_sha256 = writer
            .commit()
            .await
            .map_err(|error| anyhow::anyhow!("failed to commit migrated object: {error}"))?;
        if stored_sha256 != expected_sha256 {
            anyhow::bail!(
                "migrated object '{}' was stored as unexpected digest '{}'",
                hex::encode(expected_sha256),
                hex::encode(stored_sha256)
            );
        }
        stats.copied += 1;
    }

    info!(
        object_directory = %object_root.display(),
        copied = stats.copied,
        skipped = stats.skipped,
        "migrated filesystem objects to configured object store"
    );
    Ok(stats)
}

async fn build_s3_object_store(
    config: &ObjectStoreConfig,
    cache: &ObjectCacheConfig,
) -> anyhow::Result<SharedObjectStore> {
    #[cfg(feature = "s3")]
    {
        let bucket = config
            .bucket
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("object-store.bucket is required when backend is s3"))?;
        let store: SharedObjectStore =
            Arc::new(crate::s3_object_store::S3ObjectStore::from_bucket(bucket).await?);
        if cache.enabled {
            Ok(Arc::new(CachedObjectStore::new(store, cache.clone())))
        } else {
            Ok(store)
        }
    }
    #[cfg(not(feature = "s3"))]
    {
        let _ = (config, cache);
        anyhow::bail!("object-store.backend = \"s3\" requires the s3 Cargo feature");
    }
}

fn object_digest_from_filename(filename: &std::ffi::OsStr) -> Option<[u8; 32]> {
    let filename = filename.to_str()?;
    if filename.len() != 64 {
        return None;
    }
    let bytes = hex::decode(filename).ok()?;
    bytes.try_into().ok()
}

#[async_trait]
pub trait ObjectStore: fmt::Debug + Send + Sync {
    async fn read(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, AppError>;
    async fn check_availability(&self) -> Result<(), AppError>;
    async fn create_writer(&self) -> Result<Box<dyn ObjectWriter>, AppError>;
    async fn delete_if_exists(&self, sha256: &[u8; 32]) -> Result<(), AppError>;
    async fn list_objects(&self) -> Result<Vec<ObjectMetadata>, AppError>;
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

#[derive(Debug)]
struct CachedObjectStore {
    inner: SharedObjectStore,
    cache: ObjectDiskCache,
}

impl CachedObjectStore {
    fn new(inner: SharedObjectStore, config: ObjectCacheConfig) -> Self {
        Self {
            inner,
            cache: ObjectDiskCache::new(config),
        }
    }
}

#[async_trait]
impl ObjectStore for CachedObjectStore {
    async fn read(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        if let Some(content) = self.cache.read(sha256).await {
            return Ok(content);
        }

        let content = self.inner.read(sha256).await?;
        self.cache.store(sha256, &content).await;
        Ok(content)
    }

    async fn check_availability(&self) -> Result<(), AppError> {
        self.inner.check_availability().await
    }

    async fn create_writer(&self) -> Result<Box<dyn ObjectWriter>, AppError> {
        self.inner.create_writer().await
    }

    async fn delete_if_exists(&self, sha256: &[u8; 32]) -> Result<(), AppError> {
        self.inner.delete_if_exists(sha256).await?;
        self.cache.remove(sha256).await;
        Ok(())
    }

    async fn list_objects(&self) -> Result<Vec<ObjectMetadata>, AppError> {
        self.inner.list_objects().await
    }
}

#[derive(Debug)]
struct ObjectDiskCache {
    root: PathBuf,
    max_file_size: u64,
    max_total_size: u64,
}

#[derive(Debug)]
struct CacheEntry {
    path: PathBuf,
    size: u64,
    last_used: SystemTime,
}

impl ObjectDiskCache {
    fn new(config: ObjectCacheConfig) -> Self {
        Self {
            root: config.directory,
            max_file_size: config.max_file_size,
            max_total_size: config.max_total_size,
        }
    }

    fn object_path(&self, sha256: &[u8; 32]) -> PathBuf {
        self.root.join(hex::encode(sha256))
    }

    fn temp_path(&self) -> PathBuf {
        self.root
            .join(format!(".reposnake-cache-tmp-{}", next_temp_object_id()))
    }

    async fn read(&self, sha256: &[u8; 32]) -> Option<Vec<u8>> {
        let path = self.object_path(sha256);
        let content = match tokio::fs::read(&path).await {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    "failed to read cached object: {error}"
                );
                return None;
            }
        };

        let actual_sha256: [u8; 32] = Sha256::digest(&content).into();
        if &actual_sha256 != sha256 {
            warn!(
                path = %path.display(),
                expected = %hex::encode(sha256),
                actual = %hex::encode(actual_sha256),
                "discarding cached object with mismatched digest"
            );
            if let Err(error) = tokio::fs::remove_file(&path).await
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(path = %path.display(), "failed to remove invalid cached object: {error}");
            }
            return None;
        }

        self.touch(&path).await;
        Some(content)
    }

    async fn store(&self, sha256: &[u8; 32], content: &[u8]) {
        if content.len() as u64 > self.max_file_size {
            return;
        }

        if let Err(error) = tokio::fs::create_dir_all(&self.root).await {
            warn!(
                directory = %self.root.display(),
                "failed to create object cache directory: {error}"
            );
            return;
        }

        let temp_path = self.temp_path();
        if let Err(error) = tokio::fs::write(&temp_path, content).await {
            warn!(
                path = %temp_path.display(),
                "failed to write cached object: {error}"
            );
            return;
        }

        let path = self.object_path(sha256);
        match tokio::fs::rename(&temp_path, &path).await {
            Ok(()) => {
                self.touch(&path).await;
                self.evict().await;
            }
            Err(error) => {
                warn!(
                    path = %path.display(),
                    "failed to commit cached object: {error}"
                );
                if let Err(error) = tokio::fs::remove_file(&temp_path).await
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    warn!(
                        path = %temp_path.display(),
                        "failed to remove temporary cached object: {error}"
                    );
                }
            }
        }
    }

    async fn remove(&self, sha256: &[u8; 32]) {
        let path = self.object_path(sha256);
        if let Err(error) = tokio::fs::remove_file(&path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %path.display(), "failed to remove cached object: {error}");
        }
    }

    async fn touch(&self, path: &std::path::Path) {
        let path = path.to_path_buf();
        if let Err(error) =
            tokio::task::spawn_blocking(move || filetime::set_file_mtime(path, FileTime::now()))
                .await
                .unwrap_or_else(|error| Err(std::io::Error::other(error)))
        {
            warn!("failed to update cached object recency: {error}");
        }
    }

    async fn evict(&self) {
        let mut entries = match self.cache_entries().await {
            Ok(entries) => entries,
            Err(error) => {
                warn!("failed to inspect object cache for eviction: {error}");
                return;
            }
        };
        let mut total_size = entries.iter().map(|entry| entry.size).sum::<u64>();
        if total_size <= self.max_total_size {
            return;
        }

        entries.sort_by_key(|entry| entry.last_used);
        for entry in entries {
            if total_size <= self.max_total_size {
                break;
            }
            match tokio::fs::remove_file(&entry.path).await {
                Ok(()) => total_size = total_size.saturating_sub(entry.size),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    total_size = total_size.saturating_sub(entry.size);
                }
                Err(error) => {
                    warn!(
                        path = %entry.path.display(),
                        "failed to evict cached object: {error}"
                    );
                }
            }
        }
    }

    async fn cache_entries(&self) -> std::io::Result<Vec<CacheEntry>> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut cache_entries = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if object_digest_from_filename(&entry.file_name()).is_none() {
                continue;
            }
            let metadata = entry.metadata().await?;
            if !metadata.is_file() {
                continue;
            }
            cache_entries.push(CacheEntry {
                path: entry.path(),
                size: metadata.len(),
                last_used: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
        Ok(cache_entries)
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

    async fn check_availability(&self) -> Result<(), AppError> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(AppError::Internal(format!(
                    "failed to list object directory '{}': {error}",
                    self.root.display()
                )));
            }
        };
        entries.next_entry().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to read object directory '{}': {error}",
                self.root.display()
            ))
        })?;
        Ok(())
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

    async fn list_objects(&self) -> Result<Vec<ObjectMetadata>, AppError> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(AppError::Internal(format!(
                    "failed to list object directory '{}': {error}",
                    self.root.display()
                )));
            }
        };

        let mut objects = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to read object directory '{}': {error}",
                self.root.display()
            ))
        })? {
            let file_type = entry.file_type().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to inspect object '{}': {error}",
                    entry.path().display()
                ))
            })?;
            if !file_type.is_file() {
                continue;
            }
            let Some(sha256) = object_digest_from_filename(&entry.file_name()).map(hex::encode)
            else {
                continue;
            };
            let metadata = entry.metadata().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to stat object '{}': {error}",
                    entry.path().display()
                ))
            })?;
            objects.push(ObjectMetadata {
                sha256,
                size: metadata.len(),
            });
        }
        objects.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        Ok(objects)
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
    use super::{
        CachedObjectStore, FilesystemObjectStore, ObjectStore, migrate_filesystem_objects_to_store,
    };
    use crate::config::ObjectCacheConfig;
    use crate::error::AppError;
    use async_trait::async_trait;
    use sha2::{Digest as _, Sha256};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

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

    #[tokio::test]
    async fn filesystem_store_availability_check_is_read_only() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let missing_store = FilesystemObjectStore::new(tempdir.path().join("objects"));

        missing_store.check_availability().await?;

        let store = FilesystemObjectStore::new(tempdir.path());
        let first: [u8; 32] = Sha256::digest(b"first").into();
        tokio::fs::create_dir_all(tempdir.path()).await?;
        tokio::fs::write(tempdir.path().join(hex::encode(first)), b"first").await?;
        tokio::fs::write(tempdir.path().join("not-a-digest"), b"ignored").await?;

        store.check_availability().await?;

        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_lists_committed_objects_with_sizes() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemObjectStore::new(tempdir.path());

        let mut writer = store.create_writer().await?;
        writer.write_chunk(b"first").await?;
        let first = hex::encode(writer.commit().await?);
        let mut writer = store.create_writer().await?;
        writer.write_chunk(b"second-object").await?;
        let second = hex::encode(writer.commit().await?);
        tokio::fs::write(tempdir.path().join(".reposnake-tmp-ignore"), b"tmp").await?;

        let objects = store.list_objects().await?;

        assert_eq!(objects.len(), 2);
        assert!(objects.contains(&super::ObjectMetadata {
            sha256: first,
            size: 5,
        }));
        assert!(objects.contains(&super::ObjectMetadata {
            sha256: second,
            size: 13,
        }));
        Ok(())
    }

    #[tokio::test]
    async fn object_cache_serves_cached_small_object_without_reusing_inner_store()
    -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let content = b"small-object".to_vec();
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let inner = Arc::new(CountingObjectStore::new(digest, content.clone()));
        let store = CachedObjectStore::new(
            inner.clone(),
            ObjectCacheConfig {
                enabled: true,
                directory: tempdir.path().to_path_buf(),
                max_file_size: 200 * 1024,
                max_total_size: 1024 * 1024,
            },
        );

        assert_eq!(store.read(&digest).await?, content);
        assert_eq!(store.read(&digest).await?, content);

        assert_eq!(inner.read_count(), 1);
        assert_eq!(
            tokio::fs::read(tempdir.path().join(hex::encode(digest))).await?,
            content
        );
        Ok(())
    }

    #[tokio::test]
    async fn object_cache_does_not_store_large_objects() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let content = b"too-large".to_vec();
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let inner = Arc::new(CountingObjectStore::new(digest, content.clone()));
        let store = CachedObjectStore::new(
            inner.clone(),
            ObjectCacheConfig {
                enabled: true,
                directory: tempdir.path().to_path_buf(),
                max_file_size: (content.len() - 1) as u64,
                max_total_size: 1024 * 1024,
            },
        );

        assert_eq!(store.read(&digest).await?, content);
        assert_eq!(store.read(&digest).await?, content);

        assert_eq!(inner.read_count(), 2);
        assert!(!tokio::fs::try_exists(tempdir.path().join(hex::encode(digest))).await?);
        Ok(())
    }

    #[tokio::test]
    async fn object_cache_evicts_least_recently_used_object() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let first = b"first".to_vec();
        let first_digest: [u8; 32] = Sha256::digest(&first).into();
        let second = b"second".to_vec();
        let second_digest: [u8; 32] = Sha256::digest(&second).into();
        let inner = Arc::new(CountingObjectStore::with_objects([
            (first_digest, first.clone()),
            (second_digest, second.clone()),
        ]));
        let store = CachedObjectStore::new(
            inner.clone(),
            ObjectCacheConfig {
                enabled: true,
                directory: tempdir.path().to_path_buf(),
                max_file_size: 200 * 1024,
                max_total_size: first.len() as u64 + second.len() as u64 - 1,
            },
        );

        assert_eq!(store.read(&first_digest).await?, first);
        assert_eq!(store.read(&first_digest).await?, first);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.read(&second_digest).await?, second);

        assert!(!tokio::fs::try_exists(tempdir.path().join(hex::encode(first_digest))).await?);
        assert!(tokio::fs::try_exists(tempdir.path().join(hex::encode(second_digest))).await?);
        Ok(())
    }

    #[tokio::test]
    async fn migrates_filesystem_objects_to_destination_store() -> anyhow::Result<()> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        let content = b"package-content";
        let digest: [u8; 32] = Sha256::digest(content).into();
        let digest_hex = hex::encode(digest);
        let source_objects = source.path().join("objects");
        tokio::fs::create_dir_all(&source_objects).await?;
        tokio::fs::write(source_objects.join(&digest_hex), content).await?;

        let destination_store = FilesystemObjectStore::new(destination.path().join("objects"));
        let stats = migrate_filesystem_objects_to_store(source.path(), &destination_store).await?;

        assert_eq!(stats.copied, 1);
        assert_eq!(stats.skipped, 0);
        assert_eq!(destination_store.read(&digest).await?, content);
        Ok(())
    }

    #[tokio::test]
    async fn migration_skips_invalid_and_mismatched_filesystem_objects() -> anyhow::Result<()> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        let source_objects = source.path().join("objects");
        tokio::fs::create_dir_all(&source_objects).await?;
        tokio::fs::write(source_objects.join("not-a-digest"), b"ignored").await?;
        tokio::fs::write(source_objects.join("0".repeat(64)), b"wrong-content").await?;

        let destination_store = FilesystemObjectStore::new(destination.path().join("objects"));
        let stats = migrate_filesystem_objects_to_store(source.path(), &destination_store).await?;

        assert_eq!(stats.copied, 0);
        assert_eq!(stats.skipped, 2);
        Ok(())
    }

    #[tokio::test]
    async fn migration_is_noop_when_filesystem_objects_do_not_exist() -> anyhow::Result<()> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        let destination_store = FilesystemObjectStore::new(destination.path().join("objects"));
        let stats = migrate_filesystem_objects_to_store(source.path(), &destination_store).await?;

        assert_eq!(stats.copied, 0);
        assert_eq!(stats.skipped, 0);
        Ok(())
    }

    #[derive(Debug)]
    struct CountingObjectStore {
        objects: Vec<([u8; 32], Vec<u8>)>,
        reads: AtomicUsize,
    }

    impl CountingObjectStore {
        fn new(digest: [u8; 32], content: Vec<u8>) -> Self {
            Self::with_objects([(digest, content)])
        }

        fn with_objects(objects: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>) -> Self {
            Self {
                objects: objects.into_iter().collect(),
                reads: AtomicUsize::new(0),
            }
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl ObjectStore for CountingObjectStore {
        async fn read(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, AppError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.objects
                .iter()
                .find_map(|(digest, content)| (digest == sha256).then(|| content.clone()))
                .ok_or_else(|| {
                    AppError::NotFound(format!("object '{}' not found", hex::encode(sha256)))
                })
        }

        async fn check_availability(&self) -> Result<(), AppError> {
            Ok(())
        }

        async fn create_writer(&self) -> Result<Box<dyn super::ObjectWriter>, AppError> {
            Err(AppError::Internal("not implemented".to_string()))
        }

        async fn delete_if_exists(&self, _sha256: &[u8; 32]) -> Result<(), AppError> {
            Ok(())
        }

        async fn list_objects(&self) -> Result<Vec<super::ObjectMetadata>, AppError> {
            Ok(Vec::new())
        }
    }
}
