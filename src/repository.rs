// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::{MetadataStoreConfig, ObjectStoreBackend, ObjectStoreConfig};
use crate::error::AppError;
use crate::metadata::{FilesystemMetadataStore, SharedMetadataStore, build_metadata_store};
use crate::object_store::{
    SharedObjectStore, build_object_store, migrate_filesystem_objects_to_store,
};
use crate::package::{
    FileRecord, ProjectIndex, ProjectSummary, UploadPackage, is_safe_filename,
    is_valid_project_name, normalize_name,
};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use zip::ZipArchive;

#[derive(Clone)]
pub struct PackageRepository {
    metadata: SharedMetadataStore,
    objects: SharedObjectStore,
    write_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for PackageRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackageRepository")
            .finish_non_exhaustive()
    }
}

impl PackageRepository {
    pub async fn new(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        let metadata = Arc::new(FilesystemMetadataStore::new(root.join("metadata")));
        let object_store = ObjectStoreConfig {
            backend: ObjectStoreBackend::Filesystem,
            directory: Some(root),
            bucket: None,
        };
        let objects = build_object_store(&object_store).await?;
        Ok(Self::from_stores(metadata, objects))
    }

    pub async fn from_config(
        metadata_store: &MetadataStoreConfig,
        object_store: &ObjectStoreConfig,
    ) -> anyhow::Result<Self> {
        let metadata = build_metadata_store(metadata_store).await?;
        let objects = build_object_store(object_store).await?;
        if object_store.backend == ObjectStoreBackend::S3
            && object_store.bucket.is_some()
            && let Some(directory) = &object_store.directory
        {
            migrate_filesystem_objects_to_store(directory, objects.as_ref()).await?;
        }
        Ok(Self::from_stores(metadata, objects))
    }

    pub fn from_stores(metadata: SharedMetadataStore, objects: SharedObjectStore) -> Self {
        Self {
            metadata,
            objects,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn metadata_store(&self) -> SharedMetadataStore {
        self.metadata.clone()
    }

    pub fn object_store(&self) -> SharedObjectStore {
        self.objects.clone()
    }

    pub async fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppError> {
        self.metadata.list_projects().await
    }

    pub async fn project(&self, normalized_project: &str) -> Result<ProjectIndex, AppError> {
        let normalized_project = normalize_name(normalized_project);
        self.metadata.project(&normalized_project).await
    }

    pub async fn read_file(
        &self,
        normalized_project: &str,
        filename: &str,
    ) -> Result<(Vec<u8>, FileRecord), AppError> {
        let normalized_project = normalize_name(normalized_project);
        if !is_safe_filename(filename) {
            return Err(AppError::BadRequest("invalid filename".to_string()));
        }

        let project = self.project(&normalized_project).await?;
        let record = project
            .files
            .into_iter()
            .find(|record| record.filename == filename)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "unknown file '{filename}' for project '{normalized_project}'"
                ))
            })?;
        let sha256 = sha256_bytes(&record.sha256)?;
        let content = self.objects.read(&sha256).await.map_err(|error| {
            if matches!(error, AppError::NotFound(_)) {
                AppError::NotFound(format!("package file '{filename}' is missing from storage"))
            } else {
                error
            }
        })?;
        Ok((content, record))
    }

    pub async fn read_file_metadata(
        &self,
        normalized_project: &str,
        metadata_filename: &str,
    ) -> Result<(Vec<u8>, FileRecord), AppError> {
        let filename = metadata_filename
            .strip_suffix(".metadata")
            .ok_or_else(|| AppError::NotFound(format!("unknown metadata '{metadata_filename}'")))?;
        let normalized_project = normalize_name(normalized_project);
        if !is_safe_filename(filename) {
            return Err(AppError::BadRequest("invalid filename".to_string()));
        }

        let project = self.project(&normalized_project).await?;
        let record = project
            .files
            .into_iter()
            .find(|record| record.filename == filename)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "unknown file '{filename}' for project '{normalized_project}'"
                ))
            })?;
        let metadata_sha256 = record.metadata_sha256.as_deref().ok_or_else(|| {
            AppError::NotFound(format!(
                "metadata for package file '{filename}' is not available"
            ))
        })?;
        let sha256 = sha256_bytes(metadata_sha256)?;
        let content = self.objects.read(&sha256).await.map_err(|error| {
            if matches!(error, AppError::NotFound(_)) {
                AppError::NotFound(format!(
                    "metadata file '{metadata_filename}' is missing from storage"
                ))
            } else {
                error
            }
        })?;
        Ok((content, record))
    }

    pub async fn store_upload(&self, upload: UploadPackage) -> Result<FileRecord, AppError> {
        if !is_valid_project_name(&upload.name) {
            return Err(AppError::BadRequest(format!(
                "project name '{}' is not a valid Python project name",
                upload.name
            )));
        }
        if upload.version.is_empty() {
            return Err(AppError::BadRequest(
                "version must not be empty".to_string(),
            ));
        }
        if !is_safe_filename(&upload.filename) {
            return Err(AppError::BadRequest("invalid filename".to_string()));
        }
        if !upload.has_any_digest {
            return Err(AppError::BadRequest(
                "upload must include at least one digest field".to_string(),
            ));
        }

        let normalized_project = normalize_name(&upload.name);
        let expected_sha256 = sha256_hex(&upload.content);
        let dist_info_metadata = extract_dist_info_metadata(&upload.filename, &upload.content);
        let metadata_sha256 = dist_info_metadata
            .as_ref()
            .map(|metadata| sha256_hex(metadata));
        if let Some(provided_sha256) = &upload.provided_sha256
            && !provided_sha256.eq_ignore_ascii_case(&expected_sha256)
        {
            return Err(AppError::BadRequest(
                "sha256_digest does not match uploaded content".to_string(),
            ));
        }

        let _guard = self.write_lock.lock().await;
        let record = FileRecord {
            filename: upload.filename,
            version: upload.version,
            sha256: expected_sha256,
            size: upload.content.len() as u64,
            requires_python: upload.requires_python,
            metadata_sha256,
        };
        let project = ProjectSummary {
            name: upload.name,
            normalized_name: normalized_project.clone(),
        };
        let stored_sha256 = self.store_object(&upload.content).await?;
        let stored_sha256 = hex::encode(stored_sha256);
        if stored_sha256 != record.sha256 {
            return Err(AppError::Internal(format!(
                "stored object digest '{stored_sha256}' did not match expected digest '{}'",
                record.sha256
            )));
        }

        if let Some(metadata) = &dist_info_metadata {
            let stored_metadata_sha256 = hex::encode(self.store_object(metadata).await?);
            if record.metadata_sha256.as_deref() != Some(stored_metadata_sha256.as_str()) {
                self.objects
                    .delete_if_exists(&sha256_bytes(&record.sha256)?)
                    .await?;
                return Err(AppError::Internal(format!(
                    "stored metadata digest '{stored_metadata_sha256}' did not match expected digest '{}'",
                    record.metadata_sha256.as_deref().unwrap_or("")
                )));
            }
        }

        if let Err(error) = self.metadata.add_file(project, record.clone()).await {
            self.objects
                .delete_if_exists(&sha256_bytes(&record.sha256)?)
                .await?;
            if let Some(metadata_sha256) = &record.metadata_sha256 {
                self.objects
                    .delete_if_exists(&sha256_bytes(metadata_sha256)?)
                    .await?;
            }
            return Err(error);
        }

        Ok(record)
    }

    async fn store_object(&self, content: &[u8]) -> Result<[u8; 32], AppError> {
        let mut writer = self.objects.create_writer().await?;
        if let Err(error) = writer.write_chunk(content).await {
            writer.abort().await?;
            return Err(error);
        }
        writer.commit().await
    }
}

fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn sha256_bytes(hex_digest: &str) -> Result<[u8; 32], AppError> {
    let bytes = hex::decode(hex_digest).map_err(|error| {
        AppError::Internal(format!(
            "invalid stored sha256 digest '{hex_digest}': {error}"
        ))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::Internal(format!(
            "invalid stored sha256 digest '{hex_digest}': expected 32 bytes, got {}",
            bytes.len()
        ))
    })
}

fn extract_dist_info_metadata(filename: &str, content: &[u8]) -> Option<Vec<u8>> {
    if filename.ends_with(".whl") {
        return extract_wheel_metadata(content).ok().flatten();
    }
    if filename.ends_with(".tar.gz") {
        return extract_sdist_metadata(content).ok().flatten();
    }
    None
}

fn extract_wheel_metadata(content: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
    let cursor = Cursor::new(content);
    let mut archive = ZipArchive::new(cursor).map_err(|error| {
        AppError::BadRequest(format!("failed to inspect wheel metadata: {error}"))
    })?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).map_err(|error| {
            AppError::BadRequest(format!("failed to inspect wheel metadata: {error}"))
        })?;
        let name = file.name();
        if !is_wheel_metadata_path(name) {
            continue;
        }
        let mut metadata = Vec::new();
        file.read_to_end(&mut metadata).map_err(|error| {
            AppError::BadRequest(format!("failed to read wheel metadata: {error}"))
        })?;
        return Ok(Some(metadata));
    }
    Ok(None)
}

fn is_wheel_metadata_path(path: &str) -> bool {
    let mut parts = path.split('/');
    let Some(dist_info) = parts.next() else {
        return false;
    };
    matches!(
        (
            dist_info.ends_with(".dist-info"),
            parts.next(),
            parts.next()
        ),
        (true, Some("METADATA"), None)
    )
}

fn extract_sdist_metadata(content: &[u8]) -> Result<Option<Vec<u8>>, AppError> {
    let decoder = GzDecoder::new(Cursor::new(content));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|error| {
        AppError::BadRequest(format!("failed to inspect sdist metadata: {error}"))
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            AppError::BadRequest(format!("failed to inspect sdist metadata: {error}"))
        })?;
        let path = entry.path().map_err(|error| {
            AppError::BadRequest(format!("failed to inspect sdist metadata: {error}"))
        })?;
        if !is_sdist_metadata_path(&path) {
            continue;
        }
        let mut metadata = Vec::new();
        entry.read_to_end(&mut metadata).map_err(|error| {
            AppError::BadRequest(format!("failed to read sdist metadata: {error}"))
        })?;
        return Ok(Some(metadata));
    }
    Ok(None)
}

fn is_sdist_metadata_path(path: &std::path::Path) -> bool {
    let mut components = path.components();
    let first = components.next();
    let second = components.next();
    let third = components.next();
    first.is_some()
        && second.is_some_and(|component| component.as_os_str() == "PKG-INFO")
        && third.is_none()
}

#[cfg(test)]
mod tests {
    use super::{PackageRepository, extract_dist_info_metadata};
    use crate::config::Config;
    use crate::package::UploadPackage;

    #[tokio::test]
    async fn stores_and_reads_uploaded_package() {
        let tempdir = tempfile::tempdir().unwrap();
        let repository = PackageRepository::new(tempdir.path()).await.unwrap();

        let record = repository
            .store_upload(UploadPackage {
                name: "reposnake_demo".to_string(),
                version: "0.1.0".to_string(),
                filename: "reposnake_demo-0.1.0.tar.gz".to_string(),
                content: b"package-content".to_vec(),
                provided_sha256: None,
                has_any_digest: true,
                requires_python: Some(">=3.11".to_string()),
            })
            .await
            .unwrap();

        assert_eq!(record.version, "0.1.0");
        assert_eq!(record.size, 15);

        let projects = repository.list_projects().await.unwrap();
        assert_eq!(projects[0].normalized_name, "reposnake-demo");

        let project = repository.project("reposnake-demo").await.unwrap();
        assert_eq!(project.files[0].filename, "reposnake_demo-0.1.0.tar.gz");

        let (content, file) = repository
            .read_file("reposnake-demo", "reposnake_demo-0.1.0.tar.gz")
            .await
            .unwrap();
        assert_eq!(content, b"package-content");
        assert_eq!(file.sha256, record.sha256);
    }

    #[tokio::test]
    async fn rejects_duplicate_files() {
        let tempdir = tempfile::tempdir().unwrap();
        let repository = PackageRepository::new(tempdir.path()).await.unwrap();
        let upload = UploadPackage {
            name: "reposnake-demo".to_string(),
            version: "0.1.0".to_string(),
            filename: "reposnake_demo-0.1.0.tar.gz".to_string(),
            content: b"package-content".to_vec(),
            provided_sha256: None,
            has_any_digest: true,
            requires_python: None,
        };

        repository.store_upload(upload.clone()).await.unwrap();
        let error = repository.store_upload(upload).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            "file 'reposnake_demo-0.1.0.tar.gz' already exists"
        );
    }

    #[test]
    fn extracts_core_metadata_from_gzipped_sdist() {
        let metadata = b"Metadata-Version: 2.4\nName: reposnake-demo\nVersion: 0.1.0\n";
        let sdist = sdist_with_metadata(metadata);

        assert_eq!(
            extract_dist_info_metadata("reposnake_demo-0.1.0.tar.gz", &sdist),
            Some(metadata.to_vec())
        );
    }

    #[tokio::test]
    async fn filesystem_metadata_persists_uploaded_package_index() {
        let tempdir = tempfile::tempdir().unwrap();
        let metadata_dir = tempdir.path().join("metadata");
        let objects_dir = tempdir.path().join("objects");
        let config: Config = toml::from_str(&format!(
            r#"
origin = "http://localhost:8080"

[metadata-store]
backend = "filesystem"
directory = "{}"

[object-store]
directory = "{}"

[[publisher]]
projects = ["*"]
"#,
            metadata_dir.display(),
            objects_dir.display()
        ))
        .unwrap();
        config.validate(true).unwrap();
        let repository =
            PackageRepository::from_config(&config.metadata_store, &config.object_store)
                .await
                .unwrap();

        repository
            .store_upload(UploadPackage {
                name: "reposnake_demo".to_string(),
                version: "0.1.0".to_string(),
                filename: "reposnake_demo-0.1.0.tar.gz".to_string(),
                content: b"package-content".to_vec(),
                provided_sha256: None,
                has_any_digest: true,
                requires_python: Some(">=3.11".to_string()),
            })
            .await
            .unwrap();
        let reopened = PackageRepository::from_config(&config.metadata_store, &config.object_store)
            .await
            .unwrap();

        let project = reopened.project("reposnake-demo").await.unwrap();
        let (content, file) = reopened
            .read_file("reposnake-demo", "reposnake_demo-0.1.0.tar.gz")
            .await
            .unwrap();

        assert_eq!(project.files[0].filename, "reposnake_demo-0.1.0.tar.gz");
        assert_eq!(content, b"package-content");
        assert_eq!(file.requires_python.as_deref(), Some(">=3.11"));
    }

    fn sdist_with_metadata(metadata: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::{Builder, Header};

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_size(metadata.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "reposnake_demo-0.1.0/PKG-INFO", metadata)
            .unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap()
    }
}
