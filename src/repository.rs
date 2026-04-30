// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use crate::package::{
    FileRecord, ProjectIndex, ProjectSummary, UploadPackage, is_safe_filename,
    is_valid_project_name, normalize_name,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct PackageRepository {
    root: Arc<PathBuf>,
    write_lock: Arc<Mutex<()>>,
}

impl PackageRepository {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Arc::new(root.into()),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppError> {
        let projects_dir = self.projects_dir();
        if !path_exists(&projects_dir).await? {
            return Ok(Vec::new());
        }

        let mut entries = tokio::fs::read_dir(&projects_dir).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to list projects in '{}': {error}",
                projects_dir.display()
            ))
        })?;
        let mut projects = Vec::new();

        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to read projects in '{}': {error}",
                projects_dir.display()
            ))
        })? {
            let is_file = entry.file_type().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to inspect project entry '{}': {error}",
                    entry.path().display()
                ))
            })?;
            if !is_file.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let project = self.read_project_index_path(&path).await?;
            projects.push(ProjectSummary {
                name: project.name,
                normalized_name: project.normalized_name,
            });
        }

        projects.sort_by(|left, right| left.normalized_name.cmp(&right.normalized_name));
        Ok(projects)
    }

    pub async fn project(&self, normalized_project: &str) -> Result<ProjectIndex, AppError> {
        let normalized_project = normalize_name(normalized_project);
        let path = self.project_index_path(&normalized_project);
        let mut project = self.read_project_index_path(&path).await.map_err(|error| {
            if matches!(error, AppError::NotFound(_)) {
                AppError::NotFound(format!("unknown project '{normalized_project}'"))
            } else {
                error
            }
        })?;
        project
            .files
            .sort_by(|left, right| left.filename.cmp(&right.filename));
        Ok(project)
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
        let path = self.package_path(&normalized_project, filename);
        let content = tokio::fs::read(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("package file '{filename}' is missing from storage"))
            } else {
                AppError::Internal(format!(
                    "failed to read package file '{}': {error}",
                    path.display()
                ))
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
        let sha256 = sha256_hex(&upload.content);
        if let Some(provided_sha256) = &upload.provided_sha256
            && !provided_sha256.eq_ignore_ascii_case(&sha256)
        {
            return Err(AppError::BadRequest(
                "sha256_digest does not match uploaded content".to_string(),
            ));
        }

        let _guard = self.write_lock.lock().await;
        tokio::fs::create_dir_all(self.projects_dir())
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to create project storage: {error}"))
            })?;
        tokio::fs::create_dir_all(self.package_dir(&normalized_project))
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to create package storage: {error}"))
            })?;

        let mut project = match self.read_project_index(&normalized_project).await {
            Ok(project) => project,
            Err(AppError::NotFound(_)) => ProjectIndex {
                name: upload.name.clone(),
                normalized_name: normalized_project.clone(),
                files: Vec::new(),
            },
            Err(error) => return Err(error),
        };

        if project
            .files
            .iter()
            .any(|record| record.filename == upload.filename)
        {
            return Err(AppError::Conflict(format!(
                "file '{}' already exists",
                upload.filename
            )));
        }

        let path = self.package_path(&normalized_project, &upload.filename);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    AppError::Conflict(format!("file '{}' already exists", upload.filename))
                } else {
                    AppError::Internal(format!(
                        "failed to create package file '{}': {error}",
                        path.display()
                    ))
                }
            })?;
        file.write_all(&upload.content).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to write package file '{}': {error}",
                path.display()
            ))
        })?;
        file.flush().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to flush package file '{}': {error}",
                path.display()
            ))
        })?;

        let record = FileRecord {
            filename: upload.filename,
            version: upload.version,
            sha256,
            size: upload.content.len() as u64,
            requires_python: upload.requires_python,
        };
        project.files.push(record.clone());
        project
            .files
            .sort_by(|left, right| left.filename.cmp(&right.filename));
        self.write_project_index(&project).await?;

        Ok(record)
    }

    async fn read_project_index(&self, normalized_project: &str) -> Result<ProjectIndex, AppError> {
        self.read_project_index_path(&self.project_index_path(normalized_project))
            .await
    }

    async fn read_project_index_path(&self, path: &Path) -> Result<ProjectIndex, AppError> {
        let content = tokio::fs::read_to_string(path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AppError::NotFound(format!("project index '{}' not found", path.display()))
            } else {
                AppError::Internal(format!(
                    "failed to read project index '{}': {error}",
                    path.display()
                ))
            }
        })?;
        serde_json::from_str(&content).map_err(|error| {
            AppError::Internal(format!(
                "failed to parse project index '{}': {error}",
                path.display()
            ))
        })
    }

    async fn write_project_index(&self, project: &ProjectIndex) -> Result<(), AppError> {
        let path = self.project_index_path(&project.normalized_name);
        let content = serde_json::to_vec_pretty(project).map_err(|error| {
            AppError::Internal(format!(
                "failed to serialize project index '{}': {error}",
                project.normalized_name
            ))
        })?;
        tokio::fs::write(&path, content).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to write project index '{}': {error}",
                path.display()
            ))
        })
    }

    fn projects_dir(&self) -> PathBuf {
        self.root.join("projects")
    }

    fn package_dir(&self, normalized_project: &str) -> PathBuf {
        self.root.join("packages").join(normalized_project)
    }

    fn package_path(&self, normalized_project: &str, filename: &str) -> PathBuf {
        self.package_dir(normalized_project).join(filename)
    }

    fn project_index_path(&self, normalized_project: &str) -> PathBuf {
        self.projects_dir()
            .join(format!("{normalized_project}.json"))
    }
}

fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

async fn path_exists(path: &Path) -> Result<bool, AppError> {
    match tokio::fs::try_exists(path).await {
        Ok(exists) => Ok(exists),
        Err(error) => Err(AppError::Internal(format!(
            "failed to check path '{}': {error}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::PackageRepository;
    use crate::package::UploadPackage;

    #[tokio::test]
    async fn stores_and_reads_uploaded_package() {
        let tempdir = tempfile::tempdir().unwrap();
        let repository = PackageRepository::new(tempdir.path());

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
        let repository = PackageRepository::new(tempdir.path());
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
}
