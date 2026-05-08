// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::{MetadataStoreBackend, MetadataStoreConfig};
use crate::error::AppError;
use crate::idmouse::IdmouseClient;
use crate::package::{FileRecord, ProjectIndex, ProjectSummary};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use surrealdb::Surreal;
use surrealdb::engine::any;
use surrealdb::engine::any::Any;
use surrealdb::types::SurrealValue;
use tokio::io::AsyncWriteExt;

const NAMESPACE: &str = "default";
const DATABASE: &str = "reposnake";

pub type SharedMetadataStore = Arc<dyn MetadataStore>;

#[async_trait]
pub trait MetadataStore: fmt::Debug + Send + Sync {
    async fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppError>;
    async fn project(&self, normalized_project: &str) -> Result<ProjectIndex, AppError>;
    async fn add_file(&self, project: ProjectSummary, file: FileRecord) -> Result<(), AppError>;
}

pub async fn build_metadata_store(
    config: &MetadataStoreConfig,
) -> anyhow::Result<SharedMetadataStore> {
    match config.backend {
        MetadataStoreBackend::Surrealdb => {
            Ok(Arc::new(SurrealMetadataStore::from_config(config).await?))
        }
        MetadataStoreBackend::Filesystem => {
            let directory = config.directory.clone().ok_or_else(|| {
                anyhow::anyhow!("metadata-store.directory is required when backend is filesystem")
            })?;
            Ok(Arc::new(FilesystemMetadataStore::new(directory)))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SurrealMetadataStore {
    db: Arc<Surreal<Any>>,
}

#[derive(Debug, Clone)]
pub struct FilesystemMetadataStore {
    directory: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
#[surreal(crate = "surrealdb::types")]
struct ProjectDoc {
    name: String,
    normalized_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
#[surreal(crate = "surrealdb::types")]
struct FileDoc {
    normalized_project: String,
    filename: String,
    version: String,
    sha256: String,
    size: u64,
    requires_python: Option<String>,
}

impl SurrealMetadataStore {
    pub async fn in_memory() -> anyhow::Result<Self> {
        Ok(Self::new(mem_db().await?))
    }

    pub async fn from_config(config: &MetadataStoreConfig) -> anyhow::Result<Self> {
        Ok(Self::new(make_db(config).await?))
    }

    pub fn new(db: Arc<Surreal<Any>>) -> Self {
        Self { db }
    }

    pub async fn make_db(config: &MetadataStoreConfig) -> anyhow::Result<Arc<Surreal<Any>>> {
        make_db(config).await
    }

    pub async fn mem_db() -> anyhow::Result<Arc<Surreal<Any>>> {
        mem_db().await
    }
}

impl FilesystemMetadataStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn project_path(&self, normalized_project: &str) -> Result<PathBuf, AppError> {
        if normalized_project.is_empty()
            || !normalized_project
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AppError::NotFound(format!(
                "unknown project '{normalized_project}'"
            )));
        }
        Ok(self.directory.join(format!("{normalized_project}.json")))
    }

    async fn read_project_if_exists(
        &self,
        normalized_project: &str,
    ) -> Result<Option<ProjectIndex>, AppError> {
        let path = self.project_path(normalized_project)?;
        let content = match tokio::fs::read(&path).await {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AppError::Internal(format!(
                    "failed to read project metadata '{}': {error}",
                    path.display()
                )));
            }
        };
        serde_json::from_slice(&content).map(Some).map_err(|error| {
            AppError::Internal(format!(
                "failed to decode project metadata '{}': {error}",
                path.display()
            ))
        })
    }

    async fn write_project(&self, project: &ProjectIndex) -> Result<(), AppError> {
        tokio::fs::create_dir_all(&self.directory)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to create metadata directory '{}': {error}",
                    self.directory.display()
                ))
            })?;
        let path = self.project_path(&project.normalized_name)?;
        let temp_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let temp_path = self.directory.join(format!(
            ".{}.{}.{}.tmp",
            project.normalized_name,
            std::process::id(),
            temp_id
        ));
        let content = serde_json::to_vec_pretty(project).map_err(|error| {
            AppError::Internal(format!("failed to encode project metadata: {error}"))
        })?;
        let mut file = tokio::fs::File::create(&temp_path).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to create project metadata '{}': {error}",
                temp_path.display()
            ))
        })?;
        file.write_all(&content).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to write project metadata '{}': {error}",
                temp_path.display()
            ))
        })?;
        file.write_all(b"\n").await.map_err(|error| {
            AppError::Internal(format!(
                "failed to write project metadata '{}': {error}",
                temp_path.display()
            ))
        })?;
        file.sync_all().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to sync project metadata '{}': {error}",
                temp_path.display()
            ))
        })?;
        drop(file);
        tokio::fs::rename(&temp_path, &path)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to replace project metadata '{}': {error}",
                    path.display()
                ))
            })?;
        Ok(())
    }
}

pub async fn make_db(config: &MetadataStoreConfig) -> anyhow::Result<Arc<Surreal<Any>>> {
    let db = Arc::new(any::connect(&config.uri).await?);
    if let Some(idmouse) = config.idmouse.clone() {
        IdmouseClient::new(idmouse)
            .authenticate_db(db.clone())
            .await?;
    } else if let (Some(username), Some(password)) = (&config.username, config.password()?) {
        db.signin(surrealdb::opt::auth::Database {
            namespace: NAMESPACE.to_string(),
            database: DATABASE.to_string(),
            username: username.to_string(),
            password,
        })
        .await?;
    }
    setup_db(db.as_ref()).await?;
    Ok(db)
}

#[cfg(test)]
pub async fn mem_db() -> anyhow::Result<Arc<Surreal<Any>>> {
    let db = Arc::new(any::connect("mem://").await?);
    setup_db(db.as_ref()).await?;
    Ok(db)
}

#[cfg(not(test))]
async fn mem_db() -> anyhow::Result<Arc<Surreal<Any>>> {
    let db = Arc::new(any::connect("mem://").await?);
    setup_db(db.as_ref()).await?;
    Ok(db)
}

async fn setup_db(db: &Surreal<Any>) -> anyhow::Result<()> {
    db.use_ns(NAMESPACE).use_db(DATABASE).await?;
    db.query(
        "DEFINE TABLE IF NOT EXISTS project; \
         DEFINE TABLE IF NOT EXISTS package_file; \
         DEFINE INDEX IF NOT EXISTS packageFileByProjectFilename \
         ON package_file FIELDS normalized_project, filename UNIQUE;",
    )
    .await?;
    Ok(())
}

impl SurrealMetadataStore {
    async fn files_for_project(
        &self,
        normalized_project: &str,
    ) -> Result<Vec<FileRecord>, AppError> {
        let mut response = self
            .db
            .query(
                "SELECT normalized_project, filename, version, sha256, size, requires_python \
                 FROM package_file \
                 WHERE normalized_project = $normalized_project \
                 ORDER BY filename",
            )
            .bind(("normalized_project", normalized_project.to_string()))
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to list package files: {error}"))
            })?;
        let files: Vec<FileDoc> = response.take(0).map_err(|error| {
            AppError::Internal(format!("failed to decode package files: {error}"))
        })?;
        Ok(files
            .into_iter()
            .map(|file| FileRecord {
                filename: file.filename,
                version: file.version,
                sha256: file.sha256,
                size: file.size,
                requires_python: file.requires_python,
            })
            .collect())
    }
}

#[async_trait]
impl MetadataStore for SurrealMetadataStore {
    async fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppError> {
        let mut response = self
            .db
            .query("SELECT name, normalized_name FROM project ORDER BY normalized_name")
            .await
            .map_err(|error| AppError::Internal(format!("failed to list projects: {error}")))?;
        let projects: Vec<ProjectDoc> = response
            .take(0)
            .map_err(|error| AppError::Internal(format!("failed to decode projects: {error}")))?;
        Ok(projects
            .into_iter()
            .map(|project| ProjectSummary {
                name: project.name,
                normalized_name: project.normalized_name,
            })
            .collect())
    }

    async fn project(&self, normalized_project: &str) -> Result<ProjectIndex, AppError> {
        let project: Option<ProjectDoc> = self
            .db
            .select(("project", normalized_project))
            .await
            .map_err(|error| AppError::Internal(format!("failed to read project: {error}")))?;
        let project = project
            .ok_or_else(|| AppError::NotFound(format!("unknown project '{normalized_project}'")))?;
        Ok(ProjectIndex {
            name: project.name,
            normalized_name: project.normalized_name.clone(),
            files: self.files_for_project(&project.normalized_name).await?,
        })
    }

    async fn add_file(&self, project: ProjectSummary, file: FileRecord) -> Result<(), AppError> {
        let existing: Option<FileDoc> = self
            .db
            .select((
                "package_file",
                file_id(&project.normalized_name, &file.filename),
            ))
            .await
            .map_err(|error| AppError::Internal(format!("failed to read package file: {error}")))?;
        if existing.is_some() {
            return Err(AppError::Conflict(format!(
                "file '{}' already exists",
                file.filename
            )));
        }

        let project_doc = ProjectDoc {
            name: project.name,
            normalized_name: project.normalized_name.clone(),
        };
        let _project: Option<ProjectDoc> = self
            .db
            .upsert(("project", project.normalized_name.as_str()))
            .content(project_doc)
            .await
            .map_err(|error| AppError::Internal(format!("failed to store project: {error}")))?;

        let file_doc = FileDoc {
            normalized_project: project.normalized_name.clone(),
            filename: file.filename,
            version: file.version,
            sha256: file.sha256,
            size: file.size,
            requires_python: file.requires_python,
        };
        let _file: Option<FileDoc> = self
            .db
            .create((
                "package_file",
                file_id(&project.normalized_name, &file_doc.filename),
            ))
            .content(file_doc)
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to store package file: {error}"))
            })?;
        Ok(())
    }
}

#[async_trait]
impl MetadataStore for FilesystemMetadataStore {
    async fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppError> {
        let mut entries = match tokio::fs::read_dir(&self.directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(AppError::Internal(format!(
                    "failed to list metadata directory '{}': {error}",
                    self.directory.display()
                )));
            }
        };
        let mut projects = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to read metadata directory '{}': {error}",
                self.directory.display()
            ))
        })? {
            let file_type = entry.file_type().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to read metadata entry '{}': {error}",
                    entry.path().display()
                ))
            })?;
            if !file_type.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let content = tokio::fs::read(entry.path()).await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to read project metadata '{}': {error}",
                    entry.path().display()
                ))
            })?;
            let project: ProjectIndex = serde_json::from_slice(&content).map_err(|error| {
                AppError::Internal(format!(
                    "failed to decode project metadata '{}': {error}",
                    entry.path().display()
                ))
            })?;
            projects.push(ProjectSummary {
                name: project.name,
                normalized_name: project.normalized_name,
            });
        }
        projects.sort_by(|left, right| left.normalized_name.cmp(&right.normalized_name));
        Ok(projects)
    }

    async fn project(&self, normalized_project: &str) -> Result<ProjectIndex, AppError> {
        let mut project = self
            .read_project_if_exists(normalized_project)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("unknown project '{normalized_project}'")))?;
        project
            .files
            .sort_by(|left, right| left.filename.cmp(&right.filename));
        Ok(project)
    }

    async fn add_file(&self, project: ProjectSummary, file: FileRecord) -> Result<(), AppError> {
        let mut index = self
            .read_project_if_exists(&project.normalized_name)
            .await?
            .unwrap_or_else(|| ProjectIndex {
                name: project.name.clone(),
                normalized_name: project.normalized_name.clone(),
                files: Vec::new(),
            });
        if index
            .files
            .iter()
            .any(|existing| existing.filename == file.filename)
        {
            return Err(AppError::Conflict(format!(
                "file '{}' already exists",
                file.filename
            )));
        }
        index.name = project.name;
        index.normalized_name = project.normalized_name;
        index.files.push(file);
        index
            .files
            .sort_by(|left, right| left.filename.cmp(&right.filename));
        self.write_project(&index).await
    }
}

fn file_id(normalized_project: &str, filename: &str) -> String {
    format!("{normalized_project}/{filename}")
}

#[cfg(test)]
mod tests {
    use super::{FilesystemMetadataStore, MetadataStore, SurrealMetadataStore};
    use crate::error::AppError;
    use crate::package::{FileRecord, ProjectSummary};

    #[tokio::test]
    async fn embedded_store_starts_with_no_projects() -> anyhow::Result<()> {
        let store = SurrealMetadataStore::in_memory().await?;

        assert!(store.list_projects().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn embedded_store_adds_and_reads_simple_project_detail() -> anyhow::Result<()> {
        let store = SurrealMetadataStore::in_memory().await?;
        store
            .add_file(
                project("reposnake-demo"),
                file("demo-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;

        let project = store.project("reposnake-demo").await?;

        assert_eq!(project.name, "reposnake-demo");
        assert_eq!(project.normalized_name, "reposnake-demo");
        assert_eq!(project.files.len(), 1);
        assert_eq!(project.files[0].filename, "demo-0.1.0.tar.gz");
        assert_eq!(project.files[0].requires_python.as_deref(), Some(">=3.11"));
        Ok(())
    }

    #[tokio::test]
    async fn embedded_store_lists_projects_and_files_in_simple_api_order() -> anyhow::Result<()> {
        let store = SurrealMetadataStore::in_memory().await?;
        store
            .add_file(
                project("zebra-project"),
                file("zebra-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;
        store
            .add_file(
                project("alpha-project"),
                file("alpha-0.2.0.tar.gz", "0.2.0"),
            )
            .await?;
        store
            .add_file(
                project("alpha-project"),
                file("alpha-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;

        let projects = store.list_projects().await?;
        let alpha = store.project("alpha-project").await?;

        assert_eq!(
            projects
                .iter()
                .map(|project| project.normalized_name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha-project", "zebra-project"]
        );
        assert_eq!(
            alpha
                .files
                .iter()
                .map(|file| file.filename.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha-0.1.0.tar.gz", "alpha-0.2.0.tar.gz"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn embedded_store_rejects_duplicate_file_for_project() -> anyhow::Result<()> {
        let store = SurrealMetadataStore::in_memory().await?;
        let project = project("reposnake-demo");
        let file = file("demo-0.1.0.tar.gz", "0.1.0");

        store.add_file(project.clone(), file.clone()).await?;
        let error = store.add_file(project, file).await.unwrap_err();

        assert!(matches!(error, AppError::Conflict(_)));
        assert_eq!(error.to_string(), "file 'demo-0.1.0.tar.gz' already exists");
        Ok(())
    }

    #[tokio::test]
    async fn embedded_store_returns_not_found_for_unknown_project() -> anyhow::Result<()> {
        let store = SurrealMetadataStore::in_memory().await?;
        let error = store.project("missing-project").await.unwrap_err();

        assert!(matches!(error, AppError::NotFound(_)));
        assert_eq!(error.to_string(), "unknown project 'missing-project'");
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_starts_with_no_projects() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemMetadataStore::new(tempdir.path());

        assert!(store.list_projects().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_adds_and_reads_simple_project_detail() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemMetadataStore::new(tempdir.path());
        store
            .add_file(
                project("reposnake-demo"),
                file("demo-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;

        let project = store.project("reposnake-demo").await?;

        assert_eq!(project.name, "reposnake-demo");
        assert_eq!(project.normalized_name, "reposnake-demo");
        assert_eq!(project.files.len(), 1);
        assert_eq!(project.files[0].filename, "demo-0.1.0.tar.gz");
        assert_eq!(project.files[0].requires_python.as_deref(), Some(">=3.11"));
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_persists_projects_across_instances() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemMetadataStore::new(tempdir.path());
        store
            .add_file(
                project("reposnake-demo"),
                file("demo-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;
        let reopened = FilesystemMetadataStore::new(tempdir.path());

        let projects = reopened.list_projects().await?;
        let project = reopened.project("reposnake-demo").await?;

        assert_eq!(projects[0].normalized_name, "reposnake-demo");
        assert_eq!(project.files[0].filename, "demo-0.1.0.tar.gz");
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_lists_projects_and_files_in_simple_api_order() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemMetadataStore::new(tempdir.path());
        store
            .add_file(
                project("zebra-project"),
                file("zebra-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;
        store
            .add_file(
                project("alpha-project"),
                file("alpha-0.2.0.tar.gz", "0.2.0"),
            )
            .await?;
        store
            .add_file(
                project("alpha-project"),
                file("alpha-0.1.0.tar.gz", "0.1.0"),
            )
            .await?;

        let projects = store.list_projects().await?;
        let alpha = store.project("alpha-project").await?;

        assert_eq!(
            projects
                .iter()
                .map(|project| project.normalized_name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha-project", "zebra-project"]
        );
        assert_eq!(
            alpha
                .files
                .iter()
                .map(|file| file.filename.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha-0.1.0.tar.gz", "alpha-0.2.0.tar.gz"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_rejects_duplicate_file_for_project() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemMetadataStore::new(tempdir.path());
        let project = project("reposnake-demo");
        let file = file("demo-0.1.0.tar.gz", "0.1.0");

        store.add_file(project.clone(), file.clone()).await?;
        let error = store.add_file(project, file).await.unwrap_err();

        assert!(matches!(error, AppError::Conflict(_)));
        assert_eq!(error.to_string(), "file 'demo-0.1.0.tar.gz' already exists");
        Ok(())
    }

    #[tokio::test]
    async fn filesystem_store_returns_not_found_for_unknown_project() -> anyhow::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let store = FilesystemMetadataStore::new(tempdir.path());
        let error = store.project("missing-project").await.unwrap_err();

        assert!(matches!(error, AppError::NotFound(_)));
        assert_eq!(error.to_string(), "unknown project 'missing-project'");
        Ok(())
    }

    fn project(normalized_name: &str) -> ProjectSummary {
        ProjectSummary {
            name: normalized_name.to_string(),
            normalized_name: normalized_name.to_string(),
        }
    }

    fn file(filename: &str, version: &str) -> FileRecord {
        FileRecord {
            filename: filename.to_string(),
            version: version.to_string(),
            sha256: "a3da3fb94769c68c9f728842a4a00408ad28c5f734b093d23cc4d62f51079589".to_string(),
            size: 15,
            requires_python: Some(">=3.11".to_string()),
        }
    }
}
