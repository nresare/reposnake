// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use crate::package::{FileRecord, ProjectIndex, ProjectSummary};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

pub type SharedMetadataStore = Arc<dyn MetadataStore>;

#[async_trait]
pub trait MetadataStore: fmt::Debug + Send + Sync {
    async fn list_projects(&self) -> Result<Vec<ProjectSummary>, AppError>;
    async fn project(&self, normalized_project: &str) -> Result<ProjectIndex, AppError>;
    async fn add_file(&self, project: ProjectSummary, file: FileRecord) -> Result<(), AppError>;
}

#[derive(Debug, Clone)]
pub struct SurrealMetadataStore {
    db: Surreal<Db>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectDoc {
    name: String,
    normalized_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let db = Surreal::new::<Mem>(()).await?;
        db.use_ns("reposnake").use_db("metadata").await?;
        Ok(Self { db })
    }

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

fn file_id(normalized_project: &str, filename: &str) -> String {
    format!("{normalized_project}/{filename}")
}
