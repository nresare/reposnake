// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::{
    MetadataStoreConfig, ObjectCacheConfig, ObjectStoreBackend, ObjectStoreConfig,
};
use crate::error::AppError;
use crate::metadata::{
    FilesystemMetadataStore, OciBundleRecord, SharedMetadataStore, build_metadata_store,
};
use crate::object_store::{
    SharedObjectStore, build_object_store, build_object_store_with_cache,
    migrate_filesystem_objects_to_store,
};
use crate::package::{
    FileRecord, ProjectIndex, ProjectSummary, UploadPackage, is_safe_filename,
    is_valid_project_name, normalize_name,
};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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

#[derive(Debug, Clone)]
pub struct UtilizationReport {
    pub total_objects: usize,
    pub total_bytes: u64,
    pub attributed_objects: usize,
    pub attributed_bytes: u64,
    pub categories: Vec<UtilizationCategory>,
    pub projects: Vec<ProjectUtilization>,
    pub shared_layer_groups: Vec<SharedLayerGroupUtilization>,
    pub largest_objects: Vec<ObjectUtilization>,
}

#[derive(Debug, Clone)]
pub struct UtilizationCategory {
    pub name: String,
    pub object_count: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ProjectUtilization {
    pub name: String,
    pub normalized_name: String,
    pub file_count: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ObjectUtilization {
    pub sha256: String,
    pub size: u64,
    pub reference_count: usize,
    pub usage: String,
}

#[derive(Debug, Clone)]
pub struct SharedLayerGroupUtilization {
    pub id: String,
    pub layer_count: usize,
    pub size: u64,
    pub manifest_count: usize,
    pub oldest_created: Option<DateTime<Utc>>,
    pub newest_created: Option<DateTime<Utc>>,
    pub layers: String,
    pub usage: String,
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
        cache: &ObjectCacheConfig,
    ) -> anyhow::Result<Self> {
        let metadata = build_metadata_store(metadata_store).await?;
        let objects = build_object_store_with_cache(object_store, cache).await?;
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

    pub async fn utilization_report(&self) -> Result<UtilizationReport, AppError> {
        let objects_by_digest = self
            .objects
            .list_objects()
            .await?
            .into_iter()
            .map(|object| (object.sha256, object.size))
            .collect::<BTreeMap<_, _>>();
        let total_objects = objects_by_digest.len();
        let total_bytes = objects_by_digest.values().sum();

        let mut labels_by_digest = BTreeMap::<String, BTreeSet<String>>::new();
        let mut category_digests = BTreeMap::<String, BTreeSet<String>>::new();
        let mut projects = Vec::new();

        for project_summary in self.list_projects().await? {
            let project = self.project(&project_summary.normalized_name).await?;
            let mut project_digests = BTreeSet::new();
            for file in &project.files {
                add_object_usage(
                    &mut labels_by_digest,
                    &mut category_digests,
                    &file.sha256,
                    "Python distributions",
                    format!("{} / {}", project.name, file.filename),
                );
                project_digests.insert(file.sha256.clone());
                if let Some(metadata_sha256) = &file.metadata_sha256 {
                    add_object_usage(
                        &mut labels_by_digest,
                        &mut category_digests,
                        metadata_sha256,
                        "Python core metadata",
                        format!("{} / {}.metadata", project.name, file.filename),
                    );
                    project_digests.insert(metadata_sha256.clone());
                }
            }
            let bytes = project_digests
                .iter()
                .filter_map(|digest| objects_by_digest.get(digest))
                .sum();
            projects.push(ProjectUtilization {
                name: project.name,
                normalized_name: project.normalized_name,
                file_count: project.files.len(),
                bytes,
            });
        }

        let tags_by_bundle = self
            .metadata
            .list_oci_tag_records()
            .await?
            .into_iter()
            .fold(
                BTreeMap::<String, BTreeSet<String>>::new(),
                |mut tags, tag| {
                    tags.entry(tag.digest.clone())
                        .or_default()
                        .insert(format!("{}:{}", tag.repository, tag.tag));
                    tags
                },
            );

        let bundles = self.metadata.list_oci_bundles().await?;
        let mut shared_layer_groups =
            shared_layer_groups(&bundles, &objects_by_digest, &tags_by_bundle)?;
        shared_layer_groups.sort_by(|left, right| {
            compare_optional_datetime(left.newest_created, right.newest_created)
                .then_with(|| compare_optional_datetime(left.oldest_created, right.oldest_created))
                .then_with(|| right.size.cmp(&left.size))
                .then_with(|| left.id.cmp(&right.id))
        });
        shared_layer_groups.truncate(20);

        for bundle in &bundles {
            let labels = tags_by_bundle
                .get(&bundle.digest)
                .cloned()
                .unwrap_or_else(|| {
                    BTreeSet::from([format!("manifest {}", short_digest(&bundle.digest))])
                });
            for object in &bundle.objects {
                let sha256 = digest_sha256(&object.digest)?;
                let category = oci_category(&object.kind);
                for label in &labels {
                    add_object_usage(
                        &mut labels_by_digest,
                        &mut category_digests,
                        &sha256,
                        category,
                        format!("{label} {}", object.kind),
                    );
                }
            }
        }

        for object in self.metadata.list_oci_objects().await? {
            let sha256 = digest_sha256(&object.digest)?;
            if !labels_by_digest.contains_key(&sha256) {
                add_object_usage(
                    &mut labels_by_digest,
                    &mut category_digests,
                    &sha256,
                    oci_category(&object.kind),
                    format!("unbundled OCI {}", object.kind),
                );
            }
        }

        let attributed_digests = labels_by_digest.keys().cloned().collect::<BTreeSet<_>>();
        let attributed_objects = attributed_digests.len();
        let attributed_bytes = attributed_digests
            .iter()
            .filter_map(|digest| objects_by_digest.get(digest))
            .sum();

        let unattributed = objects_by_digest
            .keys()
            .filter(|digest| !attributed_digests.contains(*digest))
            .cloned()
            .collect::<BTreeSet<_>>();
        category_digests.insert("Other objects".to_string(), unattributed);

        let mut categories = category_digests
            .into_iter()
            .map(|(name, digests)| UtilizationCategory {
                name,
                object_count: digests.len(),
                bytes: digests
                    .iter()
                    .filter_map(|digest| objects_by_digest.get(digest))
                    .sum(),
            })
            .collect::<Vec<_>>();
        categories.sort_by(|left, right| {
            right
                .bytes
                .cmp(&left.bytes)
                .then_with(|| left.name.cmp(&right.name))
        });

        projects.sort_by(|left, right| {
            right
                .bytes
                .cmp(&left.bytes)
                .then_with(|| left.normalized_name.cmp(&right.normalized_name))
        });

        let mut largest_objects = objects_by_digest
            .iter()
            .map(|(sha256, size)| {
                let labels = labels_by_digest.get(sha256);
                let reference_count = labels.map(BTreeSet::len).unwrap_or(0);
                ObjectUtilization {
                    sha256: sha256.clone(),
                    size: *size,
                    reference_count,
                    usage: usage_summary(labels),
                }
            })
            .collect::<Vec<_>>();
        largest_objects.sort_by(|left, right| {
            right
                .size
                .cmp(&left.size)
                .then_with(|| left.sha256.cmp(&right.sha256))
        });
        largest_objects.truncate(20);

        Ok(UtilizationReport {
            total_objects,
            total_bytes,
            attributed_objects,
            attributed_bytes,
            categories,
            projects,
            shared_layer_groups,
            largest_objects,
        })
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

fn add_object_usage(
    labels_by_digest: &mut BTreeMap<String, BTreeSet<String>>,
    category_digests: &mut BTreeMap<String, BTreeSet<String>>,
    sha256: &str,
    category: &str,
    label: String,
) {
    labels_by_digest
        .entry(sha256.to_string())
        .or_default()
        .insert(label);
    category_digests
        .entry(category.to_string())
        .or_default()
        .insert(sha256.to_string());
}

fn usage_summary(labels: Option<&BTreeSet<String>>) -> String {
    let Some(labels) = labels else {
        return "Other object".to_string();
    };
    let mut summary = labels
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let remaining = labels.len().saturating_sub(3);
    if remaining > 0 {
        summary.push_str(&format!(" and {remaining} more"));
    }
    summary
}

fn shared_layer_groups(
    bundles: &[OciBundleRecord],
    objects_by_digest: &BTreeMap<String, u64>,
    tags_by_bundle: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<SharedLayerGroupUtilization>, AppError> {
    let mut layers_by_manifest = BTreeMap::<String, BTreeSet<String>>::new();
    let mut created_by_manifest = BTreeMap::new();
    let mut manifests_by_layer = BTreeMap::<String, BTreeSet<String>>::new();

    for bundle in bundles {
        let mut layers = BTreeSet::new();
        for object in &bundle.objects {
            if object.kind != "layer" {
                continue;
            }
            layers.insert(digest_sha256(&object.digest)?);
        }
        if layers.is_empty() {
            continue;
        }
        for layer in &layers {
            manifests_by_layer
                .entry(layer.clone())
                .or_default()
                .insert(bundle.digest.clone());
        }
        created_by_manifest.insert(bundle.digest.clone(), bundle.created);
        layers_by_manifest.insert(bundle.digest.clone(), layers);
    }

    let mut candidates = BTreeMap::<BTreeSet<String>, BTreeSet<String>>::new();
    for manifests in manifests_by_layer.values() {
        if manifests.len() < 2 {
            continue;
        }
        let Some(closed_layers) = intersect_manifest_layers(manifests, &layers_by_manifest) else {
            continue;
        };
        let support = layers_by_manifest
            .iter()
            .filter_map(|(manifest, layers)| {
                if closed_layers.is_subset(layers) {
                    Some(manifest.clone())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        if support.len() >= 2 {
            candidates.insert(closed_layers, support);
        }
    }

    candidates
        .into_iter()
        .map(|(layers, manifests)| {
            let labels = manifests
                .iter()
                .flat_map(|manifest| {
                    tags_by_bundle.get(manifest).cloned().unwrap_or_else(|| {
                        BTreeSet::from([format!("manifest {}", short_digest(manifest))])
                    })
                })
                .collect::<BTreeSet<_>>();
            let created = manifests
                .iter()
                .filter_map(|manifest| created_by_manifest.get(manifest).and_then(|value| *value))
                .collect::<Vec<_>>();
            let size = layers
                .iter()
                .filter_map(|layer| objects_by_digest.get(layer))
                .sum();
            Ok(SharedLayerGroupUtilization {
                id: shared_group_id(&layers),
                layer_count: layers.len(),
                size,
                manifest_count: manifests.len(),
                oldest_created: created.iter().min().copied(),
                newest_created: created.iter().max().copied(),
                layers: digest_summary(&layers),
                usage: usage_summary(Some(&labels)),
            })
        })
        .collect()
}

fn intersect_manifest_layers(
    manifests: &BTreeSet<String>,
    layers_by_manifest: &BTreeMap<String, BTreeSet<String>>,
) -> Option<BTreeSet<String>> {
    let mut manifests = manifests.iter();
    let first = layers_by_manifest.get(manifests.next()?)?.clone();
    Some(manifests.fold(first, |intersection, manifest| {
        let Some(layers) = layers_by_manifest.get(manifest) else {
            return BTreeSet::new();
        };
        intersection.intersection(layers).cloned().collect()
    }))
}

fn shared_group_id(layers: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    for layer in layers {
        hasher.update(layer.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize()).chars().take(12).collect()
}

fn digest_summary(digests: &BTreeSet<String>) -> String {
    let mut summary = digests
        .iter()
        .take(3)
        .map(|digest| digest.chars().take(12).collect::<String>())
        .collect::<Vec<_>>()
        .join(", ");
    let remaining = digests.len().saturating_sub(3);
    if remaining > 0 {
        summary.push_str(&format!(" and {remaining} more"));
    }
    summary
}

fn compare_optional_datetime(
    left: Option<DateTime<Utc>>,
    right: Option<DateTime<Utc>>,
) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn digest_sha256(digest: &str) -> Result<String, AppError> {
    digest
        .strip_prefix("sha256:")
        .filter(|sha256| sha256.len() == 64 && hex::decode(sha256).is_ok())
        .map(str::to_string)
        .ok_or_else(|| AppError::Internal(format!("invalid stored OCI digest '{digest}'")))
}

fn short_digest(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .chars()
        .take(12)
        .collect()
}

fn oci_category(kind: &str) -> &'static str {
    match kind {
        "index" => "OCI indexes",
        "manifest" => "OCI manifests",
        "config" => "OCI configs",
        "layer" => "OCI layers",
        "blob" => "OCI blobs",
        _ => "OCI objects",
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
        let repository = PackageRepository::from_config(
            &config.metadata_store,
            &config.object_store,
            &config.cache,
        )
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
        let reopened = PackageRepository::from_config(
            &config.metadata_store,
            &config.object_store,
            &config.cache,
        )
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
