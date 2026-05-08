// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::auth;
use crate::config::{Config, IdentityProviderConfig, PublisherConfig};
use crate::error::AppError;
use crate::oci::{DOCKER_DISTRIBUTION_API_VERSION, OciRegistry};
use crate::package::{
    FileRecord, ProjectIndex, ProjectSummary, SIMPLE_API_VERSION, UploadPackage, normalize_name,
};
use crate::repository::PackageRepository;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{debug, info};

const SIMPLE_HTML_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+html; charset=utf-8";
const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const SIMPLE_JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";

#[derive(Clone)]
pub struct AppState {
    pub repository: PackageRepository,
    pub oci_registry: OciRegistry,
    pub subject_validator: SubjectValidator,
    pub publishers: Arc<Vec<PublisherConfig>>,
    pub max_upload_bytes: usize,
}

pub async fn build_app_state(config: &Config, disable_auth: bool) -> anyhow::Result<AppState> {
    let object_directory = config.object_store.directory_or_default();
    Ok(AppState {
        repository: PackageRepository::from_config(&config.metadata_store, &config.object_store)
            .await?,
        oci_registry: OciRegistry::new(object_directory),
        subject_validator: SubjectValidator::new(config.identity_providers.clone(), disable_auth),
        publishers: Arc::new(config.publishers.clone()),
        max_upload_bytes: config.max_upload_bytes,
    })
}

pub fn build_router(state: AppState) -> Router {
    let max_upload_bytes = state.max_upload_bytes;
    Router::new()
        .route("/", get(simple_root))
        .route("/healthz", get(healthz))
        .route(
            "/v2",
            get(oci_api_version_check).head(oci_api_version_check),
        )
        .route(
            "/v2/",
            get(oci_api_version_check).head(oci_api_version_check),
        )
        .route(
            "/v2/{*path}",
            get(oci_dispatch)
                .head(oci_dispatch)
                .post(oci_dispatch)
                .put(oci_dispatch)
                .patch(oci_dispatch),
        )
        .route("/packages/{project}/{filename}", get(download_package))
        .route("/{project}", get(simple_project_redirect))
        .route("/{project}/", get(simple_project))
        .route("/{project}/{filename}", get(download_project_package))
        .route("/legacy", post(upload_distribution))
        .route("/legacy/", post(upload_distribution))
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn oci_api_version_check(method: Method) -> Result<Response, AppError> {
    if method != Method::GET && method != Method::HEAD {
        return method_not_allowed();
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from("{}")
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(
            "Docker-Distribution-API-Version",
            DOCKER_DISTRIBUTION_API_VERSION,
        )
        .body(body)
        .map_err(|error| AppError::Internal(format!("failed to build OCI response: {error}")))
}

async fn oci_dispatch(
    Path(path): Path<String>,
    State(state): State<AppState>,
    Query(query): Query<BTreeMap<String, String>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if let Some((repository, upload_uuid)) = split_oci_upload_path(&path) {
        return match method {
            Method::PATCH => {
                let claims = authenticate_push(&state, &headers)?;
                state.authorize_oci_repository(repository, &claims)?;
                let upload = state
                    .oci_registry
                    .append_upload(repository, upload_uuid, body)
                    .await?;
                oci_upload_response(repository, &upload.uuid, upload.size)
            }
            Method::PUT => {
                let digest = query.get("digest").ok_or_else(|| {
                    AppError::BadRequest("missing digest query parameter".to_string())
                })?;
                let claims = authenticate_push(&state, &headers)?;
                state.authorize_oci_repository(repository, &claims)?;
                let blob = state
                    .oci_registry
                    .finish_upload(repository, upload_uuid, digest, body)
                    .await?;
                oci_created_response(
                    &format!("/v2/{repository}/blobs/{}", blob.digest),
                    &blob.digest,
                )
            }
            _ => method_not_allowed(),
        };
    }

    if let Some(repository) = split_oci_upload_start_path(&path) {
        return match method {
            Method::POST => {
                let claims = authenticate_push(&state, &headers)?;
                state.authorize_oci_repository(repository, &claims)?;
                if let Some(digest) = query.get("digest") {
                    let blob = state
                        .oci_registry
                        .store_blob(repository, digest, body)
                        .await?;
                    oci_created_response(
                        &format!("/v2/{repository}/blobs/{}", blob.digest),
                        &blob.digest,
                    )
                } else {
                    let upload = state.oci_registry.start_upload(repository).await?;
                    oci_upload_response(repository, &upload.uuid, upload.size)
                }
            }
            _ => method_not_allowed(),
        };
    }

    if let Some((repository, digest)) = split_oci_blob_path(&path) {
        return match method {
            Method::GET => oci_get_blob(&state, repository, digest, false).await,
            Method::HEAD => oci_get_blob(&state, repository, digest, true).await,
            _ => method_not_allowed(),
        };
    }

    if let Some((repository, reference)) = split_oci_manifest_path(&path) {
        return match method {
            Method::GET => oci_get_manifest(&state, repository, reference, false).await,
            Method::HEAD => oci_get_manifest(&state, repository, reference, true).await,
            Method::PUT => {
                let claims = authenticate_push(&state, &headers)?;
                state.authorize_oci_repository(repository, &claims)?;
                let content_type = headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("application/vnd.oci.image.manifest.v1+json");
                let manifest = state
                    .oci_registry
                    .store_manifest(repository, reference, content_type, body)
                    .await?;
                oci_created_response(
                    &format!("/v2/{repository}/manifests/{}", manifest.digest),
                    &manifest.digest,
                )
            }
            _ => method_not_allowed(),
        };
    }

    Err(AppError::NotFound(format!(
        "unknown OCI registry path '/v2/{path}'"
    )))
}

async fn simple_project_redirect(Path(project): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/{}/", normalize_name(&project)))
}

async fn simple_root(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let projects = state.repository.list_projects().await?;
    if wants_json(&headers) {
        simple_json_response(&ProjectListJson::from(projects))
    } else {
        simple_html_response(&headers, render_project_list(&projects))
    }
}

async fn simple_project(
    Path(project): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let normalized_project = normalize_name(&project);
    if normalized_project != project {
        return Ok(Redirect::permanent(&format!("/{normalized_project}/")).into_response());
    }

    let project = state.repository.project(&normalized_project).await?;
    if wants_json(&headers) {
        simple_json_response(&ProjectDetailJson::from(project))
    } else {
        simple_html_response(&headers, render_project_detail(&project))
    }
}

async fn download_package(
    Path((project, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    package_response(&project, &filename, &state).await
}

async fn download_project_package(
    Path((project, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let normalized_project = normalize_name(&project);
    if normalized_project != project {
        return Ok(Redirect::permanent(&format!(
            "/{normalized_project}/{}",
            url_path_segment(&filename)
        ))
        .into_response());
    }

    package_response(&normalized_project, &filename, &state).await
}

async fn package_response(
    project: &str,
    filename: &str,
    state: &AppState,
) -> Result<Response, AppError> {
    let (content, _record) = state.repository.read_file(project, filename).await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .map_err(|error| AppError::Internal(format!("failed to build file response: {error}")))
}

async fn oci_get_blob(
    state: &AppState,
    repository: &str,
    digest: &str,
    headers_only: bool,
) -> Result<Response, AppError> {
    let blob = state.oci_registry.read_blob(repository, digest).await?;
    let body = if headers_only {
        Body::empty()
    } else {
        Body::from(blob.content.clone())
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, blob.content.len().to_string())
        .header("Docker-Content-Digest", blob.digest)
        .body(body)
        .map_err(|error| AppError::Internal(format!("failed to build OCI blob response: {error}")))
}

async fn oci_get_manifest(
    state: &AppState,
    repository: &str,
    reference: &str,
    headers_only: bool,
) -> Result<Response, AppError> {
    let manifest = state
        .oci_registry
        .read_manifest(repository, reference)
        .await?;
    let body = if headers_only {
        Body::empty()
    } else {
        Body::from(manifest.content.clone())
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, manifest.media_type)
        .header(header::CONTENT_LENGTH, manifest.content.len().to_string())
        .header("Docker-Content-Digest", manifest.digest)
        .body(body)
        .map_err(|error| {
            AppError::Internal(format!("failed to build OCI manifest response: {error}"))
        })
}

fn oci_upload_response(repository: &str, uuid: &str, size: u64) -> Result<Response, AppError> {
    let end = size.saturating_sub(1);
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("Docker-Upload-UUID", uuid)
        .header("Location", format!("/v2/{repository}/blobs/uploads/{uuid}"))
        .header("Range", format!("0-{end}"))
        .body(Body::empty())
        .map_err(|error| {
            AppError::Internal(format!("failed to build OCI upload response: {error}"))
        })
}

fn oci_created_response(location: &str, digest: &str) -> Result<Response, AppError> {
    Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", location)
        .header("Docker-Content-Digest", digest)
        .body(Body::empty())
        .map_err(|error| AppError::Internal(format!("failed to build OCI response: {error}")))
}

fn method_not_allowed() -> Result<Response, AppError> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::empty())
        .map_err(|error| {
            AppError::Internal(format!(
                "failed to build method-not-allowed response: {error}"
            ))
        })
}

fn authenticate_push(state: &AppState, headers: &HeaderMap) -> Result<SourceClaims, AppError> {
    let bearer_token = match auth::extract_upload_token(headers) {
        Ok(token) => Some(token),
        Err(_error) if !state.subject_validator.auth_enabled() => None,
        Err(error) => return Err(error),
    };
    state.subject_validator.validate(bearer_token.as_deref())
}

fn split_oci_blob_path(path: &str) -> Option<(&str, &str)> {
    let (repository, digest) = path.rsplit_once("/blobs/")?;
    if repository.is_empty() || digest.is_empty() {
        return None;
    }
    Some((repository, digest))
}

fn split_oci_upload_path(path: &str) -> Option<(&str, &str)> {
    let (repository, uuid) = path.rsplit_once("/blobs/uploads/")?;
    if repository.is_empty() || uuid.is_empty() {
        return None;
    }
    Some((repository, uuid))
}

fn split_oci_upload_start_path(path: &str) -> Option<&str> {
    path.strip_suffix("/blobs/uploads/")
        .or_else(|| path.strip_suffix("/blobs/uploads"))
        .filter(|repository| !repository.is_empty())
}

fn split_oci_manifest_path(path: &str) -> Option<(&str, &str)> {
    let (repository, reference) = path.rsplit_once("/manifests/")?;
    if repository.is_empty() || reference.is_empty() {
        return None;
    }
    Some((repository, reference))
}

async fn upload_distribution(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Response, AppError> {
    let bearer_token = match auth::extract_upload_token(&headers) {
        Ok(token) => {
            debug!("upload authorization token found");
            Some(token)
        }
        Err(error) if !state.subject_validator.auth_enabled() => {
            debug!(
                error = %error,
                "upload authorization token missing or invalid; continuing because auth is disabled"
            );
            None
        }
        Err(error) => return Err(error),
    };
    let source_claims = state.subject_validator.validate(bearer_token.as_deref())?;
    let upload = parse_upload_form(multipart).await?;
    let normalized_project = normalize_name(&upload.name);
    state.authorize_upload(&normalized_project, &source_claims)?;
    let record = state.repository.store_upload(upload).await?;

    info!(
        project = %normalized_project,
        filename = %record.filename,
        subject = %source_claims.subject(),
        "package uploaded"
    );
    Ok((StatusCode::OK, "OK\n").into_response())
}

impl AppState {
    fn authorize_upload(
        &self,
        normalized_project: &str,
        claims: &SourceClaims,
    ) -> Result<(), AppError> {
        if !self.subject_validator.auth_enabled() {
            debug!(
                project = %normalized_project,
                "publisher authorization skipped because auth is disabled"
            );
            return Ok(());
        }

        let mut project_policy_seen = false;
        for publisher in self.publishers.iter() {
            if !publisher_allows_project(publisher, normalized_project) {
                continue;
            }
            if !claims.matches_identity_provider(publisher.identity_provider.as_deref()) {
                continue;
            }
            project_policy_seen = true;
            if let Some((claim_name, required_value)) =
                claims.first_missing_required_claim(&publisher.required_claims)
            {
                debug!(
                    publisher = %publisher.display_name(),
                    project = %normalized_project,
                    claim_name,
                    required_value,
                    "publisher policy did not match token claims"
                );
                continue;
            }
            debug!(
                publisher = %publisher.display_name(),
                project = %normalized_project,
                subject = %claims.subject(),
                "publisher authorization check passed"
            );
            return Ok(());
        }

        if project_policy_seen {
            Err(AppError::Forbidden(format!(
                "token claims do not satisfy a publisher policy for project '{normalized_project}'"
            )))
        } else {
            Err(AppError::Forbidden(format!(
                "no publisher policy allows project '{normalized_project}'"
            )))
        }
    }

    fn authorize_oci_repository(
        &self,
        repository: &str,
        claims: &SourceClaims,
    ) -> Result<(), AppError> {
        if !self.subject_validator.auth_enabled() {
            debug!(
                repository,
                "OCI publisher authorization skipped because auth is disabled"
            );
            return Ok(());
        }

        let mut repository_policy_seen = false;
        for publisher in self.publishers.iter() {
            if !publisher_allows_oci_repository(publisher, repository) {
                continue;
            }
            if !claims.matches_identity_provider(publisher.identity_provider.as_deref()) {
                continue;
            }
            repository_policy_seen = true;
            if let Some((claim_name, required_value)) =
                claims.first_missing_required_claim(&publisher.required_claims)
            {
                debug!(
                    publisher = %publisher.display_name(),
                    repository,
                    claim_name,
                    required_value,
                    "OCI publisher policy did not match token claims"
                );
                continue;
            }
            debug!(
                publisher = %publisher.display_name(),
                repository,
                subject = %claims.subject(),
                "OCI publisher authorization check passed"
            );
            return Ok(());
        }

        if repository_policy_seen {
            Err(AppError::Forbidden(format!(
                "token claims do not satisfy a publisher policy for OCI repository '{repository}'"
            )))
        } else {
            Err(AppError::Forbidden(format!(
                "no publisher policy allows OCI repository '{repository}'"
            )))
        }
    }
}

fn publisher_allows_project(publisher: &PublisherConfig, normalized_project: &str) -> bool {
    publisher
        .projects
        .iter()
        .any(|project| project == "*" || normalize_name(project).as_str() == normalized_project)
}

fn publisher_allows_oci_repository(publisher: &PublisherConfig, repository: &str) -> bool {
    publisher
        .projects
        .iter()
        .any(|project| project == "*" || project == repository)
}

#[derive(Clone)]
pub struct SubjectValidator {
    mode: SubjectValidationMode,
}

#[derive(Clone)]
enum SubjectValidationMode {
    Disabled,
    Enabled(BTreeMap<String, IdentityProviderConfig>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceClaims {
    #[serde(skip)]
    identity_provider: Option<String>,
    sub: String,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

impl SourceClaims {
    fn unauthenticated() -> Self {
        Self {
            identity_provider: None,
            sub: "unauthenticated".to_string(),
            claims: BTreeMap::new(),
        }
    }

    pub fn subject(&self) -> &str {
        &self.sub
    }

    fn first_missing_required_claim<'a>(
        &self,
        required_claims: &'a BTreeMap<String, String>,
    ) -> Option<(&'a str, &'a str)> {
        required_claims
            .iter()
            .find(|(claim_name, required_value)| {
                self.claim_value(claim_name.as_str()) != Some(required_value.as_str())
            })
            .map(|(claim_name, required_value)| (claim_name.as_str(), required_value.as_str()))
    }

    fn claim_value(&self, claim_name: &str) -> Option<&str> {
        if claim_name == "sub" {
            return Some(&self.sub);
        }
        self.claims.get(claim_name).and_then(Value::as_str)
    }

    fn matches_identity_provider(&self, identity_provider: Option<&str>) -> bool {
        self.identity_provider.as_deref() == identity_provider
    }
}

impl SubjectValidator {
    pub fn new(identity_providers: Vec<IdentityProviderConfig>, disable_auth: bool) -> Self {
        let mode = if disable_auth {
            SubjectValidationMode::Disabled
        } else {
            let identity_providers = identity_providers
                .into_iter()
                .map(|identity_provider| (identity_provider.name.clone(), identity_provider))
                .collect();
            SubjectValidationMode::Enabled(identity_providers)
        };
        Self { mode }
    }

    pub fn validate(&self, bearer_token: Option<&str>) -> Result<SourceClaims, AppError> {
        let identity_providers = match &self.mode {
            SubjectValidationMode::Disabled => {
                debug!("upload token claim validation skipped because auth is disabled");
                return Ok(SourceClaims::unauthenticated());
            }
            SubjectValidationMode::Enabled(identity_providers) => identity_providers,
        };
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let mut last_error = None;
        for authentication in identity_providers.values() {
            match self.validate_with_provider(authentication, bearer_token) {
                Ok(mut claims) => {
                    claims.identity_provider = Some(authentication.name.clone());
                    return Ok(claims);
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            AppError::Unauthorized("no identity providers configured".to_string())
        }))
    }

    fn validate_with_provider(
        &self,
        authentication: &IdentityProviderConfig,
        bearer_token: &str,
    ) -> Result<SourceClaims, AppError> {
        let (algorithm, decoding_key) =
            auth::decoding_key_for_token(authentication, bearer_token).map_err(AppError::from)?;
        debug!(
            algorithm = ?algorithm,
            identity_provider = %authentication.name,
            audience = %authentication.audience,
            issuer = %authentication.issuer,
            "validating upload token claims"
        );
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&authentication.audience]);
        validation.set_issuer(&[&authentication.issuer]);

        let decoded =
            decode::<SourceClaims>(bearer_token, &decoding_key, &validation).map_err(|error| {
                AppError::Unauthorized(format!("failed to validate upload token: {error}"))
            })?;
        debug!(
            identity_provider = %authentication.name,
            subject = %decoded.claims.sub,
            "upload token claims validated"
        );
        Ok(decoded.claims)
    }

    pub fn auth_enabled(&self) -> bool {
        matches!(self.mode, SubjectValidationMode::Enabled(_))
    }
}

#[derive(Default)]
struct ParsedUploadForm {
    action: Option<String>,
    protocol_version: Option<String>,
    content: Option<UploadedContent>,
    filetype: Option<String>,
    pyversion: Option<String>,
    metadata_version: Option<String>,
    name: Option<String>,
    version: Option<String>,
    md5_digest: Option<String>,
    sha256_digest: Option<String>,
    blake2_256_digest: Option<String>,
    requires_python: Option<String>,
}

struct UploadedContent {
    filename: String,
    bytes: Bytes,
}

async fn parse_upload_form(mut multipart: Multipart) -> Result<UploadPackage, AppError> {
    let mut form = ParsedUploadForm::default();

    while let Some(field) = multipart.next_field().await.map_err(|error| {
        AppError::BadRequest(format!("failed to read multipart upload: {error}"))
    })? {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name == "content" {
            let filename = field
                .file_name()
                .ok_or_else(|| {
                    AppError::BadRequest("content field must include a filename".to_string())
                })?
                .to_string();
            let bytes = field.bytes().await.map_err(|error| {
                AppError::BadRequest(format!("failed to read uploaded content: {error}"))
            })?;
            form.content = Some(UploadedContent { filename, bytes });
            continue;
        }

        let bytes = field.bytes().await.map_err(|error| {
            AppError::BadRequest(format!(
                "failed to read multipart field '{field_name}': {error}"
            ))
        })?;
        let value = String::from_utf8(bytes.to_vec()).map_err(|_| {
            AppError::BadRequest(format!("multipart field '{field_name}' is not valid UTF-8"))
        })?;

        match field_name.as_str() {
            ":action" => form.action = Some(value),
            "protocol_version" => form.protocol_version = Some(value),
            "filetype" => form.filetype = Some(value),
            "pyversion" => form.pyversion = Some(value),
            "metadata_version" => form.metadata_version = Some(value),
            "name" => form.name = Some(value),
            "version" => form.version = Some(value),
            "md5_digest" => form.md5_digest = Some(value),
            "sha256_digest" => form.sha256_digest = Some(value),
            "blake2_256_digest" => form.blake2_256_digest = Some(value),
            "requires_python" => form.requires_python = non_empty_value(value),
            _ => {}
        }
    }

    form.into_upload_package()
}

impl ParsedUploadForm {
    fn into_upload_package(self) -> Result<UploadPackage, AppError> {
        require_exact(self.action.as_deref(), ":action", "file_upload")?;
        require_exact(self.protocol_version.as_deref(), "protocol_version", "1")?;
        let filetype = require_field(self.filetype, "filetype")?;
        if !matches!(filetype.as_str(), "bdist_wheel" | "sdist") {
            return Err(AppError::BadRequest(
                "filetype must be bdist_wheel or sdist".to_string(),
            ));
        }
        let pyversion = require_field(self.pyversion, "pyversion")?;
        if pyversion.is_empty() {
            return Err(AppError::BadRequest(
                "pyversion must not be empty".to_string(),
            ));
        }
        let metadata_version = require_field(self.metadata_version, "metadata_version")?;
        if metadata_version.is_empty() {
            return Err(AppError::BadRequest(
                "metadata_version must not be empty".to_string(),
            ));
        }

        let name = require_field(self.name, "name")?;
        let version = require_field(self.version, "version")?;
        let content = self
            .content
            .ok_or_else(|| AppError::BadRequest("missing content field".to_string()))?;
        let has_any_digest = self.md5_digest.is_some()
            || self.sha256_digest.is_some()
            || self.blake2_256_digest.is_some();

        Ok(UploadPackage {
            name,
            version,
            filename: content.filename,
            content: content.bytes.to_vec(),
            provided_sha256: self.sha256_digest,
            has_any_digest,
            requires_python: self.requires_python,
        })
    }
}

fn require_field(value: Option<String>, name: &str) -> Result<String, AppError> {
    let value = value.ok_or_else(|| AppError::BadRequest(format!("missing {name} field")))?;
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{name} must not be empty")));
    }
    Ok(value)
}

fn require_exact(value: Option<&str>, name: &str, expected: &str) -> Result<(), AppError> {
    match value {
        Some(value) if value == expected => Ok(()),
        Some(_) => Err(AppError::BadRequest(format!(
            "{name} must be set to {expected}"
        ))),
        None => Err(AppError::BadRequest(format!("missing {name} field"))),
    }
}

fn non_empty_value(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn wants_json(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT) else {
        return false;
    };
    let Ok(accept) = accept.to_str() else {
        return false;
    };

    let mut best_json = None;
    let mut best_html = None;

    for part in accept.split(',') {
        let mut segments = part.trim().split(';').map(str::trim);
        let media_type = segments.next().unwrap_or("").to_ascii_lowercase();
        let mut quality = 1.0;
        for segment in segments {
            if let Some(raw_quality) = segment.strip_prefix("q=")
                && let Ok(parsed_quality) = raw_quality.parse::<f32>()
            {
                quality = parsed_quality;
            }
        }

        if matches!(
            media_type.as_str(),
            "application/vnd.pypi.simple.v1+json"
                | "application/vnd.pypi.simple.latest+json"
                | "application/json"
        ) {
            best_json = Some(best_json.unwrap_or(0.0_f32).max(quality));
        }
        if matches!(
            media_type.as_str(),
            "application/vnd.pypi.simple.v1+html"
                | "application/vnd.pypi.simple.latest+html"
                | "text/html"
                | "*/*"
        ) {
            best_html = Some(best_html.unwrap_or(0.0_f32).max(quality));
        }
    }

    best_json.unwrap_or(0.0) > best_html.unwrap_or(0.0)
}

fn wants_simple_html_content_type(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT) else {
        return false;
    };
    let Ok(accept) = accept.to_str() else {
        return false;
    };

    accept.split(',').any(|part| {
        let mut segments = part.trim().split(';').map(str::trim);
        let media_type = segments.next().unwrap_or("").to_ascii_lowercase();
        if !matches!(
            media_type.as_str(),
            "application/vnd.pypi.simple.v1+html" | "application/vnd.pypi.simple.latest+html"
        ) {
            return false;
        }

        for segment in segments {
            if let Some(raw_quality) = segment.strip_prefix("q=")
                && let Ok(parsed_quality) = raw_quality.parse::<f32>()
            {
                return parsed_quality > 0.0;
            }
        }
        true
    })
}

fn simple_html_response(headers: &HeaderMap, html: String) -> Result<Response, AppError> {
    let content_type = if wants_simple_html_content_type(headers) {
        SIMPLE_HTML_CONTENT_TYPE
    } else {
        HTML_CONTENT_TYPE
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(html))
        .map_err(|error| AppError::Internal(format!("failed to build HTML response: {error}")))
}

fn simple_json_response<T: Serialize>(body: &T) -> Result<Response, AppError> {
    let body = serde_json::to_vec(body)
        .map_err(|error| AppError::Internal(format!("failed to serialize JSON: {error}")))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, SIMPLE_JSON_CONTENT_TYPE)
        .body(Body::from(body))
        .map_err(|error| AppError::Internal(format!("failed to build JSON response: {error}")))
}

fn render_project_list(projects: &[ProjectSummary]) -> String {
    let mut html = simple_html_start("reposnake projects");
    for project in projects {
        html.push_str("<a href=\"/");
        html.push_str(&escape_html_attr(&project.normalized_name));
        html.push_str("/\">");
        html.push_str(&escape_html_text(&project.name));
        html.push_str("</a>\n");
    }
    html.push_str("</body>\n</html>\n");
    html
}

fn render_project_detail(project: &ProjectIndex) -> String {
    let mut html = simple_html_start(&project.normalized_name);
    for file in &project.files {
        html.push_str("<a href=\"");
        html.push_str(&escape_html_attr(&url_path_segment(&file.filename)));
        html.push_str("#sha256=");
        html.push_str(&escape_html_attr(&file.sha256));
        html.push('"');
        if let Some(requires_python) = &file.requires_python {
            html.push_str(" data-requires-python=\"");
            html.push_str(&escape_html_attr(requires_python));
            html.push('"');
        }
        html.push('>');
        html.push_str(&escape_html_text(&file.filename));
        html.push_str("</a>\n");
    }
    html.push_str("</body>\n</html>\n");
    html
}

fn simple_html_start(title: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta name=\"pypi:repository-version\" content=\"{}\">\n<title>{}</title>\n</head>\n<body>\n",
        SIMPLE_API_VERSION,
        escape_html_text(title)
    )
}

fn escape_html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_html_attr(value: &str) -> String {
    escape_html_text(value).replace('"', "&quot;")
}

fn url_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[derive(Serialize)]
struct ProjectListJson {
    meta: SimpleMetaJson,
    projects: Vec<ProjectNameJson>,
}

impl From<Vec<ProjectSummary>> for ProjectListJson {
    fn from(projects: Vec<ProjectSummary>) -> Self {
        Self {
            meta: SimpleMetaJson::default(),
            projects: projects
                .into_iter()
                .map(|project| ProjectNameJson { name: project.name })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct ProjectDetailJson {
    meta: SimpleMetaJson,
    name: String,
    files: Vec<ProjectFileJson>,
    versions: Vec<String>,
}

impl From<ProjectIndex> for ProjectDetailJson {
    fn from(project: ProjectIndex) -> Self {
        let versions = project
            .files
            .iter()
            .map(|file| file.version.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            meta: SimpleMetaJson::default(),
            name: project.normalized_name.clone(),
            files: project
                .files
                .into_iter()
                .map(|file| ProjectFileJson::from_record(&project.normalized_name, file))
                .collect(),
            versions,
        }
    }
}

#[derive(Serialize)]
struct SimpleMetaJson {
    #[serde(rename = "api-version")]
    api_version: &'static str,
}

impl Default for SimpleMetaJson {
    fn default() -> Self {
        Self {
            api_version: SIMPLE_API_VERSION,
        }
    }
}

#[derive(Serialize)]
struct ProjectNameJson {
    name: String,
}

#[derive(Serialize)]
struct ProjectFileJson {
    filename: String,
    url: String,
    hashes: BTreeMap<String, String>,
    size: u64,
    #[serde(rename = "requires-python", skip_serializing_if = "Option::is_none")]
    requires_python: Option<String>,
}

impl ProjectFileJson {
    fn from_record(_normalized_project: &str, file: FileRecord) -> Self {
        Self {
            url: url_path_segment(&file.filename),
            filename: file.filename,
            hashes: BTreeMap::from([("sha256".to_string(), file.sha256)]),
            size: file.size,
            requires_python: file.requires_python,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, SubjectValidator, build_router};
    use crate::config::{IdentityProviderConfig, PublisherConfig};
    use crate::oci::OciRegistry;
    use crate::package::SIMPLE_API_VERSION;
    use crate::repository::PackageRepository;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn upload_then_serves_simple_html_and_package() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let body = multipart_upload_body("reposnake_demo", "0.1.0", b"package-content");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/legacy/")
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=reposnake-boundary",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/reposnake-demo/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(&format!(
            "pypi:repository-version\" content=\"{SIMPLE_API_VERSION}"
        )));
        assert!(body.contains("href=\"reposnake_demo-0.1.0.tar.gz#sha256="));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/reposnake-demo/reposnake_demo-0.1.0.tar.gz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"package-content");
    }

    #[tokio::test]
    async fn simple_html_uses_browser_content_type_unless_simple_html_is_accepted() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(
                        header::ACCEPT,
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "application/vnd.pypi.simple.v1+html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/vnd.pypi.simple.v1+html; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn simple_json_uses_relative_artifact_basenames() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/legacy/")
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=reposnake-boundary",
                    )
                    .body(Body::from(multipart_upload_body(
                        "reposnake_demo",
                        "0.1.0",
                        b"package-content",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/reposnake-demo/")
                    .header(header::ACCEPT, "application/vnd.pypi.simple.v1+json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["files"][0]["url"], "reposnake_demo-0.1.0.tar.gz");
    }

    #[tokio::test]
    async fn simple_prefix_is_not_a_compatibility_index() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/simple/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn upload_accepts_jwt_as_basic_password() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "ci");
        let credentials = general_purpose::STANDARD.encode(format!("__token__:{token}"));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/legacy/")
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=reposnake-boundary",
                    )
                    .header(header::AUTHORIZATION, format!("Basic {credentials}"))
                    .body(Body::from(multipart_upload_body(
                        "reposnake_demo",
                        "0.1.0",
                        b"package-content",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn upload_rejects_jwt_with_wrong_claims() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "other");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/legacy/")
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=reposnake-boundary",
                    )
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(multipart_upload_body(
                        "reposnake_demo",
                        "0.1.0",
                        b"package-content",
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn oci_push_then_public_pull_blob_and_manifest() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "ci");
        let layer_digest =
            "sha256:dac1d7cfa95021764849fd102524e141488c5e3a90f861dbb5a12d9ac8584f85";

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v2/team/image/blobs/uploads/?digest={layer_digest}"
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from("layer"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["Docker-Content-Digest"], layer_digest);

        let manifest = r#"{"schemaVersion":2,"layers":[]}"#;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v2/team/image/manifests/latest")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(manifest))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let manifest_digest = response.headers()["Docker-Content-Digest"]
            .to_str()
            .unwrap()
            .to_string();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v2/team/image/blobs/{layer_digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"layer");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/team/image/manifests/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["Docker-Content-Digest"], manifest_digest);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], manifest.as_bytes());
    }

    #[tokio::test]
    async fn oci_push_rejects_jwt_with_wrong_claims() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "other");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v2/team/image/manifests/latest")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    async fn unauthenticated_state(path: &std::path::Path) -> AppState {
        AppState {
            repository: PackageRepository::new(path).await.unwrap(),
            oci_registry: OciRegistry::new(path),
            subject_validator: SubjectValidator::new(Vec::new(), true),
            publishers: Arc::new(Vec::new()),
            max_upload_bytes: 1024 * 1024,
        }
    }

    async fn authenticated_state(path: &std::path::Path) -> AppState {
        AppState {
            repository: PackageRepository::new(path).await.unwrap(),
            oci_registry: OciRegistry::new(path),
            subject_validator: SubjectValidator::new(
                vec![IdentityProviderConfig {
                    name: "buildkite".to_string(),
                    audience: "reposnake".to_string(),
                    issuer: "https://issuer.example".to_string(),
                    validation_key: Some("shared-secret".to_string()),
                }],
                false,
            ),
            publishers: Arc::new(vec![PublisherConfig {
                name: "ci".to_string(),
                projects: vec!["reposnake-demo".to_string(), "team/image".to_string()],
                identity_provider: Some("buildkite".to_string()),
                required_claims: BTreeMap::from([("pipeline".to_string(), "ci".to_string())]),
            }]),
            max_upload_bytes: 1024 * 1024,
        }
    }

    fn multipart_upload_body(name: &str, version: &str, content: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        push_field(&mut body, ":action", "file_upload");
        push_field(&mut body, "protocol_version", "1");
        push_field(&mut body, "filetype", "sdist");
        push_field(&mut body, "pyversion", "source");
        push_field(&mut body, "metadata_version", "2.4");
        push_field(&mut body, "name", name);
        push_field(&mut body, "version", version);
        push_field(&mut body, "sha256_digest", &sha256(content));
        body.extend_from_slice(b"--reposnake-boundary\r\n");
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"content\"; filename=\"{name}-{version}.tar.gz\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n--reposnake-boundary--\r\n");
        body
    }

    fn push_field(body: &mut Vec<u8>, name: &str, value: &str) {
        body.extend_from_slice(b"--reposnake-boundary\r\n");
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    fn sha256(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        pipeline: &'a str,
    }

    fn test_token(subject: &str, pipeline: &str) -> String {
        crate::auth::install_jwt_crypto_provider();
        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: subject,
                iss: "https://issuer.example",
                aud: "reposnake",
                exp: 4_102_444_800,
                pipeline,
            },
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap()
    }
}
