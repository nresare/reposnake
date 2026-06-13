// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::auth;
use crate::config::{Config, IdentityProviderConfig, PublisherConfig};
use crate::embed::StaticFile;
use crate::error::AppError;
use crate::oci::{DOCKER_DISTRIBUTION_API_VERSION, OciRegistry};
use crate::package::{
    FileRecord, ProjectIndex, ProjectSummary, SIMPLE_API_VERSION, UploadPackage, normalize_name,
};
use crate::repository::{
    ObjectUtilization, PackageRepository, ProjectUtilization, SharedObjectUtilization,
    UtilizationCategory, UtilizationReport,
};
use crate::web::Templates;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
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
    pub templates: Templates,
    pub origin: String,
}

pub async fn build_app_state(config: &Config, disable_auth: bool) -> anyhow::Result<AppState> {
    let repository =
        PackageRepository::from_config(&config.metadata_store, &config.object_store).await?;
    Ok(AppState {
        oci_registry: OciRegistry::new(repository.metadata_store(), repository.object_store()),
        repository,
        subject_validator: SubjectValidator::new(config.identity_providers.clone(), disable_auth),
        publishers: Arc::new(config.publishers.clone()),
        max_upload_bytes: config.max_upload_bytes,
        templates: Templates::new()?,
        origin: config.origin.clone(),
    })
}

pub fn build_router(state: AppState) -> Router {
    let max_upload_bytes = state.max_upload_bytes;
    Router::new()
        .route("/", get(simple_root).post(upload_distribution))
        .route("/healthz", get(healthz))
        .route(
            "/v2",
            get(oci_api_version_check).head(oci_api_version_check),
        )
        .route(
            "/v2/",
            get(oci_api_version_check).head(oci_api_version_check),
        )
        .route("/v2/token", get(oci_token))
        .route(
            "/v2/{*path}",
            get(oci_dispatch)
                .head(oci_dispatch)
                .post(oci_dispatch)
                .put(oci_dispatch)
                .patch(oci_dispatch),
        )
        .route("/-/utilization", get(utilization_dashboard))
        .route("/-/utilisation", get(utilization_dashboard))
        .route("/static/{*path}", get(static_file))
        .route("/packages/{project}/{filename}", get(download_package))
        .route("/{project}", get(simple_project_redirect))
        .route("/{project}/", get(simple_project))
        .route("/{project}/{filename}", get(download_project_package))
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    state.repository.metadata_store().list_projects().await?;
    state.repository.object_store().check_availability().await?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn static_file(Path(path): Path<String>) -> StaticFile<String> {
    StaticFile(path)
}

async fn utilization_dashboard(State(state): State<AppState>) -> Result<Response, AppError> {
    let report = state.repository.utilization_report().await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, HTML_CONTENT_TYPE)
        .body(Body::from(render_utilization_report(
            &state.templates,
            &report,
        )?))
        .map_err(|error| {
            AppError::Internal(format!("failed to build utilization response: {error}"))
        })
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
                let claims = authenticate_oci_push(&state, &headers, repository)?;
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
                let claims = authenticate_oci_push(&state, &headers, repository)?;
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
                let claims = authenticate_oci_push(&state, &headers, repository)?;
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

    if let Some(repository) = split_oci_tags_path(&path) {
        return match method {
            Method::GET => oci_list_tags(&state, repository).await,
            _ => method_not_allowed(),
        };
    }

    if let Some((repository, reference)) = split_oci_manifest_path(&path) {
        return match method {
            Method::GET => oci_get_manifest(&state, repository, reference, false).await,
            Method::HEAD => oci_get_manifest(&state, repository, reference, true).await,
            Method::PUT => {
                let claims = authenticate_oci_push(&state, &headers, repository)?;
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

async fn oci_token(
    State(state): State<AppState>,
    Query(request): Query<OciTokenRequest>,
    headers: HeaderMap,
) -> Result<Json<OciTokenResponse>, AppError> {
    let token = auth::extract_upload_token(&headers)?;
    let claims = state.subject_validator.validate(Some(&token))?;
    if let Some(scope) = request.scope.as_deref() {
        authorize_oci_token_scope(&state, &claims, scope)?;
    }
    Ok(Json(OciTokenResponse {
        token: token.clone(),
        access_token: token,
    }))
}

#[derive(Deserialize)]
struct OciTokenRequest {
    scope: Option<String>,
}

#[derive(Serialize)]
struct OciTokenResponse {
    token: String,
    access_token: String,
}

#[derive(Serialize)]
struct OciTagsResponse {
    name: String,
    tags: Vec<String>,
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
        simple_html_response(
            &headers,
            render_project_list(&state.templates, &state.origin, &projects)?,
        )
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
        simple_html_response(&headers, render_project_detail(&state.templates, &project)?)
    }
}

async fn download_package(
    Path((project, filename)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    file_response(&project, &filename, &state).await
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

    file_response(&normalized_project, &filename, &state).await
}

async fn file_response(
    project: &str,
    filename: &str,
    state: &AppState,
) -> Result<Response, AppError> {
    if filename.ends_with(".metadata") {
        return metadata_response(project, filename, state).await;
    }
    package_response(project, filename, state).await
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

async fn metadata_response(
    project: &str,
    filename: &str,
    state: &AppState,
) -> Result<Response, AppError> {
    let (content, _record) = state
        .repository
        .read_file_metadata(project, filename)
        .await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .map_err(|error| AppError::Internal(format!("failed to build metadata response: {error}")))
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

async fn oci_list_tags(state: &AppState, repository: &str) -> Result<Response, AppError> {
    let tags = state.oci_registry.list_tags(repository).await?;
    let content = serde_json::to_vec(&OciTagsResponse {
        name: repository.to_string(),
        tags,
    })
    .map_err(|error| AppError::Internal(format!("failed to encode OCI tags: {error}")))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, content.len().to_string())
        .header(
            "Docker-Distribution-API-Version",
            DOCKER_DISTRIBUTION_API_VERSION,
        )
        .body(Body::from(content))
        .map_err(|error| AppError::Internal(format!("failed to build OCI tags response: {error}")))
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

fn authenticate_oci_push(
    state: &AppState,
    headers: &HeaderMap,
    repository: &str,
) -> Result<SourceClaims, AppError> {
    authenticate_push(state, headers).map_err(|error| match error {
        AppError::Unauthorized(message) => AppError::OciUnauthorized {
            message,
            authenticate: oci_authenticate_challenge(state, repository),
        },
        error => error,
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

fn oci_authenticate_challenge(state: &AppState, repository: &str) -> String {
    let realm = format!("{}/v2/token", state.origin.trim_end_matches('/'));
    format!(
        "Bearer realm=\"{}\",service=\"{}\",scope=\"repository:{}:pull,push\"",
        quoted_header_value(&realm),
        quoted_header_value(&oci_service_name(&state.origin)),
        quoted_header_value(repository)
    )
}

fn oci_service_name(origin: &str) -> String {
    origin
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(origin)
        .to_string()
}

fn quoted_header_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn authorize_oci_token_scope(
    state: &AppState,
    claims: &SourceClaims,
    scope: &str,
) -> Result<(), AppError> {
    let Some(repository_scope) = scope.strip_prefix("repository:") else {
        return Ok(());
    };
    let Some((repository, actions)) = repository_scope.rsplit_once(':') else {
        return Err(AppError::BadRequest(format!(
            "invalid OCI token scope '{scope}'"
        )));
    };
    if repository.is_empty() || actions.is_empty() {
        return Err(AppError::BadRequest(format!(
            "invalid OCI token scope '{scope}'"
        )));
    }
    if actions.split(',').any(|action| action == "push") {
        state.authorize_oci_repository(repository, claims)?;
    }
    Ok(())
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

fn split_oci_tags_path(path: &str) -> Option<&str> {
    path.strip_suffix("/tags/list")
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

fn render_project_list(
    templates: &Templates,
    origin: &str,
    projects: &[ProjectSummary],
) -> Result<String, AppError> {
    let example_project = projects
        .first()
        .map(|project| project.normalized_name.as_str())
        .unwrap_or("example-package");
    let projects = projects
        .iter()
        .map(ProjectSummaryTemplate::from)
        .collect::<Vec<_>>();
    templates
        .render(
            "index",
            &ProjectListTemplate {
                simple_api_version: SIMPLE_API_VERSION,
                origin,
                example_project,
                projects,
            },
        )
        .map_err(|error| AppError::Internal(format!("failed to render project list: {error}")))
}

fn render_project_detail(
    templates: &Templates,
    project: &ProjectIndex,
) -> Result<String, AppError> {
    let files = project
        .files
        .iter()
        .map(ProjectFileTemplate::from)
        .collect::<Vec<_>>();
    templates
        .render(
            "project",
            &ProjectDetailTemplate {
                simple_api_version: SIMPLE_API_VERSION,
                title: &project.normalized_name,
                files,
            },
        )
        .map_err(|error| AppError::Internal(format!("failed to render project detail: {error}")))
}

fn render_utilization_report(
    templates: &Templates,
    report: &UtilizationReport,
) -> Result<String, AppError> {
    templates
        .render("utilization", &UtilizationTemplate::from(report))
        .map_err(|error| {
            AppError::Internal(format!("failed to render utilization report: {error}"))
        })
}

#[derive(Serialize)]
struct ProjectListTemplate<'a> {
    simple_api_version: &'static str,
    origin: &'a str,
    example_project: &'a str,
    projects: Vec<ProjectSummaryTemplate>,
}

#[derive(Serialize)]
struct ProjectSummaryTemplate {
    name: String,
    normalized_name: String,
}

impl From<&ProjectSummary> for ProjectSummaryTemplate {
    fn from(project: &ProjectSummary) -> Self {
        Self {
            name: project.name.clone(),
            normalized_name: project.normalized_name.clone(),
        }
    }
}

#[derive(Serialize)]
struct ProjectDetailTemplate<'a> {
    simple_api_version: &'static str,
    title: &'a str,
    files: Vec<ProjectFileTemplate>,
}

#[derive(Serialize)]
struct UtilizationTemplate {
    total_objects: usize,
    total_bytes: u64,
    total_size: String,
    attributed_objects: usize,
    attributed_size: String,
    attributed_percent: u64,
    unattributed_objects: usize,
    unattributed_size: String,
    categories: Vec<UtilizationCategoryTemplate>,
    projects: Vec<ProjectUtilizationTemplate>,
    shared_objects: Vec<SharedObjectUtilizationTemplate>,
    largest_objects: Vec<ObjectUtilizationTemplate>,
}

impl From<&UtilizationReport> for UtilizationTemplate {
    fn from(report: &UtilizationReport) -> Self {
        Self {
            total_objects: report.total_objects,
            total_bytes: report.total_bytes,
            total_size: human_size(report.total_bytes),
            attributed_objects: report.attributed_objects,
            attributed_size: human_size(report.attributed_bytes),
            attributed_percent: percent(report.attributed_bytes, report.total_bytes),
            unattributed_objects: report
                .total_objects
                .saturating_sub(report.attributed_objects),
            unattributed_size: human_size(
                report.total_bytes.saturating_sub(report.attributed_bytes),
            ),
            categories: report
                .categories
                .iter()
                .map(|category| UtilizationCategoryTemplate::from_report(category, report))
                .collect(),
            projects: report
                .projects
                .iter()
                .map(|project| ProjectUtilizationTemplate::from_report(project, report))
                .collect(),
            shared_objects: report
                .shared_objects
                .iter()
                .map(SharedObjectUtilizationTemplate::from)
                .collect(),
            largest_objects: report
                .largest_objects
                .iter()
                .map(ObjectUtilizationTemplate::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct UtilizationCategoryTemplate {
    name: String,
    object_count: usize,
    size: String,
    percent: u64,
}

impl UtilizationCategoryTemplate {
    fn from_report(category: &UtilizationCategory, report: &UtilizationReport) -> Self {
        Self {
            name: category.name.clone(),
            object_count: category.object_count,
            size: human_size(category.bytes),
            percent: percent(category.bytes, report.total_bytes),
        }
    }
}

#[derive(Serialize)]
struct ProjectUtilizationTemplate {
    name: String,
    normalized_name: String,
    file_count: usize,
    size: String,
    percent: u64,
}

impl ProjectUtilizationTemplate {
    fn from_report(project: &ProjectUtilization, report: &UtilizationReport) -> Self {
        Self {
            name: project.name.clone(),
            normalized_name: project.normalized_name.clone(),
            file_count: project.file_count,
            size: human_size(project.bytes),
            percent: percent(project.bytes, report.total_bytes),
        }
    }
}

#[derive(Serialize)]
struct SharedObjectUtilizationTemplate {
    short_sha256: String,
    sha256: String,
    size: String,
    reference_count: usize,
    amortized_size: String,
    usage: String,
}

impl From<&SharedObjectUtilization> for SharedObjectUtilizationTemplate {
    fn from(object: &SharedObjectUtilization) -> Self {
        Self {
            short_sha256: object.sha256.chars().take(12).collect(),
            sha256: object.sha256.clone(),
            size: human_size(object.size),
            reference_count: object.reference_count,
            amortized_size: human_size(object.amortized_size),
            usage: object.usage.clone(),
        }
    }
}

#[derive(Serialize)]
struct ObjectUtilizationTemplate {
    short_sha256: String,
    sha256: String,
    size: String,
    reference_count: usize,
    usage: String,
}

impl From<&ObjectUtilization> for ObjectUtilizationTemplate {
    fn from(object: &ObjectUtilization) -> Self {
        Self {
            short_sha256: object.sha256.chars().take(12).collect(),
            sha256: object.sha256.clone(),
            size: human_size(object.size),
            reference_count: object.reference_count,
            usage: object.usage.clone(),
        }
    }
}

#[derive(Serialize)]
struct ProjectFileTemplate {
    filename: String,
    url: String,
    sha256: String,
    requires_python: Option<String>,
    metadata_sha256: Option<String>,
}

impl From<&FileRecord> for ProjectFileTemplate {
    fn from(file: &FileRecord) -> Self {
        Self {
            filename: file.filename.clone(),
            url: url_path_segment(&file.filename),
            sha256: file.sha256.clone(),
            requires_python: file.requires_python.clone(),
            metadata_sha256: file.metadata_sha256.clone(),
        }
    }
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

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = UNITS[0];
    for next_unit in &UNITS[1..] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next_unit;
    }
    if unit == "B" {
        format!("{bytes} B")
    } else if value < 10.0 {
        format!("{value:.1} {unit}")
    } else {
        format!("{value:.0} {unit}")
    }
}

fn percent(value: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((value as f64 / total as f64) * 100.0).round() as u64
    }
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
    #[serde(rename = "core-metadata", skip_serializing_if = "Option::is_none")]
    core_metadata: Option<BTreeMap<String, String>>,
}

impl ProjectFileJson {
    fn from_record(_normalized_project: &str, file: FileRecord) -> Self {
        Self {
            url: url_path_segment(&file.filename),
            filename: file.filename,
            hashes: BTreeMap::from([("sha256".to_string(), file.sha256)]),
            size: file.size,
            requires_python: file.requires_python,
            core_metadata: file
                .metadata_sha256
                .map(|sha256| BTreeMap::from([("sha256".to_string(), sha256)])),
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
    use crate::web::Templates;
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
    async fn healthz_checks_metadata_and_object_stores() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, serde_json::json!({ "status": "ok" }));
    }

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
                    .uri("/")
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
        assert!(body.contains("<main>"));
        assert!(body.contains("<h1 id=\"project-title\">reposnake-demo</h1>"));
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("reposnake"));
        assert!(body.contains("Using this repository"));
        assert!(
            body.contains("pip install --extra-index-url https://packages.example example-package")
        );
        assert!(body.contains("class=\"copy-button\""));
        assert!(body.contains("href=\"/static/index.css\""));
        assert!(body.contains("src=\"/static/index.js\""));

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
    async fn simple_html_uses_first_project_in_install_example() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
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
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body.contains("pip install --extra-index-url https://packages.example reposnake-demo")
        );
    }

    #[tokio::test]
    async fn utilization_dashboard_shows_object_store_totals() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
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
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/-/utilization")
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
        assert!(body.contains("<h1>Utilization</h1>"));
        assert!(body.contains("15 B across 1 objects"));
        assert!(body.contains("Python distributions"));
        assert!(body.contains("reposnake_demo-0.1.0.tar.gz"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/-/utilisation")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn utilization_dashboard_shows_shared_oci_objects() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "ci");
        let layer = b"shared-layer";
        let layer_digest = format!("sha256:{}", sha256(layer));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v2/team/image/blobs/uploads/?digest={layer_digest}"
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(layer.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        for repository in ["team/image", "team/worker"] {
            let manifest = format!(
                r#"{{"schemaVersion":2,"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
                layer.len()
            );
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/v2/{repository}/manifests/latest"))
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
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/-/utilization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<h2 id=\"shared-title\">Shared objects</h2>"));
        assert!(body.contains("<td>2</td>"));
        assert!(body.contains("6 B"));
        assert!(body.contains("team/image blob, team/worker blob"));
    }

    #[tokio::test]
    async fn static_assets_are_served_from_embedded_assets() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/static/index.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/css");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("--background"));
        assert!(body.contains(".project-link"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/static/index.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .contains("javascript")
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("navigator.clipboard.writeText"));
        assert!(body.contains("copied"));
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
                    .uri("/")
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
    async fn simple_api_serves_pep_714_metadata_for_wheels() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let metadata = b"Metadata-Version: 2.4\nName: reposnake-demo\nVersion: 0.1.0\n";
        let wheel = wheel_with_metadata(metadata);
        let metadata_sha256 = sha256(metadata);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(
                        header::CONTENT_TYPE,
                        "multipart/form-data; boundary=reposnake-boundary",
                    )
                    .body(Body::from(multipart_upload_body_with_file(
                        "reposnake_demo",
                        "0.1.0",
                        "bdist_wheel",
                        "py3",
                        "reposnake_demo-0.1.0-py3-none-any.whl",
                        &wheel,
                    )))
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(&format!("data-core-metadata=\"sha256={metadata_sha256}\"")));
        assert!(!body.contains("data-dist-info-metadata="));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/reposnake-demo/reposnake_demo-0.1.0-py3-none-any.whl.metadata")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], metadata);

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
        assert_eq!(body["files"][0]["core-metadata"]["sha256"], metadata_sha256);
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
                    .uri("/")
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
                    .uri("/")
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
    async fn oci_tags_list_returns_pushed_tags() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "ci");
        let manifest = r#"{"schemaVersion":2,"layers":[]}"#;

        for tag in ["v1.0.0", "latest"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/v2/team/image/manifests/{tag}"))
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
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/team/image/tags/list?n=1000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["name"], "team/image");
        assert_eq!(body["tags"], serde_json::json!(["latest", "v1.0.0"]));
    }

    #[tokio::test]
    async fn oci_push_without_credentials_returns_bearer_challenge() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let layer_digest =
            "sha256:dac1d7cfa95021764849fd102524e141488c5e3a90f861dbb5a12d9ac8584f85";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v2/team/image/blobs/uploads/?digest={layer_digest}"
                    ))
                    .body(Body::from("layer"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert_eq!(
            challenge,
            "Bearer realm=\"https://packages.example/v2/token\",service=\"packages.example\",scope=\"repository:team/image:pull,push\""
        );
    }

    #[tokio::test]
    async fn oci_token_endpoint_returns_validated_basic_password_token() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "ci");
        let credentials = general_purpose::STANDARD.encode(format!("__token__:{token}"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/token?service=packages.example&scope=repository:team/image:pull,push")
                    .header(header::AUTHORIZATION, format!("Basic {credentials}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["token"], token);
        assert_eq!(body["access_token"], token);
    }

    #[tokio::test]
    async fn oci_token_endpoint_rejects_push_scope_with_wrong_claims() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = authenticated_state(tempdir.path()).await;
        let app = build_router(state);
        let token = test_token("builder", "other");
        let credentials = general_purpose::STANDARD.encode(format!("__token__:{token}"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/token?scope=repository:team/image:pull,push")
                    .header(header::AUTHORIZATION, format!("Basic {credentials}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
        let repository = PackageRepository::new(path).await.unwrap();
        AppState {
            oci_registry: OciRegistry::new(repository.metadata_store(), repository.object_store()),
            repository,
            subject_validator: SubjectValidator::new(Vec::new(), true),
            publishers: Arc::new(Vec::new()),
            max_upload_bytes: 1024 * 1024,
            templates: Templates::new().unwrap(),
            origin: "https://packages.example".to_string(),
        }
    }

    async fn authenticated_state(path: &std::path::Path) -> AppState {
        let repository = PackageRepository::new(path).await.unwrap();
        AppState {
            oci_registry: OciRegistry::new(repository.metadata_store(), repository.object_store()),
            repository,
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
                projects: vec![
                    "reposnake-demo".to_string(),
                    "team/image".to_string(),
                    "team/worker".to_string(),
                ],
                identity_provider: Some("buildkite".to_string()),
                required_claims: BTreeMap::from([("pipeline".to_string(), "ci".to_string())]),
            }]),
            max_upload_bytes: 1024 * 1024,
            templates: Templates::new().unwrap(),
            origin: "https://packages.example".to_string(),
        }
    }

    fn multipart_upload_body(name: &str, version: &str, content: &[u8]) -> Vec<u8> {
        multipart_upload_body_with_file(
            name,
            version,
            "sdist",
            "source",
            &format!("{name}-{version}.tar.gz"),
            content,
        )
    }

    fn multipart_upload_body_with_file(
        name: &str,
        version: &str,
        filetype: &str,
        pyversion: &str,
        filename: &str,
        content: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        push_field(&mut body, ":action", "file_upload");
        push_field(&mut body, "protocol_version", "1");
        push_field(&mut body, "filetype", filetype);
        push_field(&mut body, "pyversion", pyversion);
        push_field(&mut body, "metadata_version", "2.4");
        push_field(&mut body, "name", name);
        push_field(&mut body, "version", version);
        push_field(&mut body, "sha256_digest", &sha256(content));
        body.extend_from_slice(b"--reposnake-boundary\r\n");
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n--reposnake-boundary--\r\n");
        body
    }

    fn wheel_with_metadata(metadata: &[u8]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::SimpleFileOptions;

        let cursor = Cursor::new(Vec::new());
        let mut wheel = zip::ZipWriter::new(cursor);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        wheel
            .start_file("reposnake_demo-0.1.0.dist-info/METADATA", options)
            .unwrap();
        wheel.write_all(metadata).unwrap();
        wheel.finish().unwrap().into_inner()
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
