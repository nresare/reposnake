// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::auth;
use crate::config::{AuthenticationConfig, Config, PublisherConfig};
use crate::error::AppError;
use crate::package::{
    FileRecord, ProjectIndex, ProjectSummary, SIMPLE_API_VERSION, UploadPackage, normalize_name,
};
use crate::repository::PackageRepository;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
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
const SIMPLE_JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";

#[derive(Clone)]
pub struct AppState {
    pub repository: PackageRepository,
    pub subject_validator: SubjectValidator,
    pub publishers: Arc<Vec<PublisherConfig>>,
    pub max_upload_bytes: usize,
}

pub fn build_app_state(config: &Config, disable_auth: bool) -> anyhow::Result<AppState> {
    Ok(AppState {
        repository: PackageRepository::new(config.storage_directory.clone()),
        subject_validator: SubjectValidator::new(config.authentication.clone(), disable_auth),
        publishers: Arc::new(config.publishers.clone()),
        max_upload_bytes: config.max_upload_bytes,
    })
}

pub fn build_router(state: AppState) -> Router {
    let max_upload_bytes = state.max_upload_bytes;
    Router::new()
        .route("/", get(simple_root))
        .route("/healthz", get(healthz))
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
        simple_html_response(render_project_list(&projects))
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
        simple_html_response(render_project_detail(&project))
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
}

fn publisher_allows_project(publisher: &PublisherConfig, normalized_project: &str) -> bool {
    publisher
        .projects
        .iter()
        .any(|project| project == "*" || normalize_name(project).as_str() == normalized_project)
}

#[derive(Clone)]
pub struct SubjectValidator {
    mode: SubjectValidationMode,
}

#[derive(Clone)]
enum SubjectValidationMode {
    Disabled,
    Enabled(AuthenticationConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceClaims {
    sub: String,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

impl SourceClaims {
    fn unauthenticated() -> Self {
        Self {
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
}

impl SubjectValidator {
    pub fn new(authentication: AuthenticationConfig, disable_auth: bool) -> Self {
        let mode = if disable_auth {
            SubjectValidationMode::Disabled
        } else {
            SubjectValidationMode::Enabled(authentication)
        };
        Self { mode }
    }

    pub fn validate(&self, bearer_token: Option<&str>) -> Result<SourceClaims, AppError> {
        let authentication = match &self.mode {
            SubjectValidationMode::Disabled => {
                debug!("upload token claim validation skipped because auth is disabled");
                return Ok(SourceClaims::unauthenticated());
            }
            SubjectValidationMode::Enabled(authentication) => authentication,
        };
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let (algorithm, decoding_key) =
            auth::decoding_key_for_token(authentication, bearer_token).map_err(AppError::from)?;
        debug!(
            algorithm = ?algorithm,
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
        debug!(subject = %decoded.claims.sub, "upload token claims validated");
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

fn simple_html_response(html: String) -> Result<Response, AppError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, SIMPLE_HTML_CONTENT_TYPE)
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
    use crate::config::{AuthenticationConfig, PublisherConfig};
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
        let state = unauthenticated_state(tempdir.path());
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
            "application/vnd.pypi.simple.v1+html; charset=utf-8"
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
    async fn simple_json_uses_relative_artifact_basenames() {
        let tempdir = tempfile::tempdir().unwrap();
        let state = unauthenticated_state(tempdir.path());
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
        let state = unauthenticated_state(tempdir.path());
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
        let state = authenticated_state(tempdir.path());
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
        let state = authenticated_state(tempdir.path());
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

    fn unauthenticated_state(path: &std::path::Path) -> AppState {
        AppState {
            repository: PackageRepository::new(path),
            subject_validator: SubjectValidator::new(AuthenticationConfig::default(), true),
            publishers: Arc::new(Vec::new()),
            max_upload_bytes: 1024 * 1024,
        }
    }

    fn authenticated_state(path: &std::path::Path) -> AppState {
        AppState {
            repository: PackageRepository::new(path),
            subject_validator: SubjectValidator::new(
                AuthenticationConfig {
                    audience: "reposnake".to_string(),
                    issuer: "https://issuer.example".to_string(),
                    validation_key: Some("shared-secret".to_string()),
                },
                false,
            ),
            publishers: Arc::new(vec![PublisherConfig {
                name: "ci".to_string(),
                projects: vec!["reposnake-demo".to_string()],
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
