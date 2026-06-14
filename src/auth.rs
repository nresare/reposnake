// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose;

pub fn install_jwt_crypto_provider() {
    // authzoo and surrealdb enable different jsonwebtoken providers. Pick the
    // provider once at startup so JWT validation cannot panic on first use.
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

pub fn extract_upload_token(headers: &HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid Authorization header".to_string()))?;
    let (scheme, credentials) = value
        .split_once(' ')
        .ok_or_else(|| AppError::Unauthorized("invalid Authorization header".to_string()))?;

    if scheme.eq_ignore_ascii_case("Bearer") {
        return non_empty_token(credentials.trim(), "empty bearer token");
    }
    if scheme.eq_ignore_ascii_case("Basic") {
        return extract_basic_password(credentials.trim());
    }

    Err(AppError::Unauthorized(
        "expected Bearer token or Basic credentials".to_string(),
    ))
}

fn extract_basic_password(credentials: &str) -> Result<String, AppError> {
    let decoded = general_purpose::STANDARD
        .decode(credentials)
        .map_err(|_| AppError::Unauthorized("invalid Basic credentials".to_string()))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| AppError::Unauthorized("invalid Basic credentials".to_string()))?;
    let (_, password) = decoded
        .split_once(':')
        .ok_or_else(|| AppError::Unauthorized("invalid Basic credentials".to_string()))?;
    non_empty_token(password, "empty Basic password")
}

fn non_empty_token(token: &str, message: &str) -> Result<String, AppError> {
    if token.is_empty() {
        return Err(AppError::Unauthorized(message.to_string()));
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::extract_upload_token;
    use axum::http::{HeaderMap, HeaderValue, header};
    use base64::Engine;
    use base64::engine::general_purpose;

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header.payload.signature"),
        );

        assert_eq!(
            extract_upload_token(&headers).unwrap(),
            "header.payload.signature"
        );
    }

    #[test]
    fn extracts_basic_password_for_twine_compatibility() {
        let credentials = general_purpose::STANDARD.encode("__token__:jwt-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
        );

        assert_eq!(extract_upload_token(&headers).unwrap(), "jwt-token");
    }
}
