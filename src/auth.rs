// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::AuthenticationConfig;
use crate::error::AppError;
use anyhow::Context;
use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose;
use jsonwebtoken::{Algorithm, DecodingKey};

pub fn algorithm(authentication: &AuthenticationConfig) -> anyhow::Result<Algorithm> {
    match authentication.algorithm.as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        other => anyhow::bail!(
            "unsupported authentication algorithm '{other}'; supported values are HS256, HS384, HS512, RS256, RS384, RS512, ES256 and ES384"
        ),
    }
}

pub fn decoding_key(authentication: &AuthenticationConfig) -> anyhow::Result<DecodingKey> {
    let validation_key = authentication.validation_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("authentication.validation_key is required to validate upload tokens")
    })?;
    match algorithm(authentication)? {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(validation_key.as_bytes()))
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(validation_key.as_bytes())
                .context("failed to parse RSA validation key")
        }
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(validation_key.as_bytes())
            .context("failed to parse EC validation key"),
        other => anyhow::bail!("unsupported authentication algorithm '{other:?}'"),
    }
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
