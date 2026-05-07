// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::IdentityProviderConfig;
use crate::error::AppError;
use crate::kubernetes;
use anyhow::Context;
use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, decode_header};
use reqwest::blocking::Client;
use serde::Deserialize;
use tracing::{debug, info};

pub fn decoding_key_for_token(
    authentication: &IdentityProviderConfig,
    bearer_token: &str,
) -> anyhow::Result<(Algorithm, DecodingKey)> {
    install_jwt_crypto_provider();
    let algorithm = decode_header(bearer_token)
        .context("failed to decode upload token header")?
        .alg;
    let decoding_key = match authentication.validation_key.as_deref() {
        Some(validation_key) => decoding_key_for_algorithm(validation_key, algorithm)?,
        None => {
            info!(
                issuer = %authentication.issuer,
                "identity-provider.validation-key not configured; attempting issuer-based validation key discovery"
            );
            discovery_decoding_key(authentication, bearer_token, algorithm)?
        }
    };
    Ok((algorithm, decoding_key))
}

pub fn install_jwt_crypto_provider() {
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

fn decoding_key_for_algorithm(
    validation_key: &str,
    algorithm: Algorithm,
) -> anyhow::Result<DecodingKey> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if looks_like_pem(validation_key) {
                anyhow::bail!(
                    "refusing to validate HMAC token with PEM validation key; issuer token algorithm was '{algorithm:?}'"
                );
            }
            Ok(DecodingKey::from_secret(validation_key.as_bytes()))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(validation_key.as_bytes())
            .context("failed to parse RSA validation key"),
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(validation_key.as_bytes())
            .context("failed to parse EC validation key"),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(validation_key.as_bytes())
            .context("failed to parse EdDSA validation key"),
    }
}

fn looks_like_pem(value: &str) -> bool {
    value.trim_start().starts_with("-----BEGIN ")
}

fn discovery_decoding_key(
    authentication: &IdentityProviderConfig,
    bearer_token: &str,
    algorithm: Algorithm,
) -> anyhow::Result<DecodingKey> {
    let openid_configuration_url = format!(
        "{}/.well-known/openid-configuration",
        authentication.issuer.trim_end_matches('/')
    );
    debug!(
        issuer = %authentication.issuer,
        openid_configuration_url = %openid_configuration_url,
        "fetching OpenID configuration for validation key discovery"
    );
    let client = discovery_client(authentication)?;

    let openid_configuration: OpenIdConfiguration = client
        .get(&openid_configuration_url)
        .send()
        .with_context(|| {
            format!("failed to fetch OpenID configuration from '{openid_configuration_url}'")
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "OpenID configuration request to '{openid_configuration_url}' returned an error status"
            )
        })?
        .json()
        .with_context(|| {
            format!("failed to parse OpenID configuration from '{openid_configuration_url}'")
        })?;
    debug!(
        jwks_uri = %openid_configuration.jwks_uri,
        "fetched OpenID configuration for validation key discovery"
    );

    debug!(
        jwks_uri = %openid_configuration.jwks_uri,
        "fetching JWKS for validation key discovery"
    );
    let jwks: JwkSet = client
        .get(&openid_configuration.jwks_uri)
        .send()
        .with_context(|| {
            format!(
                "failed to fetch JWKS from '{}'",
                openid_configuration.jwks_uri
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "JWKS request to '{}' returned an error status",
                openid_configuration.jwks_uri
            )
        })?
        .json()
        .with_context(|| {
            format!(
                "failed to parse JWKS from '{}'",
                openid_configuration.jwks_uri
            )
        })?;
    debug!(
        jwks_key_count = jwks.keys.len(),
        "fetched JWKS for validation key discovery"
    );

    let header = decode_header(bearer_token)
        .context("failed to decode upload token header for key discovery")?;
    debug!(token_kid = ?header.kid, "decoded upload token header for validation key discovery");
    let jwk = select_jwk_for_token(&jwks, &header.kid, algorithm)?;

    let decoding_key = DecodingKey::from_jwk(jwk).with_context(|| {
        let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
        format!("failed to construct decoding key from discovered JWK '{key_id}'")
    })?;
    debug!(
        discovered_jwk_kid = ?jwk.common.key_id,
        "constructed decoding key from discovered JWK"
    );
    Ok(decoding_key)
}

fn discovery_client(authentication: &IdentityProviderConfig) -> anyhow::Result<Client> {
    let mut builder = Client::builder();

    if kubernetes::is_kubernetes_service_issuer(&authentication.issuer) {
        debug!("configuring Kubernetes-specific HTTP client settings for validation key discovery");
        builder = kubernetes::configure_in_cluster_client(builder)?;
    }

    builder
        .build()
        .context("failed to build HTTP client for validation key discovery")
}

#[derive(Debug, Deserialize)]
struct OpenIdConfiguration {
    jwks_uri: String,
}

fn select_jwk_for_token<'a>(
    jwks: &'a JwkSet,
    kid: &Option<String>,
    algorithm: Algorithm,
) -> anyhow::Result<&'a Jwk> {
    if let Some(kid) = kid {
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| anyhow::anyhow!("no JWK found for token kid '{kid}'"))?;
        ensure_jwk_compatible(jwk, algorithm)?;
        return Ok(jwk);
    }

    let mut matching_keys = jwks
        .keys
        .iter()
        .filter(|jwk| jwk_matches_algorithm(jwk, algorithm));
    let jwk = matching_keys
        .next()
        .ok_or_else(|| anyhow::anyhow!("no compatible JWK found for algorithm '{algorithm:?}'"))?;
    if matching_keys.next().is_some() {
        anyhow::bail!(
            "multiple compatible JWKs found for algorithm '{algorithm:?}' but the token header did not include a kid"
        );
    }
    Ok(jwk)
}

fn ensure_jwk_compatible(jwk: &Jwk, algorithm: Algorithm) -> anyhow::Result<()> {
    if !jwk_matches_algorithm(jwk, algorithm) {
        let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
        anyhow::bail!("discovered JWK '{key_id}' is not compatible with algorithm '{algorithm:?}'");
    }
    Ok(())
}

fn jwk_matches_algorithm(jwk: &Jwk, algorithm: Algorithm) -> bool {
    if let Some(public_key_use) = &jwk.common.public_key_use
        && *public_key_use != PublicKeyUse::Signature
    {
        return false;
    }

    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            key_algorithm_matches(jwk, algorithm)
                && matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            key_algorithm_matches(jwk, algorithm)
                && matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            key_algorithm_matches(jwk, algorithm)
                && matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_))
        }
        Algorithm::EdDSA => {
            key_algorithm_matches(jwk, algorithm)
                && matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(_))
        }
    }
}

fn key_algorithm_matches(jwk: &Jwk, algorithm: Algorithm) -> bool {
    match jwk.common.key_algorithm {
        Some(key_algorithm) => key_algorithm == key_algorithm_for_algorithm(algorithm),
        None => true,
    }
}

fn key_algorithm_for_algorithm(algorithm: Algorithm) -> KeyAlgorithm {
    match algorithm {
        Algorithm::HS256 => KeyAlgorithm::HS256,
        Algorithm::HS384 => KeyAlgorithm::HS384,
        Algorithm::HS512 => KeyAlgorithm::HS512,
        Algorithm::RS256 => KeyAlgorithm::RS256,
        Algorithm::RS384 => KeyAlgorithm::RS384,
        Algorithm::RS512 => KeyAlgorithm::RS512,
        Algorithm::PS256 => KeyAlgorithm::PS256,
        Algorithm::PS384 => KeyAlgorithm::PS384,
        Algorithm::PS512 => KeyAlgorithm::PS512,
        Algorithm::ES256 => KeyAlgorithm::ES256,
        Algorithm::ES384 => KeyAlgorithm::ES384,
        Algorithm::EdDSA => KeyAlgorithm::EdDSA,
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
    use super::{decoding_key_for_token, extract_upload_token, select_jwk_for_token};
    use crate::config::IdentityProviderConfig;
    use axum::http::{HeaderMap, HeaderValue, header};
    use base64::Engine;
    use base64::engine::general_purpose;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::jwk::JwkSet;
    use serde_json::json;

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

    #[test]
    fn uses_algorithm_from_token_header() {
        let authentication = IdentityProviderConfig {
            name: "buildkite".to_string(),
            audience: "reposnake".to_string(),
            issuer: "https://issuer.example".to_string(),
            validation_key: Some("shared-secret".to_string()),
        };

        let (algorithm, _decoding_key) =
            decoding_key_for_token(&authentication, "eyJhbGciOiJIUzM4NCJ9.e30.signature").unwrap();

        assert_eq!(algorithm, Algorithm::HS384);
    }

    #[test]
    fn rejects_hmac_tokens_when_validation_key_is_pem() {
        let authentication = IdentityProviderConfig {
            name: "buildkite".to_string(),
            audience: "reposnake".to_string(),
            issuer: "https://issuer.example".to_string(),
            validation_key: Some(
                "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
            ),
        };

        let error = decoding_key_for_token(&authentication, "eyJhbGciOiJIUzI1NiJ9.e30.signature")
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "refusing to validate HMAC token with PEM validation key; issuer token algorithm was 'HS256'"
        );
    }

    #[test]
    fn selects_matching_discovered_jwk_by_kid_and_algorithm() {
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "rsa-key",
                    "alg": "RS256",
                    "n": "sXchDaQ8DhQ6q-MvFaN_xCO1u9ASWJG8XUOW92j_2GqugYx4TOYTr3yP0T5ZJ9N3s7C8c9vvzjD88AGFC8AMEmRr7A4FH5nBSWeD3D3Ap3i6zMeEz7fmQ4hoq_CYYeHpxC4M8Dbw3fk3wlM3vJdWQWg6XcV1WqYClVTfzv7LQ",
                    "e": "AQAB"
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "ec-key",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF4cRaMl76bepHGNpGxIAGLTTlU6qUI149M",
                    "y": "x_FEzRu9O8vPLCl3Bq_2ydlC8n4yZtBT7FgxQIDLOoE"
                }
            ]
        }))
        .unwrap();

        let jwk =
            select_jwk_for_token(&jwks, &Some("ec-key".to_string()), Algorithm::ES256).unwrap();

        assert_eq!(jwk.common.key_id.as_deref(), Some("ec-key"));
    }

    #[test]
    fn rejects_discovered_jwk_with_matching_kid_but_wrong_algorithm() {
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "ec-key",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF4cRaMl76bepHGNpGxIAGLTTlU6qUI149M",
                    "y": "x_FEzRu9O8vPLCl3Bq_2ydlC8n4yZtBT7FgxQIDLOoE"
                }
            ]
        }))
        .unwrap();

        let error =
            select_jwk_for_token(&jwks, &Some("ec-key".to_string()), Algorithm::RS256).unwrap_err();

        assert_eq!(
            error.to_string(),
            "discovered JWK 'ec-key' is not compatible with algorithm 'RS256'"
        );
    }
}
