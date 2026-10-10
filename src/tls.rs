// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::Config;
use anyhow::{Context, bail};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn file_paths(config: &Config, config_path: &Path) -> anyhow::Result<Option<(PathBuf, PathBuf)>> {
    let (cert, key) = match (&config.tls_cert_path, &config.tls_key_path) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) if !cert.trim().is_empty() && !key.trim().is_empty() => (cert, key),
        _ => bail!("TLS requires both non-empty tls-cert-path and tls-key-path"),
    };
    let directory = config_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(Some((directory.join(cert), directory.join(key))))
}

pub async fn load(config: &Config, config_path: &Path) -> anyhow::Result<Option<RustlsConfig>> {
    let Some((cert_path, key_path)) = file_paths(config, config_path)? else {
        return Ok(None);
    };
    let server_config = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let certs = CertificateDer::pem_file_iter(&cert_path)
            .with_context(|| format!("Could not open TLS certificate {}", cert_path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .context("Could not parse TLS certificate chain")?;
        let key = PrivateKeyDer::from_pem_file(&key_path)
            .with_context(|| format!("Could not read TLS private key {}", key_path.display()))?;
        // Select the provider explicitly: other dependencies also enable aws-lc-rs.
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Invalid TLS certificate or mismatched private key")?;
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(server_config)
    })
    .await??;
    Ok(Some(RustlsConfig::from_config(Arc::new(server_config))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(settings: &str) -> Config {
        toml::from_str(&format!("{settings}\norigin = 'https://localhost:8443'\n")).unwrap()
    }

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tls/config.toml")
    }

    #[tokio::test]
    async fn no_tls_settings_preserves_http() {
        assert!(load(&config(""), &fixtures()).await.unwrap().is_none());
        assert_eq!(config("").bind_address(), "0.0.0.0:8080");
        assert_eq!(
            config("tls-cert-path = 'cert.pem'\ntls-key-path = 'test-only-key.pem'").bind_address(),
            "0.0.0.0:8443"
        );
        assert_eq!(config("bind-address = '127.0.0.1:9443'\ntls-cert-path = 'cert.pem'\ntls-key-path = 'test-only-key.pem'").bind_address(), "127.0.0.1:9443");
    }

    #[test]
    fn validates_paired_paths() {
        for settings in [
            "tls-cert-path = 'cert.pem'",
            "tls-key-path = 'key.pem'",
            "tls-cert-path = ''\ntls-key-path = 'key.pem'",
            "tls-cert-path = 'cert.pem'\ntls-key-path = '  '",
        ] {
            let error = file_paths(&config(settings), &fixtures()).unwrap_err();
            assert!(error.to_string().contains("TLS requires both"));
        }
    }

    #[test]
    fn resolves_relative_and_absolute_paths() {
        let config = config("tls-cert-path = 'cert.pem'\ntls-key-path = '/tls/key.pem'");
        let (cert, key) = file_paths(&config, Path::new("/config/app.toml"))
            .unwrap()
            .unwrap();
        assert_eq!(cert, Path::new("/config/cert.pem"));
        assert_eq!(key, Path::new("/tls/key.pem"));
    }

    #[tokio::test]
    async fn rejects_missing_invalid_and_mismatched_files() {
        for settings in [
            "tls-cert-path = 'missing.pem'\ntls-key-path = 'test-only-key.pem'",
            "tls-cert-path = 'test-only-key.pem'\ntls-key-path = 'test-only-key.pem'",
            "tls-cert-path = 'cert.pem'\ntls-key-path = 'cert.pem'",
            "tls-cert-path = 'cert.pem'\ntls-key-path = 'other-test-only-key.pem'",
        ] {
            assert!(load(&config(settings), &fixtures()).await.is_err());
        }
    }
}
