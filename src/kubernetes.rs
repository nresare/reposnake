// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use anyhow::Context;
use reqwest::blocking::ClientBuilder;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

pub const KUBERNETES_SERVICE_HOST: &str = "https://kubernetes.default.svc";
const KUBERNETES_SERVICE_HOST_ALIASES: &[&str] = &[
    KUBERNETES_SERVICE_HOST,
    "https://kubernetes.default.svc.cluster.local",
];
const KUBERNETES_CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const KUBERNETES_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

pub fn is_kubernetes_service_issuer(issuer: &str) -> bool {
    let issuer = issuer.trim_end_matches('/');
    KUBERNETES_SERVICE_HOST_ALIASES.contains(&issuer)
}

pub fn configure_in_cluster_client(mut builder: ClientBuilder) -> anyhow::Result<ClientBuilder> {
    if let Ok(ca_cert_pem) = std::fs::read(KUBERNETES_CA_CERT_PATH) {
        let certificate = reqwest::Certificate::from_pem(&ca_cert_pem).with_context(|| {
            format!(
                "failed to parse Kubernetes CA certificate bundle at '{KUBERNETES_CA_CERT_PATH}'"
            )
        })?;
        builder = builder.add_root_certificate(certificate);
    }

    if let Ok(service_account_token) = std::fs::read_to_string(KUBERNETES_TOKEN_PATH) {
        let token = service_account_token.trim();
        if !token.is_empty() {
            let mut headers = HeaderMap::new();
            let header_value = HeaderValue::from_str(&format!("Bearer {token}")).with_context(|| {
                format!(
                    "failed to build Authorization header from Kubernetes token at '{KUBERNETES_TOKEN_PATH}'"
                )
            })?;
            headers.insert(AUTHORIZATION, header_value);
            builder = builder.default_headers(headers);
        }
    }

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::is_kubernetes_service_issuer;

    #[test]
    fn recognizes_kubernetes_service_issuer_aliases() {
        assert!(is_kubernetes_service_issuer(
            "https://kubernetes.default.svc"
        ));
        assert!(is_kubernetes_service_issuer(
            "https://kubernetes.default.svc/"
        ));
        assert!(is_kubernetes_service_issuer(
            "https://kubernetes.default.svc.cluster.local"
        ));
    }

    #[test]
    fn rejects_non_kubernetes_issuers() {
        assert!(!is_kubernetes_service_issuer("https://issuer.example"));
        assert!(!is_kubernetes_service_issuer(
            "https://kubernetes.attacker.example"
        ));
    }
}
