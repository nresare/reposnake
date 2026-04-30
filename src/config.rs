// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::package::is_valid_project_name;
use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_storage_directory")]
    pub storage_directory: PathBuf,
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: usize,
    #[serde(default)]
    pub authentication: AuthenticationConfig,
    #[serde(rename = "publisher", default)]
    pub publishers: Vec<PublisherConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthenticationConfig {
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub issuer: String,
    pub validation_key: Option<String>,
    #[serde(default = "default_authentication_algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublisherConfig {
    #[serde(default)]
    pub name: String,
    pub projects: Vec<String>,
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file '{path}'"))?;
        toml::from_str(&content)
            .map_err(|error| anyhow::anyhow!("Could not parse config file '{path}': {error}"))
    }

    pub fn validate(&self, disable_auth: bool) -> anyhow::Result<()> {
        if self.bind_address.is_empty() {
            anyhow::bail!("bind_address must not be empty");
        }
        if self.storage_directory.as_os_str().is_empty() {
            anyhow::bail!("storage_directory must not be empty");
        }
        if self.max_upload_bytes == 0 {
            anyhow::bail!("max_upload_bytes must be greater than 0");
        }
        if !disable_auth {
            self.authentication.validate()?;
            if self.publishers.is_empty() {
                anyhow::bail!("at least one [[publisher]] entry is required");
            }
        }

        for publisher in &self.publishers {
            if !disable_auth && publisher.required_claims.is_empty() {
                let publisher_name = publisher.display_name();
                anyhow::bail!(
                    "publisher '{publisher_name}' must define at least one required_claim"
                );
            }
            if publisher.projects.is_empty() {
                let publisher_name = publisher.display_name();
                anyhow::bail!("publisher '{publisher_name}' must define at least one project");
            }
            for project in &publisher.projects {
                if project == "*" {
                    continue;
                }
                if !is_valid_project_name(project) {
                    let publisher_name = publisher.display_name();
                    anyhow::bail!(
                        "publisher '{publisher_name}' project '{project}' is not a valid Python project name"
                    );
                }
            }
        }

        Ok(())
    }
}

impl AuthenticationConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.audience.is_empty() {
            anyhow::bail!("authentication.audience must not be empty");
        }
        if self.issuer.is_empty() {
            anyhow::bail!("authentication.issuer must not be empty");
        }
        match self.validation_key.as_deref() {
            Some(validation_key) if !validation_key.is_empty() => {}
            _ => anyhow::bail!("authentication.validation_key must not be empty"),
        }
        crate::auth::algorithm(self)?;
        Ok(())
    }
}

impl PublisherConfig {
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            "<unnamed>"
        } else {
            &self.name
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_storage_directory() -> PathBuf {
    "/var/lib/reposnake".into()
}

fn default_max_upload_bytes() -> usize {
    100 * 1024 * 1024
}

fn default_authentication_algorithm() -> String {
    "RS256".to_string()
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_minimal_authenticated_config() {
        let config: Config = toml::from_str(
            r#"
storage_directory = "/tmp/reposnake"

[authentication]
audience = "reposnake"
issuer = "https://issuer.example"
algorithm = "HS256"
validation_key = "shared-secret"

[[publisher]]
name = "ci"
projects = ["reposnake-demo", "other_demo"]

[publisher.required_claims]
sub = "buildkite:deploy"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.max_upload_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn disable_auth_skips_authentication_and_required_claims_validation() {
        let config: Config = toml::from_str(
            r#"
[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
    }

    #[test]
    fn rejects_missing_publisher_policy_when_auth_is_enabled() {
        let config: Config = toml::from_str(
            r#"
[authentication]
audience = "reposnake"
issuer = "https://issuer.example"
algorithm = "HS256"
validation_key = "shared-secret"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "at least one [[publisher]] entry is required"
        );
    }
}
