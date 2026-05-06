// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::oci::is_valid_repository_name;
use crate::package::is_valid_project_name;
use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
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
    pub persistence: PersistenceConfig,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublisherConfig {
    #[serde(default)]
    pub name: String,
    pub projects: Vec<String>,
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PersistenceConfig {
    #[serde(default = "default_persistence_uri")]
    pub uri: String,
    pub username: Option<String>,
    password_file: Option<Box<Path>>,
    pub idmouse: Option<IdmouseConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdmouseConfig {
    pub url: String,
    pub token_path: Box<Path>,
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
        self.persistence.validate()?;
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
                if !is_valid_project_name(project) && !is_valid_repository_name(project) {
                    let publisher_name = publisher.display_name();
                    anyhow::bail!(
                        "publisher '{publisher_name}' project '{project}' is not a valid Python project or OCI repository name"
                    );
                }
            }
        }

        Ok(())
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            uri: default_persistence_uri(),
            username: None,
            password_file: None,
            idmouse: None,
        }
    }
}

impl PersistenceConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.uri.is_empty() {
            anyhow::bail!("persistence.uri must not be empty");
        }
        if let Some(idmouse) = &self.idmouse {
            idmouse.validate()?;
            if self.username.is_some() || self.password_file.is_some() {
                anyhow::bail!(
                    "persistence.username and persistence.password_file must not be set when persistence.idmouse is configured"
                );
            }
            return Ok(());
        }
        match (&self.username, &self.password_file) {
            (Some(username), Some(_)) if !username.is_empty() => {}
            (None, None) => {}
            _ => anyhow::bail!(
                "persistence.username and persistence.password_file must be set together"
            ),
        }
        Ok(())
    }

    pub fn password(&self) -> anyhow::Result<Option<String>> {
        let Some(password_file) = self.password_file.as_deref() else {
            return Ok(None);
        };
        Ok(Some(read_secret_file(password_file)?))
    }
}

impl IdmouseConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.url.is_empty() {
            anyhow::bail!("persistence.idmouse.url must not be empty");
        }
        if self.token_path.as_os_str().is_empty() {
            anyhow::bail!("persistence.idmouse.token_path must not be empty");
        }
        Ok(())
    }

    pub fn bearer_token(&self) -> anyhow::Result<String> {
        read_secret_file(&self.token_path)
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
            None => {}
            _ => anyhow::bail!("authentication.validation_key must not be empty"),
        }
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
    "/data".into()
}

fn default_max_upload_bytes() -> usize {
    100 * 1024 * 1024
}

fn default_persistence_uri() -> String {
    "mem://".to_string()
}

fn read_secret_file(path: &Path) -> anyhow::Result<String> {
    let mut secret = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read secret file '{}'", path.display()))?;
    let len = secret.trim_end_matches(['\r', '\n']).len();
    secret.truncate(len);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::io::Write;

    #[test]
    fn parses_minimal_authenticated_config() {
        let config: Config = toml::from_str(
            r#"
storage_directory = "/tmp/reposnake"

[authentication]
audience = "reposnake"
issuer = "https://issuer.example"
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
        assert_eq!(config.persistence.uri, "mem://");
    }

    #[test]
    fn parses_persistence_config() {
        let config: Config = toml::from_str(
            r#"
[persistence]
uri = "ws://localhost:8000/"
username = "reposnake"
password_file = "/run/secrets/surrealdb-password"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.persistence.uri, "ws://localhost:8000/");
        assert_eq!(config.persistence.username.as_deref(), Some("reposnake"));
    }

    #[test]
    fn parses_idmouse_persistence_config() {
        let config: Config = toml::from_str(
            r#"
[persistence]
uri = "ws://localhost:8000/"

[persistence.idmouse]
url = "http://localhost:9000/token"
token_path = "/run/secrets/idmouse-bearer-token"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        let idmouse = config.persistence.idmouse.as_ref().unwrap();
        assert_eq!(idmouse.url, "http://localhost:9000/token");
        assert_eq!(
            idmouse.token_path.to_string_lossy(),
            "/run/secrets/idmouse-bearer-token"
        );
    }

    #[test]
    fn rejects_password_auth_when_idmouse_is_configured() {
        let config: Config = toml::from_str(
            r#"
[persistence]
uri = "ws://localhost:8000/"
username = "reposnake"
password_file = "/run/secrets/surrealdb-password"

[persistence.idmouse]
url = "http://localhost:9000/token"
token_path = "/run/secrets/idmouse-bearer-token"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "persistence.username and persistence.password_file must not be set when persistence.idmouse is configured"
        );
    }

    #[test]
    fn persistence_password_reads_and_trims_secret_file() {
        let mut password_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(password_file, "secret").unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
[persistence]
uri = "ws://localhost:8000/"
username = "reposnake"
password_file = "{}"

[[publisher]]
projects = ["*"]
"#,
            password_file.path().display()
        ))
        .unwrap();

        assert_eq!(
            config.persistence.password().unwrap().as_deref(),
            Some("secret")
        );
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

    #[test]
    fn validation_key_is_optional_when_auth_is_enabled() {
        let config: Config = toml::from_str(
            r#"
[authentication]
audience = "reposnake"
issuer = "https://issuer.example"

[[publisher]]
projects = ["*"]

[publisher.required_claims]
sub = "buildkite:deploy"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }
}
