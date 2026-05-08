// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::oci::is_valid_repository_name;
use crate::package::is_valid_project_name;
use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: usize,
    #[serde(default)]
    pub metadata_store: MetadataStoreConfig,
    #[serde(default)]
    pub object_store: ObjectStoreConfig,
    #[serde(rename = "identity-provider", default)]
    pub identity_providers: Vec<IdentityProviderConfig>,
    #[serde(rename = "publisher", default)]
    pub publishers: Vec<PublisherConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IdentityProviderConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub issuer: String,
    pub validation_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PublisherConfig {
    #[serde(default)]
    pub name: String,
    pub projects: Vec<String>,
    #[serde(rename = "identity-provider")]
    pub identity_provider: Option<String>,
    #[serde(default)]
    #[serde(rename = "required-claims")]
    pub required_claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MetadataStoreConfig {
    #[serde(default)]
    pub backend: MetadataStoreBackend,
    #[serde(default = "default_metadata_store_uri")]
    pub uri: String,
    pub directory: Option<PathBuf>,
    pub username: Option<String>,
    password_file: Option<Box<Path>>,
    pub idmouse: Option<IdmouseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum MetadataStoreBackend {
    #[default]
    Surrealdb,
    Filesystem,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IdmouseConfig {
    pub url: String,
    pub token_path: Box<Path>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ObjectStoreBackend {
    #[default]
    Filesystem,
    S3,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreConfig {
    #[serde(default)]
    pub backend: ObjectStoreBackend,
    pub directory: Option<PathBuf>,
    pub bucket: Option<String>,
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
            anyhow::bail!("bind-address must not be empty");
        }
        if self.max_upload_bytes == 0 {
            anyhow::bail!("max-upload-bytes must be greater than 0");
        }
        self.metadata_store.validate()?;
        self.object_store.validate()?;
        if !disable_auth {
            if self.identity_providers.is_empty() {
                anyhow::bail!("at least one [[identity-provider]] entry is required");
            }
            if self.publishers.is_empty() {
                anyhow::bail!("at least one [[publisher]] entry is required");
            }
        }

        let mut identity_provider_names = HashSet::new();
        for identity_provider in &self.identity_providers {
            identity_provider.validate()?;
            if !identity_provider_names.insert(identity_provider.name.clone()) {
                anyhow::bail!("duplicate identity-provider '{}'", identity_provider.name);
            }
        }

        for publisher in &self.publishers {
            if !disable_auth {
                let publisher_name = publisher.display_name();
                let identity_provider =
                    publisher.identity_provider.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "publisher '{publisher_name}' must define identity-provider"
                        )
                    })?;
                if identity_provider.is_empty() {
                    anyhow::bail!(
                        "publisher '{publisher_name}' identity-provider must not be empty"
                    );
                }
                if !identity_provider_names.contains(identity_provider) {
                    anyhow::bail!(
                        "publisher '{publisher_name}' references unknown identity-provider '{identity_provider}'"
                    );
                }
            }
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

impl Default for MetadataStoreConfig {
    fn default() -> Self {
        Self {
            backend: MetadataStoreBackend::Surrealdb,
            uri: default_metadata_store_uri(),
            directory: None,
            username: None,
            password_file: None,
            idmouse: None,
        }
    }
}

impl Default for ObjectStoreConfig {
    fn default() -> Self {
        Self {
            backend: ObjectStoreBackend::Filesystem,
            directory: Some(default_object_store_directory()),
            bucket: None,
        }
    }
}

impl ObjectStoreConfig {
    pub fn directory_or_default(&self) -> PathBuf {
        self.directory
            .clone()
            .unwrap_or_else(default_object_store_directory)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if let Some(directory) = &self.directory
            && directory.as_os_str().is_empty()
        {
            anyhow::bail!("object-store.directory must not be empty");
        }
        if let Some(bucket) = &self.bucket
            && bucket.is_empty()
        {
            anyhow::bail!("object-store.bucket must not be empty");
        }
        match self.backend {
            ObjectStoreBackend::Filesystem => {
                if self.directory.is_none() {
                    anyhow::bail!("object-store.directory is required when backend is filesystem");
                }
                Ok(())
            }
            ObjectStoreBackend::S3 => {
                if self.bucket.is_none() {
                    anyhow::bail!("object-store.bucket is required when backend is s3");
                }
                Ok(())
            }
        }
    }
}

impl MetadataStoreConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if let Some(directory) = &self.directory
            && directory.as_os_str().is_empty()
        {
            anyhow::bail!("metadata-store.directory must not be empty");
        }
        match self.backend {
            MetadataStoreBackend::Filesystem => {
                if self.directory.is_none() {
                    anyhow::bail!(
                        "metadata-store.directory is required when backend is filesystem"
                    );
                }
                if self.username.is_some() || self.password_file.is_some() || self.idmouse.is_some()
                {
                    anyhow::bail!(
                        "metadata-store.username, metadata-store.password-file, and metadata-store.idmouse must not be set when backend is filesystem"
                    );
                }
                return Ok(());
            }
            MetadataStoreBackend::Surrealdb => {
                if self.directory.is_some() {
                    anyhow::bail!(
                        "metadata-store.directory must not be set when backend is surrealdb"
                    );
                }
            }
        }
        if self.uri.is_empty() {
            anyhow::bail!("metadata-store.uri must not be empty");
        }
        if let Some(idmouse) = &self.idmouse {
            idmouse.validate()?;
            if self.username.is_some() || self.password_file.is_some() {
                anyhow::bail!(
                    "metadata-store.username and metadata-store.password-file must not be set when metadata-store.idmouse is configured"
                );
            }
            return Ok(());
        }
        match (&self.username, &self.password_file) {
            (Some(username), Some(_)) if !username.is_empty() => {}
            (None, None) => {}
            _ => anyhow::bail!(
                "metadata-store.username and metadata-store.password-file must be set together"
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
            anyhow::bail!("metadata-store.idmouse.url must not be empty");
        }
        if self.token_path.as_os_str().is_empty() {
            anyhow::bail!("metadata-store.idmouse.token-path must not be empty");
        }
        Ok(())
    }

    pub fn bearer_token(&self) -> anyhow::Result<String> {
        read_secret_file(&self.token_path)
    }
}

impl IdentityProviderConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("identity-provider names must not be empty");
        }
        if self.audience.is_empty() {
            anyhow::bail!(
                "identity-provider '{}' audience must not be empty",
                self.name
            );
        }
        if self.issuer.is_empty() {
            anyhow::bail!("identity-provider '{}' issuer must not be empty", self.name);
        }
        match self.validation_key.as_deref() {
            Some(validation_key) if !validation_key.is_empty() => {}
            None => {}
            _ => anyhow::bail!(
                "identity-provider '{}' validation-key must not be empty",
                self.name
            ),
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

fn default_object_store_directory() -> PathBuf {
    "/data".into()
}

fn default_max_upload_bytes() -> usize {
    100 * 1024 * 1024
}

fn default_metadata_store_uri() -> String {
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
    use super::{Config, MetadataStoreBackend, ObjectStoreBackend};
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn parses_minimal_authenticated_config() {
        let config: Config = toml::from_str(
            r#"
[[identity-provider]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"
validation-key = "shared-secret"

[[publisher]]
name = "ci"
projects = ["reposnake-demo", "other_demo"]
identity-provider = "buildkite"

[publisher.required-claims]
sub = "buildkite:deploy"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.max_upload_bytes, 100 * 1024 * 1024);
        assert_eq!(config.metadata_store.uri, "mem://");
        assert_eq!(config.identity_providers[0].name, "buildkite");
        assert_eq!(config.object_store.backend, ObjectStoreBackend::Filesystem);
        assert_eq!(
            config.object_store.directory.as_deref(),
            Some(Path::new("/data"))
        );
    }

    #[test]
    fn parses_filesystem_object_store_directory() {
        let config: Config = toml::from_str(
            r#"
[object-store]
directory = "/tmp/reposnake"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.object_store.backend, ObjectStoreBackend::Filesystem);
        assert_eq!(
            config.object_store.directory.as_deref(),
            Some(Path::new("/tmp/reposnake"))
        );
    }

    #[test]
    fn parses_s3_object_store_config() {
        let config: Config = toml::from_str(
            r#"
[object-store]
backend = "s3"
bucket = "reposnake-packages"
directory = "/data"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.object_store.backend, ObjectStoreBackend::S3);
        assert_eq!(
            config.object_store.bucket.as_deref(),
            Some("reposnake-packages")
        );
    }

    #[test]
    fn rejects_removed_s3_object_store_config_fields() {
        for removed_field in [
            "access-key-id = \"reposnake\"",
            "secret-access-key-file = \"/run/secrets/aws-secret-access-key\"",
            "session-token-file = \"/run/secrets/aws-session-token\"",
            "prefix = \"simple/\"",
            "region = \"eu-west-2\"",
            "force-path-style = true",
            "endpoint-url = \"http://localhost:9000\"",
            "temp-directory = \"/tmp/reposnake-s3\"",
            "storage-directory = \"/data\"",
        ] {
            let config = format!(
                r#"
[object-store]
backend = "s3"

bucket = "reposnake-packages"
{removed_field}
"#
            );

            assert!(toml::from_str::<Config>(&config).is_err());
        }
    }

    #[test]
    fn rejects_removed_top_level_storage_directory() {
        let config = r#"
storage-directory = "/data"

[[publisher]]
projects = ["*"]
"#;

        assert!(toml::from_str::<Config>(config).is_err());
    }

    #[test]
    fn rejects_snake_case_config_fields() {
        for config in [
            r#"
bind_address = "0.0.0.0:8080"
"#,
            r#"
max_upload_bytes = 104857600
"#,
            r#"
[object_store]
directory = "/data"
"#,
            r#"
[metadata-store]
password_file = "/run/secrets/surrealdb-password"
"#,
            r#"
[metadata-store.idmouse]
url = "http://localhost:9000/token"
token_path = "/run/secrets/idmouse-bearer-token"
"#,
            r#"
[[identity-provider]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"
validation_key = "shared-secret"
"#,
            r#"
[[publisher]]
projects = ["*"]

[publisher.required_claims]
repository_owner = "example"
"#,
        ] {
            assert!(toml::from_str::<Config>(config).is_err());
        }
    }

    #[test]
    fn rejects_s3_object_store_without_bucket() {
        let config: Config = toml::from_str(
            r#"
[object-store]
backend = "s3"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        assert!(config.validate(true).is_err());
    }

    #[test]
    fn accepts_s3_object_store_without_directory() {
        let config: Config = toml::from_str(
            r#"
[object-store]
backend = "s3"
bucket = "reposnake-packages"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.object_store.directory, None);
    }

    #[test]
    fn rejects_filesystem_object_store_without_directory() {
        let config: Config = toml::from_str(
            r#"
[object-store]
backend = "filesystem"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        assert!(config.validate(true).is_err());
    }

    #[test]
    fn rejects_nested_s3_object_store_config() {
        let config = r#"
[object-store]
backend = "s3"

[object-store.s3]
bucket = "reposnake-packages"
"#;

        assert!(toml::from_str::<Config>(config).is_err());
    }

    #[test]
    fn parses_metadata_store_config() {
        let config: Config = toml::from_str(
            r#"
[metadata-store]
uri = "ws://localhost:8000/"
username = "reposnake"
password-file = "/run/secrets/surrealdb-password"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.metadata_store.uri, "ws://localhost:8000/");
        assert_eq!(config.metadata_store.username.as_deref(), Some("reposnake"));
    }

    #[test]
    fn parses_filesystem_metadata_store_config() {
        let config: Config = toml::from_str(
            r#"
[metadata-store]
backend = "filesystem"
directory = "/data/metadata"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(
            config.metadata_store.backend,
            MetadataStoreBackend::Filesystem
        );
        assert_eq!(
            config.metadata_store.directory.as_deref(),
            Some(Path::new("/data/metadata"))
        );
    }

    #[test]
    fn rejects_filesystem_metadata_store_without_directory() {
        let config: Config = toml::from_str(
            r#"
[metadata-store]
backend = "filesystem"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "metadata-store.directory is required when backend is filesystem"
        );
    }

    #[test]
    fn rejects_metadata_store_directory_without_filesystem_backend() {
        let config: Config = toml::from_str(
            r#"
[metadata-store]
directory = "/data/metadata"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "metadata-store.directory must not be set when backend is surrealdb"
        );
    }

    #[test]
    fn rejects_surrealdb_auth_for_filesystem_metadata_store() {
        let config: Config = toml::from_str(
            r#"
[metadata-store]
backend = "filesystem"
directory = "/data/metadata"
username = "reposnake"
password-file = "/run/secrets/surrealdb-password"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "metadata-store.username, metadata-store.password-file, and metadata-store.idmouse must not be set when backend is filesystem"
        );
    }

    #[test]
    fn parses_idmouse_metadata_store_config() {
        let config: Config = toml::from_str(
            r#"
[metadata-store]
uri = "ws://localhost:8000/"

[metadata-store.idmouse]
url = "http://localhost:9000/token"
token-path = "/run/secrets/idmouse-bearer-token"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        let idmouse = config.metadata_store.idmouse.as_ref().unwrap();
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
[metadata-store]
uri = "ws://localhost:8000/"
username = "reposnake"
password-file = "/run/secrets/surrealdb-password"

[metadata-store.idmouse]
url = "http://localhost:9000/token"
token-path = "/run/secrets/idmouse-bearer-token"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "metadata-store.username and metadata-store.password-file must not be set when metadata-store.idmouse is configured"
        );
    }

    #[test]
    fn metadata_store_password_reads_and_trims_secret_file() {
        let mut password_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(password_file, "secret").unwrap();
        let config: Config = toml::from_str(&format!(
            r#"
[metadata-store]
uri = "ws://localhost:8000/"
username = "reposnake"
password-file = "{}"

[[publisher]]
projects = ["*"]
"#,
            password_file.path().display()
        ))
        .unwrap();

        assert_eq!(
            config.metadata_store.password().unwrap().as_deref(),
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
    fn rejects_missing_identity_provider_when_auth_is_enabled() {
        let config: Config = toml::from_str(
            r#"
[[publisher]]
projects = ["*"]

[publisher.required-claims]
sub = "buildkite:deploy"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "at least one [[identity-provider]] entry is required"
        );
    }

    #[test]
    fn rejects_missing_publisher_policy_when_auth_is_enabled() {
        let config: Config = toml::from_str(
            r#"
[[identity-provider]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"
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
[[identity-provider]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"

[[publisher]]
projects = ["*"]
identity-provider = "buildkite"

[publisher.required-claims]
sub = "buildkite:deploy"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn required_claim_keys_are_not_renamed() {
        let config: Config = toml::from_str(
            r#"
[[publisher]]
projects = ["*"]

[publisher.required-claims]
repository_owner = "example"
"#,
        )
        .unwrap();

        assert_eq!(
            config.publishers[0]
                .required_claims
                .get("repository_owner")
                .map(String::as_str),
            Some("example")
        );
    }

    #[test]
    fn rejects_publisher_with_unknown_identity_provider() {
        let config: Config = toml::from_str(
            r#"
[[identity-provider]]
name = "kubernetes"
audience = "reposnake"
issuer = "https://kubernetes.default.svc"

[[publisher]]
projects = ["*"]
identity-provider = "buildkite"

[publisher.required-claims]
sub = "buildkite:deploy"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "publisher '<unnamed>' references unknown identity-provider 'buildkite'"
        );
    }
}
