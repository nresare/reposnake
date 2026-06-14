// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::oci::is_valid_repository_name;
use crate::package::is_valid_project_name;
use anyhow::Context;
use serde::Deserialize;
use serde::de::{self, Visitor};
use std::fmt;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    pub origin: String,
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: usize,
    #[serde(default)]
    pub metadata_store: MetadataStoreConfig,
    #[serde(default)]
    pub object_store: ObjectStoreConfig,
    #[serde(default)]
    pub cache: ObjectCacheConfig,
    #[serde(rename = "role", default)]
    pub roles: Vec<authzoo::RoleConfig>,
    #[serde(rename = "publisher", default)]
    pub publishers: Vec<PublisherConfig>,
    pub admin_role: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PublisherConfig {
    #[serde(default)]
    pub name: String,
    pub projects: Vec<String>,
    pub role: Option<String>,
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
pub enum MetadataStoreBackend {
    Surrealdb,
    Filesystem,
}

impl Default for MetadataStoreBackend {
    fn default() -> Self {
        if cfg!(feature = "surrealdb") {
            Self::Surrealdb
        } else {
            Self::Filesystem
        }
    }
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ObjectCacheConfig {
    #[serde(default = "default_object_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_object_cache_directory")]
    pub directory: PathBuf,
    #[serde(
        default = "default_object_cache_max_file_size",
        deserialize_with = "deserialize_byte_size"
    )]
    pub max_file_size: u64,
    #[serde(
        default = "default_object_cache_max_total_size",
        deserialize_with = "deserialize_byte_size"
    )]
    pub max_total_size: u64,
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
        if self.origin.is_empty() {
            anyhow::bail!("origin must not be empty");
        }
        if self.max_upload_bytes == 0 {
            anyhow::bail!("max-upload-bytes must be greater than 0");
        }
        self.metadata_store.validate()?;
        self.object_store.validate()?;
        self.cache.validate()?;
        let role_validator = authzoo::TokenValidator::new(self.roles.clone())?;
        if !disable_auth {
            if self.roles.is_empty() {
                anyhow::bail!("at least one [[role]] entry is required");
            }
            if self.publishers.is_empty() {
                anyhow::bail!("at least one [[publisher]] entry is required");
            }
        }

        for publisher in &self.publishers {
            if !disable_auth {
                let publisher_name = publisher.display_name();
                let role = publisher.role.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("publisher '{publisher_name}' must define role")
                })?;
                if role.is_empty() {
                    anyhow::bail!("publisher '{publisher_name}' role must not be empty");
                }
                role_validator.ensure_roles_exist([role])?;
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

        if let Some(admin_role) = &self.admin_role
            && !disable_auth
        {
            if admin_role.is_empty() {
                anyhow::bail!("admin-role must not be empty");
            }
            role_validator.ensure_roles_exist([admin_role.as_str()])?;
        }

        Ok(())
    }
}

impl Default for MetadataStoreConfig {
    fn default() -> Self {
        let backend = MetadataStoreBackend::default();
        Self {
            directory: if backend == MetadataStoreBackend::Filesystem {
                Some(default_metadata_store_directory())
            } else {
                None
            },
            backend,
            uri: default_metadata_store_uri(),
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

impl Default for ObjectCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_object_cache_enabled(),
            directory: default_object_cache_directory(),
            max_file_size: default_object_cache_max_file_size(),
            max_total_size: default_object_cache_max_total_size(),
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
                if !cfg!(feature = "s3") {
                    anyhow::bail!("object-store.backend = \"s3\" requires the s3 Cargo feature");
                }
                if self.bucket.is_none() {
                    anyhow::bail!("object-store.bucket is required when backend is s3");
                }
                Ok(())
            }
        }
    }
}

impl ObjectCacheConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.directory.as_os_str().is_empty() {
            anyhow::bail!("cache.directory must not be empty");
        }
        if self.max_file_size == 0 {
            anyhow::bail!("cache.max-file-size must be greater than 0");
        }
        if self.max_total_size == 0 {
            anyhow::bail!("cache.max-total-size must be greater than 0");
        }
        Ok(())
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
                if !cfg!(feature = "surrealdb") {
                    anyhow::bail!(
                        "metadata-store.backend = \"surrealdb\" requires the surrealdb Cargo feature"
                    );
                }
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

fn default_object_cache_enabled() -> bool {
    true
}

fn default_object_cache_directory() -> PathBuf {
    "/var/lib/reposnake-cache".into()
}

fn default_object_cache_max_file_size() -> u64 {
    200 * 1024
}

fn default_object_cache_max_total_size() -> u64 {
    1024 * 1024 * 1024
}

fn default_metadata_store_directory() -> PathBuf {
    "/data/metadata".into()
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

fn deserialize_byte_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ByteSizeVisitor;

    impl Visitor<'_> for ByteSizeVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a byte count integer or a string like \"200KiB\"")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(value).map_err(|_| E::custom("byte size must not be negative"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_byte_size(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(ByteSizeVisitor)
}

fn parse_byte_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    let digit_len = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    if digit_len == 0 {
        return Err("byte size must start with a number".to_string());
    }
    let number = value[..digit_len]
        .parse::<u64>()
        .map_err(|error| format!("invalid byte size number: {error}"))?;
    let unit = value[digit_len..].trim();
    let multiplier = match unit {
        "" | "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        _ => {
            return Err("byte size unit must be one of B, KiB, MiB, GiB, or omitted".to_string());
        }
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| "byte size is too large".to_string())
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
origin = "http://localhost:8080"

[[role]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"
validation-key = "shared-secret"
algorithms = ["HS256"]

[role.claims]
sub = "buildkite:deploy"

[[publisher]]
name = "ci"
projects = ["reposnake-demo", "other_demo"]
role = "buildkite"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.origin, "http://localhost:8080");
        assert_eq!(config.max_upload_bytes, 100 * 1024 * 1024);
        assert_eq!(config.metadata_store.uri, "mem://");
        assert_eq!(config.roles[0].name, "buildkite");
        assert_eq!(config.object_store.backend, ObjectStoreBackend::Filesystem);
        assert_eq!(
            config.object_store.directory.as_deref(),
            Some(Path::new("/data"))
        );
        assert!(config.cache.enabled);
        assert_eq!(
            config.cache.directory.as_path(),
            Path::new("/var/lib/reposnake-cache")
        );
        assert_eq!(config.cache.max_file_size, 200 * 1024);
        assert_eq!(config.cache.max_total_size, 1024 * 1024 * 1024);
    }

    #[test]
    fn parses_cache_config() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

[cache]
enabled = false
directory = "/tmp/reposnake-cache"
max-file-size = "100KiB"
max-total-size = "2GiB"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert!(!config.cache.enabled);
        assert_eq!(
            config.cache.directory.as_path(),
            Path::new("/tmp/reposnake-cache")
        );
        assert_eq!(config.cache.max_file_size, 100 * 1024);
        assert_eq!(config.cache.max_total_size, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn rejects_invalid_cache_config() {
        for config in [
            r#"
origin = "http://localhost:8080"

[cache]
directory = ""
"#,
            r#"
origin = "http://localhost:8080"

[cache]
max-file-size = 0
"#,
            r#"
origin = "http://localhost:8080"

[cache]
max-total-size = "1GB"
"#,
        ] {
            let config = toml::from_str::<Config>(config);
            if let Ok(config) = config {
                assert!(config.validate(true).is_err());
            }
        }
    }

    #[test]
    fn parses_admin_role_config() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"
admin-role = "buildkite"

[[role]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"
validation-key = "shared-secret"

[[publisher]]
name = "ci"
projects = ["reposnake-demo"]
role = "buildkite"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.admin_role.as_deref(), Some("buildkite"));
    }

    #[test]
    fn rejects_admin_with_unknown_role() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"
admin-role = "other"

[[role]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"
validation-key = "shared-secret"

[[publisher]]
name = "ci"
projects = ["reposnake-demo"]
role = "buildkite"
"#,
        )
        .unwrap();

        assert!(config.validate(false).is_err());
    }

    #[test]
    fn parses_origin_config() {
        let config: Config = toml::from_str(
            r#"
origin = "https://packages.example"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.origin, "https://packages.example");
    }

    #[test]
    fn rejects_missing_origin_config() {
        let config = r#"
[[publisher]]
projects = ["*"]
"#;

        assert!(toml::from_str::<Config>(config).is_err());
    }

    #[test]
    fn parses_filesystem_object_store_directory() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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

    #[cfg(feature = "s3")]
    #[test]
    fn parses_s3_object_store_config() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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
[[role]]
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
origin = "http://localhost:8080"

[object-store]
backend = "s3"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        assert!(config.validate(true).is_err());
    }

    #[cfg(feature = "s3")]
    #[test]
    fn accepts_s3_object_store_without_directory() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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
origin = "http://localhost:8080"

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

    #[cfg(feature = "surrealdb")]
    #[test]
    fn parses_metadata_store_config() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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
origin = "http://localhost:8080"

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
origin = "http://localhost:8080"

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

    #[cfg(feature = "surrealdb")]
    #[test]
    fn rejects_metadata_store_directory_without_filesystem_backend() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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
origin = "http://localhost:8080"

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

    #[cfg(feature = "surrealdb")]
    #[test]
    fn parses_idmouse_metadata_store_config() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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

    #[cfg(feature = "surrealdb")]
    #[test]
    fn rejects_password_auth_when_idmouse_is_configured() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

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
origin = "http://localhost:8080"

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
    fn disable_auth_skips_role_validation() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
    }

    #[test]
    fn rejects_missing_role_when_auth_is_enabled() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

[[publisher]]
projects = ["*"]
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(error.to_string(), "at least one [[role]] entry is required");
    }

    #[test]
    fn rejects_missing_publisher_policy_when_auth_is_enabled() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

[[role]]
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
origin = "http://localhost:8080"

[[role]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"

[role.claims]
sub = "buildkite:deploy"

[[publisher]]
projects = ["*"]
role = "buildkite"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn required_claim_keys_are_not_renamed() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

[[role]]
name = "buildkite"
audience = "reposnake"
issuer = "https://issuer.example"

[role.claims]
repository_owner = "example"

[[publisher]]
projects = ["*"]
role = "buildkite"
"#,
        )
        .unwrap();

        assert_eq!(
            config.roles[0]
                .claims
                .get("repository_owner")
                .map(|requirement| requirement.matches(Some("example"))),
            Some(true)
        );
    }

    #[test]
    fn rejects_publisher_with_unknown_role() {
        let config: Config = toml::from_str(
            r#"
origin = "http://localhost:8080"

[[role]]
name = "kubernetes"
audience = "reposnake"
issuer = "https://kubernetes.default.svc"

[[publisher]]
projects = ["*"]
role = "buildkite"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(error.to_string(), "unknown role 'buildkite'");
    }
}
