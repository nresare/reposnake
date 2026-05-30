// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use serde::{Deserialize, Serialize};

pub const SIMPLE_API_VERSION: &str = "1.1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectIndex {
    pub name: String,
    pub normalized_name: String,
    #[serde(default)]
    pub files: Vec<FileRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    pub filename: String,
    pub version: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_python: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProjectSummary {
    pub name: String,
    pub normalized_name: String,
}

#[derive(Debug, Clone)]
pub struct UploadPackage {
    pub name: String,
    pub version: String,
    pub filename: String,
    pub content: Vec<u8>,
    pub provided_sha256: Option<String>,
    pub has_any_digest: bool,
    pub requires_python: Option<String>,
}

pub fn normalize_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut previous_was_separator = false;

    for byte in name.bytes() {
        let character = byte as char;
        if matches!(character, '-' | '_' | '.') {
            if !previous_was_separator {
                normalized.push('-');
                previous_was_separator = true;
            }
        } else {
            normalized.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        }
    }

    normalized
}

pub fn is_valid_project_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub fn is_safe_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename != "."
        && filename != ".."
        && !filename.contains('/')
        && !filename.contains('\\')
}

#[cfg(test)]
mod tests {
    use super::{is_safe_filename, is_valid_project_name, normalize_name};

    #[test]
    fn normalizes_python_project_names() {
        assert_eq!(normalize_name("HolyGrail"), "holygrail");
        assert_eq!(
            normalize_name("friendly_bard.example"),
            "friendly-bard-example"
        );
        assert_eq!(
            normalize_name("many---separators___here"),
            "many-separators-here"
        );
    }

    #[test]
    fn validates_project_names() {
        assert!(is_valid_project_name("reposnake_demo"));
        assert!(!is_valid_project_name(""));
        assert!(!is_valid_project_name("repo/snake"));
        assert!(!is_valid_project_name("repo snake"));
    }

    #[test]
    fn rejects_path_like_filenames() {
        assert!(is_safe_filename("reposnake_demo-0.1.0.tar.gz"));
        assert!(!is_safe_filename("../reposnake_demo-0.1.0.tar.gz"));
        assert!(!is_safe_filename("dist\\reposnake_demo-0.1.0.tar.gz"));
    }
}
