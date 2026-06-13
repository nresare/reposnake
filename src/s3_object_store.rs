// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::error::AppError;
use crate::object_store::{ObjectMetadata, ObjectStore, ObjectWriter};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{Client, Config as AwsS3Config};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

static TEMP_OBJECT_COUNTER: AtomicU64 = AtomicU64::new(0);
const OBJECT_KEY_PREFIX: &str = "objects/";

#[derive(Debug)]
pub struct S3ObjectStore {
    client: Client,
    bucket: String,
    prefix: String,
    temp_directory: PathBuf,
}

impl S3ObjectStore {
    pub async fn from_bucket(bucket: &str) -> anyhow::Result<Self> {
        let shared_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let builder = AwsS3Config::from(&shared_config).to_builder();

        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: bucket.to_string(),
            prefix: OBJECT_KEY_PREFIX.to_string(),
            temp_directory: default_temp_directory(),
        })
    }

    fn object_key(&self, sha256: &[u8; 32]) -> String {
        format!("{}{}", self.prefix, hex::encode(sha256))
    }

    fn temp_path(&self) -> PathBuf {
        self.temp_directory
            .join(format!(".reposnake-s3-tmp-{}", next_temp_object_id()))
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn read(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, AppError> {
        let key = self.object_key(sha256);
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|error| {
                if is_s3_get_not_found(&error) {
                    AppError::NotFound(format!("object '{}' not found", hex::encode(sha256)))
                } else {
                    AppError::Internal(format!("failed to read S3 object '{key}': {error}"))
                }
            })?;
        let bytes = output.body.collect().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to collect S3 object body '{key}' from bucket '{}': {error}",
                self.bucket
            ))
        })?;
        Ok(bytes.into_bytes().to_vec())
    }

    async fn check_availability(&self) -> Result<(), AppError> {
        self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&self.prefix)
            .max_keys(1)
            .send()
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to list S3 objects with prefix '{}' in bucket '{}': {error}",
                    self.prefix, self.bucket
                ))
            })?;
        Ok(())
    }

    async fn create_writer(&self) -> Result<Box<dyn ObjectWriter>, AppError> {
        tokio::fs::create_dir_all(&self.temp_directory)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to create S3 object temp directory '{}': {error}",
                    self.temp_directory.display()
                ))
            })?;

        let temp_path = self.temp_path();
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to create temporary S3 object '{}': {error}",
                    temp_path.display()
                ))
            })?;

        Ok(Box::new(S3ObjectWriter {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            temp_path,
            file: Some(file),
            hasher: Sha256::new(),
        }))
    }

    async fn delete_if_exists(&self, sha256: &[u8; 32]) -> Result<(), AppError> {
        let key = self.object_key(sha256);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to delete S3 object '{key}' from bucket '{}': {error}",
                    self.bucket
                ))
            })?;
        Ok(())
    }

    async fn list_objects(&self) -> Result<Vec<ObjectMetadata>, AppError> {
        let mut objects = Vec::new();
        let mut continuation_token = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&self.prefix);
            if let Some(token) = continuation_token.take() {
                request = request.continuation_token(token);
            }
            let output = request.send().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to list S3 objects in bucket '{}' with prefix '{}': {error}",
                    self.bucket, self.prefix
                ))
            })?;
            for object in output.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                let Some(sha256) = key.strip_prefix(&self.prefix) else {
                    continue;
                };
                if sha256.len() != 64 || hex::decode(sha256).is_err() {
                    continue;
                }
                let Some(size) = object.size().and_then(|size| u64::try_from(size).ok()) else {
                    continue;
                };
                objects.push(ObjectMetadata {
                    sha256: sha256.to_string(),
                    size,
                });
            }
            if output.is_truncated().unwrap_or(false) {
                continuation_token = output.next_continuation_token().map(str::to_string);
            } else {
                break;
            }
        }
        objects.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        Ok(objects)
    }
}

struct S3ObjectWriter {
    client: Client,
    bucket: String,
    prefix: String,
    temp_path: PathBuf,
    file: Option<tokio::fs::File>,
    hasher: Sha256,
}

#[async_trait]
impl ObjectWriter for S3ObjectWriter {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| AppError::Internal("object writer is already closed".to_string()))?;
        self.hasher.update(chunk);
        file.write_all(chunk).await.map_err(|error| {
            AppError::Internal(format!(
                "failed to write temporary S3 object '{}': {error}",
                self.temp_path.display()
            ))
        })
    }

    async fn commit(mut self: Box<Self>) -> Result<[u8; 32], AppError> {
        if let Some(mut file) = self.file.take() {
            file.flush().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to flush temporary S3 object '{}': {error}",
                    self.temp_path.display()
                ))
            })?;
            file.sync_all().await.map_err(|error| {
                AppError::Internal(format!(
                    "failed to sync temporary S3 object '{}': {error}",
                    self.temp_path.display()
                ))
            })?;
        }

        let sha256 = self.hasher.clone().finalize().into();
        let key = format!("{}{}", self.prefix, hex::encode(sha256));
        let object_exists = match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => true,
            Err(error) if is_s3_head_not_found(&error) => false,
            Err(error) => {
                let message = format!(
                    "failed to check S3 object '{key}' in bucket '{}': {error}",
                    self.bucket
                );
                self.abort().await?;
                return Err(AppError::Internal(message));
            }
        };
        if object_exists {
            self.abort().await?;
            return Ok(sha256);
        }

        let body = ByteStream::read_from()
            .path(&self.temp_path)
            .build()
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to open temporary S3 object '{}': {error}",
                    self.temp_path.display()
                ))
            })?;
        match self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .if_none_match("*")
            .body(body)
            .send()
            .await
        {
            Ok(_) => {
                self.abort().await?;
                Ok(sha256)
            }
            Err(error) if is_s3_precondition_failed(&error) => {
                self.abort().await?;
                Ok(sha256)
            }
            Err(error) => {
                let message = format!(
                    "failed to write S3 object '{key}' to bucket '{}': {error}",
                    self.bucket
                );
                self.abort().await?;
                Err(AppError::Internal(message))
            }
        }
    }

    async fn abort(mut self: Box<Self>) -> Result<(), AppError> {
        self.file.take();
        match tokio::fs::remove_file(&self.temp_path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::Internal(format!(
                "failed to remove temporary S3 object '{}': {error}",
                self.temp_path.display()
            ))),
        }
    }
}

fn default_temp_directory() -> PathBuf {
    PathBuf::from("/var/tmp/reposnake")
}

fn next_temp_object_id() -> u64 {
    TEMP_OBJECT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn is_s3_head_not_found(error: &SdkError<HeadObjectError>) -> bool {
    error.as_service_error().is_some_and(|error| {
        error.is_not_found()
            || error.code() == Some("NoSuchKey")
            || error.code() == Some("NotFound")
            || error.code() == Some("404")
    })
}

fn is_s3_get_not_found(error: &SdkError<GetObjectError>) -> bool {
    error.as_service_error().is_some_and(|error| {
        error.is_no_such_key() || error.code() == Some("NoSuchKey") || error.code() == Some("404")
    })
}

fn is_s3_precondition_failed(error: &SdkError<PutObjectError>) -> bool {
    error.as_service_error().is_some_and(|error| {
        error.code() == Some("PreconditionFailed")
            || error.code() == Some("ConditionalRequestConflict")
            || error.code() == Some("412")
            || error.code() == Some("409")
    })
}

#[cfg(test)]
mod tests {
    use super::{OBJECT_KEY_PREFIX, default_temp_directory};
    use std::path::PathBuf;

    #[test]
    fn object_prefix_is_slash_terminated() {
        assert!(OBJECT_KEY_PREFIX.ends_with('/'));
    }

    #[test]
    fn temp_directory_defaults_to_var_tmp_reposnake() {
        assert_eq!(
            default_temp_directory(),
            PathBuf::from("/var/tmp/reposnake")
        );
    }
}
