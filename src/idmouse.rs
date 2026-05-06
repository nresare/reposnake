// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use crate::config::IdmouseConfig;
use anyhow::{Context, anyhow};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;
use tokio::time::sleep;
use tracing::{debug, info, warn};

const RENEW_MARGIN: Duration = Duration::from_secs(10);
const INITIAL_RENEW_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRIES: usize = 5;

#[derive(Clone)]
pub struct IdmouseClient {
    client: reqwest::Client,
    config: IdmouseConfig,
}

#[derive(Deserialize)]
struct IdmouseTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdmouseTokenLease {
    pub access_token: String,
    pub expires_in: Duration,
}

impl IdmouseClient {
    pub fn new(config: IdmouseConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    pub async fn fetch_token_lease(&self) -> anyhow::Result<IdmouseTokenLease> {
        let bearer_token = self
            .config
            .bearer_token()
            .context("Failed to read idmouse bearer token")?;

        debug!(url = %self.config.url, "Requesting SurrealDB access token from idmouse");

        let response = self
            .client
            .post(&self.config.url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .context("Failed to call idmouse")?
            .error_for_status()
            .context("idmouse returned an error response")?;

        let token: IdmouseTokenResponse = response
            .json()
            .await
            .context("Failed to decode idmouse token response")?;

        if token.access_token.is_empty() {
            return Err(anyhow!("idmouse returned an empty access_token"));
        }
        if token.expires_in == 0 {
            return Err(anyhow!("idmouse returned an invalid expires_in of 0"));
        }

        Ok(IdmouseTokenLease {
            access_token: token.access_token,
            expires_in: Duration::from_secs(token.expires_in),
        })
    }

    pub async fn authenticate_db(&self, db: Arc<Surreal<Any>>) -> anyhow::Result<()> {
        let lease = self.fetch_token_lease().await?;
        db.authenticate(&lease.access_token).await?;
        spawn_renewal_task(db, self.clone(), lease.expires_in);
        Ok(())
    }
}

fn spawn_renewal_task(db: Arc<Surreal<Any>>, client: IdmouseClient, expires_in: Duration) {
    tokio::spawn(async move {
        sleep(renewal_delay(expires_in)).await;
        renew_authentication_loop(db, client).await;
    });
}

async fn renew_authentication_loop(db: Arc<Surreal<Any>>, client: IdmouseClient) {
    let mut retry = 0;
    loop {
        match try_renew_authentication(db.clone(), &client).await {
            Ok(next_lease) => {
                info!("Renewed SurrealDB authentication from idmouse");
                retry = 0;
                sleep(renewal_delay(next_lease.expires_in)).await;
            }
            Err(error) if retry < MAX_RETRIES => {
                let delay = retry_delay(retry);
                retry += 1;
                warn!(
                    error = %error,
                    retry,
                    max_retries = MAX_RETRIES,
                    delay = ?delay,
                    "Failed to renew SurrealDB authentication; retrying"
                );
                sleep(delay).await;
            }
            Err(error) => {
                warn!(
                    error = %error,
                    max_retries = MAX_RETRIES,
                    "Failed to renew SurrealDB authentication; giving up"
                );
                return;
            }
        }
    }
}

async fn try_renew_authentication(
    db: Arc<Surreal<Any>>,
    client: &IdmouseClient,
) -> anyhow::Result<IdmouseTokenLease> {
    let lease = client.fetch_token_lease().await?;
    db.authenticate(&lease.access_token).await?;
    Ok(lease)
}

fn renewal_delay(expires_in: Duration) -> Duration {
    expires_in.saturating_sub(RENEW_MARGIN)
}

fn retry_delay(retry: usize) -> Duration {
    INITIAL_RENEW_RETRY_DELAY.saturating_mul(1u32 << retry)
}

#[cfg(test)]
mod tests {
    use super::{IdmouseClient, IdmouseTokenLease, renewal_delay, retry_delay};
    use crate::config::IdmouseConfig;
    use axum::extract::State;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Clone)]
    struct TestState {
        expected_auth_header: Arc<String>,
    }

    #[tokio::test]
    async fn fetch_token_lease_reads_local_bearer_token_and_posts_to_idmouse() -> anyhow::Result<()>
    {
        let token_file = write_temp_token_file("local-bearer-token\n")?;
        let state = TestState {
            expected_auth_header: Arc::new("Bearer local-bearer-token".to_string()),
        };

        async fn issue_token(
            State(state): State<TestState>,
            headers: HeaderMap,
        ) -> (StatusCode, Json<serde_json::Value>) {
            let actual = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);

            if actual.as_deref() != Some(state.expected_auth_header.as_str()) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "missing bearer token" })),
                );
            }

            (
                StatusCode::OK,
                Json(json!({
                    "access_token": "surreal-jwt-token",
                    "expires_in": 42,
                })),
            )
        }

        let app = Router::new()
            .route("/", post(issue_token))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let client = IdmouseClient::new(IdmouseConfig {
            url: format!("http://{address}/"),
            token_path: token_file.into_boxed_path(),
        });

        assert_eq!(
            client.fetch_token_lease().await?,
            IdmouseTokenLease {
                access_token: "surreal-jwt-token".to_string(),
                expires_in: Duration::from_secs(42),
            }
        );

        server.abort();
        Ok(())
    }

    #[test]
    fn renewal_delay_renews_before_expiry() {
        assert_eq!(
            renewal_delay(Duration::from_secs(45)),
            Duration::from_secs(35)
        );
        assert_eq!(renewal_delay(Duration::from_secs(10)), Duration::ZERO);
        assert_eq!(renewal_delay(Duration::from_secs(3)), Duration::ZERO);
    }

    #[test]
    fn retry_delay_uses_exponential_backoff_from_one_second() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(2), Duration::from_secs(4));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(4), Duration::from_secs(16));
    }

    fn write_temp_token_file(contents: &str) -> anyhow::Result<PathBuf> {
        let file = tempfile::NamedTempFile::new()?;
        let (_file, path) = file.keep()?;
        std::fs::write(&path, contents)?;
        Ok(path)
    }
}
