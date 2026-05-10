// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tracing::{error, warn};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    PayloadTooLarge(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{message}")]
    OciUnauthorized {
        message: String,
        authenticate: String,
    },
    #[error("{0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        let status = match &self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::Unauthorized(_) | AppError::OciUnauthorized { .. } => {
                StatusCode::UNAUTHORIZED
            }
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        match &self {
            AppError::Internal(_) => {
                error!(status = status.as_u16(), error = %message, "request failed");
            }
            AppError::BadRequest(_)
            | AppError::Conflict(_)
            | AppError::Forbidden(_)
            | AppError::NotFound(_)
            | AppError::PayloadTooLarge(_)
            | AppError::Unauthorized(_)
            | AppError::OciUnauthorized { .. } => {
                warn!(status = status.as_u16(), error = %message, "request rejected");
            }
        }
        let mut response = (status, Json(ErrorBody { error: &message })).into_response();
        if let AppError::OciUnauthorized { authenticate, .. } = self {
            match authenticate.parse() {
                Ok(value) => {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
                Err(error) => {
                    error!(
                        error = %error,
                        "failed to build OCI WWW-Authenticate header"
                    );
                }
            }
        }
        response
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error.to_string())
    }
}
