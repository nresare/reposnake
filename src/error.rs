// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tracing::{error, info, warn};

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
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        match &self {
            AppError::Internal(_) => {
                error!(status = status.as_u16(), error = %message, "request failed");
            }
            AppError::NotFound(_) => {
                info!(status = status.as_u16(), error = %message, "request rejected");
            }
            AppError::BadRequest(_)
            | AppError::Conflict(_)
            | AppError::Forbidden(_)
            | AppError::PayloadTooLarge(_)
            | AppError::Unauthorized(_) => {
                warn!(status = status.as_u16(), error = %message, "request rejected");
            }
        }
        (status, Json(ErrorBody { error: &message })).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error.to_string())
    }
}
