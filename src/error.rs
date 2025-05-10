use serde_json::json;
use std::fmt::Display;

use anyhow::Error as anyhowError;
use axum::{http::StatusCode, response::IntoResponse};
#[derive(Debug)]
pub enum AppError {
    // 400 bad request
    BadRequest(anyhowError),
    // 401 unauthorized
    Unauthorized(anyhowError),
    // 403 forbidden
    Forbidden(anyhowError),
    // 404 not found
    NotFound(anyhowError),
    // 500 internal server error
    InternalServerError(anyhowError),
    // 503 service unavailable
    ServiceUnavailable(anyhowError),
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(e) => write!(f, "BadRequest: {}", e),
            AppError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            AppError::Forbidden(e) => write!(f, "Forbidden: {}", e),
            AppError::NotFound(e) => write!(f, "NotFound: {}", e),
            AppError::InternalServerError(e) => write!(f, "InternalServerError: {}", e),
            AppError::ServiceUnavailable(e) => write!(f, "ServiceUnavailable: {}", e),
        }
    }
}

impl From<anyhowError> for AppError {
    fn from(e: anyhowError) -> Self {
        AppError::InternalServerError(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match &self {
            Self::BadRequest(err) => (StatusCode::BAD_REQUEST, err.to_string()),
            Self::Unauthorized(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
            Self::Forbidden(err) => (StatusCode::FORBIDDEN, err.to_string()),
            Self::NotFound(err) => (StatusCode::NOT_FOUND, err.to_string()),
            Self::InternalServerError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            Self::ServiceUnavailable(err) => (StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
        };

        #[cfg(debug_assertions)]
        let error_response = json!({
            "error": {
                "message": error_message,
                "type": format!("{:?}", self),
            }
        });

        #[cfg(not(debug_assertions))]
        let error_response = json!({
            "error": {
                "message": status.canonical_reason().unwrap_or("An error occurred"),
            }
        });
        (status, axum::Json(error_response)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
