use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not authenticated")]
    Unauthenticated,

    #[error("forbidden")]
    Forbidden,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("csrf validation failed")]
    CsrfMismatch,

    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),

    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("unexpected response ({status}): {body}")]
    UnexpectedResponse { status: u16, body: String },

    #[error("not found")]
    NotFound,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, &'static str) = match &self {
            AppError::Unauthenticated => (StatusCode::UNAUTHORIZED,           "Not authenticated."),
            AppError::Forbidden       => (StatusCode::FORBIDDEN,              "Access denied."),
            AppError::NotFound(_)     => (StatusCode::NOT_FOUND,              "Not found."),
            AppError::CsrfMismatch    => (StatusCode::FORBIDDEN,              "Invalid or expired form token. Please reload and try again."),
            AppError::Provider(e) => {
                // Log the raw provider error server-side; never expose it to the browser.
                tracing::error!(error = %e, "identity provider error");
                match e {
                    ProviderError::NotFound => (StatusCode::NOT_FOUND, "The requested resource was not found."),
                    ProviderError::UnexpectedResponse { status, .. } => {
                        let http_status = StatusCode::from_u16(*status)
                            .unwrap_or(StatusCode::BAD_GATEWAY);
                        (http_status, "Identity provider returned an error. Check server logs.")
                    }
                    ProviderError::Http(_) => (StatusCode::BAD_GATEWAY, "Could not reach the identity provider."),
                }
            }
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal error occurred.")
            }
        };
        (status, message).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
