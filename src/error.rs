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

    #[error("validation: {0}")]
    Validation(String),

    #[error("conflict: {0}")]
    Conflict(String),
}

fn he(s: &str) -> String {
    s.chars().fold(String::with_capacity(s.len()), |mut out, c| {
        match c {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _    => out.push(c),
        }
        out
    })
}

fn error_page(status: StatusCode, title: &str, detail: &str, back: Option<&str>) -> Response {
    let title  = he(title);
    let detail = he(detail);
    let back_html = match back {
        Some(url) => format!(r#"<a href="{}" class="btn">← Go back</a>"#, he(url)),
        None      => r#"<button onclick="history.back()" class="btn">← Go back</button>"#.to_string(),
    };
    let html = format!(r#"<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Grafter</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',system-ui,sans-serif;background:#060e0d;color:#c8e6e0;
  min-height:100vh;display:flex;align-items:center;justify-content:center;}}
.card{{background:#0b1f1d;border:1px solid #1a3d38;border-radius:12px;padding:36px 32px;
  max-width:480px;width:100%;margin:20px;}}
h1{{font-size:1.1rem;font-weight:700;color:#f0faf7;margin-bottom:10px;}}
p{{font-size:0.875rem;color:#6aa89a;line-height:1.6;margin-bottom:24px;}}
.btn{{display:inline-block;padding:9px 18px;background:transparent;border:1px solid #243f3a;
  border-radius:8px;color:#6aa89a;font-size:0.84rem;font-family:inherit;cursor:pointer;
  text-decoration:none;}}
.btn:hover{{border-color:#00bfa5;color:#00bfa5;}}
.code{{font-size:0.7rem;color:#2e5a52;margin-top:20px;}}
</style></head><body>
<div class="card">
  <h1>{title}</h1>
  <p>{detail}</p>
  {back_html}
  <p class="code">HTTP {status}</p>
</div></body></html>"#);
    (status, axum::response::Html(html)).into_response()
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthenticated =>
                error_page(StatusCode::UNAUTHORIZED, "Not authenticated", "You need to sign in to access this page.", Some("/auth/login")),
            AppError::Forbidden =>
                error_page(StatusCode::FORBIDDEN, "Access denied", "You don't have permission to perform this action.", None),
            AppError::NotFound(ref msg) =>
                error_page(StatusCode::NOT_FOUND, "Not found", msg, None),
            AppError::CsrfMismatch =>
                error_page(StatusCode::FORBIDDEN, "Session expired", "Your form token expired. Please reload the page and try again.", None),
            AppError::Provider(ref e) => {
                tracing::error!(error = %e, "identity provider error");
                match e {
                    ProviderError::NotFound =>
                        error_page(StatusCode::NOT_FOUND, "Not found", "The requested resource was not found in the identity provider.", None),
                    ProviderError::Validation(msg) =>
                        error_page(StatusCode::UNPROCESSABLE_ENTITY, "Validation error", msg, None),
                    ProviderError::Conflict(msg) =>
                        error_page(StatusCode::CONFLICT, "Conflict", msg, None),
                    ProviderError::UnexpectedResponse { status, body } => {
                        tracing::error!(status, body, "unexpected provider response");
                        error_page(StatusCode::BAD_GATEWAY, "Identity provider error",
                            "The identity provider returned an unexpected error. Check server logs for details.", None)
                    }
                    ProviderError::Http(_) =>
                        error_page(StatusCode::BAD_GATEWAY, "Provider unreachable", "Could not reach the identity provider.", None),
                }
            }
            AppError::Internal(ref e) => {
                tracing::error!(error = %e, "internal error");
                error_page(StatusCode::INTERNAL_SERVER_ERROR, "Internal error", "An internal error occurred.", None)
            }
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
