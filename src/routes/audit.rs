use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use chrono::Utc;
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    error::AppError,
    routes::{pending_changes_count, require_admin},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/audit", get(list_audit))
}

#[derive(Deserialize)]
struct AuditQuery {
    date: Option<String>,
}

pub async fn list_audit(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<AuditQuery>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session, &state).await?;

    let today = Utc::now().format("%Y-%m-%d").to_string();
    let selected_date = q.date.unwrap_or(today);

    let mut entries = state
        .storage
        .list_audit(Some(&selected_date))
        .await
        .map_err(AppError::Internal)?;

    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let pending_count = pending_changes_count(&state).await;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &true);
    ctx.insert("active_tab", "audit");
    ctx.insert("entries", &entries);
    ctx.insert("selected_date", &selected_date);
    ctx.insert("pending_count", &pending_count);

    let html = state
        .tera
        .render("audit.html", &ctx)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("template error: {e}")))?;

    Ok(Html(html))
}
