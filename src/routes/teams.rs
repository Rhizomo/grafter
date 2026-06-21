use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use chrono::Utc;
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{csrf_tokens_equal, new_csrf_token},
    error::AppError,
    routes::{require_admin, require_session},
    session::{Flash, FLASH_KEY},
    storage::{AuditEntry, AuditOutcome},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/teams", get(list_teams).post(create_team))
}

// ── Helper: find teams parent group ID ───────────────────────────────────────

pub async fn teams_parent_id(state: &AppState, realm: &str) -> Result<Option<String>, AppError> {
    let groups = state.provider.list_groups(realm).await?;
    Ok(groups.into_iter().find(|g| g.name == state.config.teams_group).map(|g| g.id))
}

// ── GET /teams — list all teams (same page as users, just scrolls) ────────────

async fn list_teams(session: Session) -> Result<impl IntoResponse, AppError> {
    let _ = require_session(&session).await?;
    Ok(Redirect::to("/users"))
}

// ── POST /teams — create a new team group ─────────────────────────────────────

#[derive(Deserialize)]
struct CreateTeamForm {
    csrf_token: String,
    realm: String,
    name: String,
}

async fn create_team(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<CreateTeamForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!("team name cannot be empty")));
    }

    // Ensure the teams parent group exists; create it if not.
    let parent_id = match teams_parent_id(&state, &form.realm).await? {
        Some(id) => id,
        None => {
            let g = state.provider.create_group(&form.realm, &state.config.teams_group, None).await?;
            g.id
        }
    };

    state.provider.create_group(&form.realm, &name, Some(&parent_id)).await?;

    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "create_team".into(),
        target_realm: form.realm.clone(), target_user: None,
        detail: format!("team '{name}' created"), outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::success(format!("Team '{name}' created."))).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/users?realm={}", form.realm)))
}
