use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use chrono::Utc;
use fred::interfaces::KeysInterface;
use fred::types::{Expiration, SetOptions};
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{new_csrf_token, csrf_tokens_equal},
    error::AppError,
    provider::UpdateUser,
    routes::{require_admin, require_session},
    session::{Flash, FLASH_KEY},
    storage::{AuditEntry, AuditOutcome, ChangeStatus},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/changes", get(list_changes))
        .route("/changes/:id/approve", post(approve))
        .route("/changes/:id/reject", post(reject))
}

async fn list_changes(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session).await?;

    let mut changes = state
        .storage
        .list_changes()
        .await
        .map_err(AppError::Internal)?;

    if !current_user.role.is_admin() {
        changes.retain(|c| c.proposed_by == current_user.username);
    }

    let csrf = new_csrf_token();
    session
        .insert("csrf", &csrf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let flash: Option<Flash> = session
        .remove(FLASH_KEY)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "changes");
    ctx.insert("changes", &changes);
    ctx.insert("csrf", &csrf);
    ctx.insert("flash", &flash);

    let html = state
        .tera
        .render("changes.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

#[derive(Deserialize)]
struct ApproveForm {
    csrf_token: String,
}

async fn approve(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Form(form): Form<ApproveForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    // Acquire distributed lock — prevents two admins from double-processing.
    let lock_key = format!("grafter:change-lock:{id}");
    let acquired: Option<String> = state
        .redis
        .set(&lock_key, "1", Some(Expiration::EX(30)), Some(SetOptions::NX), false)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis lock error: {e}")))?;

    if acquired.is_none() {
        session
            .insert(FLASH_KEY, Flash::warning("This change is being processed."))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
        return Ok(Redirect::to("/changes"));
    }

    // Re-read inside the lock and guard against double-processing.
    let mut change = state
        .storage
        .get_change(&id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("change {id}")))?;

    if change.status != ChangeStatus::Pending {
        let _ = state.redis.del::<i64, _>(&lock_key).await;
        session
            .insert(FLASH_KEY, Flash::warning("This change has already been processed."))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
        return Ok(Redirect::to("/changes"));
    }

    // Batch all field changes into the fewest possible Keycloak API calls.
    let mut update = UpdateUser::default();
    let mut enabled_change: Option<bool> = None;
    let mut team_change: Option<String> = None;

    for field in &change.diff {
        match field.field.as_str() {
            "first_name" => update.first_name = Some(field.after.clone()),
            "last_name"  => update.last_name  = Some(field.after.clone()),
            "email"      => update.email      = Some(field.after.clone()),
            "enabled"    => enabled_change    = Some(field.after == "true"),
            "team"       => team_change       = Some(field.after.clone()),
            _ => {}
        }
    }

    if update.first_name.is_some() || update.last_name.is_some() || update.email.is_some() {
        state.provider.update_user(&change.realm, &change.user_id, update).await?;
    }
    if let Some(enabled) = enabled_change {
        state.provider.set_user_enabled(&change.realm, &change.user_id, enabled).await?;
    }
    if let Some(ref team) = team_change {
        state.provider.set_user_attribute(&change.realm, &change.user_id, "team", team).await?;
    }

    change.status = ChangeStatus::Approved;
    change.resolved_by = Some(current_user.username.clone());
    change.resolved_at = Some(Utc::now());

    // Only release the lock after a successful S3 write.
    // If S3 write fails, Keycloak was already mutated — leave the lock in
    // place so the 30s TTL blocks retries, and emit an error for manual reconciliation.
    match state.storage.save_change(&change).await {
        Ok(()) => { let _ = state.redis.del::<i64, _>(&lock_key).await; }
        Err(e) => {
            tracing::error!(
                change_id = %id,
                error = %e,
                "RECONCILIATION REQUIRED: change applied to Keycloak but S3 record was not persisted"
            );
            return Err(AppError::Internal(e));
        }
    }

    state
        .storage
        .append_audit(&AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            actor: current_user.username.clone(),
            action: "approve_change".into(),
            target_realm: change.realm.clone(),
            target_user: Some(change.username.clone()),
            detail: format!("change {id} approved"),
            outcome: AuditOutcome::Success,
        })
        .await
        .map_err(AppError::Internal)?;

    session
        .insert(FLASH_KEY, Flash::success(format!("Change for {} approved.", change.username)))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to("/changes"))
}

#[derive(Deserialize)]
struct RejectForm {
    csrf_token: String,
    reason: Option<String>,
}

async fn reject(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Form(form): Form<RejectForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    // Acquire distributed lock — prevents two admins from double-processing.
    let lock_key = format!("grafter:change-lock:{id}");
    let acquired: Option<String> = state
        .redis
        .set(&lock_key, "1", Some(Expiration::EX(30)), Some(SetOptions::NX), false)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("redis lock error: {e}")))?;

    if acquired.is_none() {
        session
            .insert(FLASH_KEY, Flash::warning("This change is being processed."))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
        return Ok(Redirect::to("/changes"));
    }

    // Re-read inside the lock and guard against double-processing.
    let mut change = state
        .storage
        .get_change(&id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("change {id}")))?;

    if change.status != ChangeStatus::Pending {
        let _ = state.redis.del::<i64, _>(&lock_key).await;
        session
            .insert(FLASH_KEY, Flash::warning("This change has already been processed."))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
        return Ok(Redirect::to("/changes"));
    }

    change.status = ChangeStatus::Rejected;
    change.resolved_by = Some(current_user.username.clone());
    change.resolved_at = Some(Utc::now());
    change.reject_reason = form.reason.clone();

    // Only release the lock after a successful S3 write.
    // If S3 write fails, leave the lock in place (30s TTL) to block retries.
    match state.storage.save_change(&change).await {
        Ok(()) => { let _ = state.redis.del::<i64, _>(&lock_key).await; }
        Err(e) => {
            tracing::error!(
                change_id = %id,
                error = %e,
                "RECONCILIATION REQUIRED: rejection recorded in Keycloak but S3 record was not persisted"
            );
            return Err(AppError::Internal(e));
        }
    }

    state
        .storage
        .append_audit(&AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            actor: current_user.username.clone(),
            action: "reject_change".into(),
            target_realm: change.realm.clone(),
            target_user: Some(change.username.clone()),
            detail: format!(
                "change {id} rejected: {}",
                form.reason.as_deref().unwrap_or("no reason given")
            ),
            outcome: AuditOutcome::Success,
        })
        .await
        .map_err(AppError::Internal)?;

    session
        .insert(FLASH_KEY, Flash::warning(format!("Change for {} rejected.", change.username)))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to("/changes"))
}
