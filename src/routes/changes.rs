use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use chrono::Utc;
use fred::interfaces::KeysInterface;
use fred::types::{Expiration, SetOptions};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{new_csrf_token, csrf_tokens_equal},
    error::AppError,
    routes::{pending_changes_count, require_admin, require_session, users::load_team_groups},
    session::{Flash, FLASH_KEY, SESSION_KEY},
    storage::{AuditEntry, AuditOutcome, ChangeStatus, PendingChange},
    AppState,
};

// Adds what-this-team-grants context to a change for display, since several
// "teams" also carry real realm roles (e.g. the "devops" team also grants
// "iam-admin") and that needs to be visible to whoever approves it, not
// just discoverable by cross-referencing Keycloak.
#[derive(Serialize)]
struct ChangeView<'a> {
    #[serde(flatten)]
    inner: &'a PendingChange,
    team_grants: Option<Vec<String>>,
}

fn attach_team_grants<'a>(
    changes: &'a [PendingChange],
    team_roles: &HashMap<String, Vec<String>>,
) -> Vec<ChangeView<'a>> {
    changes.iter().map(|c| {
        let team_grants = c.diff.iter()
            .find(|f| f.field == "team_group_id")
            .and_then(|f| team_roles.get(&f.after))
            .filter(|roles| !roles.is_empty())
            .cloned();
        ChangeView { inner: c, team_grants }
    }).collect()
}

// Bounds page render/DOM size as resolved history grows without limit,
// while keeping every row in one response so the client-side status-tab
// filter (pending/approved/rejected) still works over the full visible set.
const CHANGES_PAGE_LIMIT: usize = 200;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/changes", get(list_changes))
        .route("/changes/:id/approve", post(approve))
        .route("/changes/:id/reject", post(reject))
        .route("/changes/:id/cancel", post(cancel))
}

#[derive(Deserialize)]
struct ChangesQuery {
    page: Option<usize>,
}

async fn list_changes(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<ChangesQuery>,
) -> Result<impl IntoResponse, AppError> {
    let mut current_user = require_session(&session, &state).await?;

    let mut changes = state
        .storage
        .list_changes()
        .await
        .map_err(AppError::Internal)?;

    if !current_user.role.is_admin() {
        changes.retain(|c| c.proposed_by == current_user.username);
    }

    // Admins resolve changes themselves, so they don't need telling. For an
    // operator, count how many of their own proposals were resolved since
    // their last visit — computed before truncation so the count reflects
    // everything, not just what's rendered. A missing last_seen (first visit
    // with this feature) intentionally counts as zero, not "all history."
    let unseen_resolved_count = if current_user.role.is_admin() {
        0
    } else {
        current_user.last_seen_changes_at
            .map(|last_seen| {
                changes.iter()
                    .filter(|c| c.status != ChangeStatus::Pending)
                    .filter(|c| c.resolved_at.map(|t| t > last_seen).unwrap_or(false))
                    .count()
            })
            .unwrap_or(0)
    };

    if !current_user.role.is_admin() {
        current_user.last_seen_changes_at = Some(Utc::now());
        session.insert(SESSION_KEY, &current_user).await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
    }

    // Real pagination (not just a cap) — older history stays reachable via
    // ?page=N instead of silently vanishing past CHANGES_PAGE_LIMIT. Each
    // page is a full, self-contained render so the client-side status-tab
    // filter still works within it.
    let total_pages = changes.len().div_ceil(CHANGES_PAGE_LIMIT).max(1);
    let page = q.page.unwrap_or(0).min(total_pages - 1);
    let start = page * CHANGES_PAGE_LIMIT;
    let end = (start + CHANGES_PAGE_LIMIT).min(changes.len());
    changes = changes[start..end].to_vec();

    let csrf = new_csrf_token();
    session
        .insert("csrf", &csrf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let flash: Option<Flash> = session
        .remove(FLASH_KEY)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    // Look up what each team-in-play actually grants (several teams also
    // carry realm roles), so the review page can show it inline.
    let mut realms: Vec<&str> = changes.iter().map(|c| c.realm.as_str()).collect();
    realms.sort_unstable();
    realms.dedup();
    let mut team_roles: HashMap<String, Vec<String>> = HashMap::new();
    for r in realms {
        if let Ok(groups) = load_team_groups(&state, r).await {
            for g in groups {
                team_roles.insert(g.id, g.realm_roles);
            }
        }
    }
    let changes_view = attach_team_grants(&changes, &team_roles);

    let pending_count = if current_user.role.is_admin() { pending_changes_count(&state).await } else { 0 };
    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "changes");
    ctx.insert("changes", &changes_view);
    ctx.insert("pending_count", &pending_count);
    ctx.insert("unseen_resolved_count", &unseen_resolved_count);
    ctx.insert("page", &page);
    ctx.insert("total_pages", &total_pages);
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
    let current_user = require_admin(&session, &state).await?;

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

    crate::routes::audit_failure(
        &state,
        crate::service::changes::apply_change_diff(
            &*state.provider,
            &*state.storage,
            &change.realm,
            &change.user_id,
            &change.diff,
        )
        .await,
        &current_user.username, "approve_change", &change.realm, Some(&change.username),
    ).await?;
    let redirect_to = "/changes".to_string();

    change.status = ChangeStatus::Approved;
    change.resolved_by = Some(current_user.username.clone());
    change.resolved_at = Some(Utc::now());

    // Only release the lock after a successful S3 write.
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

    Ok(Redirect::to(&redirect_to))
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
    let current_user = require_admin(&session, &state).await?;

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

#[derive(Deserialize)]
struct CancelForm {
    csrf_token: String,
}

// Lets an operator withdraw their own still-pending proposal. Reuses the
// rejected state (with resolved_by = the proposer) rather than adding a new
// ChangeStatus variant, since the UI already renders rejected history fine.
async fn cancel(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session, &state).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

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

    let mut change = state
        .storage
        .get_change(&id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound(format!("change {id}")))?;

    if change.proposed_by != current_user.username {
        let _ = state.redis.del::<i64, _>(&lock_key).await;
        return Err(AppError::Forbidden);
    }

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
    change.reject_reason = Some("Cancelled by proposer".to_string());

    match state.storage.save_change(&change).await {
        Ok(()) => { let _ = state.redis.del::<i64, _>(&lock_key).await; }
        Err(e) => {
            tracing::error!(
                change_id = %id,
                error = %e,
                "RECONCILIATION REQUIRED: cancellation not persisted to S3"
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
            action: "cancel_change".into(),
            target_realm: change.realm.clone(),
            target_user: Some(change.username.clone()),
            detail: format!("change {id} cancelled by proposer"),
            outcome: AuditOutcome::Success,
        })
        .await
        .map_err(AppError::Internal)?;

    session
        .insert(FLASH_KEY, Flash::success("Proposal cancelled."))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to("/changes"))
}
