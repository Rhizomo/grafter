use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{csrf_tokens_equal, new_csrf_token},
    error::AppError,
    routes::{pending_changes_count, require_admin},
    session::{Flash, FLASH_KEY},
    storage::{AuditEntry, AuditOutcome},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(admin_panel))
        .route("/admin/grant", post(grant_access))
        .route("/admin/revoke", post(revoke_access))
}

#[derive(Deserialize)]
struct AdminQuery {
    realm: Option<String>,
    log_date: Option<String>,
}

#[derive(Serialize)]
struct AccessUser {
    id: String,
    username: String,
    full_name: String,
    email: Option<String>,
    role: &'static str,
    realm: String,
}

async fn admin_panel(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<AdminQuery>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session, &state).await?;

    let realms = state.provider.list_realms().await?;
    let realm = q.realm.clone()
        .unwrap_or_else(|| realms.first().map(|r| r.name.clone()).unwrap_or_default());

    // Fetch users with admin or operator role
    let admin_role  = &state.config.role_admin;
    let op_role     = &state.config.role_operator;

    let (admins, operators) = tokio::try_join!(
        state.provider.list_role_users(&realm, admin_role),
        state.provider.list_role_users(&realm, op_role),
    )?;

    let mut access_users: Vec<AccessUser> = admins.iter().map(|u| AccessUser {
        id: u.id.clone(), username: u.username.clone(),
        full_name: u.full_name(), email: u.email.clone(),
        role: "admin", realm: realm.clone(),
    }).collect();

    for u in &operators {
        if !access_users.iter().any(|a| a.id == u.id) {
            access_users.push(AccessUser {
                id: u.id.clone(), username: u.username.clone(),
                full_name: u.full_name(), email: u.email.clone(),
                role: "operator", realm: realm.clone(),
            });
        }
    }
    access_users.sort_by(|a, b| a.username.cmp(&b.username));

    // Audit log
    let log_date = q.log_date.as_deref();
    let mut audit = state.storage.list_audit(log_date).await.map_err(AppError::Internal)?;
    audit.reverse(); // newest first
    audit.truncate(100);

    let csrf = new_csrf_token();
    session.insert("csrf", &csrf).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let flash: Option<Flash> = session.remove(FLASH_KEY).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let pending_count = pending_changes_count(&state).await;
    let today = Utc::now().format("%Y-%m-%d").to_string();

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &true);
    ctx.insert("active_tab", "admin");
    ctx.insert("realms", &realms);
    ctx.insert("current_realm", &realm);
    ctx.insert("access_users", &access_users);
    ctx.insert("admin_role",  &state.config.role_admin);
    ctx.insert("op_role",     &state.config.role_operator);
    ctx.insert("audit", &audit);
    ctx.insert("log_date", log_date.unwrap_or(&today));
    ctx.insert("today", &today);
    ctx.insert("pending_count", &pending_count);
    ctx.insert("csrf", &csrf);
    ctx.insert("flash", &flash);

    let html = state.tera.render("admin.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

// ── Grant access ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GrantForm {
    csrf_token: String,
    realm: String,
    username: String,
    role: String,
}

async fn grant_access(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<GrantForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session, &state).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let role_name = if form.role == "admin" { &state.config.role_admin } else { &state.config.role_operator };

    // Find user by username
    let users = state.provider.list_users(
        &form.realm,
        &crate::provider::ListUsersQuery::new().search(&form.username),
    ).await?;
    let target = users.into_iter().find(|u| u.username == form.username)
        .ok_or_else(|| AppError::NotFound(format!("user {}", form.username)))?;

    // Find the role object
    let roles = state.provider.list_realm_roles(&form.realm).await?;
    let role = roles.into_iter().find(|r| r.name == *role_name)
        .ok_or_else(|| AppError::NotFound(format!("role {role_name}")))?;

    crate::routes::audit_failure(
        &state,
        state.provider.assign_realm_role(&form.realm, &target.id, &role).await,
        &current_user.username, "grant_access", &form.realm, Some(&form.username),
    ).await?;

    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "grant_access".into(),
        target_realm: form.realm.clone(), target_user: Some(form.username.clone()),
        detail: format!("granted {} role '{role_name}'", form.username),
        outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::success(
        format!("{} granted {} access.", form.username, form.role)
    )).await.map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/admin?realm={}", form.realm)))
}

// ── Revoke access ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RevokeForm {
    csrf_token: String,
    realm: String,
    user_id: String,
    username: String,
    role_name: String,
    role_id: String,
}

async fn revoke_access(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<RevokeForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session, &state).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    // Prevent self-lockout
    if form.username == current_user.username && form.role_name == state.config.role_admin {
        session.insert(FLASH_KEY, Flash::warning("You cannot revoke your own admin access.")).await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
        return Ok(Redirect::to(&format!("/admin?realm={}", form.realm)));
    }

    // Look up role ID from name (template passes empty role_id)
    let role = if form.role_id.is_empty() {
        let roles = state.provider.list_realm_roles(&form.realm).await?;
        roles.into_iter().find(|r| r.name == form.role_name)
            .ok_or_else(|| AppError::NotFound(format!("role {}", form.role_name)))?
    } else {
        crate::provider::Role {
            id: form.role_id.clone(), name: form.role_name.clone(),
            description: None, client_role: false,
        }
    };
    crate::routes::audit_failure(
        &state,
        state.provider.remove_realm_role(&form.realm, &form.user_id, &role).await,
        &current_user.username, "revoke_access", &form.realm, Some(&form.username),
    ).await?;

    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "revoke_access".into(),
        target_realm: form.realm.clone(), target_user: Some(form.username.clone()),
        detail: format!("revoked '{}' from {}", form.role_name, form.username),
        outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::warning(
        format!("Access revoked for {}.", form.username)
    )).await.map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/admin?realm={}", form.realm)))
}
