use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    auth::{csrf_tokens_equal, new_csrf_token},
    error::AppError,
    provider::{CreateUser, ListUsersQuery},
    routes::{require_admin, require_session},
    session::{Flash, FLASH_KEY},
    storage::{AuditEntry, AuditOutcome, ChangeStatus, FieldChange},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/users", get(list_users))
        .route("/users/bulk-edit", post(bulk_edit))
        .route("/users/new", get(new_user_form).post(create_user))
        .route("/users/:realm/:id", get(user_detail))
        .route("/users/:realm/:id/edit", post(edit_user))
        .route("/users/:realm/:id/roles/assign", post(assign_role))
        .route("/users/:realm/:id/roles/remove", post(remove_role))
        .route("/users/:realm/:id/set-password", post(set_user_password))
}

async fn index(session: Session) -> Result<impl IntoResponse, AppError> {
    match session
        .get::<crate::session::SessionUser>(crate::session::SESSION_KEY)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
    {
        Some(_) => Ok(Redirect::to("/users")),
        None => Ok(Redirect::to("/auth/login")),
    }
}

#[derive(Deserialize)]
struct ListQuery {
    realm: Option<String>,
    search: Option<String>,
}

async fn list_users(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session).await?;

    let realms = state.provider.list_realms().await?;
    let realm = q
        .realm
        .clone()
        .unwrap_or_else(|| realms.first().map(|r| r.name.clone()).unwrap_or_default());

    let mut lq = ListUsersQuery::new().page(0, 500);
    if let Some(ref s) = q.search {
        lq = lq.search(s);
    }

    let users = state.provider.list_users(&realm, &lq).await?;

    // Collect unique teams for the filter dropdown
    let mut teams: Vec<String> = users
        .iter()
        .filter_map(|u| u.team().map(|t| t.to_string()))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    teams.sort();

    let csrf = new_csrf_token();
    session
        .insert("csrf", &csrf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    // Attach realm to each user for the template (users don't carry realm)
    #[derive(Serialize)]
    struct UserWithRealm<'a> {
        #[serde(flatten)]
        inner: &'a crate::provider::User,
        realm: &'a str,
    }
    let users_with_realm: Vec<UserWithRealm> =
        users.iter().map(|u| UserWithRealm { inner: u, realm: &realm }).collect();

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "users");
    ctx.insert("realms", &realms);
    ctx.insert("current_realm", &realm);
    ctx.insert("users", &users_with_realm);
    ctx.insert("teams", &teams);
    ctx.insert("search", &q.search);
    ctx.insert("csrf", &csrf);

    let html = state
        .tera
        .render("users.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

// ── Bulk edit ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BulkUser {
    id: String,
    realm: String,
}

#[derive(Deserialize)]
struct BulkEditBody {
    csrf_token: String,
    users: Vec<BulkUser>,
    enabled: Option<bool>,
    team: Option<String>,
}

async fn bulk_edit(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<BulkEditBody>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&body.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    for u in &body.users {
        if let Some(enabled) = body.enabled {
            state.provider.set_user_enabled(&u.realm, &u.id, enabled).await?;
        }
        if let Some(ref team) = body.team {
            state.provider.set_user_attribute(&u.realm, &u.id, "team", team).await?;
        }
    }

    state
        .storage
        .append_audit(&AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            actor: current_user.username.clone(),
            action: "bulk_edit".into(),
            target_realm: body.users.first().map(|u| u.realm.clone()).unwrap_or_default(),
            target_user: None,
            detail: format!(
                "{} users affected — enabled={:?} team={:?}",
                body.users.len(), body.enabled, body.team
            ),
            outcome: AuditOutcome::Success,
        })
        .await
        .map_err(AppError::Internal)?;

    Ok(axum::http::StatusCode::OK)
}

// ── User detail ───────────────────────────────────────────────────────────────

async fn user_detail(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session).await?;

    let user = state.provider.get_user(&realm, &id).await?;
    let groups = state.provider.get_user_groups(&realm, &id).await?;
    let roles = state.provider.get_user_realm_roles(&realm, &id).await?;
    let all_groups = state.provider.list_groups(&realm).await?;
    let all_roles = state.provider.list_realm_roles(&realm).await?;

    let realm_users = state.provider.list_users(&realm, &ListUsersQuery::new().page(0, 500)).await?;
    let mut teams: Vec<String> = realm_users
        .iter()
        .filter_map(|u| u.team().map(|t| t.to_string()))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    teams.sort();

    let pending = state
        .storage
        .list_changes()
        .await
        .map_err(AppError::Internal)?
        .into_iter()
        .filter(|c| c.user_id == id && c.status == ChangeStatus::Pending)
        .collect::<Vec<_>>();

    let csrf = new_csrf_token();
    session
        .insert("csrf", &csrf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    // Roles not yet assigned
    let assigned_ids: std::collections::HashSet<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    let available_roles: Vec<_> = all_roles.iter().filter(|r| !assigned_ids.contains(r.id.as_str())).collect();

    let flash: Option<Flash> = session
        .remove(FLASH_KEY)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "users");
    ctx.insert("realm", &realm);
    ctx.insert("subject", &user);
    ctx.insert("groups", &groups);
    ctx.insert("roles", &roles);
    ctx.insert("all_groups", &all_groups);
    ctx.insert("available_roles", &available_roles);
    ctx.insert("pending", &pending);
    ctx.insert("teams", &teams);
    ctx.insert("csrf", &csrf);
    ctx.insert("flash", &flash);

    let html = state
        .tera
        .render("user.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

// ── Edit user ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EditForm {
    csrf_token: String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    enabled: Option<String>,
    team: Option<String>,
    phone_number: Option<String>,
    personnel_code: Option<String>,
}

async fn edit_user(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
    Form(form): Form<EditForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let existing = state.provider.get_user(&realm, &id).await?;
    let mut diff = Vec::new();

    if form.first_name.as_deref() != existing.first_name.as_deref() {
        if let Some(v) = &form.first_name {
            diff.push(FieldChange { field: "first_name".into(), before: existing.first_name.clone(), after: v.clone() });
        }
    }
    if form.last_name.as_deref() != existing.last_name.as_deref() {
        if let Some(v) = &form.last_name {
            diff.push(FieldChange { field: "last_name".into(), before: existing.last_name.clone(), after: v.clone() });
        }
    }
    if form.email.as_deref() != existing.email.as_deref() {
        if let Some(v) = &form.email {
            diff.push(FieldChange { field: "email".into(), before: existing.email.clone(), after: v.clone() });
        }
    }

    let enabled_val = form.enabled.as_deref() == Some("on");
    if enabled_val != existing.enabled {
        diff.push(FieldChange { field: "enabled".into(), before: Some(existing.enabled.to_string()), after: enabled_val.to_string() });
    }

    let current_team = existing.team().map(|s| s.to_string());
    if form.team.as_deref() != current_team.as_deref() {
        if let Some(v) = &form.team {
            diff.push(FieldChange { field: "team".into(), before: current_team, after: v.clone() });
        }
    }

    let current_phone = existing.attributes.get("phoneNumber").and_then(|v| v.first()).cloned();
    let new_phone = form.phone_number.as_ref().filter(|s| !s.is_empty());
    if new_phone.map(|s| s.as_str()) != current_phone.as_deref() {
        if let Some(v) = new_phone {
            diff.push(FieldChange { field: "phone_number".into(), before: current_phone, after: v.clone() });
        }
    }

    let current_personnel = existing.attributes.get("personnelCode").and_then(|v| v.first()).cloned();
    let new_personnel = form.personnel_code.as_ref().filter(|s| !s.is_empty());
    if new_personnel.map(|s| s.as_str()) != current_personnel.as_deref() {
        if let Some(v) = new_personnel {
            diff.push(FieldChange { field: "personnel_code".into(), before: current_personnel, after: v.clone() });
        }
    }

    if diff.is_empty() {
        return Ok(Redirect::to(&format!("/users/{realm}/{id}")));
    }

    let flash = crate::service::users::propose_or_apply(
        &current_user.role,
        &*state.provider,
        &*state.storage,
        crate::service::users::EditRequest {
            realm: &realm,
            user_id: &id,
            username: &existing.username,
            actor: &current_user.username,
            diff,
        },
    )
    .await?;

    session.insert(FLASH_KEY, flash).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/users/{realm}/{id}")))
}

// ── New user ──────────────────────────────────────────────────────────────────

async fn new_user_form(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session).await?;

    let realms = state.provider.list_realms().await?;
    let realm = q.realm.clone()
        .unwrap_or_else(|| realms.first().map(|r| r.name.clone()).unwrap_or_default());

    let users = state.provider.list_users(&realm, &ListUsersQuery::new().page(0, 500)).await?;
    let mut teams: Vec<String> = users
        .iter()
        .filter_map(|u| u.team().map(|t| t.to_string()))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    teams.sort();

    let csrf = new_csrf_token();
    session.insert("csrf", &csrf).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "users");
    ctx.insert("realms", &realms);
    ctx.insert("current_realm", &realm);
    ctx.insert("teams", &teams);
    ctx.insert("csrf", &csrf);

    let html = state.tera.render("new_user.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

#[derive(Deserialize)]
struct NewUserForm {
    csrf_token: String,
    realm: String,
    username: String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    team: Option<String>,
    phone_number: Option<String>,
    personnel_code: Option<String>,
    password: Option<String>,
    password_temporary: Option<String>,
    enabled: Option<String>,
}

async fn create_user(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<NewUserForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let mut attrs = std::collections::HashMap::new();
    if let Some(ref team) = form.team {
        if !team.is_empty() {
            attrs.insert("team".to_string(), vec![team.clone()]);
        }
    }

    let password = form.password.filter(|p| !p.is_empty());
    let password_temporary = form.password_temporary.as_deref() == Some("on");

    let new_user = CreateUser {
        username: form.username.clone(),
        email: form.email.filter(|e| !e.is_empty()),
        first_name: form.first_name.filter(|f| !f.is_empty()),
        last_name: form.last_name.filter(|l| !l.is_empty()),
        enabled: form.enabled.as_deref() == Some("on"),
        password,
        password_temporary,
        phone_number: form.phone_number.filter(|v| !v.is_empty()),
        personnel_code: form.personnel_code.filter(|v| !v.is_empty()),
        attributes: attrs,
    };

    let created = state.provider.create_user(&form.realm, new_user).await?;

    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "create_user".into(),
        target_realm: form.realm.clone(), target_user: Some(form.username.clone()),
        detail: "user created".into(), outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::success(format!("User {} created.", form.username))).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/users/{}/{}", form.realm, created.id)))
}

// ── Role assign / remove ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RoleAssignForm {
    csrf_token: String,
    role_id: String,
}

async fn assign_role(
    State(state): State<AppState>,
    session: Session,
    Path((realm, user_id)): Path<(String, String)>,
    Form(form): Form<RoleAssignForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let all_roles = state.provider.list_realm_roles(&realm).await?;
    let role = all_roles.into_iter()
        .find(|r| r.id == form.role_id)
        .ok_or_else(|| AppError::NotFound(format!("role {}", form.role_id)))?;

    state.provider.assign_realm_role(&realm, &user_id, &role).await?;

    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "assign_role".into(),
        target_realm: realm.clone(), target_user: Some(user_id.clone()),
        detail: format!("role '{}' assigned", role.name), outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::success(format!("Role '{}' assigned.", role.name))).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/users/{realm}/{user_id}")))
}

#[derive(Deserialize)]
struct RoleRemoveForm {
    csrf_token: String,
    role_id: String,
    role_name: String,
}

async fn remove_role(
    State(state): State<AppState>,
    session: Session,
    Path((realm, user_id)): Path<(String, String)>,
    Form(form): Form<RoleRemoveForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let role = crate::provider::Role {
        id: form.role_id.clone(),
        name: form.role_name.clone(),
        description: None,
        client_role: false,
    };

    state.provider.remove_realm_role(&realm, &user_id, &role).await?;

    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "remove_role".into(),
        target_realm: realm.clone(), target_user: Some(user_id.clone()),
        detail: format!("role '{}' removed", form.role_name), outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::success(format!("Role '{}' removed.", form.role_name))).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/users/{realm}/{user_id}")))
}

// ── Set password ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SetPasswordForm {
    csrf_token: String,
    password: String,
    temporary: Option<String>,
}

async fn set_user_password(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
    Form(form): Form<SetPasswordForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    if form.password.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!("password cannot be empty")));
    }

    let temporary = form.temporary.as_deref() == Some("on");
    state.provider.set_user_password(&realm, &id, &form.password, temporary).await?;

    let user = state.provider.get_user(&realm, &id).await?;
    let label = if temporary { "temporary password" } else { "password" };
    state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(), timestamp: Utc::now(),
        actor: current_user.username.clone(), action: "set_password".into(),
        target_realm: realm.clone(), target_user: Some(user.username.clone()),
        detail: format!("{label} set"), outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    session.insert(FLASH_KEY, Flash::success(format!("Password updated for {}.", user.username))).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/users/{realm}/{id}")))
}
