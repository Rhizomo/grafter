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
    provider::{CreateUser, Group, ListUsersQuery},
    routes::{pending_changes_count, require_admin, require_session},
    session::{Flash, FLASH_KEY},
    storage::{AuditEntry, AuditOutcome, FieldChange},
    AppState,
};

// ── Realm helpers ─────────────────────────────────────────────────────────────

/// The realm operators are allowed to work in — derived from OIDC issuer.
fn operator_realm(state: &AppState) -> &str {
    state.config.oidc_issuer.rsplit('/').next().unwrap_or("smartech")
}

/// Returns Err(Forbidden) if a non-admin tries to access a realm they don't own.
fn check_realm_access(state: &AppState, current_user: &crate::session::SessionUser, realm: &str) -> Result<(), AppError> {
    if !current_user.role.is_admin() && realm != operator_realm(state) {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

// ── Team group helpers ────────────────────────────────────────────────────────

async fn load_team_groups(state: &AppState, realm: &str) -> Result<Vec<Group>, AppError> {
    let mut groups = state.provider.list_groups(realm).await?;
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(groups)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/users", get(list_users))
        .route("/users/check-similar", get(check_similar))
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
    let current_user = require_session(&session, &state).await?;

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
    let team_groups = load_team_groups(&state, &realm).await?;
    let pending_count = if current_user.role.is_admin() { pending_changes_count(&state).await } else { 0 };

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
    ctx.insert("team_groups", &team_groups);
    ctx.insert("search", &q.search);
    ctx.insert("pending_count", &pending_count);
    ctx.insert("csrf", &csrf);

    let html = state
        .tera
        .render("users.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

// ── Duplicate-person check ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SimilarQuery {
    realm: String,
    q: String,
}

#[derive(Serialize)]
struct SimilarUser {
    id: String,
    realm: String,
    username: String,
    full_name: String,
}

// Warns whoever is creating a user if a similarly-named account already
// exists — a real recurring mistake here (two "maryam.f*" accounts got
// mixed up for real), not a hypothetical. Both roles get this: it's a
// safety net, not a privilege, so there's no reason to restrict it to admins.
async fn check_similar(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<SimilarQuery>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session, &state).await?;
    check_realm_access(&state, &current_user, &q.realm)?;

    if q.q.trim().chars().count() < 2 {
        return Ok(Json(Vec::<SimilarUser>::new()));
    }

    let users = state.provider.list_users(&q.realm, &ListUsersQuery::new().search(q.q.trim())).await?;
    let matches: Vec<SimilarUser> = users.into_iter().take(5).map(|u| SimilarUser {
        id: u.id.clone(),
        realm: q.realm.clone(),
        username: u.username.clone(),
        full_name: u.full_name(),
    }).collect();

    Ok(Json(matches))
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
    team_group_id: Option<String>,
}

async fn bulk_edit(
    State(state): State<AppState>,
    session: Session,
    Json(body): Json<BulkEditBody>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session, &state).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&body.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    for u in &body.users {
        check_realm_access(&state, &current_user, &u.realm)?;
    }

    // Resolve team group once (all users assumed to be in same realm)
    let realm = body.users.first().map(|u| u.realm.as_str()).unwrap_or("");
    let all_groups = if body.team_group_id.as_deref().is_some_and(|g| !g.is_empty()) {
        state.provider.list_groups(realm).await?
    } else {
        Vec::new()
    };
    let team_assignment: Option<(String, String)> = match &body.team_group_id {
        Some(gid) if !gid.is_empty() => {
            all_groups.iter().find(|g| g.id == *gid).map(|g| (g.id.clone(), g.name.clone()))
        }
        _ => None,
    };

    if current_user.role.is_admin() {
        for u in &body.users {
            if let Some(enabled) = body.enabled {
                state.provider.set_user_enabled(&u.realm, &u.id, enabled).await?;
            }
            if let Some((ref gid, ref name)) = team_assignment {
                // Remove from any existing team group first
                let user_groups = state.provider.get_user_groups(&u.realm, &u.id).await?;
                for ug in &user_groups {
                    if all_groups.iter().any(|g| g.id == ug.id) && ug.id != *gid {
                        state.provider.remove_user_from_group(&u.realm, &u.id, &ug.id).await?;
                    }
                }
                state.provider.add_user_to_group(&u.realm, &u.id, gid).await?;
                state.provider.set_user_attribute(&u.realm, &u.id, "team", name).await?;
            }
        }

        state
            .storage
            .append_audit(&AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                actor: current_user.username.clone(),
                action: "bulk_edit".into(),
                target_realm: realm.to_string(),
                target_user: None,
                detail: format!(
                    "{} users affected — enabled={:?} team={:?}",
                    body.users.len(), body.enabled, body.team_group_id
                ),
                outcome: AuditOutcome::Success,
            })
            .await
            .map_err(AppError::Internal)?;
    } else {
        // Operators can't change access directly — each user's change is
        // queued for admin approval, same granularity as a single edit.
        for u in &body.users {
            let existing = state.provider.get_user(&u.realm, &u.id).await?;
            let mut diff = Vec::new();

            if let Some(enabled) = body.enabled {
                if enabled != existing.enabled {
                    diff.push(FieldChange {
                        field: "enabled".into(),
                        before: Some(existing.enabled.to_string()),
                        after: enabled.to_string(),
                    });
                }
            }
            if let Some((ref gid, ref name)) = team_assignment {
                diff.push(FieldChange { field: "team_group_id".into(), before: None, after: gid.clone() });
                diff.push(FieldChange { field: "team".into(), before: None, after: name.clone() });
            }

            if diff.is_empty() {
                continue;
            }

            crate::service::users::propose_or_apply(
                &current_user.role,
                &*state.provider,
                &*state.storage,
                crate::service::users::EditRequest {
                    realm: &u.realm,
                    user_id: &u.id,
                    username: &existing.username,
                    actor: &current_user.username,
                    diff,
                },
            )
            .await?;
        }
    }

    Ok(axum::http::StatusCode::OK)
}

// ── User detail ───────────────────────────────────────────────────────────────

async fn user_detail(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session, &state).await?;
    check_realm_access(&state, &current_user, &realm)?;

    let user = state.provider.get_user(&realm, &id).await?;
    let groups = state.provider.get_user_groups(&realm, &id).await?;
    let roles = state.provider.get_user_realm_roles(&realm, &id).await?;
    let all_groups = state.provider.list_groups(&realm).await?;
    let all_roles = state.provider.list_realm_roles(&realm).await?;

    let team_groups = load_team_groups(&state, &realm).await?;
    // Find which team group this user currently belongs to
    let current_team_group_id: Option<String> = groups.iter()
        .find(|g| team_groups.iter().any(|tg| tg.id == g.id))
        .map(|g| g.id.clone());

    let pending = state
        .storage
        .list_pending_changes()
        .await
        .map_err(AppError::Internal)?
        .into_iter()
        .filter(|c| c.user_id == id)
        .collect::<Vec<_>>();

    let csrf = new_csrf_token();
    session
        .insert("csrf", &csrf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    // Roles not yet assigned — sorted alphabetically
    let assigned_ids: std::collections::HashSet<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    let mut available_roles: Vec<_> = all_roles.iter().filter(|r| !assigned_ids.contains(r.id.as_str())).collect();
    available_roles.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

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
    let pending_count = if current_user.role.is_admin() { pending_changes_count(&state).await } else { 0 };
    ctx.insert("pending", &pending);
    ctx.insert("team_groups", &team_groups);
    ctx.insert("current_team_group_id", &current_team_group_id);
    ctx.insert("pending_count", &pending_count);
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
    status_reason: Option<String>,
    team_group_id: Option<String>,
    phone_number: Option<String>,
    personnel_code: Option<String>,
}

async fn edit_user(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
    Form(form): Form<EditForm>,
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

    check_realm_access(&state, &current_user, &realm)?;

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
        // Only meaningful alongside a status change — captures *why*, since
        // "disabled" alone tells a future reader nothing (leave? terminated?
        // mistake?).
        if let Some(reason) = form.status_reason.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            diff.push(FieldChange { field: "status_reason".into(), before: None, after: reason.to_string() });
        }
    }

    // Team assignment — same diff/proposal flow as every other field now
    // (used to be admin-only and applied outside the diff, which silently
    // dropped an operator's team choice and, if it was the *only* change,
    // also silently dropped an admin's).
    let user_groups = state.provider.get_user_groups(&realm, &id).await?;
    let team_groups = load_team_groups(&state, &realm).await?;
    let old_team_group_id = user_groups.iter()
        .find(|g| team_groups.iter().any(|tg| tg.id == g.id))
        .map(|g| g.id.clone());
    let new_team_group_id = form.team_group_id.as_deref().filter(|s| !s.is_empty());

    if new_team_group_id != old_team_group_id.as_deref() {
        let team_name = new_team_group_id
            .and_then(|gid| team_groups.iter().find(|g| g.id == gid))
            .map(|g| g.name.clone())
            .unwrap_or_default();
        diff.push(FieldChange {
            field: "team_group_id".into(),
            before: old_team_group_id.clone(),
            after: new_team_group_id.unwrap_or("").to_string(),
        });
        diff.push(FieldChange {
            field: "team".into(),
            before: None,
            after: team_name,
        });
    }

    let current_phone = existing.attributes.get("phone_number").and_then(|v| v.first()).cloned();
    let new_phone = form.phone_number.as_deref().unwrap_or("");
    if new_phone != current_phone.as_deref().unwrap_or("") {
        diff.push(FieldChange { field: "phone_number".into(), before: current_phone, after: new_phone.to_string() });
    }

    let current_personnel = existing.attributes.get("personnel_code").and_then(|v| v.first()).cloned();
    let new_personnel = form.personnel_code.as_deref().unwrap_or("");
    if new_personnel != current_personnel.as_deref().unwrap_or("") {
        diff.push(FieldChange { field: "personnel_code".into(), before: current_personnel, after: new_personnel.to_string() });
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
    let current_user = require_session(&session, &state).await?;

    let realms = state.provider.list_realms().await?;
    let realm = if current_user.role.is_admin() {
        q.realm.clone().unwrap_or_else(|| realms.first().map(|r| r.name.clone()).unwrap_or_default())
    } else {
        operator_realm(&state).to_string()
    };

    let team_groups = load_team_groups(&state, &realm).await?;

    let csrf = new_csrf_token();
    session.insert("csrf", &csrf).await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "users");
    ctx.insert("realms", &realms);
    ctx.insert("current_realm", &realm);
    ctx.insert("team_groups", &team_groups);
    let pending_count = if current_user.role.is_admin() { pending_changes_count(&state).await } else { 0 };
    ctx.insert("pending_count", &pending_count);
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
    team_group_id: Option<String>,
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
    let current_user = require_session(&session, &state).await?;

    let session_csrf: String = session.get("csrf").await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;
    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    check_realm_access(&state, &current_user, &form.realm)?;

    // Resolve team group (id + name)
    let team_group: Option<(String, String)> = match &form.team_group_id {
        Some(gid) if !gid.is_empty() => {
            let groups = state.provider.list_groups(&form.realm).await?;
            groups.into_iter().find(|g| g.id == *gid).map(|g| (g.id, g.name))
        }
        _ => None,
    };

    // Both admins and operators create the account directly in KC — a new,
    // disabled-by-default account is low risk. Team assignment is different:
    // it grants access, so an operator's choice of team goes to the approval
    // queue instead of applying immediately; an admin's applies right away.
    let apply_team_immediately = current_user.role.is_admin();

    let mut attrs = std::collections::HashMap::new();
    if apply_team_immediately {
        if let Some((_, ref name)) = team_group {
            attrs.insert("team".to_string(), vec![name.clone()]);
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
        detail: "user created".into(),
        outcome: AuditOutcome::Success,
    }).await.map_err(AppError::Internal)?;

    let mut flash = Flash::success(format!("User {} created.", form.username));

    if let Some((ref gid, ref name)) = team_group {
        if apply_team_immediately {
            state.provider.add_user_to_group(&form.realm, &created.id, gid).await?;
        } else {
            crate::service::users::propose_or_apply(
                &current_user.role,
                &*state.provider,
                &*state.storage,
                crate::service::users::EditRequest {
                    realm: &form.realm,
                    user_id: &created.id,
                    username: &created.username,
                    actor: &current_user.username,
                    diff: vec![
                        FieldChange { field: "team_group_id".into(), before: None, after: gid.clone() },
                        FieldChange { field: "team".into(), before: None, after: name.clone() },
                    ],
                },
            )
            .await?;
            flash = Flash::success(format!(
                "User {} created. Team assignment sent for admin approval.",
                form.username
            ));
        }
    }

    session.insert(FLASH_KEY, flash).await
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
    let current_user = require_admin(&session, &state).await?;

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
    let current_user = require_admin(&session, &state).await?;

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
    let current_user = require_admin(&session, &state).await?;

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
