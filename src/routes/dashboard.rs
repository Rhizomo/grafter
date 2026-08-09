use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use serde::Serialize;
use tower_sessions::Session;

use crate::{
    error::AppError,
    provider::ListUsersQuery,
    routes::{pending_changes_count, require_session, users::load_team_groups},
    storage::ChangeStatus,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/dashboard", get(dashboard))
}

#[derive(Serialize)]
struct TeamCount {
    name: String,
    count: usize,
}

#[derive(Serialize)]
struct AttentionUser {
    id: String,
    realm: String,
    username: String,
    full_name: String,
    reason: &'static str,
}

async fn dashboard(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session, &state).await?;
    let is_admin = current_user.role.is_admin();

    let realm = state.config.oidc_issuer.rsplit('/').next().unwrap_or("smartech").to_string();

    let users = state
        .provider
        .list_users(&realm, &ListUsersQuery::new().page(0, 2000))
        .await?;

    let total = users.len();
    let active = users.iter().filter(|u| u.enabled).count();
    let disabled = total - active;

    // Attention list: accounts whose state looks unfinished or inconsistent.
    // "No team" means nobody has placed them in the org yet; "disabled but
    // still in a team" is an offboarding that was only half-completed.
    let mut attention: Vec<AttentionUser> = Vec::new();
    for u in &users {
        let has_team = u.team().map(|t| !t.is_empty()).unwrap_or(false);
        let reason = if u.enabled && !has_team {
            Some("No team assigned")
        } else if !u.enabled && has_team {
            Some("Disabled but still in a team")
        } else {
            None
        };
        if let Some(reason) = reason {
            attention.push(AttentionUser {
                id: u.id.clone(),
                realm: realm.clone(),
                username: u.username.clone(),
                full_name: u.full_name(),
                reason,
            });
        }
    }
    attention.sort_by(|a, b| a.username.cmp(&b.username));
    let attention_total = attention.len();
    attention.truncate(10);

    // Team breakdown, largest first — only teams that actually have members.
    let team_groups = load_team_groups(&state, &realm).await?;
    let mut teams: Vec<TeamCount> = team_groups
        .iter()
        .map(|g| TeamCount {
            name: g.name.clone(),
            count: users.iter().filter(|u| u.team() == Some(g.name.as_str())).count(),
        })
        .filter(|t| t.count > 0)
        .collect();
    teams.sort_by(|a, b| b.count.cmp(&a.count));

    // Request states. An operator only ever sees their own proposals, matching
    // what the changes queue shows them.
    let mut changes = state.storage.list_changes().await.map_err(AppError::Internal)?;
    if !is_admin {
        changes.retain(|c| c.proposed_by == current_user.username);
    }
    let pending = changes.iter().filter(|c| c.status == ChangeStatus::Pending).count();
    let approved = changes.iter().filter(|c| c.status == ChangeStatus::Approved).count();
    let rejected = changes.iter().filter(|c| c.status == ChangeStatus::Rejected).count();

    // Activity feed is admin-only — it exposes what everyone else has been
    // doing, which isn't an operator's business.
    let recent_audit = if is_admin {
        let mut entries = state.storage.list_audit(None).await.map_err(AppError::Internal)?;
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(12);
        entries
    } else {
        Vec::new()
    };

    let pending_count = if is_admin { pending_changes_count(&state).await } else { 0 };

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &is_admin);
    ctx.insert("active_tab", "dashboard");
    ctx.insert("realm", &realm);
    ctx.insert("total_users", &total);
    ctx.insert("active_users", &active);
    ctx.insert("disabled_users", &disabled);
    ctx.insert("attention", &attention);
    ctx.insert("attention_total", &attention_total);
    ctx.insert("teams", &teams);
    ctx.insert("req_pending", &pending);
    ctx.insert("req_approved", &approved);
    ctx.insert("req_rejected", &rejected);
    ctx.insert("recent_audit", &recent_audit);
    ctx.insert("pending_count", &pending_count);

    let html = state
        .tera
        .render("dashboard.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}
