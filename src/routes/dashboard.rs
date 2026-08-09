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
    pct: f64,
    color: &'static str,
}

// Percentages and segment colours are computed here rather than in the
// template so the view can't divide by zero on an empty realm or depend on
// fragile expression support.
const TEAM_COLORS: &[&str] = &[
    "#00bfa5", "#00e676", "#64b5f6", "#ffb74d", "#ff8a65",
    "#ba68c8", "#4db6ac", "#aed581", "#7986cb", "#f06292",
];

fn pct_of(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (count as f64) * 100.0 / (total as f64)
    }
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

    let mut users = state
        .provider
        .list_users(&realm, &ListUsersQuery::new().page(0, 2000))
        .await?;

    // Service accounts (monitoring/alerting logins) aren't people — counting
    // them would inflate headcount and, since they have no team, permanently
    // park them in the attention list where nobody can action them.
    let service_ids: std::collections::HashSet<String> = {
        let groups = state.provider.list_groups(&realm).await?;
        match groups.iter().find(|g| g.name == "service-accounts") {
            Some(g) => state
                .provider
                .list_group_members(&realm, &g.id)
                .await
                .map(|members| members.into_iter().map(|u| u.id).collect())
                .unwrap_or_default(),
            None => Default::default(),
        }
    };
    users.retain(|u| !service_ids.contains(&u.id));

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

    // Team breakdown over *active* people only. Including disabled accounts
    // would swamp the split — most of them predate teams and would show up as
    // one huge "no team" block that nobody intends to act on.
    let team_groups = load_team_groups(&state, &realm).await?;
    let mut teams: Vec<TeamCount> = team_groups
        .iter()
        .map(|g| {
            let count = users
                .iter()
                .filter(|u| u.enabled && u.team() == Some(g.name.as_str()))
                .count();
            TeamCount { name: g.name.clone(), count, pct: pct_of(count, active), color: "" }
        })
        .filter(|t| t.count > 0)
        .collect();
    teams.sort_by(|a, b| b.count.cmp(&a.count));
    for (i, t) in teams.iter_mut().enumerate() {
        t.color = TEAM_COLORS[i % TEAM_COLORS.len()];
    }

    let teamless = active.saturating_sub(teams.iter().map(|t| t.count).sum::<usize>());

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
    ctx.insert("active_pct", &pct_of(active, total));
    ctx.insert("disabled_pct", &pct_of(disabled, total));
    ctx.insert("teamless", &teamless);
    ctx.insert("teamless_pct", &pct_of(teamless, active));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{AuditEntry, AuditOutcome};
    use chrono::Utc;

    // Tera reports missing fields and bad filter usage at render time, not
    // when templates are parsed at boot — so exercise an actual render of the
    // most data-heavy page for both roles.
    fn render_with(is_admin: bool, total: usize, attention_total: usize) -> Result<String, tera::Error> {
        let tera = tera::Tera::new("templates/**/*.html").expect("templates should parse");

        let mut ctx = tera::Context::new();
        ctx.insert("user", &serde_json::json!({ "username": "someone@smartech.ir", "role": "admin" }));
        ctx.insert("is_admin", &is_admin);
        ctx.insert("active_tab", "dashboard");
        ctx.insert("realm", "smartech");
        ctx.insert("total_users", &total);
        ctx.insert("active_users", &total);
        ctx.insert("disabled_users", &0usize);
        ctx.insert("active_pct", &pct_of(total, total));
        ctx.insert("disabled_pct", &0.0f64);
        ctx.insert("teamless", &1usize);
        ctx.insert("teamless_pct", &pct_of(1, total.max(1)));
        // Mirrors the route: the list is empty exactly when the total is zero.
        let attention: Vec<AttentionUser> = if attention_total == 0 {
            Vec::new()
        } else {
            vec![AttentionUser {
                id: "u1".into(), realm: "smartech".into(),
                username: "a@smartech.ir".into(), full_name: "A Person".into(),
                reason: "No team assigned",
            }]
        };
        ctx.insert("attention", &attention);
        ctx.insert("attention_total", &attention_total);
        ctx.insert("teams", &vec![TeamCount {
            name: "devops".into(), count: 3, pct: 50.0, color: "#00bfa5",
        }]);
        ctx.insert("req_pending", &1usize);
        ctx.insert("req_approved", &2usize);
        ctx.insert("req_rejected", &0usize);
        ctx.insert("recent_audit", &vec![
            AuditEntry {
                id: "a1".into(), timestamp: Utc::now(), actor: "admin@smartech.ir".into(),
                action: "assign_role".into(), target_realm: "smartech".into(),
                target_user: Some("b@smartech.ir".into()), detail: "ok".into(),
                outcome: AuditOutcome::Success,
            },
            // A failure entry must render too — its outcome serialises as an
            // object rather than a plain string.
            AuditEntry {
                id: "a2".into(), timestamp: Utc::now(), actor: "SYSTEM".into(),
                action: "emergency_promote".into(), target_realm: "smartech".into(),
                target_user: None, detail: "boom".into(),
                outcome: AuditOutcome::Failure("boom".into()),
            },
        ]);
        ctx.insert("pending_count", &1usize);

        tera.render("dashboard.html", &ctx)
    }

    #[test]
    fn renders_for_admin() {
        let html = render_with(true, 6, 1).expect("admin dashboard should render");
        assert!(html.contains("Latest activity"), "admin should see the activity feed");
        assert!(html.contains("failed"), "a failed audit entry should be marked");
    }

    #[test]
    fn renders_for_operator_without_activity_feed() {
        let html = render_with(false, 6, 1).expect("operator dashboard should render");
        assert!(!html.contains("Latest activity"), "operators must not see the activity feed");
    }

    // An empty realm previously risked a divide-by-zero in the template.
    #[test]
    fn renders_with_no_users_and_nothing_to_fix() {
        let html = render_with(true, 0, 0).expect("empty dashboard should render");
        assert!(html.contains("Nothing to clean up."));
    }

    #[test]
    fn pct_of_is_zero_when_total_is_zero() {
        assert_eq!(pct_of(0, 0), 0.0);
        assert_eq!(pct_of(1, 4), 25.0);
    }
}
