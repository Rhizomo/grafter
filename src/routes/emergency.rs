use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Instant};
use uuid::Uuid;

use crate::{
    provider::ListUsersQuery,
    storage::{AuditEntry, AuditOutcome},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/emergency/promote", post(emergency_promote))
}

#[derive(Deserialize)]
struct Req {
    token: String,
    username: String,
}

#[derive(Serialize)]
struct Resp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

fn ok() -> (StatusCode, Json<Resp>) {
    (StatusCode::OK, Json(Resp { ok: true, error: None }))
}
fn deny(msg: &'static str) -> (StatusCode, Json<Resp>) {
    (StatusCode::FORBIDDEN, Json(Resp { ok: false, error: Some(msg) }))
}
fn err(msg: &'static str) -> (StatusCode, Json<Resp>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(Resp { ok: false, error: Some(msg) }))
}

pub async fn emergency_promote(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<Req>,
) -> (StatusCode, Json<Resp>) {
    let ip = addr.ip().to_string();
    let ts = Utc::now().to_rfc3339();

    // Feature gate
    let Some(ref expected) = state.config.emergency_token else {
        eprintln!("[{ts}] emergency/{ip}: rejected — feature disabled");
        return deny("disabled");
    };

    // Rate limit: 3 attempts per IP per hour
    {
        let mut map = state.emergency_limiter.lock().unwrap();
        let attempts = map.entry(ip.clone()).or_default();
        attempts.retain(|t: &Instant| t.elapsed().as_secs() < 3600);
        if attempts.len() >= 3 {
            eprintln!("[{ts}] emergency/{ip}: rate limited");
            return deny("rate limited");
        }
        attempts.push(Instant::now());
    }

    // Verify token
    if body.token != *expected {
        eprintln!("[{ts}] emergency/{ip}: invalid token for username='{}'", body.username);
        return deny("forbidden");
    }

    eprintln!("[{ts}] emergency/{ip}: VALID — promoting '{}' to admin", body.username);

    let realm = state.config.oidc_issuer
        .split("/realms/").nth(1).unwrap_or("smartech").to_string();

    // Look up user
    let users = match state.provider.list_users(&realm, &ListUsersQuery::new().search(&body.username)).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("[{ts}] emergency/{ip}: user lookup error: {e}");
            return err("user lookup failed");
        }
    };
    let target = match users.into_iter().find(|u| u.username == body.username) {
        Some(u) => u,
        None => {
            eprintln!("[{ts}] emergency/{ip}: user '{}' not found", body.username);
            return (StatusCode::NOT_FOUND, Json(Resp { ok: false, error: Some("user not found") }));
        }
    };

    // Find admin role
    let roles = match state.provider.list_realm_roles(&realm).await {
        Ok(r) => r,
        Err(e) => { eprintln!("[{ts}] emergency/{ip}: list roles error: {e}"); return err("role lookup failed"); }
    };
    let admin_role = match roles.into_iter().find(|r| r.name == state.config.role_admin) {
        Some(r) => r,
        None => { eprintln!("[{ts}] emergency/{ip}: admin role not found"); return err("admin role not found"); }
    };

    // Assign
    if let Err(e) = state.provider.assign_realm_role(&realm, &target.id, &admin_role).await {
        eprintln!("[{ts}] emergency/{ip}: assign role error: {e}");
        return err("role assignment failed");
    }

    // Audit
    let _ = state.storage.append_audit(&AuditEntry {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        actor: "SYSTEM".into(),
        action: "emergency_promote".into(),
        target_realm: realm,
        target_user: Some(body.username.clone()),
        detail: format!("break-glass: promoted '{}' to admin from {}", body.username, ip),
        outcome: AuditOutcome::Success,
    }).await;

    eprintln!("[{ts}] emergency/{ip}: '{}' promoted to admin successfully", body.username);
    ok()
}
