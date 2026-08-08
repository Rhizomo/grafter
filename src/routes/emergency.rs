use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use fred::interfaces::KeysInterface;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    auth::csrf_tokens_equal,
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

    // Feature gate
    let Some(ref expected) = state.config.emergency_token else {
        tracing::warn!(%ip, "emergency promote: rejected — feature disabled");
        return deny("disabled");
    };

    // Rate limit: 3 attempts per IP per hour, tracked in Redis so it holds
    // across replicas/restarts instead of a per-process in-memory map.
    let rl_key = format!("grafter:emergency-rl:{ip}");
    let attempts: i64 = match state.redis.incr(&rl_key).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(%ip, error = %e, "emergency promote: redis rate-limit error");
            return err("rate limit check failed");
        }
    };
    if attempts == 1 {
        let _ = state.redis.expire::<i64, _>(&rl_key, 3600).await;
    }
    if attempts > 3 {
        tracing::warn!(%ip, "emergency promote: rate limited");
        return deny("rate limited");
    }

    // Verify token (constant-time to prevent timing attacks)
    if !csrf_tokens_equal(&body.token, expected) {
        tracing::warn!(%ip, username = %body.username, "emergency promote: invalid token");
        return deny("forbidden");
    }

    tracing::warn!(%ip, username = %body.username, "emergency promote: valid token — promoting to admin");

    let realm = state.config.oidc_issuer
        .split("/realms/").nth(1).unwrap_or("smartech").to_string();

    // Look up user
    let users = match state.provider.list_users(&realm, &ListUsersQuery::new().search(&body.username)).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(%ip, error = %e, "emergency promote: user lookup error");
            return err("user lookup failed");
        }
    };
    let target = match users.into_iter().find(|u| u.username == body.username) {
        Some(u) => u,
        None => {
            tracing::warn!(%ip, username = %body.username, "emergency promote: user not found");
            return (StatusCode::NOT_FOUND, Json(Resp { ok: false, error: Some("user not found") }));
        }
    };

    // Find admin role
    let roles = match state.provider.list_realm_roles(&realm).await {
        Ok(r) => r,
        Err(e) => { tracing::error!(%ip, error = %e, "emergency promote: list roles error"); return err("role lookup failed"); }
    };
    let admin_role = match roles.into_iter().find(|r| r.name == state.config.role_admin) {
        Some(r) => r,
        None => { tracing::error!(%ip, "emergency promote: admin role not found"); return err("admin role not found"); }
    };

    // Assign
    if let Err(e) = state.provider.assign_realm_role(&realm, &target.id, &admin_role).await {
        tracing::error!(%ip, error = %e, "emergency promote: assign role error");
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

    tracing::warn!(%ip, username = %body.username, "emergency promote: promoted to admin successfully");
    ok()
}
