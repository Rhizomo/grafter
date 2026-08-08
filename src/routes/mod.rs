pub mod admin;
pub mod audit;
pub mod auth;
pub mod changes;
pub mod clients;
pub mod emergency;
pub mod profile;
pub mod teams;
pub mod users;

use axum::{routing::get, Router};
use tower_sessions::Session;

use crate::{
    error::AppError,
    session::{Role, SessionUser, SESSION_KEY},
    AppState,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(auth::router())
        .merge(admin::router())
        .merge(audit::router())
        .merge(emergency::router())
        .merge(profile::router())
        .merge(users::router())
        .merge(changes::router())
        .merge(teams::router())
        .merge(clients::router())
        .with_state(state)
}

pub async fn pending_changes_count(state: &crate::AppState) -> usize {
    state.storage.list_pending_changes().await.ok()
        .map(|cs| cs.len())
        .unwrap_or(0)
}

// Re-checks the session's role against Keycloak on every call, using the
// same effective (group/composite-inclusive) role set the login token was
// built from. This means a role revoked in Keycloak takes effect immediately
// instead of only at the next login — the session cache is refreshed here,
// not trusted.
pub async fn require_session(session: &Session, state: &AppState) -> Result<SessionUser, AppError> {
    let mut user = session
        .get::<SessionUser>(SESSION_KEY)
        .await
        .map_err(|_| AppError::Unauthenticated)?
        .ok_or(AppError::Unauthenticated)?;

    let realm = state.config.oidc_issuer.rsplit('/').next().unwrap_or("smartech");
    let roles = state
        .provider
        .get_user_effective_realm_roles(realm, &user.sub)
        .await
        .map_err(AppError::Provider)?;
    let names: Vec<String> = roles.into_iter().map(|r| r.name).collect();

    let Some(fresh_role) = Role::from_claims(&names, &state.config.role_admin, &state.config.role_operator) else {
        // Role was revoked in Keycloak since login — end the session now
        // rather than letting the cached role keep working until logout.
        let _ = session.flush().await;
        return Err(AppError::Forbidden);
    };

    if fresh_role != user.role {
        user.role = fresh_role;
        session
            .insert(SESSION_KEY, &user)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
    }

    Ok(user)
}

pub async fn require_admin(session: &Session, state: &AppState) -> Result<SessionUser, AppError> {
    let user = require_session(session, state).await?;
    if !user.role.is_admin() {
        return Err(AppError::Forbidden);
    }
    Ok(user)
}
