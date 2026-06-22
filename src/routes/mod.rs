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
    session::{SessionUser, SESSION_KEY},
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
    state.storage.list_changes().await.ok()
        .map(|cs| cs.iter().filter(|c| c.status == crate::storage::ChangeStatus::Pending).count())
        .unwrap_or(0)
}

pub async fn require_session(session: &Session) -> Result<SessionUser, AppError> {
    session
        .get::<SessionUser>(SESSION_KEY)
        .await
        .map_err(|_| AppError::Unauthenticated)?
        .ok_or(AppError::Unauthenticated)
}

pub async fn require_admin(session: &Session) -> Result<SessionUser, AppError> {
    let user = require_session(session).await?;
    if !user.role.is_admin() {
        return Err(AppError::Forbidden);
    }
    Ok(user)
}
