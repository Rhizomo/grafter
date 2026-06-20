pub mod auth;
pub mod changes;
pub mod clients;
pub mod users;

use axum::Router;
use tower_sessions::Session;

use crate::{
    error::AppError,
    session::{SessionUser, SESSION_KEY},
    AppState,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(auth::router())
        .merge(users::router())
        .merge(changes::router())
        .merge(clients::router())
        .with_state(state)
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
