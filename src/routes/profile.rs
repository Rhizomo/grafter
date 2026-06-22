use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use tower_sessions::Session;

use crate::{
    error::AppError,
    provider::ListUsersQuery,
    routes::{pending_changes_count, require_session},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/profile", get(show_profile))
}

async fn show_profile(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_session(&session).await?;

    // Derive realm from OIDC issuer: ".../realms/{realm}"
    let realm = state.config.oidc_issuer
        .split("/realms/")
        .nth(1)
        .unwrap_or("smartech")
        .to_string();

    // Look up the full user record by username
    let users = state.provider.list_users(
        &realm,
        &ListUsersQuery::new().search(&current_user.username),
    ).await?;

    let subject = users.into_iter()
        .find(|u| u.username == current_user.username)
        .ok_or_else(|| AppError::NotFound(format!("user {}", current_user.username)))?;

    let (roles, groups) = tokio::try_join!(
        state.provider.get_user_realm_roles(&realm, &subject.id),
        state.provider.get_user_groups(&realm, &subject.id),
    )?;

    let pending_count = if current_user.role.is_admin() {
        pending_changes_count(&state).await
    } else {
        0
    };

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &current_user.role.is_admin());
    ctx.insert("active_tab", "profile");
    ctx.insert("subject", &subject);
    ctx.insert("roles", &roles);
    ctx.insert("groups", &groups);
    ctx.insert("realm", &realm);
    ctx.insert("pending_count", &pending_count);

    let html = state.tera.render("profile.html", &ctx)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("template error: {e}")))?;

    Ok(Html(html))
}
