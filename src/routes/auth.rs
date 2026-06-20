use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use serde::Deserialize;
use tower_sessions::Session;

use crate::{
    auth::{
        authorization_url, csrf_tokens_equal, exchange_code, logout_url, nonce_from_id_token,
        random_string, session_user_from_token,
    },
    error::{AppError, AppResult},
    session::SESSION_KEY,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/start", get(start_login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", get(logout))
}

/// Render the login landing page. Linked to by AppError::Unauthorized and
/// by the post-logout redirect from Keycloak.
async fn login(State(state): State<AppState>) -> AppResult<impl IntoResponse> {
    let realm = state
        .config
        .oidc_issuer
        .rsplit('/')
        .next()
        .unwrap_or("your organization")
        .to_string();

    let mut ctx = tera::Context::new();
    ctx.insert("realm", &realm);

    let html = state
        .tera
        .render("login.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

/// Begin the OIDC authorization code flow. Generates state + nonce,
/// stores them in the session, redirects to Keycloak.
async fn start_login(
    State(state): State<AppState>,
    session: Session,
) -> AppResult<impl IntoResponse> {
    let oauth_state = random_string();
    let nonce = random_string();

    session
        .insert("oauth_state", &oauth_state)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
    session
        .insert("oauth_nonce", &nonce)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let url = authorization_url(&state.config, &oauth_state, &nonce);
    Ok(Redirect::to(&url))
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<CallbackParams>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(err) = params.error {
        return Err(AppError::Internal(anyhow::anyhow!("OIDC error: {err}")));
    }

    let code = params.code.ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing code")))?;

    let saved_state: Option<String> = session
        .get("oauth_state")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
    if saved_state.as_deref() != params.state.as_deref() {
        return Err(AppError::Internal(anyhow::anyhow!("state mismatch")));
    }

    let session_nonce: String = session
        .get("oauth_nonce")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing nonce in session")))?;

    let tokens = exchange_code(&state.http, &state.config, &code)
        .await
        .map_err(AppError::Internal)?;

    if let Some(ref id_token) = tokens.id_token {
        let token_nonce = nonce_from_id_token(id_token).unwrap_or_default();
        if !csrf_tokens_equal(&token_nonce, &session_nonce) {
            return Err(AppError::Internal(anyhow::anyhow!(
                "nonce mismatch — possible replay attack"
            )));
        }
    }

    let user = session_user_from_token(&tokens.access_token, &state.config, &state.jwks)
        .await
        .map_err(AppError::Internal)?;

    session
        .remove::<String>("oauth_state")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
    session
        .remove::<String>("oauth_nonce")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;
    session
        .insert(SESSION_KEY, &user)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to("/"))
}

async fn logout(State(state): State<AppState>, session: Session) -> impl IntoResponse {
    if let Err(e) = session.flush().await {
        tracing::warn!(error = %e, "failed to flush session on logout — session may remain active in Redis");
    }
    Redirect::to(&logout_url(&state.config))
}
