use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Json, Redirect},
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::{
    auth::{csrf_tokens_equal, new_csrf_token},
    error::AppError,
    provider::UpdateAppClient,
    routes::require_admin,
    session::{Flash, FLASH_KEY},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/clients", get(list_clients))
        .route("/clients/:realm/:id", get(client_detail))
        .route("/clients/:realm/:id/edit", post(edit_client))
        .route("/clients/:realm/:id/secret", get(reveal_secret))
}

#[derive(Deserialize)]
struct RealmQuery {
    realm: Option<String>,
}

async fn list_clients(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<RealmQuery>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let realms = state.provider.list_realms().await?;
    let realm = q
        .realm
        .clone()
        .unwrap_or_else(|| realms.first().map(|r| r.name.clone()).unwrap_or_default());

    let clients = state.provider.list_clients(&realm).await?;

    let flash: Option<Flash> = session
        .remove(FLASH_KEY)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &true);
    ctx.insert("active_tab", "clients");
    ctx.insert("realms", &realms);
    ctx.insert("current_realm", &realm);
    ctx.insert("clients", &clients);
    ctx.insert("flash", &flash);

    let html = state
        .tera
        .render("clients.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

async fn client_detail(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = require_admin(&session).await?;

    let client = state.provider.get_client(&realm, &id).await?;

    let csrf = new_csrf_token();
    session
        .insert("csrf", &csrf)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let flash: Option<Flash> = session
        .remove(FLASH_KEY)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    let mut ctx = tera::Context::new();
    ctx.insert("user", &current_user);
    ctx.insert("is_admin", &true);
    ctx.insert("active_tab", "clients");
    ctx.insert("realm", &realm);
    ctx.insert("client", &client);
    ctx.insert("csrf", &csrf);
    ctx.insert("flash", &flash);

    let html = state
        .tera
        .render("client.html", &ctx)
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Html(html))
}

#[derive(Deserialize)]
struct EditClientForm {
    csrf_token: String,
    enabled: Option<String>,
    redirect_uris: Option<String>,
    web_origins: Option<String>,
}

async fn edit_client(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
    Form(form): Form<EditClientForm>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&session).await?;

    let session_csrf: String = session
        .get("csrf")
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?
        .ok_or(AppError::CsrfMismatch)?;

    if !csrf_tokens_equal(&form.csrf_token, &session_csrf) {
        return Err(AppError::CsrfMismatch);
    }

    let parse_lines = |s: &str| -> Vec<String> {
        s.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };

    let update = UpdateAppClient {
        enabled:       form.enabled.as_deref().map(|v| v == "on"),
        redirect_uris: form.redirect_uris.as_deref().map(parse_lines),
        web_origins:   form.web_origins.as_deref().map(parse_lines),
    };

    state.provider.update_client(&realm, &id, update).await?;

    session
        .insert(FLASH_KEY, Flash::success("Client settings saved."))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("session error: {e}")))?;

    Ok(Redirect::to(&format!("/clients/{realm}/{id}")))
}

#[derive(Serialize)]
struct SecretResponse {
    secret: Option<String>,
}

async fn reveal_secret(
    State(state): State<AppState>,
    session: Session,
    Path((realm, id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&session).await?;
    let secret = state.provider.get_client_secret(&realm, &id).await?;
    Ok(Json(SecretResponse { secret }))
}
