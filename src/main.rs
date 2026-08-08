mod auth;
mod config;
mod error;
mod provider;
mod routes;
mod service;
mod session;
mod storage;

use anyhow::Result;
use axum::{
    http::{header, HeaderValue},
    Router,
};
use reqwest::Client;
use std::{net::SocketAddr, sync::Arc};
use tera::Tera;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use tower_sessions::{cookie::SameSite, SessionManagerLayer};
use fred::clients::RedisPool;
use tower_sessions_redis_store::{fred::prelude::*, RedisStore};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth::JwksCache;
use config::Config;
use provider::{keycloak::KeycloakProvider, IdentityProvider};
use storage::{s3::S3Storage, ChangeStorage};

// Field names on a PendingChange diff are internal keys ("first_name",
// "team_group_id") — the Changes page shows these to HR/admins, so they
// need a plain-English label instead of a code identifier.
fn humanize_field_filter(
    value: &tera::Value,
    _args: &std::collections::HashMap<String, tera::Value>,
) -> tera::Result<tera::Value> {
    let field = value.as_str().unwrap_or_default();
    let label = match field {
        "first_name" => "First name",
        "last_name" => "Last name",
        "email" => "Email",
        "enabled" => "Account enabled",
        "team" | "team_group_id" => "Team",
        "phone_number" => "Phone number",
        "personnel_code" => "Personnel code",
        "status_reason" => "Reason",
        other => return Ok(tera::Value::String(other.to_string())),
    };
    Ok(tera::Value::String(label.to_string()))
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub provider: Arc<dyn IdentityProvider>,
    pub storage: Arc<dyn ChangeStorage>,
    pub tera: Arc<Tera>,
    pub http: Client,
    pub jwks: Arc<JwksCache>,
    pub redis: RedisPool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(Config::from_env());

    let http = Client::new();

    let provider = Arc::new(KeycloakProvider::new(
        &config.kc_admin_url,
        &config.kc_admin_realm,
        &config.kc_admin_client_id,
        &config.kc_admin_client_secret,
    ));

    let storage = Arc::new(S3Storage::new(
        &config.s3_endpoint,
        &config.s3_bucket,
        &config.s3_access_key,
        &config.s3_secret_key,
    )?);

    let mut tera_inner = Tera::new("templates/**/*.html")?;
    tera_inner.register_filter("humanize_field", humanize_field_filter);
    let tera = Arc::new(tera_inner);

    let jwks = Arc::new(JwksCache::new(http.clone(), &config.oidc_issuer));

    let redis_cfg = RedisConfig::from_url(&config.redis_url)
        .expect("invalid REDIS_URL");
    let redis_pool = RedisPool::new(redis_cfg, None, None, None, 6)
        .expect("failed to create Redis pool");
    redis_pool.connect();
    redis_pool.wait_for_connect().await
        .expect("failed to connect to Redis");
    let session_store = RedisStore::new(redis_pool.clone());

    let state = AppState {
        config: config.clone(),
        provider,
        storage,
        tera,
        http,
        jwks,
        redis: redis_pool,
    };

    let is_https = config.oidc_redirect_uri.starts_with("https://");
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(is_https)
        .with_http_only(true)
        .with_same_site(SameSite::Lax);

    // Every dynamic page is session/role-specific — never let a browser or
    // intermediary proxy cache and replay one across a role change or
    // between users. Static assets under /static are unaffected.
    let dynamic = routes::router(state).layer(SetResponseHeaderLayer::overriding(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    ));

    let app = Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .merge(dynamic)
        .layer(session_layer);

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("grafter listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
