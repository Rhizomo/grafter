mod auth;
mod config;
mod error;
mod provider;
mod routes;
mod service;
mod session;
mod storage;

use anyhow::Result;
use axum::Router;
use reqwest::Client;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tera::Tera;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::SameSite, SessionManagerLayer};
use fred::clients::RedisPool;
use tower_sessions_redis_store::{fred::prelude::*, RedisStore};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth::JwksCache;
use config::Config;
use provider::{keycloak::KeycloakProvider, IdentityProvider};
use storage::{s3::S3Storage, ChangeStorage};

pub type EmergencyLimiter = Arc<Mutex<HashMap<String, Vec<Instant>>>>;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub provider: Arc<dyn IdentityProvider>,
    pub storage: Arc<dyn ChangeStorage>,
    pub tera: Arc<Tera>,
    pub http: Client,
    pub jwks: Arc<JwksCache>,
    pub redis: RedisPool,
    pub emergency_limiter: EmergencyLimiter,
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

    let tera = Arc::new(Tera::new("templates/**/*.html")?);

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
        emergency_limiter: Arc::new(Mutex::new(HashMap::new())),
    };

    let is_https = config.oidc_redirect_uri.starts_with("https://");
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(is_https)
        .with_http_only(true)
        .with_same_site(SameSite::Lax);

    let app = Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .merge(routes::router(state))
        .layer(session_layer);

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("grafter listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
