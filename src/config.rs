use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,

    // OIDC / Keycloak login
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_uri: String,

    // Keycloak Admin API (service account)
    pub kc_admin_url: String,
    pub kc_admin_realm: String,
    pub kc_admin_client_id: String,
    pub kc_admin_client_secret: String,

    // Roles
    pub role_admin: String,
    pub role_operator: String,

    // Teams
    pub teams_group: String,

    // Storage (MinIO / S3)
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,

    // Session (must be >= 32 bytes)
    pub session_secret: String,
    pub redis_url: String,

    // Break-glass emergency promotion (disabled if not set)
    pub emergency_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env_or("HOST", "0.0.0.0"),
            port: env_or("PORT", "3000").parse().expect("PORT must be a number"),

            oidc_issuer: env_require("OIDC_ISSUER"),
            oidc_client_id: env_require("OIDC_CLIENT_ID"),
            oidc_client_secret: env_require("OIDC_CLIENT_SECRET"),
            oidc_redirect_uri: env_require("OIDC_REDIRECT_URI"),

            kc_admin_url: env_require("KC_ADMIN_URL"),
            kc_admin_realm: env_or("KC_ADMIN_REALM", "master"),
            kc_admin_client_id: env_require("KC_ADMIN_CLIENT_ID"),
            kc_admin_client_secret: env_require("KC_ADMIN_CLIENT_SECRET"),

            role_admin: env_or("IAM_ROLE_ADMIN", "iam-admin"),
            role_operator: env_or("IAM_ROLE_OPERATOR", "iam-operator"),

            teams_group: env_or("TEAMS_GROUP", "teams"),

            s3_endpoint: env_require("S3_ENDPOINT"),
            s3_bucket: env_or("S3_BUCKET", "grafter"),
            s3_access_key: env_require("S3_ACCESS_KEY"),
            s3_secret_key: env_require("S3_SECRET_KEY"),

            session_secret: {
                let s = env_require("SESSION_SECRET");
                assert!(s.len() >= 32, "SESSION_SECRET must be at least 32 bytes");
                s
            },
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),

            emergency_token: env::var("EMERGENCY_TOKEN").ok()
                .filter(|s| !s.is_empty()),
        }
    }
}

fn env_require(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("missing required env var: {key}"))
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
