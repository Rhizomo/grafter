use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
    DecodingKey, Validation,
};
use rand::Rng;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::session::{Role, SessionUser};

// ── JWKS cache ────────────────────────────────────────────────────────────────

struct JwksEntry {
    jwks: JwkSet,
    fetched_at: Instant,
}

pub struct JwksCache {
    client: Client,
    jwks_url: String,
    issuer: String,
    cache: Arc<RwLock<Option<JwksEntry>>>,
}

impl JwksCache {
    pub fn new(client: Client, issuer: &str) -> Self {
        let jwks_url = format!("{}/protocol/openid-connect/certs", issuer);
        Self {
            client,
            jwks_url,
            issuer: issuer.to_string(),
            cache: Arc::new(RwLock::new(None)),
        }
    }

    async fn fetch_jwks(&self) -> Result<JwkSet> {
        let jwks: JwkSet = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .context("failed to fetch JWKS")?
            .json()
            .await
            .context("failed to parse JWKS")?;
        Ok(jwks)
    }

    async fn get_jwks(&self) -> Result<JwkSet> {
        {
            let cache = self.cache.read().await;
            if let Some(entry) = &*cache {
                if entry.fetched_at.elapsed() < Duration::from_secs(3600) {
                    // Re-serialize to get owned value (JwkSet isn't Clone)
                    let raw = serde_json::to_value(&entry.jwks)?;
                    return Ok(serde_json::from_value(raw)?);
                }
            }
        }

        let jwks = self.fetch_jwks().await?;
        let raw = serde_json::to_value(&jwks)?;
        *self.cache.write().await = Some(JwksEntry {
            jwks,
            fetched_at: Instant::now(),
        });
        Ok(serde_json::from_value(raw)?)
    }

    pub async fn verify_and_decode(&self, token: &str) -> Result<Value> {
        let header = decode_header(token).context("bad JWT header")?;
        let kid = header.kid.as_deref().unwrap_or("");

        let jwks = self.get_jwks().await?;
        let jwk = jwks
            .find(kid)
            .or_else(|| {
                // kid might be empty — try first key
                jwks.keys.first()
            })
            .ok_or_else(|| anyhow::anyhow!("no matching JWK for kid '{kid}'"))?;

        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                .context("bad RSA key components")?,
            AlgorithmParameters::EllipticCurve(ec) => {
                DecodingKey::from_ec_components(&ec.x, &ec.y)
                    .context("bad EC key components")?
            }
            other => anyhow::bail!("unsupported JWK algorithm: {:?}", other),
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        // Keycloak access tokens use the realm URL as issuer and don't
        // always include the client_id as audience, so we skip aud validation
        // here. The issuer check is the important one.
        validation.validate_aud = false;

        let data = decode::<Value>(token, &decoding_key, &validation)
            .context("JWT verification failed")?;

        Ok(data.claims)
    }

    /// Re-fetch JWKS after a key-not-found error (handles key rotation).
    pub async fn verify_and_decode_with_refresh(&self, token: &str) -> Result<Value> {
        match self.verify_and_decode(token).await {
            Ok(claims) => Ok(claims),
            Err(_) => {
                // Force refresh and retry once
                *self.cache.write().await = None;
                self.verify_and_decode(token).await
            }
        }
    }
}

// ── OIDC helpers ──────────────────────────────────────────────────────────────

pub fn authorization_url(config: &Config, state: &str, nonce: &str) -> String {
    format!(
        "{}/protocol/openid-connect/auth\
         ?response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &scope=openid+profile+email\
         &state={}\
         &nonce={}",
        config.oidc_issuer,
        urlencoding::encode(&config.oidc_client_id),
        urlencoding::encode(&config.oidc_redirect_uri),
        state,
        nonce,
    )
}

pub fn logout_url(config: &Config) -> String {
    // post_logout_redirect_uri must be registered in Keycloak.
    // We redirect to /auth/login (the app's own login page), derived from
    // oidc_redirect_uri by stripping the path and appending the login path.
    let base = config
        .oidc_redirect_uri
        .find("://")
        .and_then(|i| config.oidc_redirect_uri[i + 3..].find('/').map(|j| &config.oidc_redirect_uri[..i + 3 + j]))
        .unwrap_or(&config.oidc_redirect_uri);
    let login_uri = format!("{}/auth/login", base);
    format!(
        "{}/protocol/openid-connect/logout?client_id={}&post_logout_redirect_uri={}",
        config.oidc_issuer,
        urlencoding::encode(&config.oidc_client_id),
        urlencoding::encode(&login_uri),
    )
}

pub fn random_string() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    #[allow(dead_code)]
    pub refresh_token: Option<String>,
}

/// Extract the nonce claim from an ID token without re-verifying the signature.
/// Safe because we use the nonce only to detect replay — the access_token is
/// what we actually trust for identity.
pub fn nonce_from_id_token(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub async fn exchange_code(
    client: &Client,
    config: &Config,
    code: &str,
) -> Result<TokenResponse> {
    let token_url = format!("{}/protocol/openid-connect/token", config.oidc_issuer);

    let resp = client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &config.oidc_client_id),
            ("client_secret", &config.oidc_client_secret),
            ("redirect_uri", &config.oidc_redirect_uri),
            ("code", code),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("token exchange failed ({status}): {body}");
    }

    Ok(resp.json::<TokenResponse>().await?)
}

pub async fn session_user_from_token(
    token: &str,
    config: &Config,
    jwks: &JwksCache,
) -> Result<SessionUser> {
    let claims = jwks
        .verify_and_decode_with_refresh(token)
        .await
        .context("token verification failed")?;

    let sub = claims["sub"].as_str().unwrap_or("").to_string();
    let username = claims
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .unwrap_or(&sub)
        .to_string();
    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let realm_roles: Vec<String> = claims
        .get("realm_access")
        .and_then(|v| v.get("roles"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let role = Role::from_claims(&realm_roles, &config.role_admin, &config.role_operator)
        .ok_or_else(|| anyhow::anyhow!("user has no grafter role assigned"))?;

    Ok(SessionUser {
        sub,
        username,
        email,
        role,
    })
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

/// Generate a random CSRF token.
pub fn new_csrf_token() -> String {
    random_string()
}

/// Constant-time comparison to prevent timing attacks.
pub fn csrf_tokens_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
