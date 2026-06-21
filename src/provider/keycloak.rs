use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    AppClient, CreateUser, Group, IdentityProvider, ListUsersQuery, ProviderResult, Realm, Role,
    UpdateAppClient, UpdateUser, User,
};
use crate::error::ProviderError;

fn parse_kc_error(status: u16, body: String) -> ProviderError {
    if status == 409 {
        let msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["errorMessage"].as_str().map(String::from))
            .unwrap_or_else(|| "A resource with that identifier already exists.".to_string());
        return ProviderError::Conflict(msg);
    }
    if status == 400 {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            let msg = v["errorMessage"].as_str().map(String::from)
                .or_else(|| v["error_description"].as_str().map(String::from));
            if let Some(m) = msg {
                let field = v["field"].as_str().map(|f| format!("Field \"{f}\": "));
                return ProviderError::Validation(format!("{}{m}", field.unwrap_or_default()));
            }
        }
    }
    ProviderError::UnexpectedResponse { status, body }
}

// ── Token cache ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct TokenCache {
    token: Option<String>,
    expires_at: Option<std::time::Instant>,
}

// ── Keycloak Admin API client ─────────────────────────────────────────────────

pub struct KeycloakProvider {
    client: Client,
    admin_url: String,
    admin_realm: String,
    client_id: String,
    client_secret: String,
    token_cache: Arc<RwLock<TokenCache>>,
}

impl KeycloakProvider {
    pub fn new(
        admin_url: impl Into<String>,
        admin_realm: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            admin_url: admin_url.into(),
            admin_realm: admin_realm.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            token_cache: Arc::new(RwLock::new(TokenCache::default())),
        }
    }

    async fn admin_token(&self) -> ProviderResult<String> {
        {
            let cache = self.token_cache.read().await;
            if let (Some(token), Some(exp)) = (&cache.token, cache.expires_at) {
                if std::time::Instant::now() < exp {
                    return Ok(token.clone());
                }
            }
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let url = format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.admin_url, self.admin_realm
        );

        let resp = self
            .client
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::UnexpectedResponse { status, body });
        }

        let tr: TokenResponse = resp.json().await?;

        let expires_at = std::time::Instant::now()
            + std::time::Duration::from_secs(tr.expires_in.saturating_sub(30));

        let mut cache = self.token_cache.write().await;
        cache.token = Some(tr.access_token.clone());
        cache.expires_at = Some(expires_at);

        Ok(tr.access_token)
    }

    fn admin_url(&self, realm: &str) -> String {
        format!("{}/admin/realms/{}", self.admin_url, realm)
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
    ) -> ProviderResult<T> {
        let token = self.admin_token().await?;
        let resp = self.client.get(url).bearer_auth(&token).send().await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(ProviderError::NotFound);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::UnexpectedResponse { status, body });
        }

        Ok(resp.json().await?)
    }

    async fn post(&self, url: &str, body: &serde_json::Value) -> ProviderResult<reqwest::Response> {
        let token = self.admin_token().await?;
        let resp = self
            .client
            .post(url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(parse_kc_error(status, text));
        }

        Ok(resp)
    }

    async fn put(&self, url: &str, body: &serde_json::Value) -> ProviderResult<()> {
        let token = self.admin_token().await?;
        let resp = self
            .client
            .put(url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(parse_kc_error(status, text));
        }

        Ok(())
    }

    async fn delete(&self, url: &str) -> ProviderResult<()> {
        let token = self.admin_token().await?;
        let resp = self.client.delete(url).bearer_auth(&token).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(parse_kc_error(status, text));
        }

        Ok(())
    }
}

// ── Keycloak-specific response shapes ─────────────────────────────────────────

#[derive(Deserialize)]
struct KcRealm {
    id: String,
    realm: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct KcUser {
    id: Option<String>,
    username: String,
    email: Option<String>,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    enabled: Option<bool>,
    attributes: Option<HashMap<String, Vec<String>>>,
}

#[derive(Deserialize)]
struct KcGroup {
    id: String,
    name: String,
    path: String,
    #[serde(rename = "subGroups", default)]
    sub_groups: Vec<KcGroup>,
}

#[derive(Deserialize, Serialize, Clone)]
struct KcRole {
    id: String,
    name: String,
    description: Option<String>,
    #[serde(rename = "clientRole", default)]
    client_role: bool,
}

fn kc_user_to_user(u: KcUser) -> User {
    User {
        id: u.id.unwrap_or_default(),
        username: u.username,
        email: u.email,
        first_name: u.first_name,
        last_name: u.last_name,
        enabled: u.enabled.unwrap_or(false),
        attributes: u.attributes.unwrap_or_default(),
    }
}

fn kc_group_to_group(g: KcGroup) -> Group {
    Group {
        id: g.id,
        name: g.name,
        path: g.path,
        subgroups: g.sub_groups.into_iter().map(kc_group_to_group).collect(),
    }
}

fn kc_role_to_role(r: KcRole) -> Role {
    Role {
        id: r.id,
        name: r.name,
        description: r.description,
        client_role: r.client_role,
    }
}

// ── Keycloak client representation ───────────────────────────────────────────

#[derive(Deserialize, Serialize)]
struct KcClientRep {
    id: Option<String>,
    #[serde(rename = "clientId")]
    client_id: String,
    name: Option<String>,
    description: Option<String>,
    #[serde(default = "bool_true")]
    enabled: bool,
    #[serde(rename = "publicClient", default)]
    public_client: bool,
    #[serde(rename = "redirectUris", default)]
    redirect_uris: Vec<String>,
    #[serde(rename = "webOrigins", default)]
    web_origins: Vec<String>,
    protocol: Option<String>,
    #[serde(rename = "serviceAccountsEnabled", default)]
    service_accounts_enabled: bool,
}

fn bool_true() -> bool { true }

fn kc_client_to_client(c: KcClientRep) -> Option<AppClient> {
    Some(AppClient {
        id: c.id?,
        client_id: c.client_id,
        name: c.name,
        description: c.description,
        enabled: c.enabled,
        public_client: c.public_client,
        redirect_uris: c.redirect_uris,
        web_origins: c.web_origins,
        protocol: c.protocol,
        service_accounts_enabled: c.service_accounts_enabled,
    })
}

// ── IdentityProvider impl ─────────────────────────────────────────────────────

#[async_trait]
impl IdentityProvider for KeycloakProvider {
    fn name(&self) -> &'static str {
        "keycloak"
    }

    async fn list_realms(&self) -> ProviderResult<Vec<Realm>> {
        // GET /admin/realms requires master-realm admin. A realm-scoped service
        // account can only read its own realm via /admin/realms/{realm}.
        let url = format!("{}/admin/realms/{}", self.admin_url, self.admin_realm);
        let r: KcRealm = self.get(&url).await?;
        Ok(vec![Realm {
            id: r.id,
            name: r.realm,
            display_name: r.display_name,
        }])
    }

    async fn list_users(&self, realm: &str, query: &ListUsersQuery) -> ProviderResult<Vec<User>> {
        let mut url = format!(
            "{}/users?first={}&max={}",
            self.admin_url(realm),
            query.offset,
            query.max
        );
        if let Some(q) = &query.search {
            url.push_str(&format!("&search={}", urlencoding::encode(q)));
        }
        let users: Vec<KcUser> = self.get(&url).await?;
        Ok(users.into_iter().map(kc_user_to_user).collect())
    }

    async fn get_user(&self, realm: &str, id: &str) -> ProviderResult<User> {
        let url = format!("{}/users/{}", self.admin_url(realm), id);
        let u: KcUser = self.get(&url).await?;
        Ok(kc_user_to_user(u))
    }

    async fn create_user(&self, realm: &str, user: CreateUser) -> ProviderResult<User> {
        let url = format!("{}/users", self.admin_url(realm));

        let body = json!({
            "username": user.username,
            "email": user.email,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "enabled": user.enabled,
            "attributes": user.attributes,
            "credentials": user.temporary_password.map(|p| vec![json!({
                "type": "password",
                "value": p,
                "temporary": true
            })]).unwrap_or_default(),
        });

        let resp = self.post(&url, &body).await?;

        // Keycloak returns the new user's URL in the Location header.
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ProviderError::UnexpectedResponse {
                status: 201,
                body: "Keycloak did not return a Location header after user creation".into(),
            })?;

        let id = location
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ProviderError::UnexpectedResponse {
                status: 201,
                body: format!("could not extract user ID from Location header: {location}"),
            })?
            .to_string();

        self.get_user(realm, &id).await
    }

    async fn update_user(&self, realm: &str, id: &str, update: UpdateUser) -> ProviderResult<()> {
        let url = format!("{}/users/{}", self.admin_url(realm), id);

        // Keycloak's declarative user profile validates ALL required fields on
        // every PUT, even for partial updates. Fetch current and merge so we
        // always send a complete representation.
        let cur = self.get_user(realm, id).await?;
        let mut body = serde_json::Map::new();
        body.insert("firstName".into(), json!(update.first_name.or(cur.first_name).unwrap_or_default()));
        body.insert("lastName".into(),  json!(update.last_name.or(cur.last_name).unwrap_or_default()));
        body.insert("email".into(),     json!(update.email.or(cur.email).unwrap_or_default()));
        body.insert("enabled".into(),   json!(update.enabled.unwrap_or(cur.enabled)));
        body.insert("attributes".into(), json!(update.attributes.unwrap_or(cur.attributes)));

        self.put(&url, &serde_json::Value::Object(body)).await
    }

    async fn set_user_enabled(&self, realm: &str, id: &str, enabled: bool) -> ProviderResult<()> {
        self.update_user(realm, id, UpdateUser { enabled: Some(enabled), ..Default::default() })
            .await
    }

    async fn set_user_attribute(
        &self,
        realm: &str,
        id: &str,
        key: &str,
        value: &str,
    ) -> ProviderResult<()> {
        let mut user = self.get_user(realm, id).await?;
        user.attributes
            .insert(key.to_string(), vec![value.to_string()]);

        self.update_user(
            realm,
            id,
            UpdateUser {
                attributes: Some(user.attributes),
                ..Default::default()
            },
        )
        .await
    }

    async fn set_user_password(&self, realm: &str, id: &str, password: &str, temporary: bool) -> ProviderResult<()> {
        let url = format!("{}/users/{}/reset-password", self.admin_url(realm), id);
        self.put(&url, &json!({
            "type": "password",
            "value": password,
            "temporary": temporary
        })).await
    }

    async fn delete_user(&self, realm: &str, id: &str) -> ProviderResult<()> {
        let url = format!("{}/users/{}", self.admin_url(realm), id);
        self.delete(&url).await
    }

    async fn list_groups(&self, realm: &str) -> ProviderResult<Vec<Group>> {
        let url = format!("{}/groups", self.admin_url(realm));
        let groups: Vec<KcGroup> = self.get(&url).await?;
        Ok(groups.into_iter().map(kc_group_to_group).collect())
    }

    async fn get_user_groups(&self, realm: &str, user_id: &str) -> ProviderResult<Vec<Group>> {
        let url = format!("{}/users/{}/groups", self.admin_url(realm), user_id);
        let groups: Vec<KcGroup> = self.get(&url).await?;
        Ok(groups.into_iter().map(kc_group_to_group).collect())
    }

    async fn add_user_to_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> ProviderResult<()> {
        let url = format!(
            "{}/users/{}/groups/{}",
            self.admin_url(realm),
            user_id,
            group_id
        );
        self.put(&url, &serde_json::Value::Object(Default::default()))
            .await
    }

    async fn remove_user_from_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> ProviderResult<()> {
        let url = format!(
            "{}/users/{}/groups/{}",
            self.admin_url(realm),
            user_id,
            group_id
        );
        self.delete(&url).await
    }

    async fn list_realm_roles(&self, realm: &str) -> ProviderResult<Vec<Role>> {
        let url = format!("{}/roles", self.admin_url(realm));
        let roles: Vec<KcRole> = self.get(&url).await?;
        Ok(roles.into_iter().map(kc_role_to_role).collect())
    }

    async fn get_user_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> ProviderResult<Vec<Role>> {
        let url = format!(
            "{}/users/{}/role-mappings/realm",
            self.admin_url(realm),
            user_id
        );
        let roles: Vec<KcRole> = self.get(&url).await?;
        Ok(roles.into_iter().map(kc_role_to_role).collect())
    }

    async fn assign_realm_role(
        &self,
        realm: &str,
        user_id: &str,
        role: &Role,
    ) -> ProviderResult<()> {
        let url = format!(
            "{}/users/{}/role-mappings/realm",
            self.admin_url(realm),
            user_id
        );
        let body = json!([{"id": role.id, "name": role.name}]);
        self.post(&url, &body).await?;
        Ok(())
    }

    async fn remove_realm_role(
        &self,
        realm: &str,
        user_id: &str,
        role: &Role,
    ) -> ProviderResult<()> {
        let token = self.admin_token().await?;
        let url = format!(
            "{}/users/{}/role-mappings/realm",
            self.admin_url(realm),
            user_id
        );
        let body = json!([{"id": role.id, "name": role.name}]);
        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::UnexpectedResponse { status, body });
        }
        Ok(())
    }

    // ── Clients ───────────────────────────────────────────────────────────────

    async fn list_clients(&self, realm: &str) -> ProviderResult<Vec<AppClient>> {
        let url = format!("{}/clients?max=200", self.admin_url(realm));
        let clients: Vec<KcClientRep> = self.get(&url).await?;
        Ok(clients.into_iter().filter_map(kc_client_to_client).collect())
    }

    async fn get_client(&self, realm: &str, id: &str) -> ProviderResult<AppClient> {
        let url = format!("{}/clients/{}", self.admin_url(realm), id);
        let c: KcClientRep = self.get(&url).await?;
        kc_client_to_client(c).ok_or(ProviderError::NotFound)
    }

    async fn update_client(&self, realm: &str, id: &str, update: UpdateAppClient) -> ProviderResult<()> {
        let url = format!("{}/clients/{}", self.admin_url(realm), id);
        let mut current: serde_json::Value = self.get(&url).await?;
        if let Some(v) = update.enabled        { current["enabled"]      = json!(v); }
        if let Some(v) = update.redirect_uris  { current["redirectUris"] = json!(v); }
        if let Some(v) = update.web_origins    { current["webOrigins"]   = json!(v); }
        self.put(&url, &current).await
    }

    async fn get_client_secret(&self, realm: &str, id: &str) -> ProviderResult<Option<String>> {
        let url = format!("{}/clients/{}/client-secret", self.admin_url(realm), id);
        #[derive(Deserialize)]
        struct SecretResp { value: Option<String> }
        match self.get::<SecretResp>(&url).await {
            Ok(s)                        => Ok(s.value),
            Err(ProviderError::NotFound) => Ok(None),
            Err(e)                       => Err(e),
        }
    }
}
