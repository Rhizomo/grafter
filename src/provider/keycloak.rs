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

// Keycloak's user-profile validation errors come back as machine codes like
// "error-user-attribute-required" with a separate "field" name — surfacing
// those raw to an HR operator is meaningless, so translate the common ones.
fn humanize_field(field: &str) -> String {
    match field {
        "firstName" => "First name".into(),
        "lastName" => "Last name".into(),
        "phone_number" => "Phone number".into(),
        "personnel_code" => "Personnel code".into(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => "This field".into(),
            }
        }
    }
}

// Arabic block plus the Arabic Supplement/Extended ranges Persian draws from.
fn is_arabic_script(c: char) -> bool {
    matches!(c, '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' | '\u{FB50}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}')
}

fn humanize_kc_code(code: &str, field: Option<&str>) -> String {
    let subject = field.map(humanize_field).unwrap_or_else(|| "This field".to_string());

    // Realm admins can attach their own error-message text to a user-profile
    // validator, and it may be written in any language (the phone_number
    // pattern here carries a Persian one). Grafter's UI is English, so rather
    // than passing that straight through, fall back to a message we control.
    // Detect the script rather than testing is_ascii(), so a perfectly good
    // English message containing an em-dash or curly quote isn't discarded.
    if code.chars().any(is_arabic_script) {
        return match field {
            Some("phone_number") => {
                "Phone number must be 11 digits starting with 09 — e.g. 09123456789.".to_string()
            }
            _ => format!("{subject} is not in the expected format."),
        };
    }

    match code {
        "error-user-attribute-required" => format!("{subject} is required."),
        "error-invalid-email" => format!("{subject} must be a valid email address."),
        "error-invalid-length" | "error-invalid-length-too-short" => format!("{subject} is too short."),
        "error-invalid-length-too-long" => format!("{subject} is too long."),
        "error-username-invalid-character"
        | "error-person-name-invalid-character"
        | "error-username-prohibited-character"
        | "error-invalid-value" => format!("{subject} contains characters that aren't allowed."),
        other => format!("{subject}: {other}"),
    }
}

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
            let field = v["field"].as_str();
            let msg = v["errorMessage"].as_str()
                .or_else(|| v["error_description"].as_str());
            if let Some(m) = msg {
                return ProviderError::Validation(humanize_kc_code(m, field));
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
    #[serde(rename = "createdTimestamp")]
    created_timestamp: Option<i64>,
}

#[derive(Deserialize)]
struct KcGroup {
    id: String,
    name: String,
    path: String,
    #[serde(rename = "subGroups", default)]
    sub_groups: Vec<KcGroup>,
    #[serde(rename = "realmRoles", default)]
    realm_roles: Vec<String>,
    // Keycloak's group list returns only a count here, not the children
    // themselves — they have to be fetched per parent.
    #[serde(rename = "subGroupCount", default)]
    sub_group_count: u32,
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
        created_at: u.created_timestamp,
    }
}

fn kc_group_to_group(g: KcGroup) -> Group {
    Group {
        id: g.id,
        name: g.name,
        path: g.path,
        subgroups: g.sub_groups.into_iter().map(kc_group_to_group).collect(),
        realm_roles: g.realm_roles,
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
            "{}/users?briefRepresentation=false&first={}&max={}",
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

        let mut attrs = user.attributes.clone();
        if let Some(ref v) = user.phone_number {
            if !v.is_empty() { attrs.insert("phone_number".to_string(), vec![v.clone()]); }
        }
        if let Some(ref v) = user.personnel_code {
            if !v.is_empty() { attrs.insert("personnel_code".to_string(), vec![v.clone()]); }
        }

        let has_password = user.password.as_ref().map(|p| !p.is_empty()).unwrap_or(false);

        let build_body = |with_creds: bool| -> serde_json::Value {
            let creds = if with_creds && has_password {
                json!([{"type": "password", "value": user.password.as_deref().unwrap_or(""), "temporary": user.password_temporary}])
            } else {
                json!([])
            };
            let required_actions: &[&str] = if !with_creds && user.password_temporary { &["UPDATE_PASSWORD"] } else { &[] };
            json!({
                "username": user.username,
                "email": user.email,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "enabled": user.enabled,
                "attributes": attrs,
                "credentials": creds,
                "requiredActions": required_actions,
            })
        };

        // For temporary passwords: if the realm password policy rejects the value,
        // fall back to creating the user without credentials and require UPDATE_PASSWORD.
        let resp = match self.post(&url, &build_body(true)).await {
            Err(ProviderError::Validation(_)) if has_password && user.password_temporary => {
                self.post(&url, &build_body(false)).await?
            }
            other => other?,
        };

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
        // Merge rather than replace — a partial attributes map (e.g. just
        // "team") must not wipe out other existing attributes like
        // phone_number/personnel_code that weren't part of this update.
        let mut attrs = cur.attributes;
        if let Some(new_attrs) = update.attributes {
            attrs.extend(new_attrs);
        }
        if let Some(ref v) = update.phone_number {
            attrs.insert("phone_number".to_string(), vec![v.clone()]);
        }
        if let Some(ref v) = update.personnel_code {
            attrs.insert("personnel_code".to_string(), vec![v.clone()]);
        }
        body.insert("attributes".into(), json!(attrs));

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

    // Returns top-level groups with their children populated. The list
    // endpoint reports only subGroupCount, so children are fetched per parent
    // that has any — without this, teams nested under a parent (e.g.
    // /adverge/core-services) are invisible to Grafter even though users
    // are assigned to them.
    async fn list_groups(&self, realm: &str) -> ProviderResult<Vec<Group>> {
        let url = format!("{}/groups?briefRepresentation=false", self.admin_url(realm));
        let groups: Vec<KcGroup> = self.get(&url).await?;

        let mut out = Vec::with_capacity(groups.len());
        for g in groups {
            let needs_children = g.sub_group_count > 0 && g.sub_groups.is_empty();
            let id = g.id.clone();
            let mut group = kc_group_to_group(g);
            if needs_children {
                let children_url = format!(
                    "{}/groups/{}/children?briefRepresentation=false",
                    self.admin_url(realm),
                    id
                );
                if let Ok(children) = self.get::<Vec<KcGroup>>(&children_url).await {
                    group.subgroups = children.into_iter().map(kc_group_to_group).collect();
                }
            }
            out.push(group);
        }
        Ok(out)
    }

    async fn get_user_groups(&self, realm: &str, user_id: &str) -> ProviderResult<Vec<Group>> {
        let url = format!("{}/users/{}/groups", self.admin_url(realm), user_id);
        let groups: Vec<KcGroup> = self.get(&url).await?;
        Ok(groups.into_iter().map(kc_group_to_group).collect())
    }

    async fn list_group_members(&self, realm: &str, group_id: &str) -> ProviderResult<Vec<User>> {
        let url = format!("{}/groups/{}/members?max=2000", self.admin_url(realm), group_id);
        let users: Vec<KcUser> = self.get(&url).await?;
        Ok(users.into_iter().map(kc_user_to_user).collect())
    }

    async fn create_group(&self, realm: &str, name: &str, parent_id: Option<&str>) -> ProviderResult<Group> {
        let url = match parent_id {
            Some(pid) => format!("{}/groups/{}/children", self.admin_url(realm), pid),
            None      => format!("{}/groups", self.admin_url(realm)),
        };
        let resp = self.post(&url, &json!({"name": name})).await?;
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ProviderError::UnexpectedResponse { status: 201, body: "no Location header".into() })?;
        let id = location.rsplit('/').next().filter(|s| !s.is_empty())
            .ok_or_else(|| ProviderError::UnexpectedResponse { status: 201, body: format!("bad Location: {location}") })?
            .to_string();
        let path = match parent_id {
            Some(_) => format!("/teams/{name}"),
            None    => format!("/{name}"),
        };
        Ok(Group { id, name: name.to_string(), path, subgroups: vec![], realm_roles: vec![] })
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

    async fn list_role_users(&self, realm: &str, role_name: &str) -> ProviderResult<Vec<User>> {
        let url = format!(
            "{}/roles/{}/users?max=500",
            self.admin_url(realm),
            urlencoding::encode(role_name)
        );
        let users: Vec<KcUser> = self.get(&url).await?;
        Ok(users.into_iter().map(kc_user_to_user).collect())
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

    async fn get_user_effective_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> ProviderResult<Vec<Role>> {
        let url = format!(
            "{}/users/{}/role-mappings/realm/composite",
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

#[cfg(test)]
mod error_message_tests {
    use super::*;

    #[test]
    fn required_field_error_is_readable() {
        let msg = humanize_kc_code("error-user-attribute-required", Some("email"));
        assert_eq!(msg, "Email is required.");
    }

    #[test]
    fn camel_case_field_gets_a_readable_label() {
        let msg = humanize_kc_code("error-user-attribute-required", Some("firstName"));
        assert_eq!(msg, "First name is required.");
    }

    #[test]
    fn unmapped_code_still_names_the_field() {
        let msg = humanize_kc_code("some-future-error-code", Some("username"));
        assert_eq!(msg, "Username: some-future-error-code");
    }

    #[test]
    fn no_field_falls_back_to_generic_subject() {
        let msg = humanize_kc_code("error-user-attribute-required", None);
        assert_eq!(msg, "This field is required.");
    }

    #[test]
    fn parse_kc_error_400_uses_humanized_message() {
        let body = r#"{"field":"email","errorMessage":"error-user-attribute-required"}"#.to_string();
        match parse_kc_error(400, body) {
            ProviderError::Validation(msg) => assert_eq!(msg, "Email is required."),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // The realm's phone_number validator carries a Persian error-message,
    // which must never reach an English-only UI verbatim.
    #[test]
    fn non_english_custom_message_is_replaced_for_phone_number() {
        let msg = humanize_kc_code(
            "شماره موبایل معتبر وارد کنید (مثلاً 09123456789)",
            Some("phone_number"),
        );
        assert!(
            !msg.chars().any(is_arabic_script),
            "message shown to users must not carry through non-English text: {msg}"
        );
        assert!(msg.contains("09"));
    }

    #[test]
    fn non_english_custom_message_falls_back_generically() {
        let msg = humanize_kc_code("مقدار نامعتبر", Some("personnel_code"));
        assert_eq!(msg, "Personnel code is not in the expected format.");
    }
}
