pub mod keycloak;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::ProviderError;

pub type ProviderResult<T> = Result<T, ProviderError>;

// ── Common models ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub attributes: HashMap<String, Vec<String>>,
}

impl User {
    pub fn full_name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(f), Some(l)) => format!("{f} {l}"),
            (Some(f), None) => f.clone(),
            (None, Some(l)) => l.clone(),
            _ => self.username.clone(),
        }
    }

    pub fn team(&self) -> Option<&str> {
        self.attributes
            .get("team")
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub path: String,
    pub subgroups: Vec<Group>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub client_role: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub temporary_password: Option<String>,
    pub attributes: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Default)]
pub struct ListUsersQuery {
    pub search: Option<String>,
    pub offset: u32,
    pub max: u32,
}

impl ListUsersQuery {
    pub fn new() -> Self {
        Self {
            max: 100,
            ..Default::default()
        }
    }

    pub fn search(mut self, q: impl Into<String>) -> Self {
        self.search = Some(q.into());
        self
    }

    pub fn page(mut self, offset: u32, max: u32) -> Self {
        self.offset = offset;
        self.max = max;
        self
    }
}

// ── Client models ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppClient {
    pub id: String,
    pub client_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub public_client: bool,
    pub redirect_uris: Vec<String>,
    pub web_origins: Vec<String>,
    pub protocol: Option<String>,
    pub service_accounts_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateAppClient {
    pub enabled: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
}

// ── Provider trait ────────────────────────────────────────────────────────────

#[async_trait]
pub trait IdentityProvider: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    // Realms
    async fn list_realms(&self) -> ProviderResult<Vec<Realm>>;

    // Users
    async fn list_users(&self, realm: &str, query: &ListUsersQuery) -> ProviderResult<Vec<User>>;
    async fn get_user(&self, realm: &str, id: &str) -> ProviderResult<User>;
    async fn create_user(&self, realm: &str, user: CreateUser) -> ProviderResult<User>;
    async fn update_user(&self, realm: &str, id: &str, update: UpdateUser) -> ProviderResult<()>;
    async fn set_user_enabled(&self, realm: &str, id: &str, enabled: bool) -> ProviderResult<()>;

    // Keycloak represents attributes as multi-value; we store team as a single
    // string under the "team" key. This goes through update_user so the full
    // attribute map is sent in one request, but callers should use this helper
    // to avoid N+1 round-trips for single-attribute updates.
    async fn set_user_attribute(
        &self,
        realm: &str,
        id: &str,
        key: &str,
        value: &str,
    ) -> ProviderResult<()>;

    async fn delete_user(&self, realm: &str, id: &str) -> ProviderResult<()>;

    // Groups
    async fn list_groups(&self, realm: &str) -> ProviderResult<Vec<Group>>;
    async fn get_user_groups(&self, realm: &str, user_id: &str) -> ProviderResult<Vec<Group>>;
    async fn add_user_to_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> ProviderResult<()>;
    async fn remove_user_from_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> ProviderResult<()>;

    // Realm roles
    async fn list_realm_roles(&self, realm: &str) -> ProviderResult<Vec<Role>>;
    async fn get_user_realm_roles(&self, realm: &str, user_id: &str) -> ProviderResult<Vec<Role>>;
    async fn assign_realm_role(
        &self,
        realm: &str,
        user_id: &str,
        role: &Role,
    ) -> ProviderResult<()>;
    async fn remove_realm_role(
        &self,
        realm: &str,
        user_id: &str,
        role: &Role,
    ) -> ProviderResult<()>;

    // Clients
    async fn list_clients(&self, realm: &str) -> ProviderResult<Vec<AppClient>>;
    async fn get_client(&self, realm: &str, id: &str) -> ProviderResult<AppClient>;
    async fn update_client(
        &self,
        realm: &str,
        id: &str,
        update: UpdateAppClient,
    ) -> ProviderResult<()>;
    async fn get_client_secret(
        &self,
        realm: &str,
        id: &str,
    ) -> ProviderResult<Option<String>>;
}
