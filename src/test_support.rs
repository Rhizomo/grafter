// In-memory fakes for IdentityProvider and ChangeStorage, used only by
// tests. Lets service-layer logic (propose_or_apply, apply_change_diff) be
// exercised end-to-end — including actual group add/remove calls — without
// a live Keycloak, S3, or Redis, which the unit tests elsewhere can't cover.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::ProviderError;
use crate::provider::{
    AppClient, CreateUser, Group, IdentityProvider, ListUsersQuery, ProviderResult, Realm, Role,
    UpdateAppClient, UpdateUser, User,
};
use crate::storage::{AuditEntry, ChangeStatus, ChangeStorage, PendingChange, UserMeta};

#[derive(Default)]
pub struct FakeProvider {
    users: Mutex<HashMap<String, User>>,
    groups: Mutex<Vec<Group>>,
    user_groups: Mutex<HashMap<String, Vec<String>>>,
}

fn user_key(realm: &str, id: &str) -> String {
    format!("{realm}/{id}")
}

impl FakeProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_user(&self, realm: &str, user: User) {
        self.users.lock().unwrap().insert(user_key(realm, &user.id), user);
    }

    pub fn seed_group(&self, group: Group) {
        self.groups.lock().unwrap().push(group);
    }

    pub fn get_seeded_user(&self, realm: &str, id: &str) -> User {
        self.users.lock().unwrap().get(&user_key(realm, id)).cloned().expect("user not seeded")
    }

    pub fn group_ids_of(&self, realm: &str, user_id: &str) -> Vec<String> {
        self.user_groups.lock().unwrap().get(&user_key(realm, user_id)).cloned().unwrap_or_default()
    }
}

#[async_trait]
impl IdentityProvider for FakeProvider {
    fn name(&self) -> &'static str {
        "fake"
    }

    async fn list_realms(&self) -> ProviderResult<Vec<Realm>> {
        Ok(vec![])
    }

    async fn list_users(&self, _realm: &str, _query: &ListUsersQuery) -> ProviderResult<Vec<User>> {
        Ok(self.users.lock().unwrap().values().cloned().collect())
    }

    async fn get_user(&self, realm: &str, id: &str) -> ProviderResult<User> {
        self.users.lock().unwrap().get(&user_key(realm, id)).cloned().ok_or(ProviderError::NotFound)
    }

    async fn create_user(&self, realm: &str, user: CreateUser) -> ProviderResult<User> {
        let mut users = self.users.lock().unwrap();
        let id = format!("generated-{}", users.len());
        let u = User {
            id: id.clone(),
            username: user.username,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            enabled: user.enabled,
            attributes: user.attributes,
            created_at: Some(chrono::Utc::now().timestamp_millis()),
        };
        users.insert(user_key(realm, &id), u.clone());
        Ok(u)
    }

    async fn update_user(&self, realm: &str, id: &str, update: UpdateUser) -> ProviderResult<()> {
        let mut users = self.users.lock().unwrap();
        let u = users.get_mut(&user_key(realm, id)).ok_or(ProviderError::NotFound)?;
        if let Some(v) = update.first_name { u.first_name = Some(v); }
        if let Some(v) = update.last_name { u.last_name = Some(v); }
        if let Some(v) = update.email { u.email = Some(v); }
        if let Some(v) = update.enabled { u.enabled = v; }
        if let Some(attrs) = update.attributes { u.attributes.extend(attrs); }
        Ok(())
    }

    async fn set_user_enabled(&self, realm: &str, id: &str, enabled: bool) -> ProviderResult<()> {
        self.update_user(realm, id, UpdateUser { enabled: Some(enabled), ..Default::default() }).await
    }

    async fn set_user_attribute(&self, realm: &str, id: &str, key: &str, value: &str) -> ProviderResult<()> {
        let mut attrs = HashMap::new();
        attrs.insert(key.to_string(), vec![value.to_string()]);
        self.update_user(realm, id, UpdateUser { attributes: Some(attrs), ..Default::default() }).await
    }

    async fn set_user_password(&self, _realm: &str, _id: &str, _password: &str, _temporary: bool) -> ProviderResult<()> {
        Ok(())
    }

    async fn delete_user(&self, realm: &str, id: &str) -> ProviderResult<()> {
        self.users.lock().unwrap().remove(&user_key(realm, id));
        Ok(())
    }

    async fn list_groups(&self, _realm: &str) -> ProviderResult<Vec<Group>> {
        Ok(self.groups.lock().unwrap().clone())
    }

    async fn get_user_groups(&self, realm: &str, user_id: &str) -> ProviderResult<Vec<Group>> {
        let ids = self.group_ids_of(realm, user_id);
        Ok(self.groups.lock().unwrap().iter().filter(|g| ids.contains(&g.id)).cloned().collect())
    }

    async fn list_group_members(&self, realm: &str, group_id: &str) -> ProviderResult<Vec<User>> {
        let ug = self.user_groups.lock().unwrap();
        let users = self.users.lock().unwrap();
        Ok(users
            .iter()
            .filter(|(key, _)| {
                key.starts_with(&format!("{realm}/"))
                    && ug.get(*key).is_some_and(|gs| gs.iter().any(|g| g == group_id))
            })
            .map(|(_, u)| u.clone())
            .collect())
    }

    async fn create_group(&self, _realm: &str, name: &str, _parent_id: Option<&str>) -> ProviderResult<Group> {
        let g = Group { id: format!("group-{name}"), name: name.to_string(), path: format!("/{name}"), subgroups: vec![], realm_roles: vec![] };
        self.groups.lock().unwrap().push(g.clone());
        Ok(g)
    }

    async fn add_user_to_group(&self, realm: &str, user_id: &str, group_id: &str) -> ProviderResult<()> {
        let mut ug = self.user_groups.lock().unwrap();
        let entry = ug.entry(user_key(realm, user_id)).or_default();
        if !entry.iter().any(|g| g == group_id) {
            entry.push(group_id.to_string());
        }
        Ok(())
    }

    async fn remove_user_from_group(&self, realm: &str, user_id: &str, group_id: &str) -> ProviderResult<()> {
        let mut ug = self.user_groups.lock().unwrap();
        if let Some(entry) = ug.get_mut(&user_key(realm, user_id)) {
            entry.retain(|g| g != group_id);
        }
        Ok(())
    }

    async fn list_realm_roles(&self, _realm: &str) -> ProviderResult<Vec<Role>> { Ok(vec![]) }
    async fn get_user_realm_roles(&self, _realm: &str, _user_id: &str) -> ProviderResult<Vec<Role>> { Ok(vec![]) }
    async fn get_user_effective_realm_roles(&self, _realm: &str, _user_id: &str) -> ProviderResult<Vec<Role>> { Ok(vec![]) }
    async fn list_role_users(&self, _realm: &str, _role_name: &str) -> ProviderResult<Vec<User>> { Ok(vec![]) }
    async fn assign_realm_role(&self, _realm: &str, _user_id: &str, _role: &Role) -> ProviderResult<()> { Ok(()) }
    async fn remove_realm_role(&self, _realm: &str, _user_id: &str, _role: &Role) -> ProviderResult<()> { Ok(()) }

    async fn list_clients(&self, _realm: &str) -> ProviderResult<Vec<AppClient>> { Ok(vec![]) }
    async fn get_client(&self, _realm: &str, _id: &str) -> ProviderResult<AppClient> { Err(ProviderError::NotFound) }
    async fn update_client(&self, _realm: &str, _id: &str, _update: UpdateAppClient) -> ProviderResult<()> { Ok(()) }
    async fn get_client_secret(&self, _realm: &str, _id: &str) -> ProviderResult<Option<String>> { Ok(None) }
}

#[derive(Default)]
pub struct FakeStorage {
    pub changes: Mutex<Vec<PendingChange>>,
    pub audit: Mutex<Vec<AuditEntry>>,
    pub user_meta: Mutex<HashMap<String, UserMeta>>,
}

impl FakeStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChangeStorage for FakeStorage {
    async fn save_change(&self, change: &PendingChange) -> anyhow::Result<()> {
        let mut changes = self.changes.lock().unwrap();
        if let Some(existing) = changes.iter_mut().find(|c| c.id == change.id) {
            *existing = change.clone();
        } else {
            changes.push(change.clone());
        }
        Ok(())
    }

    async fn get_change(&self, id: &str) -> anyhow::Result<Option<PendingChange>> {
        Ok(self.changes.lock().unwrap().iter().find(|c| c.id == id).cloned())
    }

    async fn list_changes(&self) -> anyhow::Result<Vec<PendingChange>> {
        Ok(self.changes.lock().unwrap().clone())
    }

    async fn list_pending_changes(&self) -> anyhow::Result<Vec<PendingChange>> {
        Ok(self.changes.lock().unwrap().iter().filter(|c| c.status == ChangeStatus::Pending).cloned().collect())
    }

    async fn delete_change(&self, id: &str) -> anyhow::Result<()> {
        self.changes.lock().unwrap().retain(|c| c.id != id);
        Ok(())
    }

    async fn append_audit(&self, entry: &AuditEntry) -> anyhow::Result<()> {
        self.audit.lock().unwrap().push(entry.clone());
        Ok(())
    }

    async fn list_audit(&self, _date: Option<&str>) -> anyhow::Result<Vec<AuditEntry>> {
        Ok(self.audit.lock().unwrap().clone())
    }

    async fn get_user_meta(&self, realm: &str, user_id: &str) -> anyhow::Result<UserMeta> {
        Ok(self.user_meta.lock().unwrap().get(&format!("{realm}/{user_id}")).cloned().unwrap_or_default())
    }

    async fn save_user_meta(&self, realm: &str, user_id: &str, meta: &UserMeta) -> anyhow::Result<()> {
        self.user_meta.lock().unwrap().insert(format!("{realm}/{user_id}"), meta.clone());
        Ok(())
    }
}
