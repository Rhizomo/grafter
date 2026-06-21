pub mod s3;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use anyhow::Result;

// ── Models ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    Pending,
    Approved,
    Rejected,
}

fn default_action() -> String { "edit_user".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChange {
    pub id: String,
    pub realm: String,
    pub user_id: String,   // empty string for create_user proposals
    pub username: String,
    pub proposed_by: String,
    pub proposed_at: DateTime<Utc>,
    pub status: ChangeStatus,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub reject_reason: Option<String>,
    pub diff: Vec<FieldChange>,
    #[serde(default = "default_action")]
    pub action: String,    // "edit_user" | "create_user"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub before: Option<String>,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target_realm: String,
    pub target_user: Option<String>,
    pub detail: String,
    pub outcome: AuditOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure(String),
}

// ── Storage trait ──────────────────────────────────────────────────────────────

#[async_trait]
pub trait ChangeStorage: Send + Sync + 'static {
    async fn save_change(&self, change: &PendingChange) -> Result<()>;
    async fn get_change(&self, id: &str) -> Result<Option<PendingChange>>;
    async fn list_changes(&self) -> Result<Vec<PendingChange>>;
    async fn delete_change(&self, id: &str) -> Result<()>;

    async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn list_audit(&self, date: Option<&str>) -> Result<Vec<AuditEntry>>;
}
