use anyhow::{Context, Result};
use std::cmp::Reverse;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use object_store::{aws::AmazonS3Builder, path::Path, ObjectStore};
use std::sync::Arc;

use super::{AuditEntry, ChangeStorage, PendingChange};

pub struct S3Storage {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl S3Storage {
    pub fn new(
        endpoint: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        let store = AmazonS3Builder::new()
            .with_endpoint(endpoint)
            .with_bucket_name(bucket)
            .with_access_key_id(access_key)
            .with_secret_access_key(secret_key)
            .with_allow_http(true)
            .build()
            .context("failed to build S3 client")?;

        Ok(Self {
            store: Arc::new(store),
            prefix: "grafter".into(),
        })
    }

    fn pending_change_path(&self, id: &str) -> Path {
        Path::from(format!("{}/changes/pending/{}.json", self.prefix, id))
    }

    fn resolved_change_path(&self, id: &str) -> Path {
        Path::from(format!("{}/changes/resolved/{}.json", self.prefix, id))
    }

    // Each audit entry is its own object — no read-modify-write race.
    fn audit_entry_path(&self, date: &str, id: &str) -> Path {
        Path::from(format!("{}/audit/{}/{}.json", self.prefix, date, id))
    }

    fn audit_prefix(&self, date: &str) -> Path {
        Path::from(format!("{}/audit/{}/", self.prefix, date))
    }
}

#[async_trait]
impl ChangeStorage for S3Storage {
    async fn save_change(&self, change: &PendingChange) -> Result<()> {
        let data = serde_json::to_vec(change)?;
        let path = match change.status {
            super::ChangeStatus::Pending => self.pending_change_path(&change.id),
            _ => self.resolved_change_path(&change.id),
        };
        self.store
            .put(&path, Bytes::from(data).into())
            .await
            .context("s3 put change")?;

        // If this change just left the pending state, remove its old pending
        // object so it isn't scanned twice and doesn't linger in the small
        // pending set that pending_changes_count() relies on staying small.
        if !matches!(change.status, super::ChangeStatus::Pending) {
            let _ = self.store.delete(&self.pending_change_path(&change.id)).await;
        }
        Ok(())
    }

    async fn get_change(&self, id: &str) -> Result<Option<PendingChange>> {
        match self.store.get(&self.pending_change_path(id)).await {
            Ok(obj) => {
                let bytes = obj.bytes().await?;
                return Ok(Some(serde_json::from_slice(&bytes)?));
            }
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        match self.store.get(&self.resolved_change_path(id)).await {
            Ok(obj) => {
                let bytes = obj.bytes().await?;
                Ok(Some(serde_json::from_slice(&bytes)?))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn list_changes(&self) -> Result<Vec<PendingChange>> {
        let prefix = Path::from(format!("{}/changes/", self.prefix));
        let mut list = self.store.list(Some(&prefix));
        let mut changes = Vec::new();

        while let Some(meta) = list.next().await {
            let meta = meta?;
            let obj = self.store.get(&meta.location).await?;
            let bytes = obj.bytes().await?;
            match serde_json::from_slice::<PendingChange>(&bytes) {
                Ok(c) => changes.push(c),
                Err(e) => tracing::warn!(key = %meta.location, error = %e, "skipping corrupt change object"),
            }
        }

        changes.sort_by_key(|c| Reverse(c.proposed_at));
        Ok(changes)
    }

    // Scans only the pending/ prefix, which stays small — used on every page
    // render for the pending-count badge, so it must not scan resolved history.
    async fn list_pending_changes(&self) -> Result<Vec<PendingChange>> {
        let prefix = Path::from(format!("{}/changes/pending/", self.prefix));
        let mut list = self.store.list(Some(&prefix));
        let mut changes = Vec::new();

        while let Some(meta) = list.next().await {
            let meta = meta?;
            let obj = self.store.get(&meta.location).await?;
            let bytes = obj.bytes().await?;
            match serde_json::from_slice::<PendingChange>(&bytes) {
                Ok(c) => changes.push(c),
                Err(e) => tracing::warn!(key = %meta.location, error = %e, "skipping corrupt change object"),
            }
        }

        changes.sort_by_key(|c| Reverse(c.proposed_at));
        Ok(changes)
    }

    async fn delete_change(&self, id: &str) -> Result<()> {
        for path in [self.pending_change_path(id), self.resolved_change_path(id)] {
            match self.store.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e).context("s3 delete change"),
            }
        }
        Ok(())
    }

    async fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        let date = entry.timestamp.format("%Y-%m-%d").to_string();
        let path = self.audit_entry_path(&date, &entry.id);
        let data = serde_json::to_vec(entry)?;
        self.store
            .put(&path, Bytes::from(data).into())
            .await
            .context("s3 put audit entry")?;
        Ok(())
    }

    async fn list_audit(&self, date: Option<&str>) -> Result<Vec<AuditEntry>> {
        let date = date
            .map(|d| d.to_string())
            .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());

        let prefix = self.audit_prefix(&date);
        let mut list = self.store.list(Some(&prefix));
        let mut entries = Vec::new();

        while let Some(meta) = list.next().await {
            let meta = meta?;
            let obj = self.store.get(&meta.location).await?;
            let bytes = obj.bytes().await?;
            match serde_json::from_slice::<AuditEntry>(&bytes) {
                Ok(e) => entries.push(e),
                Err(err) => tracing::warn!(key = %meta.location, error = %err, "skipping corrupt audit object"),
            }
        }

        entries.sort_by_key(|e| e.timestamp);
        Ok(entries)
    }
}
