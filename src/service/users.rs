use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::AppError,
    provider::IdentityProvider,
    session::{Flash, Role},
    storage::{AuditEntry, AuditOutcome, ChangeStatus, ChangeStorage, FieldChange, PendingChange},
};

use super::changes::apply_change_diff;

pub struct EditRequest<'a> {
    pub realm: &'a str,
    pub user_id: &'a str,
    pub username: &'a str, // target user's username
    pub actor: &'a str,    // current user performing the action
    pub diff: Vec<FieldChange>,
}

pub async fn propose_or_apply(
    role: &Role,
    provider: &dyn IdentityProvider,
    storage: &dyn ChangeStorage,
    req: EditRequest<'_>,
) -> Result<Flash, AppError> {
    match role {
        Role::Admin => {
            apply_change_diff(provider, req.realm, req.user_id, &req.diff).await?;
            storage
                .append_audit(&AuditEntry {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    actor: req.actor.to_string(),
                    action: "update_user".into(),
                    target_realm: req.realm.to_string(),
                    target_user: Some(req.username.to_string()),
                    detail: format!("{} field(s) changed", req.diff.len()),
                    outcome: AuditOutcome::Success,
                })
                .await
                .map_err(AppError::Internal)?;
            Ok(Flash::success("User updated."))
        }
        Role::Operator => {
            let change = PendingChange {
                id: Uuid::new_v4().to_string(),
                realm: req.realm.to_string(),
                user_id: req.user_id.to_string(),
                username: req.username.to_string(),
                proposed_by: req.actor.to_string(),
                proposed_at: Utc::now(),
                status: ChangeStatus::Pending,
                resolved_by: None,
                resolved_at: None,
                reject_reason: None,
                diff: req.diff,
                action: "edit_user".into(),
            };
            storage.save_change(&change).await.map_err(AppError::Internal)?;
            storage
                .append_audit(&AuditEntry {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    actor: req.actor.to_string(),
                    action: "propose_change".into(),
                    target_realm: req.realm.to_string(),
                    target_user: Some(req.username.to_string()),
                    detail: format!("change {} pending approval", change.id),
                    outcome: AuditOutcome::Success,
                })
                .await
                .map_err(AppError::Internal)?;
            Ok(Flash::warning("Change proposed and queued for admin approval."))
        }
    }
}
