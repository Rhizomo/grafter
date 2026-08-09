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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Group, User};
    use crate::test_support::{FakeProvider, FakeStorage};
    use std::collections::HashMap;

    fn seeded() -> (FakeProvider, FakeStorage) {
        let provider = FakeProvider::new();
        provider.seed_user("smartech", User {
            id: "u1".into(),
            username: "test.user@smartech.ir".into(),
            email: Some("test.user@smartech.ir".into()),
            first_name: Some("Test".into()),
            last_name: Some("User".into()),
            enabled: true,
            attributes: HashMap::new(),
        });
        provider.seed_group(Group {
            id: "g-old".into(), name: "old-team".into(), path: "/old-team".into(),
            subgroups: vec![], realm_roles: vec![],
        });
        provider.seed_group(Group {
            id: "g-new".into(), name: "new-team".into(), path: "/new-team".into(),
            subgroups: vec![], realm_roles: vec!["iam-admin".into()],
        });
        (provider, FakeStorage::new())
    }

    fn req<'a>(diff: Vec<FieldChange>) -> EditRequest<'a> {
        EditRequest {
            realm: "smartech",
            user_id: "u1",
            username: "test.user@smartech.ir",
            actor: "actor@smartech.ir",
            diff,
        }
    }

    #[tokio::test]
    async fn admin_edit_applies_immediately_and_queues_nothing() {
        let (provider, storage) = seeded();
        let diff = vec![FieldChange { field: "first_name".into(), before: Some("Test".into()), after: "Changed".into() }];

        propose_or_apply(&Role::Admin, &provider, &storage, req(diff)).await.unwrap();

        assert_eq!(provider.get_seeded_user("smartech", "u1").first_name.as_deref(), Some("Changed"));
        assert!(storage.changes.lock().unwrap().is_empty(), "admin edits must not queue a change");
    }

    #[tokio::test]
    async fn operator_edit_queues_and_does_not_touch_the_user() {
        let (provider, storage) = seeded();
        let diff = vec![FieldChange { field: "first_name".into(), before: Some("Test".into()), after: "Changed".into() }];

        propose_or_apply(&Role::Operator, &provider, &storage, req(diff)).await.unwrap();

        assert_eq!(
            provider.get_seeded_user("smartech", "u1").first_name.as_deref(),
            Some("Test"),
            "operator proposals must not apply before approval"
        );
        let changes = storage.changes.lock().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].status, ChangeStatus::Pending);
    }

    // Regression: an operator's team choice used to be silently dropped —
    // neither applied nor queued. It must survive into the pending change.
    #[tokio::test]
    async fn operator_team_change_is_queued_not_dropped() {
        let (provider, storage) = seeded();
        let diff = vec![
            FieldChange { field: "team_group_id".into(), before: None, after: "g-new".into() },
            FieldChange { field: "team".into(), before: None, after: "new-team".into() },
        ];

        propose_or_apply(&Role::Operator, &provider, &storage, req(diff)).await.unwrap();

        let changes = storage.changes.lock().unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].diff.iter().any(|f| f.field == "team_group_id" && f.after == "g-new"));
    }

    // Regression: a team-only change by an admin used to be dropped by an
    // early return. Applying it must actually move group membership.
    #[tokio::test]
    async fn admin_team_only_change_moves_group_membership() {
        let (provider, storage) = seeded();
        provider.add_user_to_group("smartech", "u1", "g-old").await.unwrap();

        let diff = vec![
            FieldChange { field: "team_group_id".into(), before: Some("g-old".into()), after: "g-new".into() },
            FieldChange { field: "team".into(), before: None, after: "new-team".into() },
        ];
        propose_or_apply(&Role::Admin, &provider, &storage, req(diff)).await.unwrap();

        let groups = provider.group_ids_of("smartech", "u1");
        assert_eq!(groups, vec!["g-new".to_string()], "old team must be left, new team joined");
        assert_eq!(
            provider.get_seeded_user("smartech", "u1").team(),
            Some("new-team"),
            "team attribute should be synced for list display"
        );
    }

    #[tokio::test]
    async fn clearing_the_team_leaves_every_group() {
        let (provider, storage) = seeded();
        provider.add_user_to_group("smartech", "u1", "g-old").await.unwrap();

        let diff = vec![
            FieldChange { field: "team_group_id".into(), before: Some("g-old".into()), after: "".into() },
            FieldChange { field: "team".into(), before: None, after: "".into() },
        ];
        propose_or_apply(&Role::Admin, &provider, &storage, req(diff)).await.unwrap();

        assert!(provider.group_ids_of("smartech", "u1").is_empty());
    }

    #[tokio::test]
    async fn every_path_writes_an_audit_entry() {
        let (provider, storage) = seeded();
        let diff = vec![FieldChange { field: "email".into(), before: None, after: "new@smartech.ir".into() }];

        propose_or_apply(&Role::Admin, &provider, &storage, req(diff)).await.unwrap();
        assert_eq!(storage.audit.lock().unwrap().len(), 1);
    }
}
