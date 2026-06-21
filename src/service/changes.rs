use crate::{
    provider::{IdentityProvider, UpdateUser},
    storage::FieldChange,
};
use crate::error::ProviderError;

pub async fn apply_change_diff(
    provider: &dyn IdentityProvider,
    realm: &str,
    user_id: &str,
    diff: &[FieldChange],
) -> Result<(), ProviderError> {
    let mut update = UpdateUser::default();
    let mut enabled_change: Option<bool> = None;
    let mut attr_changes: Vec<(&str, &str)> = Vec::new();

    for field in diff {
        match field.field.as_str() {
            "first_name"     => update.first_name    = Some(field.after.clone()),
            "last_name"      => update.last_name     = Some(field.after.clone()),
            "email"          => update.email         = Some(field.after.clone()),
            "enabled"        => enabled_change       = Some(field.after == "true"),
            "team"           => attr_changes.push(("team", &field.after)),
            "phone_number"   => attr_changes.push(("phone_number", &field.after)),
            "personnel_code" => attr_changes.push(("personnel_code", &field.after)),
            _ => {}
        }
    }

    if update.first_name.is_some() || update.last_name.is_some() || update.email.is_some() {
        provider.update_user(realm, user_id, update).await?;
    }
    if let Some(enabled) = enabled_change {
        provider.set_user_enabled(realm, user_id, enabled).await?;
    }
    for (key, value) in attr_changes {
        provider.set_user_attribute(realm, user_id, key, value).await?;
    }

    Ok(())
}
