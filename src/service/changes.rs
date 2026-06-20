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
    let mut team_change: Option<&str> = None;

    for field in diff {
        match field.field.as_str() {
            "first_name" => update.first_name = Some(field.after.clone()),
            "last_name"  => update.last_name  = Some(field.after.clone()),
            "email"      => update.email      = Some(field.after.clone()),
            "enabled"    => enabled_change    = Some(field.after == "true"),
            "team"       => team_change       = Some(&field.after),
            _ => {}
        }
    }

    if update.first_name.is_some() || update.last_name.is_some() || update.email.is_some() {
        provider.update_user(realm, user_id, update).await?;
    }
    if let Some(enabled) = enabled_change {
        provider.set_user_enabled(realm, user_id, enabled).await?;
    }
    if let Some(team) = team_change {
        provider.set_user_attribute(realm, user_id, "team", team).await?;
    }

    Ok(())
}
