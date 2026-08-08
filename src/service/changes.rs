use std::collections::HashMap;

use crate::{
    provider::{IdentityProvider, UpdateUser},
    storage::FieldChange,
};
use crate::error::ProviderError;

// Pure mapping from a field diff to a single UpdateUser, kept separate from
// apply_change_diff so it's testable without a live IdentityProvider.
fn diff_to_update(diff: &[FieldChange]) -> UpdateUser {
    let mut update = UpdateUser::default();
    let mut attrs: HashMap<String, Vec<String>> = HashMap::new();

    for field in diff {
        match field.field.as_str() {
            "first_name"     => update.first_name = Some(field.after.clone()),
            "last_name"      => update.last_name  = Some(field.after.clone()),
            "email"          => update.email      = Some(field.after.clone()),
            "enabled"        => update.enabled    = Some(field.after == "true"),
            "team"           => { attrs.insert("team".into(), vec![field.after.clone()]); }
            "phone_number"   => { attrs.insert("phone_number".into(), vec![field.after.clone()]); }
            "personnel_code" => { attrs.insert("personnel_code".into(), vec![field.after.clone()]); }
            _ => {}
        }
    }

    if !attrs.is_empty() {
        update.attributes = Some(attrs);
    }

    update
}

fn has_any_change(update: &UpdateUser) -> bool {
    update.first_name.is_some()
        || update.last_name.is_some()
        || update.email.is_some()
        || update.enabled.is_some()
        || update.attributes.is_some()
}

// Collapses the whole diff into a single UpdateUser so apply_change_diff
// issues exactly one Keycloak round trip (one GET+PUT inside update_user),
// instead of one call per changed field.
pub async fn apply_change_diff(
    provider: &dyn IdentityProvider,
    realm: &str,
    user_id: &str,
    diff: &[FieldChange],
) -> Result<(), ProviderError> {
    let update = diff_to_update(diff);

    if has_any_change(&update) {
        provider.update_user(realm, user_id, update).await?;
    }

    // Group membership is a separate Keycloak API, not part of the user
    // representation PUT — diff_to_update deliberately ignores this field,
    // so it's applied here as its own step once a proposal is approved.
    if let Some(field) = diff.iter().find(|f| f.field == "team_group_id") {
        provider.add_user_to_group(realm, user_id, &field.after).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, before: Option<&str>, after: &str) -> FieldChange {
        FieldChange { field: name.into(), before: before.map(String::from), after: after.into() }
    }

    #[test]
    fn maps_name_and_email_fields() {
        let update = diff_to_update(&[
            field("first_name", Some("Old"), "New"),
            field("email", None, "new@smartech.ir"),
        ]);
        assert_eq!(update.first_name.as_deref(), Some("New"));
        assert_eq!(update.email.as_deref(), Some("new@smartech.ir"));
        assert!(update.last_name.is_none());
        assert!(update.enabled.is_none());
        assert!(update.attributes.is_none());
    }

    #[test]
    fn maps_enabled_as_bool_from_string() {
        let update = diff_to_update(&[field("enabled", Some("true"), "false")]);
        assert_eq!(update.enabled, Some(false));
    }

    #[test]
    fn collects_attribute_fields_into_one_map() {
        let update = diff_to_update(&[
            field("team", None, "platform"),
            field("phone_number", None, "0912"),
            field("personnel_code", None, "1234"),
        ]);
        let attrs = update.attributes.expect("attributes should be set");
        assert_eq!(attrs.get("team"), Some(&vec!["platform".to_string()]));
        assert_eq!(attrs.get("phone_number"), Some(&vec!["0912".to_string()]));
        assert_eq!(attrs.get("personnel_code"), Some(&vec!["1234".to_string()]));
    }

    #[test]
    fn team_group_id_is_not_part_of_update_user() {
        // Handled separately in apply_change_diff via add_user_to_group,
        // not through the UpdateUser PUT.
        let update = diff_to_update(&[field("team_group_id", None, "abc")]);
        assert!(!has_any_change(&update));
    }

    #[test]
    fn ignores_unknown_fields() {
        let update = diff_to_update(&[field("some_future_field", None, "abc")]);
        assert!(!has_any_change(&update));
    }

    #[test]
    fn empty_diff_has_no_change() {
        assert!(!has_any_change(&diff_to_update(&[])));
    }
}
