use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Operator,
}

impl Role {
    pub fn from_claims(roles: &[String], admin_role: &str, operator_role: &str) -> Option<Self> {
        if roles.iter().any(|r| r == admin_role) {
            Some(Role::Admin)
        } else if roles.iter().any(|r| r == operator_role) {
            Some(Role::Operator)
        } else {
            None
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub role: Role,
    // When this operator last viewed /changes — used to show "resolved
    // since you last checked". Missing on already-active sessions from
    // before this field existed, hence the default.
    #[serde(default)]
    pub last_seen_changes_at: Option<DateTime<Utc>>,
}

pub const SESSION_KEY: &str = "user";
pub const FLASH_KEY: &str = "flash";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlashKind {
    Success,
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flash {
    pub text: String,
    pub kind: FlashKind,
}

impl Flash {
    pub fn success(text: impl Into<String>) -> Self {
        Self { text: text.into(), kind: FlashKind::Success }
    }
    pub fn warning(text: impl Into<String>) -> Self {
        Self { text: text.into(), kind: FlashKind::Warning }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_role_wins_when_both_present() {
        let roles = vec!["iam-operator".to_string(), "iam-admin".to_string()];
        assert_eq!(Role::from_claims(&roles, "iam-admin", "iam-operator"), Some(Role::Admin));
    }

    #[test]
    fn operator_role_alone() {
        let roles = vec!["iam-operator".to_string()];
        assert_eq!(Role::from_claims(&roles, "iam-admin", "iam-operator"), Some(Role::Operator));
    }

    #[test]
    fn no_matching_role_is_none() {
        let roles = vec!["some-other-role".to_string()];
        assert_eq!(Role::from_claims(&roles, "iam-admin", "iam-operator"), None);
    }

    #[test]
    fn empty_roles_is_none() {
        assert_eq!(Role::from_claims(&[], "iam-admin", "iam-operator"), None);
    }
}
