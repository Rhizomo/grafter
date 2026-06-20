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
