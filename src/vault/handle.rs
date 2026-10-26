//! Handle System for Secret References
//!
//! Handles are unique identifiers that reference secrets in the vault.
//! Format: ⟦H<id>⟧ where id is a UUID

use std::fmt;
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Handle for referencing secrets in the vault
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Handle(String);

impl Handle {
    /// Generate a new random handle
    pub fn new() -> Self {
        let id = Uuid::new_v4();
        Self(format!("⟦H{}⟧", id))
    }

    /// Create handle from UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(format!("⟦H{}⟧", uuid))
    }

    /// Get the UUID from handle
    pub fn uuid(&self) -> Option<Uuid> {
        self.0.strip_prefix("⟦H").and_then(|s| s.strip_suffix("⟧"))
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    /// Check if string is a valid handle
    pub fn is_valid(s: &str) -> bool {
        s.starts_with("⟦H") && s.ends_with("⟧") && s.len() > 4
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Handle {
    type Err = HandleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Self::is_valid(s) {
            Ok(Self(s.to_string()))
        } else {
            Err(HandleParseError::InvalidFormat)
        }
    }
}

/// Handle parsing error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleParseError {
    InvalidFormat,
}

impl fmt::Display for HandleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandleParseError::InvalidFormat => write!(f, "Invalid handle format"),
        }
    }
}

impl std::error::Error for HandleParseError {}

/// Handle generator
#[derive(Debug, Default)]
pub struct HandleGenerator;

impl HandleGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a new handle with random UUID
    pub fn generate(&self) -> Handle {
        Handle::new()
    }

    /// Generate handle from existing UUID
    pub fn generate_from_uuid(&self, uuid: Uuid) -> Handle {
        Handle::from_uuid(uuid)
    }
}
