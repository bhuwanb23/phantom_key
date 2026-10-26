//! Vault system for Phantom Key v2
//!
//! This module contains:
//! - Vault storage (memory, SQLite)
//! - Per-secret encryption with HKDF
//! - Handle system for secret references
//! - Decoy generation (format-preserving)
//! - Decoy-to-handle mapping

pub mod storage;
pub mod encryption;
pub mod handle;
pub mod decoy;
pub mod mapping;

// Re-export main types
pub use storage::{VaultStorage, VaultEntry, VaultMetadata, SecretType, MemoryStorage, SqliteStorage};
pub use encryption::VaultEncryption;
pub use handle::Handle;
pub use decoy::{DecoyGenerator, DecoyRegistry, AwsAccessKeyGenerator, AwsSecretKeyGenerator, IbanGenerator, CreditCardGenerator, GenericDecoyGenerator};
pub use mapping::{DecoyMap, DecoyManager};

/// Vault error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Handle error: {0}")]
    HandleError(String),
    #[error("Decoy error: {0}")]
    DecoyError(String),
    #[error("Mapping error: {0}")]
    MappingError(String),
}
