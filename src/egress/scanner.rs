//! Secret Scanner
//!
//! Scans payloads for exact matches of real vault secrets.
//! Only matches exact values (plus base64, hex, URL-encoded forms).

use std::sync::Arc;
use crate::vault::storage::{VaultStorage, VaultEntry};
use crate::vault::encryption::VaultEncryption;
use crate::crypto::group::GroupElement;

/// A detected secret in the payload
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub handle: String,
    pub secret_type: String,
    pub position: usize,
    pub encoding: String,
}

/// Scanner for detecting real secrets in payloads
pub struct SecretScanner {
    vault_storage: Arc<dyn VaultStorage>,
    vault_encryption: VaultEncryption,
    R: GroupElement,
}

impl SecretScanner {
    pub fn new(
        vault_storage: Arc<dyn VaultStorage>,
        vault_encryption: VaultEncryption,
        R: GroupElement,
    ) -> Self {
        Self {
            vault_storage,
            vault_encryption,
            R,
        }
    }

    /// Scan payload for real secrets
    pub fn scan(&self, payload: &[u8]) -> Vec<SecretMatch> {
        let text = String::from_utf8_lossy(payload);
        let mut matches = Vec::new();

        let entries = self.vault_storage.list();

        for entry in entries {
            if let Some(secret) = self.vault_encryption.get_secret(&entry, &self.R) {
                let secret_str = String::from_utf8_lossy(&secret);

                // Check for exact match (raw)
                if let Some(pos) = text.find(&secret_str) {
                    matches.push(SecretMatch {
                        handle: entry.handle.clone(),
                        secret_type: format!("{:?}", entry.metadata.secret_type),
                        position: pos,
                        encoding: "raw".to_string(),
                    });
                }

                // Check for base64 encoded
                let base64_encoded = base64::encode(&secret);
                if let Some(pos) = text.find(&base64_encoded) {
                    matches.push(SecretMatch {
                        handle: entry.handle.clone(),
                        secret_type: format!("{:?}", entry.metadata.secret_type),
                        position: pos,
                        encoding: "base64".to_string(),
                    });
                }

                // Check for hex encoded
                let hex_encoded = hex::encode(&secret);
                if let Some(pos) = text.find(&hex_encoded) {
                    matches.push(SecretMatch {
                        handle: entry.handle.clone(),
                        secret_type: format!("{:?}", entry.metadata.secret_type),
                        position: pos,
                        encoding: "hex".to_string(),
                    });
                }

                // Check for URL encoded
                let url_encoded = urlencoding::encode(&secret_str);
                if let Some(pos) = text.find(&url_encoded) {
                    matches.push(SecretMatch {
                        handle: entry.handle.clone(),
                        secret_type: format!("{:?}", entry.metadata.secret_type),
                        position: pos,
                        encoding: "url".to_string(),
                    });
                }
            }
        }

        matches
    }

    /// Check if payload contains any secrets
    pub fn contains_secrets(&self, payload: &[u8]) -> bool {
        !self.scan(payload).is_empty()
    }

    /// Update R for new threshold DH operation
    pub fn update_r(&mut self, R: GroupElement) {
        self.R = R;
    }
}
