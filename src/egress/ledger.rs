//! Signed, Hash-Chained Audit Ledger
//!
//! This module implements a tamper-evident audit log using
//! Ed25519 signatures and SHA-256 hash chains.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};

/// A single entry in the audit ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: Uuid,
    pub prev_hash: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub request_id: Uuid,
    pub provider: String,
    pub method: String,
    pub url: String,
    pub payload: Vec<u8>,
    pub hash: [u8; 32],
}

impl LedgerEntry {
    /// Compute hash of this entry
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.prev_hash);
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.provider.as_bytes());
        hasher.update(self.method.as_bytes());
        hasher.update(self.url.as_bytes());
        hasher.update(&self.payload);
        hasher.finalize().into()
    }

    /// Verify this entry's hash
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

/// A signed ledger entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLedgerEntry {
    pub entry: LedgerEntry,
    pub signature: Signature,
}

impl SignedLedgerEntry {
    /// Verify the signature
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        verifying_key.verify(&self.entry.hash, &self.signature).is_ok()
    }
}

/// Chain status
#[derive(Debug, Clone)]
pub enum ChainStatus {
    Valid {
        head_hash: [u8; 32],
        entry_count: usize,
    },
    Invalid {
        entry_count: usize,
    },
}

/// Ledger error type
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Entry verification failed")]
    VerificationFailed,
    #[error("Storage error")]
    StorageError,
}

/// The audit ledger
pub struct Ledger {
    storage: Arc<Mutex<VecDeque<SignedLedgerEntry>>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ledger {
    pub fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            storage: Arc::new(Mutex::new(VecDeque::new())),
            signing_key,
            verifying_key,
        }
    }

    /// Get the genesis hash (all zeros)
    pub fn genesis_hash() -> [u8; 32] {
        [0u8; 32]
    }

    /// Get the current head hash
    pub fn head_hash(&self) -> Option<[u8; 32]> {
        let storage = self.storage.lock().unwrap();
        storage.back().map(|entry| entry.entry.hash)
    }

    /// Append a new entry to the ledger
    pub fn append(&self, mut entry: LedgerEntry) -> Result<(), LedgerError> {
        let prev_hash = self.head_hash().unwrap_or_else(Self::genesis_hash);

        entry.prev_hash = prev_hash;
        entry.hash = entry.compute_hash();

        let signature = self.signing_key.sign(&entry.hash);

        let signed_entry = SignedLedgerEntry { entry, signature };

        self.storage.lock().unwrap().push_back(signed_entry);

        Ok(())
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<SignedLedgerEntry> {
        self.storage.lock().unwrap().iter().cloned().collect()
    }

    /// Get entry by ID
    pub fn get(&self, id: &Uuid) -> Option<SignedLedgerEntry> {
        self.entries().into_iter().find(|e| e.entry.id == *id)
    }

    /// Verify the entire chain
    pub fn verify_chain(&self) -> bool {
        let entries = self.entries();
        let mut prev_hash = Self::genesis_hash();

        for signed_entry in &entries {
            if signed_entry.entry.prev_hash != prev_hash {
                return false;
            }

            if !signed_entry.entry.verify_hash() {
                return false;
            }

            if !signed_entry.verify(&self.verifying_key) {
                return false;
            }

            prev_hash = signed_entry.entry.hash;
        }

        true
    }

    /// Get chain status
    pub fn chain_status(&self) -> ChainStatus {
        if self.verify_chain() {
            ChainStatus::Valid {
                head_hash: self.head_hash().unwrap_or([0u8; 32]),
                entry_count: self.entries().len(),
            }
        } else {
            ChainStatus::Invalid {
                entry_count: self.entries().len(),
            }
        }
    }

    /// Get entries since a specific timestamp
    pub fn entries_since(&self, timestamp: DateTime<Utc>) -> Vec<SignedLedgerEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.entry.timestamp >= timestamp)
            .collect()
    }

    /// Clear all entries (for testing)
    pub fn clear(&self) {
        self.storage.lock().unwrap().clear();
    }
}
