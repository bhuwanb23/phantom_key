//! Vault Storage Backend
//!
//! This module provides the storage backend for the vault system,
//! supporting both in-memory and SQLite storage.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Type of secret stored in vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    AwsSessionToken,
    IbAN,
    CreditCard,
    ApiKey,
    Password,
    Generic,
    Custom(String),
}

impl Default for SecretType {
    fn default() -> Self {
        Self::Generic
    }
}

/// Metadata about a vault entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub secret_type: SecretType,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub access_count: u64,
}

impl Default for VaultMetadata {
    fn default() -> Self {
        Self {
            created_at: Utc::now(),
            updated_at: Utc::now(),
            secret_type: SecretType::default(),
            description: None,
            tags: Vec::new(),
            access_count: 0,
        }
    }
}

/// A single entry in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    pub handle: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub metadata: VaultMetadata,
}

/// Storage backend trait for flexibility
pub trait VaultStorage: Send + Sync {
    fn get(&self, id: &Uuid) -> Option<VaultEntry>;
    fn get_by_handle(&self, handle: &str) -> Option<VaultEntry>;
    fn insert(&mut self, entry: VaultEntry) -> Uuid;
    fn update(&mut self, entry: VaultEntry) -> bool;
    fn delete(&mut self, id: &Uuid) -> bool;
    fn list(&self) -> Vec<VaultEntry>;
    fn search(&self, query: &str) -> Vec<VaultEntry>;
}

/// In-memory storage for development/testing
#[derive(Debug, Default)]
pub struct MemoryStorage {
    entries: Arc<Mutex<HashMap<Uuid, VaultEntry>>>,
    handle_index: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            handle_index: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl VaultStorage for MemoryStorage {
    fn get(&self, id: &Uuid) -> Option<VaultEntry> {
        self.entries.lock().unwrap().get(id).cloned()
    }

    fn get_by_handle(&self, handle: &str) -> Option<VaultEntry> {
        let id = self.handle_index.lock().unwrap().get(handle)?;
        self.get(id)
    }

    fn insert(&mut self, mut entry: VaultEntry) -> Uuid {
        let id = entry.id;
        {
            let mut entries = self.entries.lock().unwrap();
            let mut handle_index = self.handle_index.lock().unwrap();
            entries.insert(id, entry.clone());
            handle_index.insert(entry.handle.clone(), id);
        }
        id
    }

    fn update(&mut self, entry: VaultEntry) -> bool {
        let mut entries = self.entries.lock().unwrap();
        if let Some(existing) = entries.get_mut(&entry.id) {
            *existing = entry.clone();
            true
        } else {
            false
        }
    }

    fn delete(&mut self, id: &Uuid) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let mut handle_index = self.handle_index.lock().unwrap();
        if let Some(entry) = entries.remove(id) {
            handle_index.remove(&entry.handle);
            true
        } else {
            false
        }
    }

    fn list(&self) -> Vec<VaultEntry> {
        self.entries.lock().unwrap().values().cloned().collect()
    }

    fn search(&self, query: &str) -> Vec<VaultEntry> {
        self.list().into_iter()
            .filter(|entry| {
                entry.handle.contains(query)
                    || entry.metadata.description.as_ref().map_or(false, |d| d.contains(query))
                    || entry.metadata.tags.iter().any(|t| t.contains(query))
            })
            .collect()
    }
}
