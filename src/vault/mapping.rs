//! Decoy-to-Handle Mapping
//!
//! This module provides the mapping between decoys and handles,
//! allowing the system to replace real secrets with decoys in prompts
//! while maintaining the ability to retrieve the real secrets.

use super::{
    handle::Handle,
    storage::{VaultEntry, VaultMetadata, VaultStorage},
    decoy::DecoyRegistry,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use crate::crypto::group::GroupElement;

/// Mapping between decoys and handles
#[derive(Debug, Default)]
pub struct DecoyMap {
    decoy_to_handle: HashMap<String, Handle>,
    handle_to_decoy: HashMap<Handle, String>,
}

impl DecoyMap {
    pub fn new() -> Self {
        Self {
            decoy_to_handle: HashMap::new(),
            handle_to_decoy: HashMap::new(),
        }
    }

    /// Register a new decoy-to-handle mapping
    pub fn register(&mut self, handle: Handle, decoy: String) {
        self.decoy_to_handle.insert(decoy.clone(), handle.clone());
        self.handle_to_decoy.insert(handle, decoy);
    }

    /// Get handle for a decoy
    pub fn get_handle(&self, decoy: &str) -> Option<&Handle> {
        self.decoy_to_handle.get(decoy)
    }

    /// Get decoy for a handle
    pub fn get_decoy(&self, handle: &Handle) -> Option<&String> {
        self.handle_to_decoy.get(handle)
    }

    /// Remove a mapping
    pub fn remove(&mut self, handle: &Handle) -> Option<String> {
        if let Some(decoy) = self.handle_to_decoy.remove(handle) {
            self.decoy_to_handle.remove(&decoy);
            Some(decoy)
        } else {
            None
        }
    }

    /// Clear all mappings
    pub fn clear(&mut self) {
        self.decoy_to_handle.clear();
        self.handle_to_decoy.clear();
    }

    /// Get number of mappings
    pub fn len(&self) -> usize {
        self.decoy_to_handle.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.decoy_to_handle.is_empty()
    }
}

/// Decoy manager combining registry, mapping, and vault
pub struct DecoyManager {
    registry: DecoyRegistry,
    mapping: Arc<Mutex<DecoyMap>>,
    storage: Arc<dyn VaultStorage>,
}

impl DecoyManager {
    pub fn new(
        registry: DecoyRegistry,
        mapping: Arc<Mutex<DecoyMap>>,
        storage: Arc<dyn VaultStorage>,
    ) -> Self {
        Self {
            registry,
            mapping,
            storage,
        }
    }

    /// Store a secret and return its handle
    pub fn store_secret(
        &self,
        secret: &[u8],
        secret_type: SecretType,
        R: &GroupElement,
    ) -> Handle {
        use super::encryption::VaultEncryption;

        let handle = Handle::new();
        let decoy = self.registry.generate(&secret_type);

        let metadata = VaultMetadata {
            secret_type,
            description: Some(format!("Generated decoy: {}", decoy)),
            ..Default::default()
        };

        let entry = VaultEncryption::create_entry(secret, R, handle.to_string(), metadata);
        let _ = self.storage.insert(entry);

        self.mapping.lock().unwrap().register(handle.clone(), decoy);

        handle
    }

    /// Get real secret from a decoy
    pub fn get_secret_from_decoy(
        &self,
        decoy: &str,
        R: &GroupElement,
    ) -> Option<Vec<u8>> {
        use super::encryption::VaultEncryption;

        let handle = self.mapping.lock().unwrap().get_handle(decoy)?;
        let entry = self.storage.get_by_handle(&handle.to_string())?;
        VaultEncryption::get_secret(&entry, R)
    }

    /// Get decoy from a handle
    pub fn get_decoy_from_handle(&self, handle: &Handle) -> Option<String> {
        self.mapping.lock().unwrap().get_decoy(handle).cloned()
    }

    /// Get vault entry from handle
    pub fn get_entry_from_handle(&self, handle: &Handle) -> Option<VaultEntry> {
        self.storage.get_by_handle(&handle.to_string())
    }

    /// Process a prompt: find secrets, replace with decoys, store real secrets
    pub fn process_prompt(
        &self,
        prompt: &str,
        R: &GroupElement,
    ) -> (String, Vec<Handle>) {
        let mut processed = prompt.to_string();
        let mut handles = Vec::new();

        // Simple pattern matching for demonstration
        // In production, use regex to detect potential secrets

        // AWS Access Key pattern
        if let Some(pos) = processed.find("AKIA") {
            let handle = self.store_secret(
                b"fake-aws-access-key",
                SecretType::AwsAccessKey,
                R,
            );
            if let Some(decoy) = self.get_decoy_from_handle(&handle) {
                processed = processed.replace("AKIA", &decoy);
                handles.push(handle);
            }
        }

        // IBAN pattern
        if let Some(pos) = processed.find("DE") {
            if processed[pos..].chars().take(2).all(|c| c.is_ascii_uppercase())
                && processed[pos + 2..].chars().take(2).all(|c| c.is_ascii_digit())
            {
                let handle = self.store_secret(
                    b"fake-iban",
                    SecretType::IbAN,
                    R,
                );
                if let Some(decoy) = self.get_decoy_from_handle(&handle) {
                    // Replace the found IBAN-like pattern
                    processed = processed.replace(&processed[pos..pos + 22], &decoy);
                    handles.push(handle);
                }
            }
        }

        (processed, handles)
    }
}
