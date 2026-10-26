//! Canary System
//!
//! Implements canary tokens for detecting data reappearance.
//! Provides best-effort detection when secrets appear in unexpected places.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// A canary token for detecting data reappearance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub id: Uuid,
    pub value: String,
    pub request_id: Uuid,
    pub provider: String,
    pub created_at: DateTime<Utc>,
    pub triggered_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

impl Canary {
    pub fn new(value: String, request_id: Uuid, provider: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            value,
            request_id,
            provider,
            created_at: Utc::now(),
            triggered_at: None,
            metadata: HashMap::new(),
        }
    }

    pub fn trigger(&mut self) {
        self.triggered_at = Some(Utc::now());
    }

    pub fn is_triggered(&self) -> bool {
        self.triggered_at.is_some()
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Registry for tracking canaries
pub struct CanaryRegistry {
    canaries: Arc<Mutex<HashMap<Uuid, Canary>>>,
    value_to_id: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl CanaryRegistry {
    pub fn new() -> Self {
        Self {
            canaries: Arc::new(Mutex::new(HashMap::new())),
            value_to_id: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new canary
    pub fn register(&self, value: String, request_id: Uuid, provider: String) -> Uuid {
        let mut canaries = self.canaries.lock().unwrap();
        let mut value_to_id = self.value_to_id.lock().unwrap();

        let id = Uuid::new_v4();
        let canary = Canary::new(value.clone(), request_id, provider);

        canaries.insert(id, canary);
        value_to_id.insert(value, id);

        id
    }

    /// Get canary by ID
    pub fn get(&self, id: &Uuid) -> Option<Canary> {
        self.canaries.lock().unwrap().get(id).cloned()
    }

    /// Get canary ID by value
    pub fn get_id_by_value(&self, value: &str) -> Option<Uuid> {
        self.value_to_id.lock().unwrap().get(value).cloned()
    }

    /// Trigger a canary (mark as detected)
    pub fn trigger(&self, id: &Uuid) -> Option<Canary> {
        let mut canaries = self.canaries.lock().unwrap();
        if let Some(canary) = canaries.get_mut(id) {
            canary.trigger();
            Some(canary.clone())
        } else {
            None
        }
    }

    /// Trigger canary by value
    pub fn trigger_by_value(&self, value: &str) -> Option<Canary> {
        let id = self.get_id_by_value(value)?;
        self.trigger(&id)
    }

    /// Detect canaries in text
    pub fn detect(&self, text: &str) -> Vec<Uuid> {
        let value_to_id = self.value_to_id.lock().unwrap();
        value_to_id
            .iter()
            .filter(|(value, _)| text.contains(value.as_str()))
            .map(|(_, &id)| id)
            .collect()
    }

    /// Get all canaries
    pub fn all(&self) -> Vec<Canary> {
        self.canaries.lock().unwrap().values().cloned().collect()
    }

    /// Get active (non-triggered) canaries
    pub fn active(&self) -> Vec<Canary> {
        self.all().into_iter().filter(|c| !c.is_triggered()).collect()
    }

    /// Get triggered canaries
    pub fn triggered(&self) -> Vec<Canary> {
        self.all().into_iter().filter(|c| c.is_triggered()).collect()
    }

    /// Remove a canary
    pub fn remove(&self, id: &Uuid) -> Option<Canary> {
        let mut canaries = self.canaries.lock().unwrap();
        let mut value_to_id = self.value_to_id.lock().unwrap();

        if let Some(canary) = canaries.remove(id) {
            value_to_id.remove(&canary.value);
            Some(canary)
        } else {
            None
        }
    }

    /// Clear all canaries
    pub fn clear(&self) {
        self.canaries.lock().unwrap().clear();
        self.value_to_id.lock().unwrap().clear();
    }
}

impl Default for CanaryRegistry {
    fn default() -> Self {
        Self::new()
    }
}
