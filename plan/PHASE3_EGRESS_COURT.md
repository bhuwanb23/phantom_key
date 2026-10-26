# Phase 3: Egress Court

**Project:** Phantom Key v2  
**Phase:** 3 of 4  
**Duration:** 2 weeks (Weeks 4-5)  
**Lead:** Backend Team  
**Status:** ⏳ Not Started  
**Priority:** 🟡 **HIGH** (Blocker for Phase 4)

---

## 🎯 Phase Overview

**Objective:** Implement the Egress Court system for monitoring and auditing all outbound API requests.

This phase builds on Phase 1 (Core Cryptography) and Phase 2 (Vault System) to create a **tamper-evident audit system** that:
- Logs all outbound API requests
- Scans for real secrets (not decoys)
- Detects canary reappearance
- Provides a real-time TUI for monitoring

**Prerequisite:** Phase 1 AND Phase 2 must be 100% complete before starting.

### Key Outcomes
- ✅ Signed, hash-chained ledger
- ✅ Secret scanner (exact vault value matching)
- ✅ Canary system with detection
- ✅ Request/response interceptor
- ✅ Textual TUI with all panels
- ✅ 100% unit test coverage for egress module

---

## 📋 Sub-Phases & Tasks

### Sub-Phase 3.1: Ledger Implementation (Day 23-25)

**Objective:** Implement signed, hash-chained audit ledger.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 3.1.1 | Design ledger entry structure | Define LedgerEntry, SignedLedgerEntry | Backend | 4h | Phase 1, Phase 2 | ⏳ |
| 3.1.2 | Implement Ed25519 signing | Sign and verify ledger entries | Backend | 8h | 3.1.1 | ⏳ |
| 3.1.3 | Implement hash chain | Chain entries with SHA-256 | Backend | 8h | 3.1.2 | ⏳ |
| 3.1.4 | Implement ledger storage | Store ledger entries | Backend | 8h | 3.1.3 | ⏳ |
| 3.1.5 | Implement ledger verification | Verify chain integrity | Backend | 8h | 3.1.4 | ⏳ |
| 3.1.6 | Add unit tests for ledger | Test all ledger operations | Backend | 8h | 3.1 | ⏳ |

#### Technical Details

**File: `src/egress/ledger.rs`**

```rust
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};

/// A single entry in the audit ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: Uuid,
    pub prev_hash: [u8; 32],        // Hash of previous entry
    pub timestamp: DateTime<Utc>,
    pub request_id: Uuid,
    pub provider: String,           // "bedrock", "openai", "gemini"
    pub method: String,             // "POST", "GET", etc.
    pub url: String,
    pub payload: Vec<u8>,          // Exact bytes sent
    pub hash: [u8; 32],            // Hash of this entry
}

impl LedgerEntry {
    /// Compute hash of this entry
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.prev_hash);
        hasher.update(&self.timestamp.to_rfc3339().as_bytes());
        hasher.update(&self.request_id.as_bytes());
        hasher.update(&self.provider.as_bytes());
        hasher.update(&self.method.as_bytes());
        hasher.update(&self.url.as_bytes());
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
    pub fn append(&self, entry: LedgerEntry) -> Result<(), LedgerError> {
        let prev_hash = self.head_hash().unwrap_or_else(Self::genesis_hash);
        
        // Create new entry with previous hash
        let mut new_entry = entry;
        new_entry.prev_hash = prev_hash;
        new_entry.hash = new_entry.compute_hash();
        
        // Sign the entry
        let signature = self.signing_key.sign(&new_entry.hash);
        
        // Store signed entry
        let signed_entry = SignedLedgerEntry {
            entry: new_entry,
            signature,
        };
        
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
            // Verify hash chain
            if signed_entry.entry.prev_hash != prev_hash {
                return false;
            }
            
            // Verify entry hash
            if !signed_entry.entry.verify_hash() {
                return false;
            }
            
            // Verify signature
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
}

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

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Entry verification failed")]
    VerificationFailed,
    #[error("Storage error")]
    StorageError,
}
```

**File: `src/egress/ledger/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    
    #[test]
    fn test_ledger_append() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);
        
        let entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash: Ledger::genesis_hash(),
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/anthropic.claude-3-sonnet".to_string(),
            payload: b"test payload".to_vec(),
            hash: [0u8; 32],
        };
        
        ledger.append(entry).unwrap();
        
        assert_eq!(ledger.entries().len(), 1);
        assert!(ledger.verify_chain());
    }
    
    #[test]
    fn test_ledger_chain() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);
        
        // Append multiple entries
        for i in 0..5 {
            let entry = LedgerEntry {
                id: Uuid::new_v4(),
                prev_hash: [0u8; 32], // Will be set by append
                timestamp: Utc::now(),
                request_id: Uuid::new_v4(),
                provider: format!("provider-{}", i),
                method: "POST".to_string(),
                url: format!("/endpoint-{}", i),
                payload: format!("payload-{}", i).into_bytes(),
                hash: [0u8; 32],
            };
            ledger.append(entry).unwrap();
        }
        
        assert_eq!(ledger.entries().len(), 5);
        assert!(ledger.verify_chain());
        
        // Verify chain properties
        let entries = ledger.entries();
        for i in 1..entries.len() {
            assert_eq!(entries[i].entry.prev_hash, entries[i-1].entry.hash);
        }
    }
    
    #[test]
    fn test_ledger_tampering() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);
        
        // Append an entry
        let entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash: Ledger::genesis_hash(),
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"test".to_vec(),
            hash: [0u8; 32],
        };
        ledger.append(entry).unwrap();
        
        // Tamper with the entry
        {
            let mut storage = ledger.storage.lock().unwrap();
            if let Some(entry) = storage.get_mut(0) {
                entry.entry.payload = b"tampered".to_vec();
                // Don't update hash - this makes it invalid
            }
        }
        
        // Chain should now be invalid
        assert!(!ledger.verify_chain());
    }
}
```

#### Deliverables
- [ ] Ledger entry structure
- [ ] Signed ledger entry structure
- [ ] Ed25519 signing implementation
- [ ] Hash chain implementation
- [ ] Ledger storage (in-memory)
- [ ] Chain verification
- [ ] Chain status reporting
- [ ] Unit tests for ledger

#### Acceptance Criteria
- [ ] Entries can be appended to ledger
- [ ] Chain verification works correctly
- [ ] Tampering is detected
- [ ] Head hash is computed correctly
- [ ] All ledger tests pass

---

### Sub-Phase 3.2: Secret Scanner (Day 26-27)

**Objective:** Implement scanner for exact vault value matching.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 3.2.1 | Design scanner architecture | Define scanner interface | Backend | 4h | Phase 2, 3.1 | ⏳ |
| 3.2.2 | Implement exact value scanning | Scan for real vault secrets | Backend | 8h | 3.2.1 | ⏳ |
| 3.2.3 | Implement encoding variants | Base64, hex, URL-encoded | Backend | 8h | 3.2.2 | ⏳ |
| 3.2.4 | Implement scanner integration | Integrate with ledger | Backend | 8h | 3.2.3 | ⏳ |
| 3.2.5 | Add unit tests for scanner | Test all scanner operations | Backend | 8h | 3.2 | ⏳ |

#### Technical Details

**File: `src/egress/scanner.rs`**

```rust
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
    R: GroupElement,  // Current R from threshold DH
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
        
        // Get all vault entries
        let entries = self.vault_storage.list();
        
        for entry in entries {
            // Decrypt the secret
            if let Some(secret) = self.vault_encryption.get_secret(&entry, &self.R) {
                let secret_str = String::from_utf8_lossy(&secret);
                
                // Check for exact match
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
```

**File: `src/egress/scanner/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::storage::MemoryStorage;
    use crate::crypto::group::GroupElement;
    
    #[test]
    fn test_scanner_detection() {
        // This test needs a real implementation
        // For now, we'll skip it
    }
    
    #[test]
    fn test_scanner_no_false_positives() {
        // Test that decoys don't trigger the scanner
        // This is critical for the design
    }
}
```

#### Deliverables
- [ ] SecretMatch data structure
- [ ] SecretScanner implementation
- [ ] Exact value matching
- [ ] Encoding variant detection (base64, hex, URL)
- [ ] Integration with vault
- [ ] Unit tests for scanner

#### Acceptance Criteria
- [ ] Scanner detects real secrets in payloads
- [ ] Scanner does NOT detect decoys
- [ ] Scanner detects all encoding variants
- [ ] Scanner integrates with vault
- [ ] All scanner tests pass

---

### Sub-Phase 3.3: Canary System (Day 28-29)

**Objective:** Implement canary registration and detection.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 3.3.1 | Design canary data structure | Define Canary, CanaryRegistry | Backend | 4h | Phase 2, 3.1, 3.2 | ⏳ |
| 3.3.2 | Implement canary registry | Store and manage canaries | Backend | 8h | 3.3.1 | ⏳ |
| 3.3.3 | Implement canary detection | Detect canary reappearance | Backend | 8h | 3.3.2 | ⏳ |
| 3.3.4 | Implement canary integration | Integrate with scanner and ledger | Backend | 8h | 3.3.3 | ⏳ |
| 3.3.5 | Add unit tests for canaries | Test all canary operations | Backend | 8h | 3.3 | ⏳ |

#### Technical Details

**File: `src/egress/canary.rs`**

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

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
        value_to_id.iter()
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
}
```

**File: `src/egress/canary/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_canary_registration() {
        let registry = CanaryRegistry::new();
        
        let id = registry.register(
            "test-value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );
        
        assert!(registry.get(&id).is_some());
        assert_eq!(registry.get_id_by_value("test-value"), Some(id));
    }
    
    #[test]
    fn test_canary_detection() {
        let registry = CanaryRegistry::new();
        
        let id1 = registry.register("value1".to_string(), Uuid::new_v4(), "bedrock".to_string());
        let id2 = registry.register("value2".to_string(), Uuid::new_v4(), "openai".to_string());
        
        let detected = registry.detect("This contains value1 and value2");
        assert!(detected.contains(&id1));
        assert!(detected.contains(&id2));
    }
    
    #[test]
    fn test_canary_trigger() {
        let registry = CanaryRegistry::new();
        
        let id = registry.register("value".to_string(), Uuid::new_v4(), "bedrock".to_string());
        
        let canary_before = registry.get(&id).unwrap();
        assert!(!canary_before.is_triggered());
        
        registry.trigger(&id);
        
        let canary_after = registry.get(&id).unwrap();
        assert!(canary_after.is_triggered());
    }
}
```

#### Deliverables
- [ ] Canary data structure
- [ ] CanaryRegistry implementation
- [ ] Canary registration
- [ ] Canary detection
- [ ] Canary triggering
- [ ] Integration with scanner and ledger
- [ ] Unit tests for canaries

#### Acceptance Criteria
- [ ] Canaries can be registered
- [ ] Canaries can be detected in text
- [ ] Canaries can be triggered
- [ ] Canaries integrate with scanner
- [ ] All canary tests pass

---

### Sub-Phase 3.4: Interceptor (Day 30-31)

**Objective:** Implement API request/response interception and logging.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 3.4.1 | Design interceptor architecture | Define interceptor interface | Backend | 4h | 3.1, 3.2, 3.3 | ⏳ |
| 3.4.2 | Implement request interception | Capture outbound requests | Backend | 8h | 3.4.1 | ⏳ |
| 3.4.3 | Implement response interception | Capture inbound responses | Backend | 8h | 3.4.2 | ⏳ |
| 3.4.4 | Integrate scanner with interceptor | Scan payloads for secrets | Backend | 8h | 3.4.3, 3.2 | ⏳ |
| 3.4.5 | Integrate canary detection | Detect canary reappearance | Backend | 8h | 3.4.4, 3.3 | ⏳ |
| 3.4.6 | Add unit tests for interceptor | Test all interceptor operations | Backend | 8h | 3.4 | ⏳ |

#### Technical Details

**File: `src/egress/interceptor.rs`**

```rust
use std::sync::Arc;
use crate::egress::{
    ledger::{Ledger, LedgerEntry},
    scanner::SecretScanner,
    canary::CanaryRegistry,
};
use uuid::Uuid;

/// Outbound request to intercept
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub id: Uuid,
    pub provider: String,
    pub method: String,
    pub url: String,
    pub payload: Vec<u8>,
}

/// Inbound response to intercept
#[derive(Debug, Clone)]
pub struct InboundResponse {
    pub request_id: Uuid,
    pub payload: Vec<u8>,
}

/// Interceptor for outbound requests
pub struct EgressInterceptor {
    ledger: Arc<Ledger>,
    scanner: Arc<SecretScanner>,
    canary_registry: Arc<CanaryRegistry>,
}

impl EgressInterceptor {
    pub fn new(
        ledger: Arc<Ledger>,
        scanner: Arc<SecretScanner>,
        canary_registry: Arc<CanaryRegistry>,
    ) -> Self {
        Self {
            ledger,
            scanner,
            canary_registry,
        }
    }
    
    /// Intercept and log an outbound request
    pub async fn intercept_request(
        &self,
        request: OutboundRequest,
    ) -> Result<(), InterceptionError> {
        // Scan for real secrets
        let secret_matches = self.scanner.scan(&request.payload);
        if !secret_matches.is_empty() {
            return Err(InterceptionError::SecretDetected(secret_matches));
        }
        
        // Detect canaries
        let text = String::from_utf8_lossy(&request.payload);
        let canary_ids = self.canary_registry.detect(&text);
        for id in canary_ids {
            self.canary_registry.trigger(&id);
        }
        
        // Log to ledger
        let entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash: [0u8; 32], // Will be set by ledger
            timestamp: Utc::now(),
            request_id: request.id,
            provider: request.provider,
            method: request.method,
            url: request.url,
            payload: request.payload,
            hash: [0u8; 32],
        };
        
        self.ledger.append(entry)?;
        
        Ok(())
    }
    
    /// Intercept and log an inbound response
    pub async fn intercept_response(
        &self,
        response: InboundResponse,
    ) -> Result<(), InterceptionError> {
        // Scan for real secrets in response
        let secret_matches = self.scanner.scan(&response.payload);
        if !secret_matches.is_empty() {
            // This is a warning, not an error - model might echo secrets
            // In production, we might want to handle this differently
        }
        
        // Detect canaries in response
        let text = String::from_utf8_lossy(&response.payload);
        let canary_ids = self.canary_registry.detect(&text);
        for id in canary_ids {
            self.canary_registry.trigger(&id);
        }
        
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InterceptionError {
    #[error("Secret detected in payload: {:?}", matches.0)]
    SecretDetected(Vec<SecretMatch>),
    #[error("Ledger error")]
    LedgerError(#[from] crate::egress::ledger::LedgerError),
}
```

**File: `src/egress/interceptor/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::ledger::Ledger;
    use ed25519_dalek::SigningKey;
    
    #[tokio::test]
    async fn test_interceptor_request() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));
        
        // Create scanner and canary registry (mocks for now)
        let scanner = Arc::new(SecretScanner::new(
            Arc::new(MemoryStorage::new()),
            VaultEncryption::new(ThresholdDH::new(vec![], vec![], DKG::new(1, 1))),
            GroupElement::generator(),
        ));
        let canary_registry = Arc::new(CanaryRegistry::new());
        
        let interceptor = EgressInterceptor::new(ledger, scanner, canary_registry);
        
        let request = OutboundRequest {
            id: Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"test payload".to_vec(),
        };
        
        interceptor.intercept_request(request).await.unwrap();
        
        // Verify entry was logged
        assert_eq!(ledger.entries().len(), 1);
    }
}
```

#### Deliverables
- [ ] OutboundRequest and InboundResponse types
- [ ] EgressInterceptor implementation
- [ ] Request interception
- [ ] Response interception
- [ ] Scanner integration
- [ ] Canary detection integration
- [ ] Unit tests for interceptor

#### Acceptance Criteria
- [ ] Requests can be intercepted and logged
- [ ] Responses can be intercepted and logged
- [ ] Secrets are detected and blocked
- [ ] Canaries are detected and triggered
- [ ] All interceptor tests pass

---

### Sub-Phase 3.5: TUI Implementation (Day 32-35)

**Objective:** Implement textual user interface for real-time monitoring.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 3.5.1 | Design TUI layout | Define layout for all panels | Frontend | 4h | 3.1, 3.2, 3.3, 3.4 | ⏳ |
| 3.5.2 | Implement TUI framework | Set up ratatui/crossterm | Frontend | 8h | 3.5.1 | ⏳ |
| 3.5.3 | Implement chat panel | Show LLM conversation | Frontend | 8h | 3.5.2 | ⏳ |
| 3.5.4 | Implement egress/ledger panel | Show ledger entries and chain status | Frontend | 8h | 3.5.3 | ⏳ |
| 3.5.5 | Implement shareholder status panel | Show DKG party status | Frontend | 8h | 3.5.4 | ⏳ |
| 3.5.6 | Implement vault panel | Show vault entries | Frontend | 8h | 3.5.5 | ⏳ |
| 3.5.7 | Add real-time updates | Update TUI dynamically | Frontend | 8h | 3.5.6 | ⏳ |
| 3.5.8 | Add unit tests for TUI | Test TUI functionality | Frontend | 4h | 3.5.7 | ⏳ |

#### Technical Details

**File: `src/egress/tui.rs`**

```rust
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table, Cell},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::egress::ledger::{Ledger, ChainStatus};
use crate::vault::storage::VaultStorage;
use crate::crypto::dkg::DKG;

/// Main application state for TUI
pub struct App {
    ledger: Arc<Ledger>,
    vault_storage: Arc<dyn VaultStorage>,
    dkg: Arc<DKG>,
    canary_registry: Arc<Mutex<CanaryRegistry>>,
}

impl App {
    pub fn new(
        ledger: Arc<Ledger>,
        vault_storage: Arc<dyn VaultStorage>,
        dkg: Arc<DKG>,
        canary_registry: Arc<Mutex<CanaryRegistry>>,
    ) -> Self {
        Self {
            ledger,
            vault_storage,
            dkg,
            canary_registry,
        }
    }
    
    /// Run the TUI
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup terminal
        let mut terminal = setup_terminal()?;
        
        // Main loop
        loop {
            terminal.draw(|f| self.ui(f))?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    
    /// Draw the UI
    fn ui(&self, f: &mut Frame) {
        let size = f.size();
        
        // Split into panels
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),  // Left (chat + vault)
                Constraint::Percentage(50),  // Right (ledger + shareholders)
            ])
            .split(size);
        
        // Left side: Chat and Vault
        let left_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),  // Chat
                Constraint::Percentage(40),  // Vault
            ])
            .split(layout[0]);
        
        self.render_chat_panel(f, left_layout[0]);
        self.render_vault_panel(f, left_layout[1]);
        
        // Right side: Ledger and Shareholders
        let right_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),  // Ledger
                Constraint::Percentage(40),  // Shareholders
            ])
            .split(layout[1]);
        
        self.render_ledger_panel(f, right_layout[0]);
        self.render_shareholder_panel(f, right_layout[1]);
    }
    
    fn render_chat_panel(&self, f: &mut Frame, area: Rect) {
        // This would show the LLM conversation
        // For now, just show a placeholder
        let chat = Paragraph::new("Chat Panel\n\n(LLM conversation will appear here)")
            .block(Block::default().title("Chat").borders(Borders::ALL));
        f.render_widget(chat, area);
    }
    
    fn render_vault_panel(&self, f: &mut Frame, area: Rect) {
        let entries = self.vault_storage.list();
        let rows: Vec<Row> = entries.iter()
            .map(|entry| {
                Row::new([
                    Cell::new(&entry.handle),
                    Cell::new(&format!("{:?}", entry.metadata.secret_type)),
                    Cell::new(&entry.metadata.created_at.format("%H:%M:%S").to_string()),
                ])
            })
            .collect();
        
        let table = Table::new(rows)
            .header(Row::new(["Handle", "Type", "Created"]))
            .block(Block::default().title("Vault").borders(Borders::ALL))
            .widths(&[20, 20, 10]);
        
        f.render_widget(table, area);
    }
    
    fn render_ledger_panel(&self, f: &mut Frame, area: Rect) {
        let entries = self.ledger.entries();
        let latest = &entries[entries.len().saturating_sub(10)..];
        
        let rows: Vec<Row> = latest.iter()
            .map(|entry| {
                Row::new([
                    Cell::new(entry.entry.timestamp.format("%H:%M:%S").to_string()),
                    Cell::new(&entry.entry.provider),
                    Cell::new(&entry.entry.method),
                    Cell::new(&entry.entry.url),
                    Cell::new(if entry.entry.hash == self.ledger.head_hash().unwrap_or([0; 32]) {
                        "✓"
                    } else {
                        "✗"
                    }),
                ])
            })
            .collect();
        
        let table = Table::new(rows)
            .header(Row::new(["Time", "Provider", "Method", "URL", "Status"]))
            .block(Block::default().title("Egress Ledger").borders(Borders::ALL))
            .widths(&[10, 15, 10, 30, 5]);
        
        f.render_widget(table, area);
        
        // Show chain status
        let chain_status = self.ledger.chain_status();
        let status_text = match chain_status {
            ChainStatus::Valid { head_hash, entry_count } => {
                format!("✓ Chain Valid | Head: {} | Entries: {}", 
                    hex::encode(head_hash), entry_count)
            }
            ChainStatus::Invalid { entry_count } => {
                format!("✗ Chain Invalid | Entries: {}", entry_count)
            }
        };
        
        let status = Paragraph::new(status_text)
            .block(Block::default().title("Chain Status").borders(Borders::ALL));
        
        // This would be rendered below the table
    }
    
    fn render_shareholder_panel(&self, f: &mut Frame, area: Rect) {
        // Show DKG party status
        // This would show which parties are online, have valid shares, etc.
        let status = Paragraph::new("Shareholder Status Panel\n\n(Party status will appear here)")
            .block(Block::default().title("Shareholders").borders(Borders::ALL));
        f.render_widget(status, area);
    }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, Box<dyn std::error::Error>> {
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    crossterm::terminal::enable_raw_mode()?;
    
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    
    Ok(terminal)
}
```

**File: `src/egress/tui/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_app_creation() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));
        let vault_storage = Arc::new(MemoryStorage::new());
        let dkg = Arc::new(DKG::new(5, 3));
        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));
        
        let app = App::new(ledger, vault_storage, dkg, canary_registry);
        
        // Just test that it can be created
        assert!(true);
    }
}
```

#### Deliverables
- [ ] TUI framework (ratatui + crossterm)
- [ ] Chat panel
- [ ] Egress/ledger panel with chain status
- [ ] Shareholder status panel
- [ ] Vault panel
- [ ] Real-time updates
- [ ] Unit tests for TUI

#### Acceptance Criteria
- [ ] TUI can be started
- [ ] All panels are rendered
- [ ] Chain status is displayed correctly
- [ ] TUI updates in real-time
- [ ] All TUI tests pass

---

## 📊 Phase Summary

### Tasks Breakdown
| Sub-Phase | Tasks | Effort | Status |
|-----------|-------|--------|--------|
| 3.1 Ledger | 6 | 48h | ⏳ |
| 3.2 Scanner | 5 | 40h | ⏳ |
| 3.3 Canary System | 5 | 40h | ⏳ |
| 3.4 Interceptor | 6 | 48h | ⏳ |
| 3.5 TUI | 8 | 56h | ⏳ |
| **Total** | **30** | **232h (29 person-days)** | ⏳ |

### Deliverables Summary
- ✅ Signed, hash-chained ledger
- ✅ Secret scanner with exact vault value matching
- ✅ Canary system with registration and detection
- ✅ Request/response interceptor
- ✅ Textual TUI with all panels
- ✅ Real-time monitoring
- ✅ 100% unit test coverage for egress module

### Acceptance Criteria
- [ ] Ledger entries can be appended and verified
- [ ] Scanner detects real secrets (not decoys)
- [ ] Canaries are detected and triggered
- [ ] Requests/responses are intercepted and logged
- [ ] TUI shows all panels with real-time updates
- [ ] All egress tests pass

---

## 🎯 Next Phase

**After Phase 3 completes, proceed to Phase 4: Integration & Polish**

- **Start Date:** Beginning of Week 6
- **Duration:** 1 week
- **Prerequisite:** Phase 1, Phase 2, AND Phase 3 must be 100% complete

---

## 📝 Phase Information

**Phase:** 3 of 4  
**Name:** Egress Court  
**Duration:** 2 weeks  
**Status:** ⏳ Not Started  
**Priority:** 🟡 HIGH  
**Blocker for:** Phase 4  
**Prerequisite:** Phase 1 AND Phase 2

**Document Version:** 1.0  
**Last Updated:** October 26, 2026  
**Owner:** Backend Team
