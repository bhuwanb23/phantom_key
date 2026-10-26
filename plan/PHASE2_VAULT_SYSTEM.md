# Phase 2: Vault System

**Project:** Phantom Key v2  
**Phase:** 2 of 4  
**Duration:** 1 week (Week 3)  
**Lead:** Security Team  
**Status:** ⏳ Not Started  
**Priority:** 🟡 **HIGH** (Blocker for Phase 3)

---

## 🎯 Phase Overview

**Objective:** Implement the sealed vault system that protects real secrets while providing decoys to the LLM.

This phase builds on Phase 1 (Core Cryptography) to create a **secure storage system** for secrets that:
- Encrypts each secret with a unique key derived from threshold DH
- Generates format-preserving decoys for LLM prompts
- Manages handles that reference real secrets
- Maintains mappings between decoys and handles

**Prerequisite:** Phase 1 (Core Cryptography) must be 100% complete before starting.

### Key Outcomes
- ✅ Sealed vault with per-secret encryption
- ✅ Handle system for secret references
- ✅ Format-preserving decoy generation
- ✅ Decoy-to-handle mapping
- ✅ 100% unit test coverage for vault module

---

## 📋 Sub-Phases & Tasks

### Sub-Phase 2.1: Vault Storage (Day 15-16)

**Objective:** Implement secure vault storage backend.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 2.1.1 | Design vault data structure | Define VaultEntry, VaultMetadata, etc. | Security | 4h | Phase 1 | ⏳ |
| 2.1.2 | Implement storage backend | SQLite or in-memory storage | Security | 8h | 2.1.1 | ⏳ |
| 2.1.3 | Implement vault encryption at rest | Encrypt vault data on disk | Security | 8h | 2.1.2 | ⏳ |
| 2.1.4 | Implement vault access control | Who can read/write vault | Security | 8h | 2.1.2 | ⏳ |
| 2.1.5 | Add unit tests for vault storage | Test all storage operations | Security | 4h | 2.1 | ⏳ |

#### Technical Details

**File: `src/vault/storage.rs`**

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Type of secret stored in vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
            secret_type: SecretType::Generic,
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
    pub handle: String,           // e.g., "⟦H1⟧"
    pub ciphertext: Vec<u8>,     // Encrypted secret
    pub nonce: Vec<u8>,          // Nonce for AEAD
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

/// In-memory storage (for development/testing)
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
                entry.handle.contains(query) ||
                entry.metadata.description.as_ref().map_or(false, |d| d.contains(query)) ||
                entry.metadata.tags.iter().any(|t| t.contains(query))
            })
            .collect()
    }
}

/// SQLite storage (for production)
pub struct SqliteStorage {
    conn: rusqlite::Connection,
}

impl SqliteStorage {
    pub fn new(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vault_entries (
                id BLOB PRIMARY KEY,
                handle TEXT UNIQUE NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                metadata BLOB NOT NULL
            )",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_handle ON vault_entries(handle)",
            [],
        )?;
        
        Ok(Self { conn })
    }
}

impl VaultStorage for SqliteStorage {
    // Implement all trait methods for SQLite
    // ...
}
```

**File: `src/vault/storage/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_storage() {
        let mut storage = MemoryStorage::new();
        
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H1⟧".to_string(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            metadata: VaultMetadata::default(),
        };
        
        let id = storage.insert(entry.clone());
        
        // Test get by ID
        assert_eq!(storage.get(&id), Some(entry.clone()));
        
        // Test get by handle
        assert_eq!(storage.get_by_handle("⟦H1⟧"), Some(entry));
        
        // Test list
        assert_eq!(storage.list().len(), 1);
    }
    
    #[test]
    fn test_storage_update() {
        let mut storage = MemoryStorage::new();
        
        let mut entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H1⟧".to_string(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            metadata: VaultMetadata::default(),
        };
        
        storage.insert(entry.clone());
        
        // Update
        entry.ciphertext = vec![7, 8, 9];
        assert!(storage.update(entry.clone()));
        
        // Verify update
        assert_eq!(storage.get(&entry.id).unwrap().ciphertext, vec![7, 8, 9]);
    }
}
```

#### Deliverables
- [ ] Vault data structures (VaultEntry, VaultMetadata, SecretType)
- [ ] Storage backend trait
- [ ] In-memory storage implementation
- [ ] SQLite storage implementation
- [ ] Vault encryption at rest
- [ ] Vault access control
- [ ] Unit tests for vault storage

#### Acceptance Criteria
- [ ] Vault entries can be stored and retrieved
- [ ] Vault entries can be searched by handle
- [ ] Vault data is encrypted at rest
- [ ] Access control prevents unauthorized access
- [ ] All storage operations work correctly

---

### Sub-Phase 2.2: Per-Secret Encryption (Day 17-18)

**Objective:** Implement HKDF-based per-secret encryption.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 2.2.1 | Implement HKDF key derivation | HKDF-SHA256 for key derivation | Security | 8h | Phase 1, 2.1 | ⏳ |
| 2.2.2 | Implement per-secret key binding | Bind keys to secret handles | Security | 8h | 2.2.1 | ⏳ |
| 2.2.3 | Implement AEAD encryption | ChaCha20-Poly1305 for encryption | Security | 8h | 2.2.2 | ⏳ |
| 2.2.4 | Implement encryption/decryption | Encrypt and decrypt vault entries | Security | 8h | 2.2.3 | ⏳ |
| 2.2.5 | Add unit tests for encryption | Test all encryption operations | Security | 8h | 2.2 | ⏳ |

#### Technical Details

**File: `src/vault/encryption.rs`**

```rust
use super::storage::{VaultEntry, VaultMetadata, SecretType};
use crate::crypto::{
    group::{GroupElement, GroupScalar},
    threshold_dh::ThresholdDH,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use sha2::Sha256;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// Vault encryption/decryption
pub struct VaultEncryption {
    threshold_dh: ThresholdDH,
}

impl VaultEncryption {
    pub fn new(threshold_dh: ThresholdDH) -> Self {
        Self { threshold_dh }
    }
    
    /// Derive encryption key for a specific secret
    pub fn derive_key(
        &self,
        R: &GroupElement,
        handle: &str,
        context: Option<&[u8]>,
    ) -> Vec<u8> {
        // K = HKDF(s·R, handle || context)
        // where s·R is the threshold DH result
        
        // For now, we'll use a simplified version
        // In production, we'd compute s·R first
        
        let mut hkdf = HmacSha256::new_from_slice(R.to_bytes().as_ref())
            .expect("HKDF init failed");
        
        // Extract
        let mut prk = [0u8; 32];
        hkdf.update(handle.as_bytes());
        if let Some(ctx) = context {
            hkdf.update(ctx);
        }
        hkdf.finalize_into(&mut prk).expect("HKDF extract failed");
        
        // Expand to get 32-byte key for ChaCha20-Poly1305
        let mut key = [0u8; 32];
        HmacSha256::new_from_slice(&prk)
            .and_then(|mut h| {
                h.update(b"phantom-key-v2-vault");
                h.finalize_into(&mut key)
            })
            .expect("HKDF expand failed");
        
        key.to_vec()
    }
    
    /// Encrypt a secret
    pub fn encrypt(
        &self,
        secret: &[u8],
        R: &GroupElement,
        handle: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let key = self.derive_key(R, handle, None);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("Invalid key length");
        
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, secret)
            .expect("Encryption failed");
        
        (ciphertext, nonce.to_vec())
    }
    
    /// Decrypt a secret
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        R: &GroupElement,
        handle: &str,
    ) -> Option<Vec<u8>> {
        let key = self.derive_key(R, handle, None);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("Invalid key length");
        
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).ok()
    }
    
    /// Create a new vault entry
    pub fn create_entry(
        &self,
        secret: &[u8],
        R: &GroupElement,
        handle: String,
        metadata: VaultMetadata,
    ) -> VaultEntry {
        let (ciphertext, nonce) = self.encrypt(secret, R, &handle);
        
        VaultEntry {
            id: Uuid::new_v4(),
            handle,
            ciphertext,
            nonce,
            metadata,
        }
    }
    
    /// Get secret from vault entry
    pub fn get_secret(
        &self,
        entry: &VaultEntry,
        R: &GroupElement,
    ) -> Option<Vec<u8>> {
        self.decrypt(&entry.ciphertext, &entry.nonce, R, &entry.handle)
    }
}
```

**File: `src/vault/encryption/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::group::GroupElement;
    
    #[test]
    fn test_encryption_decryption() {
        // This test needs a real ThresholdDH instance
        // For now, we'll use a mock
        
        let R = GroupElement::generator();
        let encryption = VaultEncryption {
            threshold_dh: ThresholdDH::new(vec![], vec![], DKG::new(1, 1)),
        };
        
        let secret = b"my-secret-password";
        let handle = "⟦H1⟧";
        
        let (ciphertext, nonce) = encryption.encrypt(secret, &R, handle);
        let decrypted = encryption.decrypt(&ciphertext, &nonce, &R, handle).unwrap();
        
        assert_eq!(decrypted, secret);
    }
    
    #[test]
    fn test_different_handles_different_keys() {
        let R = GroupElement::generator();
        let encryption = VaultEncryption {
            threshold_dh: ThresholdDH::new(vec![], vec![], DKG::new(1, 1)),
        };
        
        let key1 = encryption.derive_key(&R, "⟦H1⟧", None);
        let key2 = encryption.derive_key(&R, "⟦H2⟧", None);
        
        assert_ne!(key1, key2);
    }
}
```

#### Deliverables
- [ ] HKDF key derivation implementation
- [ ] Per-secret key binding
- [ ] AEAD encryption (ChaCha20-Poly1305)
- [ ] Encryption/decryption functions
- [ ] Vault entry creation
- [ ] Secret retrieval
- [ ] Unit tests for encryption

#### Acceptance Criteria
- [ ] Secrets can be encrypted and decrypted
- [ ] Each secret has a unique encryption key
- [ ] Keys are bound to handles
- [ ] Encryption/decryption works correctly
- [ ] All encryption tests pass

---

### Sub-Phase 2.3: Handle System (Day 19)

**Objective:** Implement handle generation and management.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 2.3.1 | Design handle format | Define handle syntax and semantics | Security | 4h | 2.1, 2.2 | ⏳ |
| 2.3.2 | Implement handle generation | Generate unique handles | Security | 4h | 2.3.1 | ⏳ |
| 2.3.3 | Implement handle parsing | Parse handles from strings | Security | 4h | 2.3.2 | ⏳ |
| 2.3.4 | Implement handle validation | Validate handle format | Security | 4h | 2.3.3 | ⏳ |
| 2.3.5 | Add unit tests for handles | Test all handle operations | Security | 4h | 2.3 | ⏳ |

#### Technical Details

**File: `src/vault/handle.rs`**

```rust
use std::fmt;
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Handle for referencing secrets in the vault
/// Format: ⟦H<id>⟧ where id is a unique identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Handle(String);

impl Handle {
    /// Generate a new random handle
    pub fn new() -> Self {
        let id = Uuid::new_v4();
        Self(format!("⟦H{}⟧", id))
    }
    
    /// Create handle from numeric ID
    pub fn from_id(id: u64) -> Self {
        Self(format!("⟦H{}⟧", id))
    }
    
    /// Create handle from UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(format!("⟦H{}⟧", uuid))
    }
    
    /// Get the numeric ID from handle
    pub fn id(&self) -> Option<u64> {
        self.0.strip_prefix("⟦H").and_then(|s| s.strip_suffix("⟧"))
            .and_then(|s| s.parse().ok())
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
pub struct HandleGenerator {
    counter: std::sync::atomic::AtomicU64,
}

impl HandleGenerator {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Generate a new handle with sequential ID
    pub fn generate(&self) -> Handle {
        let id = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Handle::from_id(id)
    }
    
    /// Generate a new handle with random UUID
    pub fn generate_random(&self) -> Handle {
        Handle::new()
    }
}

impl Default for HandleGenerator {
    fn default() -> Self {
        Self::new()
    }
}
```

**File: `src/vault/handle/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handle_creation() {
        let handle = Handle::new();
        assert!(handle.0.starts_with("⟦H"));
        assert!(handle.0.ends_with("⟧"));
    }
    
    #[test]
    fn test_handle_from_id() {
        let handle = Handle::from_id(123);
        assert_eq!(handle.0, "⟦H123⟧");
        assert_eq!(handle.id(), Some(123));
    }
    
    #[test]
    fn test_handle_from_uuid() {
        let uuid = Uuid::new_v4();
        let handle = Handle::from_uuid(uuid);
        assert!(handle.0.starts_with("⟦H"));
        assert!(handle.0.ends_with("⟧"));
        assert_eq!(handle.uuid(), Some(uuid));
    }
    
    #[test]
    fn test_handle_parsing() {
        let handle = Handle::from_id(456);
        let parsed: Handle = "⟦H456⟧".parse().unwrap();
        assert_eq!(handle, parsed);
    }
    
    #[test]
    fn test_handle_validation() {
        assert!(Handle::is_valid("⟦H1⟧"));
        assert!(Handle::is_valid("⟦H1234567890⟧"));
        assert!(!Handle::is_valid("H1⟧"));
        assert!(!Handle::is_valid("⟦H1"));
        assert!(!Handle::is_valid("⟦X1⟧"));
    }
    
    #[test]
    fn test_handle_generator() {
        let generator = HandleGenerator::new();
        
        let h1 = generator.generate();
        let h2 = generator.generate();
        
        assert_ne!(h1, h2);
        assert_eq!(h1.id(), Some(0));
        assert_eq!(h2.id(), Some(1));
    }
}
```

#### Deliverables
- [ ] Handle type implementation
- [ ] Handle generation (sequential and random)
- [ ] Handle parsing from strings
- [ ] Handle validation
- [ ] Handle generator
- [ ] Unit tests for handles

#### Acceptance Criteria
- [ ] Handles can be created
- [ ] Handles can be parsed from strings
- [ ] Handles can be validated
- [ ] Handle generator produces unique handles
- [ ] All handle tests pass

---

### Sub-Phase 2.4: Decoy Generation (Day 20-21)

**Objective:** Implement format-preserving decoy generation for various secret types.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 2.4.1 | Design decoy generator trait | Abstract interface for all decoy types | Security | 4h | 2.1, 2.2, 2.3 | ⏳ |
| 2.4.2 | Implement AWS key decoy generator | Generate fake AWS access/secret keys | Security | 4h | 2.4.1 | ⏳ |
| 2.4.3 | Implement IBAN decoy generator | Generate fake IBANs with valid checksums | Security | 4h | 2.4.1 | ⏳ |
| 2.4.4 | Implement credit card decoy generator | Generate fake cards with valid Luhn | Security | 4h | 2.4.1 | ⏳ |
| 2.4.5 | Implement generic decoy generator | For custom secret types | Security | 4h | 2.4.1 | ⏳ |
| 2.4.6 | Add unit tests for decoys | Test all decoy generators | Security | 4h | 2.4 | ⏳ |

#### Technical Details

**File: `src/vault/decoy.rs`**

```rust
use super::handle::Handle;
use std::collections::HashMap;
use rand::Rng;

/// Trait for decoy generators
pub trait DecoyGenerator: Send + Sync {
    /// Generate a new decoy
    fn generate(&self) -> String;
    
    /// Validate that a value matches the expected format
    fn validate_format(&self, value: &str) -> bool;
    
    /// Get the secret type this generator produces
    fn secret_type(&self) -> SecretType;
}

/// AWS Access Key Generator
/// Format: AKIA + 16 uppercase alphanumeric characters
pub struct AwsAccessKeyGenerator;

impl DecoyGenerator for AwsAccessKeyGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        let random_part: String = (0..16)
            .map(|_| {
                const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                CHARSET[rng.gen_range(0..CHARSET.len())] as char
            })
            .collect();
        format!("AKIA{}", random_part)
    }
    
    fn validate_format(&self, value: &str) -> bool {
        value.starts_with("AKIA") && value.len() == 20
    }
    
    fn secret_type(&self) -> SecretType {
        SecretType::AwsAccessKey
    }
}

/// AWS Secret Key Generator
/// Format: 40-character base64-like string
pub struct AwsSecretKeyGenerator;

impl DecoyGenerator for AwsSecretKeyGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..40)
            .map(|_| {
                const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                CHARSET[rng.gen_range(0..CHARSET.len())] as char
            })
            .collect()
    }
    
    fn validate_format(&self, value: &str) -> bool {
        value.len() == 40 && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        })
    }
    
    fn secret_type(&self) -> SecretType {
        SecretType::AwsSecretKey
    }
}

/// IBAN Generator
/// Format: 2-letter country code + 2-digit checksum + BBAN
pub struct IbanGenerator {
    country_code: String,
}

impl IbanGenerator {
    pub fn new(country_code: &str) -> Self {
        Self {
            country_code: country_code.to_uppercase(),
        }
    }
}

impl DecoyGenerator for IbanGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        
        // Generate random BBAN (Basic Bank Account Number)
        let bban_length = 18; // Typical length
        let bban: String = (0..bban_length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect();
        
        // Calculate checksum: 98 - (BBAN + country_code + "00") mod 97
        let check_input = format!("{}{}", bban, self.country_code);
        let check_num = self.mod97(&format!("{}{}", check_input, "00"));
        let checksum = 98 - check_num;
        let checksum = format!("{:02}", checksum % 97);
        
        format!("{}{}{}", self.country_code, checksum, bban)
    }
    
    fn validate_format(&self, value: &str) -> bool {
        value.starts_with(&self.country_code) && value.len() >= 4
    }
    
    fn secret_type(&self) -> SecretType {
        SecretType::IbAN
    }
}

impl IbanGenerator {
    /// Calculate MOD-97-10 checksum
    fn mod97(&self, input: &str) -> u32 {
        let mut remainder: u64 = 0;
        
        for c in input.chars() {
            let digit = if c.is_ascii_digit() {
                c.to_digit(10).unwrap() as u64
            } else {
                // For letters in IBAN, A=10, B=11, ..., Z=35
                (c as u64) - ('A' as u64) + 10
            };
            remainder = (remainder * 10 + digit) % 97;
        }
        
        remainder as u32
    }
}

/// Credit Card Generator (Luhn algorithm)
pub struct CreditCardGenerator {
    issuer: String,
}

impl CreditCardGenerator {
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_lowercase(),
        }
    }
}

impl DecoyGenerator for CreditCardGenerator {
    fn generate(&self) -> String {
        let prefixes: HashMap<&str, &str> = [
            ("visa", "4"),
            ("mastercard", "5"),
            ("amex", "37"),
            ("discover", "6011"),
        ].iter().cloned().collect();
        
        let prefix = prefixes.get(self.issuer.as_str())
            .unwrap_or(&"4");
        
        let mut rng = rand::thread_rng();
        let length = match self.issuer.as_str() {
            "amex" => 15,
            _ => 16,
        };
        
        let mut digits: Vec<u8> = prefix.chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        
        // Fill with random digits
        while digits.len() < length - 1 {
            digits.push(rng.gen_range(0..10) as u8);
        }
        
        // Calculate Luhn checksum
        let checksum = self.luhn_checksum(&digits);
        digits.push(checksum);
        
        digits.iter().map(|&d| d.to_string()).collect()
    }
    
    fn validate_format(&self, value: &str) -> bool {
        // Basic validation
        value.chars().all(|c| c.is_ascii_digit())
    }
    
    fn secret_type(&self) -> SecretType {
        SecretType::CreditCard
    }
}

impl CreditCardGenerator {
    /// Calculate Luhn checksum digit
    fn luhn_checksum(&self, digits: &[u8]) -> u8 {
        let mut sum = 0;
        
        for (i, &digit) in digits.iter().enumerate() {
            let mut d = digit as u32;
            if (digits.len() - i) % 2 == 0 {
                // Double every second digit from the right
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
        }
        
        ((10 - (sum % 10)) % 10) as u8
    }
}

/// Generic Decoy Generator for custom patterns
pub struct GenericDecoyGenerator {
    pattern: String,
}

impl GenericDecoyGenerator {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
        }
    }
}

impl DecoyGenerator for GenericDecoyGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        let mut result = String::new();
        
        for c in self.pattern.chars() {
            match c {
                '0'..='9' => {
                    result.push(rng.gen_range(0..10).to_string().chars().next().unwrap());
                },
                'a'..='z' => {
                    result.push(rng.gen_range(b'a'..b'z'+1) as char);
                },
                'A'..='Z' => {
                    result.push(rng.gen_range(b'A'..b'Z'+1) as char);
                },
                'x' => {
                    // Hex digit (lowercase)
                    result.push(rng.gen_range(0..16).to_string().chars().next().unwrap());
                },
                'X' => {
                    // Hex digit (uppercase)
                    result.push(rng.gen_range(0..16).to_string().to_uppercase().chars().next().unwrap());
                },
                c => {
                    result.push(c);
                }
            }
        }
        
        result
    }
    
    fn validate_format(&self, value: &str) -> bool {
        value.len() == self.pattern.len()
    }
    
    fn secret_type(&self) -> SecretType {
        SecretType::Generic
    }
}

/// Decoy registry for tracking generated decoys
pub struct DecoyRegistry {
    generators: HashMap<SecretType, Box<dyn DecoyGenerator>>,
}

impl DecoyRegistry {
    pub fn new() -> Self {
        let mut generators = HashMap::new();
        
        // Register default generators
        generators.insert(SecretType::AwsAccessKey, Box::new(AwsAccessKeyGenerator));
        generators.insert(SecretType::AwsSecretKey, Box::new(AwsSecretKeyGenerator));
        generators.insert(SecretType::IbAN, Box::new(IbanGenerator::new("DE")));
        generators.insert(SecretType::CreditCard, Box::new(CreditCardGenerator::new("visa")));
        
        Self { generators }
    }
    
    /// Generate a decoy for a specific secret type
    pub fn generate(&self, secret_type: &SecretType) -> String {
        self.generators.get(secret_type)
            .map(|g| g.generate())
            .unwrap_or_else(|| {
                // Default to generic generator
                GenericDecoyGenerator::new("XXXXXXXX").generate()
            })
    }
    
    /// Register a custom generator
    pub fn register_generator(&mut self, secret_type: SecretType, generator: Box<dyn DecoyGenerator>) {
        self.generators.insert(secret_type, generator);
    }
}
```

**File: `src/vault/decoy/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aws_access_key() {
        let generator = AwsAccessKeyGenerator;
        let key = generator.generate();
        
        assert!(key.starts_with("AKIA"));
        assert_eq!(key.len(), 20);
        assert!(generator.validate_format(&key));
    }
    
    #[test]
    fn test_aws_secret_key() {
        let generator = AwsSecretKeyGenerator;
        let key = generator.generate();
        
        assert_eq!(key.len(), 40);
        assert!(generator.validate_format(&key));
    }
    
    #[test]
    fn test_iban() {
        let generator = IbanGenerator::new("DE");
        let iban = generator.generate();
        
        assert!(iban.starts_with("DE"));
        assert!(generator.validate_format(&iban));
        
        // Verify checksum
        let check_input = &iban[4..]; // Remove DE + checksum
        let checksum = &iban[2..4];
        let check_num = generator.mod97(&format!("{}{}", check_input, "00"));
        let expected_checksum = 98 - check_num;
        assert_eq!(checksum.parse::<u32>().unwrap() % 97, expected_checksum % 97);
    }
    
    #[test]
    fn test_credit_card() {
        let generator = CreditCardGenerator::new("visa");
        let card = generator.generate();
        
        assert!(card.starts_with("4"));
        assert!(generator.validate_format(&card));
        
        // Verify Luhn checksum
        let digits: Vec<u8> = card.chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        let checksum = digits.last().unwrap();
        let calculated = generator.luhn_checksum(&digits[..digits.len()-1]);
        assert_eq!(*checksum, calculated);
    }
    
    #[test]
    fn test_generic_decoy() {
        let generator = GenericDecoyGenerator::new("AKIAxxxxxxxxxxxxxxxx");
        let decoy = generator.generate();
        
        assert!(decoy.starts_with("AKIA"));
        assert_eq!(decoy.len(), 20);
        assert!(generator.validate_format(&decoy));
    }
}
```

#### Deliverables
- [ ] Decoy generator trait
- [ ] AWS access key generator
- [ ] AWS secret key generator
- [ ] IBAN generator
- [ ] Credit card generator
- [ ] Generic decoy generator
- [ ] Decoy registry
- [ ] Unit tests for all decoy generators

#### Acceptance Criteria
- [ ] All decoy generators produce format-valid output
- [ ] All decoy generators can validate their output
- [ ] Decoy registry can generate decoys for all types
- [ ] All decoy tests pass

---

### Sub-Phase 2.5: Decoy-to-Handle Mapping (Day 22)

**Objective:** Implement mapping between decoys and handles for secret retrieval.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 2.5.1 | Design mapping data structure | Define DecoyMap and its operations | Security | 4h | 2.3, 2.4 | ⏳ |
| 2.5.2 | Implement mapping storage | Store decoy-to-handle mappings | Security | 8h | 2.5.1 | ⏳ |
| 2.5.3 | Implement decoy generation with mapping | Generate decoys and register mappings | Security | 8h | 2.5.2 | ⏳ |
| 2.5.4 | Implement handle resolution | Resolve handles to real secrets | Security | 4h | 2.5.3 | ⏳ |
| 2.5.5 | Add unit tests for mapping | Test all mapping operations | Security | 4h | 2.5 | ⏳ |

#### Technical Details

**File: `src/vault/mapping.rs`**

```rust
use super::{
    handle::Handle,
    storage::{VaultEntry, VaultStorage},
    decoy::DecoyRegistry,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Mapping between decoys and handles
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

/// Decoy manager that combines registry, mapping, and vault
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
    
    /// Generate a decoy for a secret and store it in the vault
    pub fn store_secret(
        &self,
        secret: &[u8],
        secret_type: SecretType,
        R: &GroupElement,
    ) -> Handle {
        // Generate handle
        let handle = Handle::new();
        
        // Generate decoy
        let decoy = self.registry.generate(&secret_type);
        
        // Create metadata
        let metadata = VaultMetadata {
            secret_type,
            description: Some(format!("Generated decoy: {}", decoy)),
            ..Default::default()
        };
        
        // Create vault entry
        // Note: This needs the encryption module
        // For now, we'll create a placeholder
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: handle.clone(),
            ciphertext: secret.to_vec(), // In real implementation, this would be encrypted
            nonce: vec![],
            metadata,
        };
        
        // Store in vault
        let _ = self.storage.insert(entry);
        
        // Register mapping
        self.mapping.lock().unwrap().register(handle.clone(), decoy);
        
        handle
    }
    
    /// Get real secret from a decoy
    pub fn get_secret_from_decoy(
        &self,
        decoy: &str,
        R: &GroupElement,
    ) -> Option<Vec<u8>> {
        // Get handle from decoy
        let handle = self.mapping.lock().unwrap().get_handle(decoy)?;
        
        // Get vault entry from handle
        let entry = self.storage.get_by_handle(&handle.0)?;
        
        // In real implementation, we would decrypt here
        // For now, return the ciphertext (which is the secret in this placeholder)
        Some(entry.ciphertext)
    }
    
    /// Get decoy from a handle
    pub fn get_decoy_from_handle(&self, handle: &Handle) -> Option<String> {
        self.mapping.lock().unwrap().get_decoy(handle).cloned()
    }
    
    /// Process a prompt: replace secrets with decoys and register mappings
    pub fn process_prompt(
        &self,
        prompt: &str,
        R: &GroupElement,
    ) -> (String, Vec<Handle>) {
        let mut processed = prompt.to_string();
        let mut handles = Vec::new();
        
        // This is a simplified version
        // In production, we'd use regex to find potential secrets
        // and replace them with decoys
        
        // For now, just demonstrate the concept
        if prompt.contains("AKIA") {
            let handle = self.store_secret(b"fake-aws-key", SecretType::AwsAccessKey, R);
            let decoy = self.get_decoy_from_handle(&handle).unwrap();
            processed = processed.replace("AKIA", &decoy);
            handles.push(handle);
        }
        
        (processed, handles)
    }
}
```

**File: `src/vault/mapping/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::storage::MemoryStorage;
    
    #[test]
    fn test_decoy_map() {
        let mut map = DecoyMap::new();
        
        let handle1 = Handle::from_id(1);
        let decoy1 = "AKIAIOSFODNN7EXAMPLE".to_string();
        
        let handle2 = Handle::from_id(2);
        let decoy2 = "DE89370400440532013000".to_string();
        
        // Register mappings
        map.register(handle1.clone(), decoy1.clone());
        map.register(handle2.clone(), decoy2.clone());
        
        // Test lookups
        assert_eq!(map.get_handle(&decoy1), Some(&handle1));
        assert_eq!(map.get_decoy(&handle1), Some(&decoy1));
        
        assert_eq!(map.get_handle(&decoy2), Some(&handle2));
        assert_eq!(map.get_decoy(&handle2), Some(&decoy2));
    }
    
    #[test]
    fn test_decoy_manager() {
        let registry = DecoyRegistry::new();
        let mapping = Arc::new(Mutex::new(DecoyMap::new()));
        let storage = Arc::new(MemoryStorage::new());
        
        let manager = DecoyManager::new(registry, mapping.clone(), storage.clone());
        
        // This test would need a real GroupElement
        // For now, we'll skip it
    }
}
```

#### Deliverables
- [ ] DecoyMap data structure
- [ ] DecoyManager combining registry, mapping, and vault
- [ ] Decoy generation with automatic mapping registration
- [ ] Handle resolution to real secrets
- [ ] Prompt processing (replace secrets with decoys)
- [ ] Unit tests for mapping

#### Acceptance Criteria
- [ ] Decoys can be registered and looked up
- [ ] Handles can be resolved to decoys
- [ ] Secrets can be stored and retrieved via decoys
- [ ] Prompts can be processed (secrets → decoys)
- [ ] All mapping tests pass

---

## 📊 Phase Summary

### Tasks Breakdown
| Sub-Phase | Tasks | Effort | Status |
|-----------|-------|--------|--------|
| 2.1 Vault Storage | 5 | 32h | ⏳ |
| 2.2 Per-Secret Encryption | 5 | 40h | ⏳ |
| 2.3 Handle System | 5 | 24h | ⏳ |
| 2.4 Decoy Generation | 6 | 24h | ⏳ |
| 2.5 Decoy-to-Handle Mapping | 5 | 24h | ⏳ |
| **Total** | **26** | **144h (18 person-days)** | ⏳ |

### Deliverables Summary
- ✅ Sealed vault with storage backend
- ✅ Per-secret encryption with HKDF
- ✅ Handle system
- ✅ Format-preserving decoy generation
- ✅ Decoy-to-handle mapping
- ✅ Prompt processing
- ✅ 100% unit test coverage for vault module

### Acceptance Criteria
- [ ] Vault entries can be stored and retrieved
- [ ] Secrets are encrypted with unique keys
- [ ] Handles are generated and parsed correctly
- [ ] Decoys are format-preserving
- [ ] Decoys map to handles and vice versa
- [ ] Prompts can be processed (secrets → decoys)
- [ ] All tests pass

---

## 🎯 Next Phase

**After Phase 2 completes, proceed to Phase 3: Egress Court**

- **Start Date:** Beginning of Week 4
- **Duration:** 2 weeks
- **Prerequisite:** Phase 1 AND Phase 2 must be 100% complete

---

## 📝 Phase Information

**Phase:** 2 of 4  
**Name:** Vault System  
**Duration:** 1 week  
**Status:** ⏳ Not Started  
**Priority:** 🟡 HIGH  
**Blocker for:** Phase 3, Phase 4  
**Prerequisite:** Phase 1 (Core Cryptography)

**Document Version:** 1.0  
**Last Updated:** October 26, 2026  
**Owner:** Security Team
