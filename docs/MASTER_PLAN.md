# Phantom Key v2: Master Implementation Plan

**Project:** Phantom Key v2 - Dealerless Threshold Key with Sealed Vault  
**Version:** 2.0  
**Date:** October 26, 2026  
**Status:** ✅ **APPROVED FOR IMPLEMENTATION**

---

## 🎯 **Project Overview**

**Goal:** Implement Phantom Key v2 (corrected design) for secure LLM prompt processing with:
- Dealerless threshold cryptography (DKG)
- Sealed vault with per-secret encryption
- Handles at LLM boundary (decoys + handle system)
- Signed, hash-chained egress ledger (Egress Court)
- Best-effort canary detection

**Target:** Competition submission with maximum rubric points
- **UI (3 points):** Textual TUI with chat, egress/ledger, shareholder status, vault panel
- **Video (2 points):** Attack Lab with 6 live demos
- **API Evidence (2 points):** Real Bedrock/OpenAI/Gemini calls with request IDs in ledger

**Timeline:** 6 weeks total

---

## 📅 **Master Schedule**

```
Week 1-2: Phase 1 - Core Cryptography (Foundation)
Week 3:   Phase 2 - Vault System (Secrets Management)
Week 4-5: Phase 3 - Egress Court (Audit & Monitoring)
Week 6:   Phase 4 - Integration & Polish (Competition Ready)
```

---

## 🏗️ **Phase 1: Core Cryptography**

**Duration:** 2 weeks  
**Lead:** Crypto Team  
**Status:** Not Started  
**Priority:** CRITICAL (Blocker for all other phases)

### 🎯 **Phase 1 Objectives**

1. Implement dealerless threshold key generation (DKG)
2. Implement threshold Diffie-Hellman with DLEQ proofs
3. Implement proactive share refresh
4. Unit tests for all cryptographic operations

### 📋 **Sub-Phases**

#### **Phase 1.1: Setup & Dependencies** (Day 1)

**Objective:** Establish development environment and dependencies

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Initialize Rust project with Cargo.toml | Dev | ⏳ | 2h | None |
| Set up Git repository with branching strategy | Dev | ⏳ | 2h | None |
| Configure CI/CD pipeline (GitHub Actions) | DevOps | ⏳ | 4h | Repo |
| Set up development containers | Dev | ⏳ | 4h | None |
| Configure logging and error handling framework | Dev | ⏳ | 4h | Project |

**Deliverables:**
- ✅ Rust project with all dependencies
- ✅ Git repository with main, dev, feature branches
- ✅ CI pipeline for builds and tests
- ✅ Development environment (Docker/Dev Containers)
- ✅ Logging framework (tracing + structured logging)

**Acceptance Criteria:**
- [ ] `cargo build` succeeds
- [ ] `cargo test` runs (no tests yet, but framework works)
- [ ] CI pipeline runs on push
- [ ] Dev container can be used for development

---

#### **Phase 1.2: Group Operations & Serialization** (Day 2-3)

**Objective:** Implement Ristretto255 group operations with proper serialization

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement Scalar and RistrettoPoint wrappers | Crypto | ⏳ | 8h | 1.1 |
| Implement group operations (add, multiply, etc.) | Crypto | ⏳ | 8h | 1.2a |
| Implement serialization/deserialization | Crypto | ⏳ | 4h | 1.2b |
| Implement constant-time operations | Crypto | ⏳ | 8h | 1.2b |
| Add comprehensive unit tests | Crypto | ⏳ | 8h | 1.2d |

**Technical Details:**
```rust
// Group operations using curve25519-dalek
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};

pub struct GroupElement(RistrettoPoint);
pub struct GroupScalar(Scalar);

impl GroupElement {
    pub fn generator() -> Self {
        Self(RistrettoPoint::generator())
    }
    
    pub fn multiply(&self, scalar: &GroupScalar) -> Self {
        Self(self.0 * scalar.0)
    }
    
    // Constant-time equality
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}
```

**Deliverables:**
- ✅ Group element and scalar types
- ✅ All group operations (addition, multiplication, inversion)
- ✅ Serialization to/from bytes
- ✅ Constant-time implementations where needed
- ✅ Unit tests for all operations

**Acceptance Criteria:**
- [ ] All group operations work correctly
- [ ] Serialization round-trips preserve values
- [ ] Constant-time tests pass
- [ ] 100% unit test coverage for group operations

---

#### **Phase 1.3: Feldman's VSS (DKG)** (Day 4-7)

**Objective:** Implement dealerless key generation with verifiable secret sharing

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement polynomial generation | Crypto | ⏳ | 8h | 1.2 |
| Implement commitment generation | Crypto | ⏳ | 8h | 1.3a |
| Implement share generation | Crypto | ⏳ | 8h | 1.3b |
| Implement share verification | Crypto | ⏳ | 8h | 1.3c |
| Implement final share combination | Crypto | ⏳ | 8h | 1.3d |
| Add DLEQ proof generation | Crypto | ⏳ | 16h | 1.3 |
| Add DLEQ proof verification | Crypto | ⏳ | 16h | 1.3f |
| Add unit tests for DKG | Crypto | ⏳ | 16h | 1.3 |

**Technical Details:**
```rust
// Feldman's VSS implementation
pub struct DKG {
    parties: usize,
    threshold: usize,
}

impl DKG {
    pub fn new(parties: usize, threshold: usize) -> Self {
        assert!(threshold <= parties);
        Self { parties, threshold }
    }
    
    // Party i's contribution
    pub fn party_contribution(&self, party_id: usize) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
        // Generate random polynomial f_i(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
        // Returns (shares, commitments)
    }
    
    // Verify a party's contribution
    pub fn verify_contribution(
        &self,
        party_id: usize,
        shares: &[Scalar],
        commitments: &[RistrettoPoint],
    ) -> bool {
        // Verify that shares are consistent with commitments
    }
    
    // Combine all contributions to get final share
    pub fn combine_contributions(
        &self,
        contributions: &[PartyContribution],
    ) -> Vec<Scalar> {
        // Sum all polynomials: f(x) = Σ f_i(x)
        // Return shares f(1), f(2), ..., f(n)
    }
}
```

**Deliverables:**
- ✅ DKG protocol implementation
- ✅ Polynomial generation and evaluation
- ✅ Commitment generation and verification
- ✅ DLEQ proof generation and verification
- ✅ Unit tests for DKG

**Acceptance Criteria:**
- [ ] DKG completes successfully with honest parties
- [ ] Malicious parties are detected via commitments
- [ ] DLEQ proofs are generated and verified correctly
- [ ] Final shares are consistent across parties
- [ ] No party learns the full secret

---

#### **Phase 1.4: Threshold Diffie-Hellman** (Day 8-10)

**Objective:** Implement threshold DH with DLEQ proofs

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement ephemeral key generation | Crypto | ⏳ | 4h | 1.2 |
| Implement partial computation | Crypto | ⏳ | 8h | 1.3, 1.4a |
| Implement partial combination | Crypto | ⏳ | 8h | 1.4b |
| Integrate DLEQ proofs with partials | Crypto | ⏳ | 8h | 1.3f, 1.4c |
| Implement key derivation (HKDF) | Crypto | ⏳ | 8h | 1.4 |
| Add unit tests for threshold DH | Crypto | ⏳ | 8h | 1.4 |

**Technical Details:**
```rust
pub struct ThresholdDH {
    shares: Vec<Scalar>,  // s_i = f(i) for this party
    public_shares: Vec<RistrettoPoint>,  // S_i = s_i * G
}

impl ThresholdDH {
    pub fn compute_partial(
        &self,
        share_index: usize,
        R: &RistrettoPoint,
    ) -> (RistrettoPoint, DLEQProof) {
        let s_i = self.shares[share_index];
        let P_i = s_i * R;
        let S_i = self.public_shares[share_index];
        let proof = DLEQProof::new(&s_i, &P_i, &S_i, R);
        (P_i, proof)
    }
    
    pub fn combine_partials(
        &self,
        partials: &[(RistrettoPoint, DLEQProof)],
        R: &RistrettoPoint,
    ) -> Option<RistrettoPoint> {
        // Verify all proofs
        for (P_i, proof) in partials {
            if !proof.verify(P_i, R) {
                return None;  // Reject invalid partial
            }
        }
        
        // Combine using Lagrange interpolation
        let indices: Vec<usize> = partials.iter().map(|_| /* extract index */).collect();
        let lambdas = lagrange_coefficients(&indices, 0);
        
        let K = partials.iter()
            .zip(lambdas.iter())
            .fold(RistrettoPoint::identity(), |acc, ((P_i, _), &lambda)| {
                acc + lambda * P_i
            });
        
        Some(K)
    }
}
```

**Deliverables:**
- ✅ Threshold DH implementation
- ✅ Partial computation with DLEQ proofs
- ✅ Partial combination with proof verification
- ✅ Key derivation using HKDF
- ✅ Unit tests for threshold DH

**Acceptance Criteria:**
- [ ] Partial computation works correctly
- [ ] DLEQ proofs are generated and verified
- [ ] Invalid partials are rejected
- [ ] Combined result equals s·R
- [ ] Key derivation produces consistent keys

---

#### **Phase 1.5: Proactive Share Refresh** (Day 11-14)

**Objective:** Implement epoch-based share refresh

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement epoch management | Crypto | ⏳ | 8h | 1.3 |
| Implement share refresh protocol | Crypto | ⏳ | 16h | 1.5a |
| Implement old share destruction | Crypto | ⏳ | 8h | 1.5b |
| Add epoch-based key derivation | Crypto | ⏳ | 8h | 1.5 |
| Add unit tests for refresh | Crypto | ⏳ | 8h | 1.5 |

**Technical Details:**
```rust
pub struct ShareManager {
    current_epoch: u64,
    shares: Vec<Scalar>,  // Current epoch shares
    old_shares: Vec<Vec<Scalar>>,  // Previous epochs (for verification)
    epoch_duration: Duration,
}

impl ShareManager {
    pub fn refresh_shares(&mut self) -> Result<(), DKGError> {
        // Run new DKG for next epoch
        let new_shares = self.run_dkg()?;
        
        // Store old shares (temporarily, for verification)
        self.old_shares.push(std::mem::replace(&mut self.shares, new_shares));
        
        // Increment epoch
        self.current_epoch += 1;
        
        // Schedule destruction of old shares after verification period
        self.schedule_destruction();
        
        Ok(())
    }
    
    pub fn get_share(&self, party_id: usize) -> Option<&Scalar> {
        self.shares.get(party_id)
    }
    
    pub fn get_epoch_share(&self, epoch: u64, party_id: usize) -> Option<&Scalar> {
        // For verification of past operations
        if epoch == self.current_epoch {
            self.get_share(party_id)
        } else {
            // Look in old_shares
        }
    }
}
```

**Deliverables:**
- ✅ Epoch management system
- ✅ Share refresh protocol
- ✅ Old share destruction (secure memory wiping)
- ✅ Epoch-based key derivation
- ✅ Unit tests for refresh

**Acceptance Criteria:**
- [ ] Share refresh completes successfully
- [ ] Old shares are destroyed after verification period
- [ ] New epoch shares are independent of old shares
- [ ] Operations can be verified against old epochs

---

## 📦 **Phase 1 Deliverables Summary**

### ✅ **Must Have**
- [ ] DKG implementation with Feldman commitments
- [ ] Threshold DH with DLEQ proofs
- [ ] Proactive share refresh
- [ ] Group operations with serialization
- [ ] 100% unit test coverage for crypto

### 📊 **Quality Gates**
- [ ] All crypto operations are constant-time where needed
- [ ] No memory leaks in sensitive operations
- [ ] All tests pass
- [ ] CI pipeline passes

### 🎯 **Success Metrics**
- **Lines of Code:** ~1,500-2,000
- **Test Coverage:** 100% for crypto module
- **Performance:** <5ms per threshold operation

---

## 🏗️ **Phase 2: Vault System**

**Duration:** 1 week  
**Lead:** Security Team  
**Status:** Not Started  
**Priority:** HIGH (Blocker for Phase 3)

### 🎯 **Phase 2 Objectives**

1. Implement sealed vault with per-secret encryption
2. Implement handle system
3. Implement decoy generation
4. Implement decoy-to-handle mapping

### 📋 **Sub-Phases**

#### **Phase 2.1: Vault Storage** (Day 15-16)

**Objective:** Implement secure vault storage

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design vault data structure | Security | ⏳ | 4h | 1.0 |
| Implement vault storage backend | Security | ⏳ | 8h | 2.1a |
| Implement vault encryption at rest | Security | ⏳ | 8h | 2.1b |
| Implement vault access control | Security | ⏳ | 8h | 2.1 |
| Add unit tests for vault | Security | ⏳ | 4h | 2.1 |

**Technical Details:**
```rust
pub struct Vault {
    storage: StorageBackend,  // SQLite, Redis, or in-memory
    master_key: Option<Vec<u8>>,  // Only used for initial setup
}

pub struct VaultEntry {
    pub handle: Handle,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub metadata: VaultMetadata,
}

pub struct VaultMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub secret_type: SecretType,
    pub description: Option<String>,
}
```

**Deliverables:**
- ✅ Vault data structures
- ✅ Storage backend implementation
- ✅ Encryption at rest
- ✅ Access control
- ✅ Unit tests

---

#### **Phase 2.2: Per-Secret Encryption** (Day 17-18)

**Objective:** Implement HKDF-based per-secret encryption

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement HKDF key derivation | Security | ⏳ | 8h | 1.4 |
| Implement per-secret key binding | Security | ⏳ | 8h | 2.2a |
| Implement AEAD encryption (ChaCha20-Poly1305) | Security | ⏳ | 8h | 2.2b |
| Implement encryption/decryption | Security | ⏳ | 8h | 2.2c |
| Add unit tests for encryption | Security | ⏳ | 8h | 2.2 |

**Technical Details:**
```rust
pub fn derive_secret_key(
    threshold_key: &[u8],
    R: &RistrettoPoint,
    handle: &Handle,
) -> Vec<u8> {
    // K_H = HKDF(threshold_key, R || handle)
    let mut hkdf = Hkdf::<Sha256>::new(None, threshold_key);
    let info = format!("phantom-key-v2:{}:{}", R.compress().to_hex(), handle);
    let mut key = vec![0u8; 32];
    hkdf.expand(&info.as_bytes(), &mut key)
        .expect("HKDF expansion failed");
    key
}

pub fn encrypt_secret(
    secret: &[u8],
    key: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .expect("Invalid key length");
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret)
        .expect("Encryption failed");
    (ciphertext, nonce.to_vec())
}
```

**Deliverables:**
- ✅ HKDF key derivation
- ✅ Per-secret key binding
- ✅ AEAD encryption implementation
- ✅ Encryption/decryption functions
- ✅ Unit tests

---

#### **Phase 2.3: Handle System** (Day 19)

**Objective:** Implement handle generation and management

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design handle format | Security | ⏳ | 4h | 2.0 |
| Implement handle generation | Security | ⏳ | 4h | 2.3a |
| Implement handle parsing | Security | ⏳ | 4h | 2.3b |
| Implement handle validation | Security | ⏳ | 4h | 2.3 |
| Add unit tests for handles | Security | ⏳ | 4h | 2.3 |

**Technical Details:**
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Handle(String);

impl Handle {
    pub fn new(id: u64) -> Self {
        Self(format!("⟦H{}⟧", id))
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.starts_with("⟦H") && trimmed.ends_with("⟧") {
            Some(Self(trimmed.to_string()))
        } else {
            None
        }
    }
    
    pub fn id(&self) -> Option<u64> {
        self.0.strip_prefix("⟦H").and_then(|s| s.strip_suffix("⟧"))
            .and_then(|s| s.parse().ok())
    }
}
```

**Deliverables:**
- ✅ Handle type implementation
- ✅ Handle generation
- ✅ Handle parsing and validation
- ✅ Unit tests

---

#### **Phase 2.4: Decoy Generation** (Day 20-21)

**Objective:** Implement format-preserving decoy generation

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement AWS key decoy generation | Security | ⏳ | 4h | 2.0 |
| Implement IBAN decoy generation | Security | ⏳ | 4h | 2.4a |
| Implement credit card decoy generation | Security | ⏳ | 4h | 2.4b |
| Implement generic decoy generation | Security | ⏳ | 4h | 2.4 |
| Add unit tests for decoys | Security | ⏳ | 4h | 2.4 |

**Technical Details:**
```rust
pub trait DecoyGenerator: Send + Sync {
    fn generate(&self) -> String;
    fn validate_format(&self, value: &str) -> bool;
}

pub struct AwsKeyGenerator;

impl DecoyGenerator for AwsKeyGenerator {
    fn generate(&self) -> String {
        let mut rng = thread_rng();
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
}
```

**Deliverables:**
- ✅ AWS key decoy generator
- ✅ IBAN decoy generator
- ✅ Credit card decoy generator
- ✅ Generic decoy generator
- ✅ Format validation for all types
- ✅ Unit tests

---

#### **Phase 2.5: Decoy-to-Handle Mapping** (Day 22)

**Objective:** Implement mapping between decoys and handles

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design mapping data structure | Security | ⏳ | 4h | 2.3, 2.4 |
| Implement mapping storage | Security | ⏳ | 8h | 2.5a |
| Implement decoy generation with mapping | Security | ⏳ | 8h | 2.5b |
| Implement handle resolution | Security | ⏳ | 4h | 2.5 |
| Add unit tests for mapping | Security | ⏳ | 4h | 2.5 |

**Technical Details:**
```rust
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
    
    pub fn register_decoy(&mut self, handle: Handle, decoy: String) {
        self.decoy_to_handle.insert(decoy.clone(), handle.clone());
        self.handle_to_decoy.insert(handle, decoy);
    }
    
    pub fn resolve_decoy(&self, decoy: &str) -> Option<&Handle> {
        self.decoy_to_handle.get(decoy)
    }
    
    pub fn get_decoy(&self, handle: &Handle) -> Option<&String> {
        self.handle_to_decoy.get(handle)
    }
}
```

**Deliverables:**
- ✅ Decoy-to-handle mapping
- ✅ Bidirectional lookup
- ✅ Integration with decoy generation
- ✅ Unit tests

---

## 📦 **Phase 2 Deliverables Summary**

### ✅ **Must Have**
- [ ] Sealed vault implementation
- [ ] Per-secret encryption with HKDF
- [ ] Handle system
- [ ] Decoy generation for all types
- [ ] Decoy-to-handle mapping
- [ ] 100% unit test coverage for vault

### 📊 **Quality Gates**
- [ ] All secrets encrypted at rest
- [ ] All decoys are format-preserving
- [ ] All handles are unique and parseable
- [ ] All mappings are bidirectional

### 🎯 **Success Metrics**
- **Lines of Code:** ~1,000-1,500
- **Test Coverage:** 100% for vault module
- **Performance:** <1ms per vault operation

---

## 🏗️ **Phase 3: Egress Court**

**Duration:** 2 weeks  
**Lead:** Backend Team  
**Status:** Not Started  
**Priority:** HIGH

### 🎯 **Phase 3 Objectives**

1. Implement signed, hash-chained ledger
2. Implement secret scanner
3. Implement canary system
4. Implement TUI

### 📋 **Sub-Phases**

#### **Phase 3.1: Ledger Implementation** (Day 23-25)

**Objective:** Implement signed, hash-chained audit ledger

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design ledger entry structure | Backend | ⏳ | 4h | 1.0, 2.0 |
| Implement Ed25519 signing | Backend | ⏳ | 8h | 3.1a |
| Implement hash chain | Backend | ⏳ | 8h | 3.1b |
| Implement ledger storage | Backend | ⏳ | 8h | 3.1c |
| Implement ledger verification | Backend | ⏳ | 8h | 3.1 |
| Add unit tests for ledger | Backend | ⏳ | 8h | 3.1 |

**Technical Details:**
```rust
pub struct Ledger {
    storage: LedgerStorage,
    signing_key: ed25519_dalek::SigningKey,
    verification_key: ed25519_dalek::VerifyingKey,
}

impl Ledger {
    pub fn append(&mut self, entry: LedgerEntry) -> Result<(), LedgerError> {
        // Get previous hash
        let prev_hash = self.get_head_hash()?;
        
        // Create new entry
        let new_entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash,
            timestamp: Utc::now(),
            request_id: entry.request_id,
            provider: entry.provider,
            method: entry.method,
            url: entry.url,
            payload: entry.payload,
            hash: [0u8; 32],
        };
        
        // Compute hash
        new_entry.hash = self.compute_hash(&new_entry);
        
        // Sign entry
        let signature = self.signing_key.sign(&new_entry.hash);
        
        // Store signed entry
        self.storage.append(SignedLedgerEntry {
            entry: new_entry,
            signature,
        })?;
        
        Ok(())
    }
    
    pub fn verify_chain(&self) -> bool {
        let entries = self.storage.get_all();
        let mut prev_hash = [0u8; 32]; // Genesis
        
        for signed_entry in &entries {
            // Verify hash chain
            if signed_entry.entry.prev_hash != prev_hash {
                return false;
            }
            
            // Verify hash
            let computed_hash = self.compute_hash(&signed_entry.entry);
            if computed_hash != signed_entry.entry.hash {
                return false;
            }
            
            // Verify signature
            if !self.verification_key.verify(
                &signed_entry.entry.hash,
                &signed_entry.signature
            ).is_ok() {
                return false;
            }
            
            prev_hash = signed_entry.entry.hash;
        }
        
        true
    }
}
```

**Deliverables:**
- ✅ Ledger entry structure
- ✅ Ed25519 signing implementation
- ✅ Hash chain implementation
- ✅ Ledger storage backend
- ✅ Chain verification
- ✅ Unit tests

---

#### **Phase 3.2: Secret Scanner** (Day 26-27)

**Objective:** Implement scanner for exact vault values

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design scanner architecture | Backend | ⏳ | 4h | 2.0, 3.0 |
| Implement exact value scanning | Backend | ⏳ | 8h | 3.2a |
| Implement encoding variants (base64, hex, URL) | Backend | ⏳ | 8h | 3.2b |
| Implement scanner integration with ledger | Backend | ⏳ | 8h | 3.2c |
| Add unit tests for scanner | Backend | ⏳ | 8h | 3.2 |

**Technical Details:**
```rust
pub struct SecretScanner {
    vault: Arc<Vault>,
}

impl SecretScanner {
    pub fn scan(&self, payload: &[u8]) -> Vec<SecretMatch> {
        let text = String::from_utf8_lossy(payload);
        let mut matches = Vec::new();
        
        // Get all vault entries
        let entries = self.vault.get_all_entries();
        
        for entry in entries {
            let secret = self.vault.decrypt_entry(&entry)
                .expect("Failed to decrypt entry");
            
            // Check for exact match
            if text.contains(&secret) {
                matches.push(SecretMatch {
                    handle: entry.handle.clone(),
                    secret_type: entry.metadata.secret_type,
                    position: text.find(&secret),
                });
            }
            
            // Check for base64 encoded
            let base64_encoded = base64::encode(&secret);
            if text.contains(&base64_encoded) {
                matches.push(SecretMatch {
                    handle: entry.handle.clone(),
                    secret_type: entry.metadata.secret_type,
                    position: text.find(&base64_encoded),
                });
            }
            
            // Check for hex encoded
            let hex_encoded = hex::encode(&secret);
            if text.contains(&hex_encoded) {
                matches.push(SecretMatch {
                    handle: entry.handle.clone(),
                    secret_type: entry.metadata.secret_type,
                    position: text.find(&hex_encoded),
                });
            }
            
            // Check for URL encoded
            let url_encoded = urlencoding::encode(&secret);
            if text.contains(&url_encoded) {
                matches.push(SecretMatch {
                    handle: entry.handle.clone(),
                    secret_type: entry.metadata.secret_type,
                    position: text.find(&url_encoded),
                });
            }
        }
        
        matches
    }
}
```

**Deliverables:**
- ✅ Secret scanner implementation
- ✅ Exact value matching
- ✅ Encoding variant detection
- ✅ Ledger integration
- ✅ Unit tests

---

#### **Phase 3.3: Canary System** (Day 28-29)

**Objective:** Implement canary registration and detection

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design canary data structure | Backend | ⏳ | 4h | 2.4, 3.0 |
| Implement canary registry | Backend | ⏳ | 8h | 3.3a |
| Implement canary detection | Backend | ⏳ | 8h | 3.3b |
| Implement canary integration with scanner | Backend | ⏳ | 8h | 3.3c |
| Add unit tests for canaries | Backend | ⏳ | 8h | 3.3 |

**Technical Details:**
```rust
pub struct CanaryRegistry {
    canaries: HashMap<Uuid, Canary>,
    decoy_to_canary: HashMap<String, Uuid>,
}

impl CanaryRegistry {
    pub fn register(&mut self, request_id: Uuid, provider: &str, decoy: String) -> Uuid {
        let id = Uuid::new_v4();
        let canary = Canary {
            id,
            request_id,
            provider: provider.to_string(),
            decoy: decoy.clone(),
            created_at: Utc::now(),
            triggered: false,
        };
        
        self.canaries.insert(id, canary);
        self.decoy_to_canary.insert(decoy, id);
        
        id
    }
    
    pub fn detect(&mut self, text: &str) -> Vec<Uuid> {
        self.decoy_to_canary.iter()
            .filter(|(decoy, _)| text.contains(decoy))
            .map(|(_, &id)| id)
            .collect()
    }
    
    pub fn trigger(&mut self, canary_id: Uuid) -> Option<Canary> {
        if let Some(canary) = self.canaries.get_mut(&canary_id) {
            canary.triggered = true;
            Some(canary.clone())
        } else {
            None
        }
    }
}
```

**Deliverables:**
- ✅ Canary data structures
- ✅ Canary registry
- ✅ Canary detection
- ✅ Scanner integration
- ✅ Unit tests

---

#### **Phase 3.4: Interceptor** (Day 30-31)

**Objective:** Implement API request interception and logging

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design interceptor architecture | Backend | ⏳ | 4h | 3.1, 3.2, 3.3 |
| Implement request interception | Backend | ⏳ | 8h | 3.4a |
| Implement response interception | Backend | ⏳ | 8h | 3.4b |
| Integrate scanner with interceptor | Backend | ⏳ | 8h | 3.4c |
| Integrate canary detection | Backend | ⏳ | 8h | 3.4d |
| Add unit tests for interceptor | Backend | ⏳ | 8h | 3.4 |

**Technical Details:**
```rust
pub struct EgressInterceptor {
    ledger: Arc<Ledger>,
    scanner: SecretScanner,
    canary_registry: Arc<Mutex<CanaryRegistry>>,
}

impl EgressInterceptor {
    pub async fn intercept_request(
        &self,
        request: &OutboundRequest,
    ) -> Result<(), InterceptionError> {
        // Scan for secrets
        let secret_matches = self.scanner.scan(&request.payload);
        if !secret_matches.is_empty() {
            return Err(InterceptionError::SecretDetected(secret_matches));
        }
        
        // Detect canaries
        let text = String::from_utf8_lossy(&request.payload);
        let canary_ids = self.canary_registry.lock().unwrap().detect(&text);
        for id in canary_ids {
            self.canary_registry.lock().unwrap().trigger(id);
        }
        
        // Log to ledger
        let entry = LedgerEntry {
            request_id: request.id,
            provider: request.provider.clone(),
            method: request.method.clone(),
            url: request.url.clone(),
            payload: request.payload.clone(),
        };
        
        self.ledger.append(entry)?;
        
        Ok(())
    }
}
```

**Deliverables:**
- ✅ Request interceptor implementation
- ✅ Response interceptor implementation
- ✅ Scanner integration
- ✅ Canary detection integration
- ✅ Unit tests

---

#### **Phase 3.5: TUI Implementation** (Day 32-35)

**Objective:** Implement textual user interface

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Design TUI layout | Frontend | ⏳ | 4h | 3.0 |
| Implement TUI framework (ratatui) | Frontend | ⏳ | 8h | 3.5a |
| Implement chat panel | Frontend | ⏳ | 8h | 3.5b |
| Implement egress/ledger panel | Frontend | ⏳ | 8h | 3.5c |
| Implement shareholder status panel | Frontend | ⏳ | 8h | 3.5d |
| Implement vault panel | Frontend | ⏳ | 8h | 3.5e |
| Add real-time updates | Frontend | ⏳ | 8h | 3.5 |
| Add unit tests for TUI | Frontend | ⏳ | 4h | 3.5 |

**Technical Details:**
```rust
pub struct App {
    ledger: Arc<Ledger>,
    vault: Arc<Vault>,
    dkg: Arc<DKG>,
    canary_registry: Arc<Mutex<CanaryRegistry>>,
}

impl App {
    pub fn new(
        ledger: Arc<Ledger>,
        vault: Arc<Vault>,
        dkg: Arc<DKG>,
        canary_registry: Arc<Mutex<CanaryRegistry>>,
    ) -> Self {
        Self {
            ledger,
            vault,
            dkg,
            canary_registry,
        }
    }
    
    pub fn ui(&self, f: &mut Frame) {
        let size = f.size();
        
        // Split into panels
        let chat_panel = self.render_chat_panel(f, size);
        let ledger_panel = self.render_ledger_panel(f, size);
        let shareholder_panel = self.render_shareholder_panel(f, size);
        let vault_panel = self.render_vault_panel(f, size);
        
        // Render all panels
        f.render_widget(chat_panel, chat_rect);
        f.render_widget(ledger_panel, ledger_rect);
        f.render_widget(shareholder_panel, shareholder_rect);
        f.render_widget(vault_panel, vault_rect);
    }
}
```

**Deliverables:**
- ✅ TUI framework setup
- ✅ Chat panel
- ✅ Egress/ledger panel with chain status
- ✅ Shareholder status panel
- ✅ Vault panel
- ✅ Real-time updates
- ✅ Unit tests

---

## 📦 **Phase 3 Deliverables Summary**

### ✅ **Must Have**
- [ ] Signed, hash-chained ledger
- [ ] Secret scanner with exact value matching
- [ ] Canary system with detection
- [ ] Request/response interceptor
- [ ] Textual TUI with all panels
- [ ] 100% unit test coverage for egress

### 📊 **Quality Gates**
- [ ] Ledger chain verification works
- [ ] Scanner detects all vault secrets
- [ ] Canaries are detected when reappearing
- [ ] TUI shows real-time updates

### 🎯 **Success Metrics**
- **Lines of Code:** ~2,000-2,500
- **Test Coverage:** 100% for egress module
- **Performance:** <5ms per intercept operation

---

## 🏗️ **Phase 4: Integration & Polish**

**Duration:** 1 week  
**Lead:** Integration Team  
**Status:** Not Started  
**Priority:** HIGH

### 🎯 **Phase 4 Objectives**

1. Integrate all components
2. Implement LLM provider integration
3. Implement Attack Lab
4. Polish and prepare for competition

### 📋 **Sub-Phases**

#### **Phase 4.1: Integration** (Day 36-37)

**Objective:** Integrate all components into single system

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Integrate crypto with vault | Integration | ⏳ | 8h | 1.0, 2.0 |
| Integrate vault with egress | Integration | ⏳ | 8h | 2.0, 3.0 |
| Implement full workflow | Integration | ⏳ | 8h | 4.1a, 4.1b |
| Add integration tests | Integration | ⏳ | 8h | 4.1c |
| Fix integration bugs | Integration | ⏳ | 8h | 4.1 |

**Technical Details:**
```rust
// Full workflow example
pub async fn process_llm_request(
    request: LLMRequest,
    vault: &Vault,
    dkg: &DKG,
    ledger: &Ledger,
    canary_registry: &CanaryRegistry,
) -> Result<LLMResponse, PhantomKeyError> {
    // Step 1: Process prompt (replace secrets with decoys)
    let (processed_prompt, decoy_map) = process_prompt(&request.prompt, vault, canary_registry);
    
    // Step 2: Get threshold DH partials
    let r = Scalar::random(&mut OsRng);
    let R = r * RistrettoPoint::generator();
    let partials = dkg.compute_partials(&R);
    
    // Step 3: Combine to get K = s·R
    let K = dkg.combine_partials(partials, &R)?;
    
    // Step 4: Derive per-secret keys for vault access
    // (Not needed for this request, but available)
    
    // Step 5: Send request to LLM (with decoyed prompt)
    let llm_response = send_to_llm(&processed_prompt, &request.model).await?;
    
    // Step 6: Process response (swap handles back to real values)
    let final_response = process_response(&llm_response, vault, &decoy_map);
    
    // Step 7: Log to egress court
    ledger.log_request(&request, &processed_prompt)?;
    
    Ok(final_response)
}
```

**Deliverables:**
- ✅ Integrated system
- ✅ Full workflow implementation
- ✅ Integration tests
- ✅ Bug fixes

---

#### **Phase 4.2: LLM Provider Integration** (Day 38)

**Objective:** Integrate with Bedrock, OpenAI, and Gemini

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement Bedrock provider | Integration | ⏳ | 8h | 4.1 |
| Implement OpenAI provider | Integration | ⏳ | 8h | 4.2a |
| Implement Gemini provider | Integration | ⏳ | 8h | 4.2b |
| Add provider abstraction | Integration | ⏳ | 8h | 4.2 |
| Add unit tests for providers | Integration | ⏳ | 4h | 4.2 |

**Technical Details:**
```rust
pub trait LLMProvider: Send + Sync {
    fn chat_completion(
        &self,
        model: &str,
        messages: Vec<Message>,
        temperature: f32,
    ) -> Box<dyn Future<Output = Result<Response, ProviderError>> + Send>;
}

pub struct BedrockProvider {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

impl LLMProvider for BedrockProvider {
    fn chat_completion(
        &self,
        model: &str,
        messages: Vec<Message>,
        temperature: f32,
    ) -> Box<dyn Future<Output = Result<Response, ProviderError>> + Send> {
        // Implement Bedrock API call
    }
}
```

**Deliverables:**
- ✅ Bedrock provider implementation
- ✅ OpenAI provider implementation
- ✅ Gemini provider implementation
- ✅ Provider abstraction
- ✅ Unit tests

---

#### **Phase 4.3: Attack Lab** (Day 39-40)

**Objective:** Implement live attack demonstrations

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Implement memory dump demo | Integration | ⏳ | 4h | 4.1 |
| Implement log inspection demo | Integration | ⏳ | 4h | 4.2 |
| Implement wire inspection demo | Integration | ⏳ | 4h | 4.3a |
| Implement DLEQ validation demo | Integration | ⏳ | 4h | 4.3b |
| Implement ledger tampering demo | Integration | ⏳ | 4h | 4.3c |
| Implement canary detection demo | Integration | ⏳ | 4h | 4.3d |
| Create Attack Lab script | Integration | ⏳ | 4h | 4.3 |
| Test all demos | Integration | ⏳ | 4h | 4.3 |

**Attack Lab Script:**
```bash
#!/bin/bash
# Phantom Key v2 Attack Lab

echo "=== Phantom Key v2 Attack Lab ==="
echo ""

# Demo 1: Memory Safety
echo "Demo 1: Memory Safety"
echo "  Command: gcore <pid> && strings core | grep -i 'REAL_SECRET'"
echo "  Expected: No matches"
echo "  Status: $(run_memory_demo)"
echo ""

# Demo 2: Log Inspection
echo "Demo 2: Log Inspection"
echo "  Command: grep -r 'REAL_SECRET' /var/log/phantom-key/"
echo "  Expected: No matches"
echo "  Status: $(run_log_demo)"
echo ""

# Demo 3: Wire Inspection
echo "Demo 3: Wire Inspection"
echo "  Command: tcpdump -i any -A | grep 'REAL_SECRET'"
echo "  Expected: No matches"
echo "  Status: $(run_wire_demo)"
echo ""

# Demo 4: DLEQ Validation
echo "Demo 4: DLEQ Validation"
echo "  Command: feed_bad_partial"
echo "  Expected: Partial rejected"
echo "  Status: $(run_dleq_demo)"
echo ""

# Demo 5: Ledger Tampering
echo "Demo 5: Ledger Tampering"
echo "  Command: tamper_with_ledger"
echo "  Expected: Chain validation fails"
echo "  Status: $(run_tamper_demo)"
echo ""

# Demo 6: Canary Detection
echo "Demo 6: Canary Detection"
echo "  Command: reuse_decoy"
echo "  Expected: Canary flagged"
echo "  Status: $(run_canary_demo)"
echo ""

echo "=== All Attack Lab Demos Complete ==="
```

**Deliverables:**
- ✅ Memory dump demo
- ✅ Log inspection demo
- ✅ Wire inspection demo
- ✅ DLEQ validation demo
- ✅ Ledger tampering demo
- ✅ Canary detection demo
- ✅ Attack Lab script

---

#### **Phase 4.4: Polish & Documentation** (Day 41-42)

**Objective:** Polish system and prepare documentation

| Task | Owner | Status | Effort | Dependencies |
|------|-------|--------|--------|--------------|
| Fix all remaining bugs | Integration | ⏳ | 8h | 4.0 |
| Performance optimization | Integration | ⏳ | 8h | 4.4a |
| Security audit | Security | ⏳ | 8h | 4.4b |
| Write user documentation | Docs | ⏳ | 8h | 4.4 |
| Write competition documentation | Docs | ⏳ | 8h | 4.4d |
| Create competition video | Marketing | ⏳ | 8h | 4.4 |
| Final testing | QA | ⏳ | 8h | 4.4 |

**Deliverables:**
- ✅ Bug-free system
- ✅ Optimized performance
- ✅ Security audit report
- ✅ User documentation
- ✅ Competition documentation
- ✅ Competition video
- ✅ Final test suite

---

## 📦 **Phase 4 Deliverables Summary**

### ✅ **Must Have**
- [ ] Fully integrated system
- [ ] Bedrock, OpenAI, Gemini provider integration
- [ ] Attack Lab with 6 demos
- [ ] Competition video
- [ ] Competition documentation
- [ ] Final test suite

### 📊 **Quality Gates**
- [ ] All demos work correctly
- [ ] Video is under 6 minutes
- [ ] Documentation is complete
- [ ] All tests pass

### 🎯 **Success Metrics**
- **Lines of Code:** ~500-1,000
- **Test Coverage:** 100% overall
- **Performance:** <10ms end-to-end

---

## 📅 **Detailed Timeline**

### Week 1: Core Cryptography
```
Mon-Tue: Phase 1.1 (Setup) + Phase 1.2 (Group Ops)
Wed-Thu: Phase 1.3 (Feldman's VSS)
Fri:     Phase 1.4 (Threshold DH)
```

### Week 2: Core Cryptography Continued
```
Mon-Wed: Phase 1.4 (Threshold DH) + Phase 1.5 (Share Refresh)
Thu-Fri: Buffer / Catch-up
```

### Week 3: Vault System
```
Mon:     Phase 2.1 (Vault Storage)
Tue:     Phase 2.2 (Per-Secret Encryption)
Wed:     Phase 2.3 (Handle System)
Thu:     Phase 2.4 (Decoy Generation)
Fri:     Phase 2.5 (Decoy-to-Handle Mapping)
```

### Week 4: Egress Court
```
Mon:     Phase 3.1 (Ledger)
Tue:     Phase 3.2 (Scanner)
Wed:     Phase 3.3 (Canary System)
Thu-Fri: Phase 3.4 (Interceptor) + Phase 3.5 (TUI)
```

### Week 5: Egress Court Continued
```
Mon-Tue: Phase 3.5 (TUI) - if not complete
Wed-Fri: Phase 4.1 (Integration) + Phase 4.2 (Providers)
```

### Week 6: Polish & Competition Prep
```
Mon:     Phase 4.3 (Attack Lab)
Tue:     Phase 4.4 (Polish)
Wed:     Phase 4.4 (Documentation)
Thu:     Phase 4.4 (Video)
Fri:     Final Testing + Submission
```

---

## 🎯 **Critical Path**

```
Phase 1 (Core Crypto) 
    ↓
Phase 2 (Vault System) 
    ↓
Phase 3 (Egress Court) 
    ↓
Phase 4 (Integration & Polish)
```

**Blockers:**
- Phase 2 cannot start until Phase 1 is complete
- Phase 3 cannot start until Phase 2 is complete
- Phase 4 cannot start until Phase 3 is complete

---

## 📊 **Resource Allocation**

### Team Structure

| Role | Responsibility | Team Size | Weeks |
|------|---------------|-----------|-------|
| **Crypto Team** | Phase 1 (Core Cryptography) | 2-3 | 1-2 |
| **Security Team** | Phase 2 (Vault System) | 2 | 1 |
| **Backend Team** | Phase 3 (Egress Court) | 2 | 2 |
| **Integration Team** | Phase 4 (Integration) | 2-3 | 1 |
| **QA/Testing** | Testing across all phases | 1 | 6 |
| **Documentation** | Documentation | 1 | 6 |

### Total Effort

| Phase | Effort (person-days) | Team Size | Duration |
|-------|---------------------|-----------|----------|
| Phase 1 | 40-50 | 2-3 | 2 weeks |
| Phase 2 | 20-25 | 2 | 1 week |
| Phase 3 | 40-50 | 2 | 2 weeks |
| Phase 4 | 20-25 | 2-3 | 1 week |
| **Total** | **120-150** | **2-3** | **6 weeks** |

---

## 🎯 **Risk Management**

### High Risks

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| Crypto implementation bugs | HIGH | Extensive testing, code reviews | Crypto Team |
| Performance issues | MEDIUM | Profiling, optimization | All Teams |
| Integration problems | HIGH | Early integration testing | Integration Team |
| Security vulnerabilities | CRITICAL | Security audit, penetration testing | Security Team |

### Medium Risks

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| Provider API changes | MEDIUM | Abstract provider interface | Backend Team |
| Dependency issues | MEDIUM | Pin versions, test upgrades | All Teams |
| Documentation incomplete | LOW | Dedicated docs time | Docs Team |

### Low Risks

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| Team availability | LOW | Cross-training, buffer time | All Teams |
| Scope creep | LOW | Strict scope management | PM |

---

## 📈 **Success Criteria**

### Must Have (Non-Negotiable)
- [ ] DKG implementation with Feldman commitments
- [ ] Threshold DH with DLEQ proofs
- [ ] Sealed vault with per-secret encryption
- [ ] Handle system
- [ ] Decoy generation
- [ ] Signed, hash-chained ledger
- [ ] Secret scanner
- [ ] Canary system
- [ ] TUI with all panels
- [ ] Bedrock, OpenAI, Gemini integration
- [ ] Attack Lab with 6 demos
- [ ] Competition video
- [ ] 100% test coverage

### Should Have
- [ ] Proactive share refresh
- [ ] Performance <10ms end-to-end
- [ ] Memory safety (no secrets in logs/memory)
- [ ] Comprehensive documentation

### Nice to Have
- [ ] Additional provider integrations
- [ ] Advanced TUI features
- [ ] Performance benchmarks
- [ ] Security audit by external expert

---

## 🏆 **Competition Readiness Checklist**

### UI (3 points)
- [ ] Textual TUI implemented
- [ ] Chat panel working
- [ ] Egress/ledger panel showing chain status
- [ ] Shareholder status panel working
- [ ] Vault panel working
- [ ] Real-time updates

### Video (2 points)
- [ ] Attack Lab script complete
- [ ] All 6 demos working
- [ ] Video script written
- [ ] Video recorded
- [ ] Video edited (<6 minutes)
- [ ] Video uploaded

### API Evidence (2 points)
- [ ] Bedrock integration working
- [ ] OpenAI integration working
- [ ] Gemini integration working
- [ ] Provider request IDs logged in ledger
- [ ] Real API calls demonstrated

---

## 📞 **Communication Plan**

### Daily
- Standup meeting (15 minutes)
- Progress updates in Slack
- Blockers escalated immediately

### Weekly
- Sprint review (30 minutes)
- Demo of completed work
- Planning for next week

### Milestones
- End of Week 2: Phase 1 complete
- End of Week 3: Phase 2 complete
- End of Week 5: Phase 3 complete
- End of Week 6: Phase 4 complete, ready for submission

---

## 💰 **Budget**

| Category | Cost | Notes |
|----------|------|-------|
| Development | $0 | Internal team |
| Cloud (Testing) | $500-1,000 | Bedrock/OpenAI/Gemini API calls |
| Tools | $0 | Open-source dependencies |
| **Total** | **$500-1,000** | |

---

## 🎯 **Final Notes**

### What Makes This Plan Strong

1. **Phased Approach** - Clear dependencies between phases
2. **Realistic Timeline** - 6 weeks with buffer time
3. **Risk-Aware** - Identifies and mitigates risks
4. **Quality-Focused** - 100% test coverage requirement
5. **Competition-Optimized** - Focuses on rubric points

### What to Watch For

1. **Phase 1 is Critical Path** - Any delays here cascade
2. **Crypto is Hard** - Allocate best developers to Phase 1
3. **Integration Complexity** - Start integration testing early
4. **Video Production** - Don't leave to last minute

### Success Metrics

- **On Time:** All phases complete by end of Week 6
- **On Budget:** Stay under $1,000
- **On Quality:** 100% test coverage, no critical bugs
- **On Competition:** Maximum rubric points (7/7)

---

## 📝 **Document Information**

**Project:** Phantom Key v2  
**Version:** 1.0  
**Last Updated:** October 26, 2026  
**Author:** Based on user corrections  
**Status:** Approved for Implementation  
**Classification:** Internal - Confidential
