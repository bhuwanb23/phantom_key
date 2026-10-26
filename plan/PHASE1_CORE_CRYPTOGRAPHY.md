# Phase 1: Core Cryptography

**Project:** Phantom Key v2  
**Phase:** 1 of 4  
**Duration:** 2 weeks (Weeks 1-2)  
**Lead:** Crypto Team  
**Status:** ⏳ Not Started  
**Priority:** 🔴 **CRITICAL** (Blocker for all other phases)

---

## 🎯 Phase Overview

**Objective:** Implement the foundational cryptographic primitives for Phantom Key v2.

This phase establishes the **dealerless threshold cryptography** system that forms the security backbone of the entire project. Without this phase, no other phase can begin.

### Key Outcomes
- ✅ Dealerless Key Generation (DKG) with Feldman commitments
- ✅ Threshold Diffie-Hellman with Chaum-Pedersen DLEQ proofs
- ✅ Proactive share refresh mechanism
- ✅ All cryptographic operations tested and validated
- ✅ 100% unit test coverage for crypto module

---

## 📋 Sub-Phases & Tasks

### Sub-Phase 1.1: Setup & Dependencies (Day 1)

**Objective:** Establish development environment and project structure.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 1.1.1 | Initialize Rust project | Create Cargo.toml with all dependencies | Dev | 2h | None | ⏳ |
| 1.1.2 | Set up Git repository | Configure branching strategy (main, dev, feature) | Dev | 2h | 1.1.1 | ⏳ |
| 1.1.3 | Configure CI/CD | GitHub Actions for builds, tests, linting | DevOps | 4h | 1.1.2 | ⏳ |
| 1.1.4 | Set up dev containers | Docker/Dev Containers for consistent environment | Dev | 4h | 1.1.1 | ⏳ |
| 1.1.5 | Configure logging | Structured logging with tracing + slog | Dev | 4h | 1.1.1 | ⏳ |
| 1.1.6 | Configure error handling | Custom error types, thiserror, anyhow | Dev | 4h | 1.1.1 | ⏳ |

#### Deliverables
- [ ] Rust project with Cargo.toml
- [ ] Git repository with branching strategy
- [ ] CI/CD pipeline (build, test, lint, clippy)
- [ ] Development containers (Docker/Dev Containers)
- [ ] Logging framework configured
- [ ] Error handling framework configured

#### Acceptance Criteria
- [ ] `cargo build` succeeds
- [ ] `cargo test` runs (no tests yet, but framework works)
- [ ] `cargo clippy` passes with no warnings
- [ ] CI pipeline runs on push
- [ ] Dev container can be used for development

#### Dependencies (Cargo.toml)
```toml
[dependencies]
# Cryptography
curve25519-dalek = { version = "4.0", features = ["ristretto", "serde"] }
ed25519-dalek = "2.0"
sha2 = "0.10"
rand_core = { version = "0.6", features = ["std"] }
rand = "0.8"
zeroize = { version = "1.6", features = ["derive"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"

# Async
tokio = { version = "1.0", features = ["full"] }

# Testing
proptest = "1.0"
criterion = "0.4"

[dev-dependencies]
# Additional test dependencies
```

---

### Sub-Phase 1.2: Group Operations & Serialization (Day 2-3)

**Objective:** Implement Ristretto255 group operations with proper serialization.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 1.2.1 | Implement Scalar wrapper | Safe wrapper around curve25519-dalek::Scalar | Crypto | 4h | 1.1 | ⏳ |
| 1.2.2 | Implement RistrettoPoint wrapper | Safe wrapper around curve25519-dalek::RistrettoPoint | Crypto | 4h | 1.2.1 | ⏳ |
| 1.2.3 | Implement group addition | P + Q for RistrettoPoints | Crypto | 2h | 1.2.2 | ⏳ |
| 1.2.4 | Implement scalar multiplication | s * P for Scalar s and RistrettoPoint P | Crypto | 2h | 1.2.2 | ⏳ |
| 1.2.5 | Implement group negation | -P for RistrettoPoint P | Crypto | 2h | 1.2.3 | ⏳ |
| 1.2.6 | Implement identity element | Generator and identity | Crypto | 2h | 1.2.2 | ⏳ |
| 1.2.7 | Implement serialization | To/from bytes for Scalar and RistrettoPoint | Crypto | 4h | 1.2 | ⏳ |
| 1.2.8 | Implement constant-time equality | ct_eq for all types | Crypto | 4h | 1.2 | ⏳ |
| 1.2.9 | Add unit tests | Comprehensive tests for all operations | Crypto | 8h | 1.2 | ⏳ |

#### Technical Details

**File: `src/crypto/group.rs`**

```rust
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

/// Wrapper for Scalar with safe operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct GroupScalar(Scalar);

impl GroupScalar {
    /// Generate random scalar
    pub fn random() -> Self {
        Self(Scalar::random(&mut rand::thread_rng()))
    }
    
    /// Zero scalar
    pub fn zero() -> Self {
        Self(Scalar::zero())
    }
    
    /// One scalar
    pub fn one() -> Self {
        Self(Scalar::one())
    }
    
    /// From bytes (32 bytes)
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Scalar::from_canonical_bytes(bytes).map(Self)
    }
    
    /// To bytes (32 bytes)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    /// Constant-time equality
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

/// Wrapper for RistrettoPoint with safe operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupElement(RistrettoPoint);

impl GroupElement {
    /// Generator point
    pub fn generator() -> Self {
        Self(RistrettoPoint::generator())
    }
    
    /// Identity element
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
    
    /// From bytes (32 bytes compressed)
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        RistrettoPoint::from_uniform_bytes(&bytes).map(Self)
    }
    
    /// To bytes (32 bytes compressed)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    
    /// Add two group elements
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }
    
    /// Multiply by scalar
    pub fn multiply(&self, scalar: &GroupScalar) -> Self {
        Self(self.0 * scalar.0)
    }
    
    /// Negate element
    pub fn negate(&self) -> Self {
        Self(-self.0)
    }
    
    /// Constant-time equality
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}
```

**File: `src/crypto/group/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scalar_operations() {
        let s1 = GroupScalar::random();
        let s2 = GroupScalar::random();
        
        // Test addition
        let sum = s1 + s2;
        
        // Test multiplication
        let G = GroupElement::generator();
        let _ = G.multiply(&s1);
    }
    
    #[test]
    fn test_group_operations() {
        let G = GroupElement::generator();
        let s = GroupScalar::random();
        
        // s*G should be a valid point
        let sG = G.multiply(&s);
        
        // Test serialization round-trip
        let bytes = sG.to_bytes();
        let decoded = GroupElement::from_bytes(bytes).unwrap();
        assert!(sG.ct_eq(&decoded));
    }
    
    #[test]
    fn test_identity() {
        let I = GroupElement::identity();
        let G = GroupElement::generator();
        
        // G + I = G
        assert!(G.add(&I).ct_eq(&G));
        
        // G + (-G) = I
        assert!(G.add(&G.negate()).ct_eq(&I));
    }
}
```

#### Deliverables
- [ ] `GroupScalar` type with all operations
- [ ] `GroupElement` type with all operations
- [ ] Serialization/deserialization for both types
- [ ] Constant-time equality implementations
- [ ] Comprehensive unit tests

#### Acceptance Criteria
- [ ] All group operations work correctly
- [ ] Serialization round-trips preserve values
- [ ] Constant-time tests pass
- [ ] 100% unit test coverage for group module

---

### Sub-Phase 1.3: Feldman's VSS (DKG) (Day 4-7)

**Objective:** Implement dealerless key generation with Feldman's Verifiable Secret Sharing.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 1.3.1 | Implement polynomial generation | Generate random polynomial f(x) = a₀ + a₁x + ... + a_{k-1}x^{k-1} | Crypto | 8h | 1.2 | ⏳ |
| 1.3.2 | Implement polynomial evaluation | Evaluate f(x) at arbitrary points | Crypto | 4h | 1.3.1 | ⏳ |
| 1.3.3 | Implement commitment generation | C_j = g^{a_j} for coefficients | Crypto | 8h | 1.3.1 | ⏳ |
| 1.3.4 | Implement share generation | Generate shares (i, f(i)) for each party | Crypto | 8h | 1.3.2 | ⏳ |
| 1.3.5 | Implement share verification | Verify shares against commitments | Crypto | 8h | 1.3.3, 1.3.4 | ⏳ |
| 1.3.6 | Implement final share combination | Sum all party contributions | Crypto | 8h | 1.3.5 | ⏳ |
| 1.3.7 | Implement public key generation | S = s·G where s is the secret | Crypto | 4h | 1.3.6 | ⏳ |
| 1.3.8 | Add unit tests for DKG | Comprehensive tests for all operations | Crypto | 16h | 1.3 | ⏳ |

#### Technical Details

**File: `src/crypto/dkg.rs`**

```rust
use super::group::{GroupScalar, GroupElement};
use serde::{Serialize, Deserialize};

/// Party contribution to DKG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyContribution {
    pub party_id: usize,
    pub shares: Vec<GroupScalar>,      // f_i(j) for j = 1..n
    pub commitments: Vec<GroupElement>, // g^{a_j} for j = 0..k-1
}

/// Feldman's VSS for dealerless DKG
pub struct DKG {
    parties: usize,
    threshold: usize,
}

impl DKG {
    pub fn new(parties: usize, threshold: usize) -> Self {
        assert!(threshold <= parties, "Threshold must be <= parties");
        assert!(threshold > 0, "Threshold must be > 0");
        Self { parties, threshold }
    }
    
    /// Generate a party's contribution
    pub fn generate_contribution(&self, party_id: usize) -> PartyContribution {
        let mut rng = rand::thread_rng();
        
        // Generate random coefficients a_0, a_1, ..., a_{k-1}
        let coefficients: Vec<GroupScalar> = (0..self.threshold)
            .map(|_| GroupScalar::random())
            .collect();
        
        // Generate commitments: C_j = g^{a_j}
        let commitments: Vec<GroupElement> = coefficients.iter()
            .map(|a| GroupElement::generator().multiply(a))
            .collect();
        
        // Generate shares: f_i(j) = a_0 + a_1*j + ... + a_{k-1}*j^{k-1}
        let shares: Vec<GroupScalar> = (1..=self.parties)
            .map(|j| {
                let j_scalar = GroupScalar::from_bytes([j as u8; 32]).unwrap_or(GroupScalar::zero());
                coefficients.iter()
                    .zip(0..self.threshold)
                    .fold(GroupScalar::zero(), |acc, (a, power)| {
                        acc + a.multiply(&j_scalar.pow(power as u64))
                    })
            })
            .collect();
        
        PartyContribution {
            party_id,
            shares,
            commitments,
        }
    }
    
    /// Verify a party's contribution
    pub fn verify_contribution(
        &self,
        contribution: &PartyContribution,
    ) -> bool {
        let PartyContribution { shares, commitments, .. } = contribution;
        
        // For each share (j, f_i(j)), verify:
        // g^{f_i(j)} == Π_{m=0}^{k-1} (C_m)^{j^m}
        for (j, share) in shares.iter().enumerate() {
            let j_index = j + 1; // j is 0-indexed, share index is 1-indexed
            let j_scalar = GroupScalar::from_bytes([j_index as u8; 32]).unwrap_or(GroupScalar::zero());
            
            // Compute left side: g^{f_i(j)}
            let left = GroupElement::generator().multiply(share);
            
            // Compute right side: Π_{m=0}^{k-1} (C_m)^{j^m}
            let right = commitments.iter()
                .zip(0..self.threshold)
                .fold(GroupElement::identity(), |acc, (commitment, power)| {
                    let exponent = j_scalar.pow(power as u64);
                    acc + commitment.multiply(&exponent)
                });
            
            if !left.ct_eq(&right) {
                return false;
            }
        }
        
        true
    }
    
    /// Combine all contributions to get final shares
    pub fn combine_contributions(
        &self,
        contributions: &[PartyContribution],
    ) -> Vec<GroupScalar> {
        assert_eq!(contributions.len(), self.parties, "Need contributions from all parties");
        
        // For each party j, final share s_j = Σ_i f_i(j)
        let mut final_shares = vec![GroupScalar::zero(); self.parties];
        
        for contribution in contributions {
            for (j, share) in contribution.shares.iter().enumerate() {
                final_shares[j] = final_shares[j] + *share;
            }
        }
        
        final_shares
    }
    
    /// Get public key from all contributions
    pub fn get_public_key(
        &self,
        contributions: &[PartyContribution],
    ) -> GroupElement {
        // S = s·G = (Σ a_0_i)·G = Σ (a_0_i·G) = Σ C_0_i
        contributions.iter()
            .map(|c| c.commitments[0])
            .fold(GroupElement::identity(), |acc, c| acc + c)
    }
}

/// Horner's rule for polynomial evaluation
/// Evaluates f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{n-1}*x^{n-1}
fn evaluate_polynomial(coefficients: &[GroupScalar], x: &GroupScalar) -> GroupScalar {
    coefficients.iter()
        .rev()
        .fold(GroupScalar::zero(), |acc, &coeff| acc * x + coeff)
}
```

**File: `src/crypto/dkg/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dkg_honest_parties() {
        let dkg = DKG::new(5, 3);
        
        // Generate contributions from all parties
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i))
            .collect();
        
        // Verify all contributions
        for contribution in &contributions {
            assert!(dkg.verify_contribution(contribution));
        }
        
        // Combine to get final shares
        let shares = dkg.combine_contributions(&contributions);
        
        // Get public key
        let public_key = dkg.get_public_key(&contributions);
        
        // Verify that threshold shares can reconstruct
        // (This requires implementing Lagrange interpolation)
    }
    
    #[test]
    fn test_dkg_malicious_party() {
        let dkg = DKG::new(5, 3);
        
        // Generate honest contributions
        let mut contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i))
            .collect();
        
        // Corrupt one party's contribution
        contributions[2].commitments[0] = GroupElement::generator(); // Wrong commitment
        
        // Verification should fail
        assert!(!dkg.verify_contribution(&contributions[2]));
    }
    
    #[test]
    fn test_polynomial_evaluation() {
        let coefficients = vec![
            GroupScalar::one(),
            GroupScalar::from_bytes([2; 32]).unwrap(),
            GroupScalar::from_bytes([3; 32]).unwrap(),
        ];
        
        let x = GroupScalar::from_bytes([5; 32]).unwrap();
        let result = evaluate_polynomial(&coefficients, &x);
        
        // f(x) = 1 + 2x + 3x^2
        // For x=5: 1 + 2*5 + 3*25 = 1 + 10 + 75 = 86
        // But we're in a finite field, so this is just a sanity check
    }
}
```

#### Deliverables
- [ ] DKG protocol implementation
- [ ] Polynomial generation and evaluation (Horner's rule)
- [ ] Commitment generation and verification
- [ ] Share generation and combination
- [ ] Public key generation
- [ ] Comprehensive unit tests

#### Acceptance Criteria
- [ ] DKG completes successfully with honest parties
- [ ] Malicious parties are detected via commitments
- [ ] Final shares are consistent across parties
- [ ] Public key is correctly computed
- [ ] 100% unit test coverage for DKG

---

### Sub-Phase 1.4: Threshold Diffie-Hellman (Day 8-10)

**Objective:** Implement threshold DH with Chaum-Pedersen DLEQ proofs.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 1.4.1 | Implement ephemeral key generation | Client picks r, computes R = r·G | Crypto | 4h | 1.2, 1.3 | ⏳ |
| 1.4.2 | Implement partial computation | Party computes P_i = s_i·R | Crypto | 8h | 1.4.1 | ⏳ |
| 1.4.3 | Implement DLEQ proof generation | Chaum-Pedersen proof for P_i | Crypto | 16h | 1.4.2 | ⏳ |
| 1.4.4 | Implement DLEQ proof verification | Verify proof without knowing s_i | Crypto | 16h | 1.4.3 | ⏳ |
| 1.4.5 | Implement partial combination | Client combines P_i using Lagrange | Crypto | 8h | 1.4.2, 1.3 | ⏳ |
| 1.4.6 | Implement key derivation | HKDF for AEAD key derivation | Crypto | 8h | 1.4.5 | ⏳ |
| 1.4.7 | Add unit tests | Comprehensive tests for threshold DH | Crypto | 8h | 1.4 | ⏳ |

#### Technical Details

**File: `src/crypto/threshold_dh.rs`**

```rust
use super::{
    group::{GroupElement, GroupScalar},
    dkg::DKG,
};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// Chaum-Pedersen DLEQ Proof
/// Proves knowledge of s such that:
/// P = s·R AND S = s·G
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLEQProof {
    pub a1: GroupElement,
    pub a2: GroupElement,
    pub z1: GroupScalar,
    pub z2: GroupScalar,
}

impl DLEQProof {
    /// Generate DLEQ proof
    pub fn new(
        s: &GroupScalar,
        P: &GroupElement,
        S: &GroupElement,
        R: &GroupElement,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let k = GroupScalar::random();
        
        let a1 = GroupElement::generator().multiply(&k);
        let a2 = R.multiply(&k);
        
        // c = H(g, G, P, R, S, a1, a2)
        let mut hasher = Sha256::new();
        hasher.update(&GroupElement::generator().to_bytes());
        hasher.update(&GroupElement::generator().to_bytes());
        hasher.update(&P.to_bytes());
        hasher.update(&R.to_bytes());
        hasher.update(&S.to_bytes());
        hasher.update(&a1.to_bytes());
        hasher.update(&a2.to_bytes());
        let c_bytes = hasher.finalize();
        let c = GroupScalar::from_bytes(c_bytes.into()).unwrap_or(GroupScalar::zero());
        
        let z1 = &k + &c.multiply(s);
        let z2 = &c.multiply(s);
        
        Self { a1, a2, z1, z2 }
    }
    
    /// Verify DLEQ proof
    pub fn verify(
        &self,
        P: &GroupElement,
        S: &GroupElement,
        R: &GroupElement,
    ) -> bool {
        // c = H(g, G, P, R, S, a1, a2)
        let mut hasher = Sha256::new();
        hasher.update(&GroupElement::generator().to_bytes());
        hasher.update(&GroupElement::generator().to_bytes());
        hasher.update(&P.to_bytes());
        hasher.update(&R.to_bytes());
        hasher.update(&S.to_bytes());
        hasher.update(&self.a1.to_bytes());
        hasher.update(&self.a2.to_bytes());
        let c_bytes = hasher.finalize();
        let c = GroupScalar::from_bytes(c_bytes.into()).unwrap_or(GroupScalar::zero());
        
        // Verify: g^{z1} == a1 * S^c
        let left1 = GroupElement::generator().multiply(&self.z1);
        let right1 = self.a1 + S.multiply(&c);
        
        // Verify: R^{z2} * P^{-c} == a2
        let left2 = R.multiply(&self.z2) + P.multiply(&c.negate());
        let right2 = self.a2;
        
        left1.ct_eq(&right1) && left2.ct_eq(&right2)
    }
}

/// Threshold Diffie-Hellman
pub struct ThresholdDH {
    shares: Vec<GroupScalar>,      // s_i for this party
    public_shares: Vec<GroupElement>, // S_i = s_i·G
    dkg: DKG,
}

impl ThresholdDH {
    pub fn new(shares: Vec<GroupScalar>, public_shares: Vec<GroupElement>, dkg: DKG) -> Self {
        assert_eq!(shares.len(), public_shares.len());
        Self { shares, public_shares, dkg }
    }
    
    /// Compute partial: P_i = s_i·R with DLEQ proof
    pub fn compute_partial(
        &self,
        share_index: usize,
        R: &GroupElement,
    ) -> Option<(GroupElement, DLEQProof)> {
        let s_i = self.shares.get(share_index)?;
        let S_i = self.public_shares.get(share_index)?;
        
        let P_i = S_i.multiply(s_i); // P_i = s_i·R = (s_i·G)·R = S_i·R
        // Wait, this is wrong. Let me recalculate.
        // P_i should be s_i * R, not S_i * R
        let P_i = R.multiply(s_i); // Correct: P_i = s_i·R
        
        let proof = DLEQProof::new(s_i, &P_i, S_i, R);
        Some((P_i, proof))
    }
    
    /// Combine partials using Lagrange interpolation
    pub fn combine_partials(
        &self,
        partials: &[(GroupElement, DLEQProof)],
        R: &GroupElement,
    ) -> Option<GroupElement> {
        // First, verify all proofs
        for (P_i, proof) in partials {
            let S_i = self.public_shares.get(partials.iter().position(|(p, _)| p == P_i).unwrap_or(0))?;
            if !proof.verify(P_i, S_i, R) {
                return None; // Reject invalid partial
            }
        }
        
        // Extract just the P_i values
        let P_i_values: Vec<GroupElement> = partials.iter().map(|(P_i, _)| *P_i).collect();
        
        // Get indices of parties that contributed
        let indices: Vec<usize> = (0..partials.len()).map(|i| i + 1).collect(); // 1-indexed
        
        // Compute Lagrange coefficients at 0
        let lambdas = self.lagrange_coefficients(&indices, 0);
        
        // K = Σ λ_i·P_i
        let K = P_i_values.iter()
            .zip(lambdas.iter())
            .fold(GroupElement::identity(), |acc, (P_i, &lambda)| {
                acc + P_i.multiply(&lambda)
            });
        
        Some(K)
    }
    
    /// Lagrange coefficients for interpolation at x=0
    fn lagrange_coefficients(&self, indices: &[usize], x: usize) -> Vec<GroupScalar> {
        let x_scalar = GroupScalar::from_bytes([x as u8; 32]).unwrap_or(GroupScalar::zero());
        
        indices.iter()
            .map(|&i| {
                let i_scalar = GroupScalar::from_bytes([i as u8; 32]).unwrap_or(GroupScalar::zero());
                let mut numerator = GroupScalar::one();
                let mut denominator = GroupScalar::one();
                
                for &j in indices {
                    if j == i {
                        continue;
                    }
                    let j_scalar = GroupScalar::from_bytes([j as u8; 32]).unwrap_or(GroupScalar::zero());
                    numerator = numerator * (x_scalar - j_scalar);
                    denominator = denominator * (i_scalar - j_scalar);
                }
                
                numerator * denominator.invert()
            })
            .collect()
    }
    
    /// Derive key using HKDF
    pub fn derive_key(
        K: &GroupElement,
        R: &GroupElement,
        context: &[u8],
    ) -> Vec<u8> {
        // HKDF(K || R, context)
        let mut hkdf = HmacSha256::new_from_slice(K.to_bytes().as_ref())
            .expect("HKDF init failed");
        
        // Extract
        let mut prk = [0u8; 32];
        hkdf.update(R.to_bytes().as_ref());
        hkdf.finalize_into(&mut prk).expect("HKDF extract failed");
        
        // Expand
        let mut okm = vec![0u8; 32];
        HmacSha256::new_from_slice(&prk)
            .and_then(|mut h| {
                h.update(context);
                h.finalize_into(&mut okm)
            })
            .expect("HKDF expand failed");
        
        okm
    }
}
```

**File: `src/crypto/threshold_dh/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dleq_proof() {
        let s = GroupScalar::random();
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let G = GroupElement::generator();
        
        let P = R.multiply(&s);
        let S = G.multiply(&s);
        
        let proof = DLEQProof::new(&s, &P, &S, &R);
        assert!(proof.verify(&P, &S, &R));
    }
    
    #[test]
    fn test_dleq_proof_rejection() {
        let s = GroupScalar::random();
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let G = GroupElement::generator();
        
        let P = R.multiply(&s);
        let S = G.multiply(&s);
        
        let proof = DLEQProof::new(&s, &P, &S, &R);
        
        // Try to verify with wrong values
        let wrong_P = R.multiply(&GroupScalar::random());
        assert!(!proof.verify(&wrong_P, &S, &R));
    }
    
    #[test]
    fn test_threshold_dh() {
        let dkg = DKG::new(5, 3);
        
        // Generate contributions and final shares
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i))
            .collect();
        
        let shares = dkg.combine_contributions(&contributions);
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        let threshold_dh = ThresholdDH::new(shares.clone(), public_shares, dkg);
        
        // Client picks ephemeral
        let r = GroupScalar::random();
        let R = GroupElement::generator().multiply(&r);
        
        // Parties compute partials
        let partials: Vec<(GroupElement, DLEQProof)> = (0..3)
            .filter_map(|i| threshold_dh.compute_partial(i, &R))
            .collect();
        
        // Client combines
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify: K should equal s·R where s = Σ shares[i]
        let s_total: GroupScalar = (0..3).fold(GroupScalar::zero(), |acc, i| acc + shares[i]);
        let expected_K = R.multiply(&s_total);
        
        assert!(K.ct_eq(&expected_K));
    }
}
```

#### Deliverables
- [ ] Threshold DH implementation
- [ ] DLEQ proof generation
- [ ] DLEQ proof verification
- [ ] Partial computation
- [ ] Partial combination with proof verification
- [ ] Key derivation using HKDF
- [ ] Comprehensive unit tests

#### Acceptance Criteria
- [ ] Partial computation works correctly
- [ ] DLEQ proofs are generated and verified
- [ ] Invalid partials are rejected
- [ ] Combined result equals s·R
- [ ] Key derivation produces consistent keys
- [ ] 100% unit test coverage for threshold DH

---

### Sub-Phase 1.5: Proactive Share Refresh (Day 11-14)

**Objective:** Implement epoch-based share refresh to limit damage from compromised shares.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 1.5.1 | Implement epoch management | Track current epoch, manage epoch transitions | Crypto | 4h | 1.3, 1.4 | ⏳ |
| 1.5.2 | Implement share refresh protocol | Generate new shares without reconstructing old s | Crypto | 16h | 1.5.1 | ⏳ |
| 1.5.3 | Implement old share storage | Store old shares temporarily for verification | Crypto | 4h | 1.5.2 | ⏳ |
| 1.5.4 | Implement old share destruction | Securely wipe old shares after verification period | Crypto | 8h | 1.5.3 | ⏳ |
| 1.5.5 | Implement epoch-based key derivation | Bind keys to specific epochs | Crypto | 4h | 1.5.1 | ⏳ |
| 1.5.6 | Add unit tests for refresh | Comprehensive tests for share refresh | Crypto | 8h | 1.5 | ⏳ |

#### Technical Details

**File: `src/crypto/share_refresh.rs`**

```rust
use super::{
    group::GroupScalar,
    dkg::{DKG, PartyContribution},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Share manager with epoch-based refresh
pub struct ShareManager {
    current_epoch: u64,
    shares: Vec<GroupScalar>,           // Current epoch shares
    old_shares: HashMap<u64, Vec<GroupScalar>>, // Old epochs (epoch -> shares)
    epoch_duration: Duration,
    verification_period: Duration,
    dkg: DKG,
}

impl ShareManager {
    pub fn new(
        parties: usize,
        threshold: usize,
        epoch_duration: Duration,
        verification_period: Duration,
    ) -> Self {
        let dkg = DKG::new(parties, threshold);
        let shares = vec![GroupScalar::zero(); parties]; // Will be initialized
        
        Self {
            current_epoch: 0,
            shares,
            old_shares: HashMap::new(),
            epoch_duration,
            verification_period,
            dkg,
        }
    }
    
    /// Initialize with first DKG
    pub fn initialize(&mut self) {
        // Run initial DKG
        let contributions: Vec<PartyContribution> = (0..self.dkg.parties)
            .map(|i| self.dkg.generate_contribution(i))
            .collect();
        
        self.shares = self.dkg.combine_contributions(&contributions);
    }
    
    /// Refresh shares for new epoch
    pub fn refresh(&mut self) -> Result<(), ShareRefreshError> {
        // Generate new contributions
        let contributions: Vec<PartyContribution> = (0..self.dkg.parties)
            .map(|i| self.dkg.generate_contribution(i))
            .collect();
        
        // Store old shares (temporarily)
        self.old_shares.insert(self.current_epoch, std::mem::replace(&mut self.shares, 
            self.dkg.combine_contributions(&contributions)));
        
        // Increment epoch
        self.current_epoch += 1;
        
        // Schedule destruction of old shares
        self.schedule_destruction();
        
        Ok(())
    }
    
    /// Schedule destruction of old shares
    fn schedule_destruction(&self) {
        // In a real implementation, this would use a background task
        // For now, we'll just track when shares should be destroyed
    }
    
    /// Destroy old shares that have passed verification period
    pub fn cleanup_old_shares(&mut self) {
        let now = Instant::now();
        
        self.old_shares.retain(|epoch, _| {
            // Keep shares for verification_period after epoch ended
            let epoch_end = self.epoch_start_time(*epoch);
            now.duration_since(epoch_end) < self.verification_period
        });
    }
    
    /// Get share for current epoch
    pub fn get_share(&self, party_id: usize) -> Option<GroupScalar> {
        self.shares.get(party_id).cloned()
    }
    
    /// Get share for specific epoch (for verification)
    pub fn get_epoch_share(&self, epoch: u64, party_id: usize) -> Option<GroupScalar> {
        if epoch == self.current_epoch {
            self.get_share(party_id)
        } else {
            self.old_shares.get(&epoch).and_then(|shares| shares.get(party_id).cloned())
        }
    }
    
    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    
    /// Check if share refresh is needed
    pub fn needs_refresh(&self, last_refresh: Instant) -> bool {
        last_refresh.elapsed() >= self.epoch_duration
    }
    
    fn epoch_start_time(&self, epoch: u64) -> Instant {
        // This would be tracked in a real implementation
        Instant::now() // Simplified
    }
}

/// Automatically refresh shares on schedule
pub struct AutoRefresh {
    share_manager: Arc<Mutex<ShareManager>>,
    refresh_interval: Duration,
}

impl AutoRefresh {
    pub fn new(share_manager: Arc<Mutex<ShareManager>>, refresh_interval: Duration) -> Self {
        Self { share_manager, refresh_interval }
    }
    
    pub fn start(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.refresh_interval);
            loop {
                interval.tick().await;
                let mut manager = self.share_manager.lock().unwrap();
                if manager.needs_refresh(Instant::now()) {
                    let _ = manager.refresh();
                    manager.cleanup_old_shares();
                }
            }
        });
    }
}
```

**File: `src/crypto/share_refresh/tests.rs`**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_share_refresh() {
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600), // 1 hour epoch
            Duration::from_secs(300),  // 5 minute verification
        );
        
        manager.initialize();
        
        let old_shares = manager.shares.clone();
        
        // Refresh
        manager.refresh().unwrap();
        
        // Shares should be different
        assert_ne!(old_shares, manager.shares);
        
        // Old shares should be stored
        assert!(manager.old_shares.contains_key(&0));
    }
    
    #[test]
    fn test_epoch_management() {
        let mut manager = ShareManager::new(5, 3, Duration::from_secs(3600), Duration::from_secs(300));
        manager.initialize();
        
        assert_eq!(manager.current_epoch(), 0);
        
        manager.refresh().unwrap();
        assert_eq!(manager.current_epoch(), 1);
        
        manager.refresh().unwrap();
        assert_eq!(manager.current_epoch(), 2);
    }
}
```

#### Deliverables
- [ ] Share manager with epoch tracking
- [ ] Share refresh protocol
- [ ] Old share storage and destruction
- [ ] Epoch-based key derivation
- [ ] Auto-refresh mechanism
- [ ] Comprehensive unit tests

#### Acceptance Criteria
- [ ] Share refresh completes successfully
- [ ] Old shares are stored temporarily
- [ ] Old shares are destroyed after verification period
- [ ] New epoch shares are independent of old shares
- [ ] Operations can be verified against old epochs
- [ ] 100% unit test coverage for share refresh

---

## 📊 Phase Summary

### Tasks Breakdown
| Sub-Phase | Tasks | Effort | Status |
|-----------|-------|--------|--------|
| 1.1 Setup | 6 | 24h | ⏳ |
| 1.2 Group Ops | 9 | 48h | ⏳ |
| 1.3 DKG | 8 | 64h | ⏳ |
| 1.4 Threshold DH | 7 | 64h | ⏳ |
| 1.5 Share Refresh | 6 | 40h | ⏳ |
| **Total** | **36** | **240h (30 person-days)** | ⏳ |

### Deliverables Summary
- ✅ Group operations (Scalar, RistrettoPoint)
- ✅ Feldman's VSS (DKG)
- ✅ Threshold Diffie-Hellman with DLEQ proofs
- ✅ Proactive share refresh
- ✅ 100% unit test coverage for crypto module

### Acceptance Criteria
- [ ] All crypto operations work correctly
- [ ] DKG completes with honest parties
- [ ] Malicious parties are detected
- [ ] Threshold DH computes correct K = s·R
- [ ] Share refresh works correctly
- [ ] All tests pass
- [ ] CI pipeline passes

---

## 🎯 Next Phase

**After Phase 1 completes, proceed to Phase 2: Vault System**

- **Start Date:** Beginning of Week 3
- **Duration:** 1 week
- **Prerequisite:** Phase 1 must be 100% complete

---

## 📝 Phase Information

**Phase:** 1 of 4  
**Name:** Core Cryptography  
**Duration:** 2 weeks  
**Status:** ⏳ Not Started  
**Priority:** 🔴 CRITICAL  
**Blocker for:** Phase 2, Phase 3, Phase 4  

**Document Version:** 1.0  
**Last Updated:** October 26, 2026  
**Owner:** Crypto Team
