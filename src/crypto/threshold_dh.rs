//! Threshold Diffie-Hellman with Chaum-Pedersen DLEQ Proofs
//!
//! This module implements threshold DH where:
//! - Client picks ephemeral r, computes R = r·G
//! - Each party with share s_i computes partial P_i = s_i·R
//! - Each party provides DLEQ proof that P_i = s_i·R
//! - Client combines partials using Lagrange interpolation
//! - Result K = s·R where s is the distributed secret

use super::{
    group::{GroupScalar, GroupElement, GroupError},
    dkg::{DKG, PartyContribution},
};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

/// Error type for threshold DH operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ThresholdDhError {
    #[error("Invalid parameters")]
    InvalidParameters,
    #[error("Invalid partial")]
    InvalidPartial,
    #[error("DLEQ proof verification failed")]
    DleqVerificationFailed,
    #[error("Insufficient partials: need {0}, got {1}")]
    InsufficientPartials(usize, usize),
    #[error("Group error: {0}")]
    GroupError(#[from] GroupError),
}

/// Chaum-Pedersen DLEQ Proof
///
/// Proves knowledge of secret s such that:
/// - P = s·R (where R is some fixed base)
/// - S = s·G (where G is the generator)
///
/// This is a Sigma protocol that provides:
/// - Completeness: Honest prover can convince verifier
/// - Soundness: Only someone knowing s can produce valid proof
/// - Zero-knowledge: Proof reveals nothing about s
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLEQProof {
    /// First commitment: A1 = g^k
    pub a1: GroupElement,
    /// Second commitment: A2 = R^k
    pub a2: GroupElement,
    /// First response: z1 = k + c*s
    pub z1: GroupScalar,
    /// Second response: z2 = c*s
    pub z2: GroupScalar,
}

impl DLEQProof {
    /// Generate a new DLEQ proof
    ///
    /// Proves: P = s·R AND S = s·G
    ///
    /// Protocol:
    /// 1. Prover picks random k
    /// 2. Prover sends A1 = g^k, A2 = R^k
    /// 3. Verifier sends random challenge c = H(g, G, P, R, S, A1, A2)
    /// 4. Prover sends z1 = k + c*s, z2 = c*s
    /// 5. Verifier checks:
    ///    - g^z1 == A1 * S^c
    ///    - R^z2 * P^{-c} == A2
    pub fn new(
        s: &GroupScalar,
        P: &GroupElement,
        S: &GroupElement,
        R: &GroupElement,
    ) -> Self {
        let k = GroupScalar::random();
        
        let a1 = GroupElement::generator().multiply(&k);
        let a2 = R.multiply(&k);
        
        // Compute challenge: c = H(g, G, P, R, S, a1, a2)
        let c = Self::compute_challenge(&GroupElement::generator(), &GroupElement::generator(), P, R, S, &a1, &a2);
        
        let z1 = &k + &(c * s);
        let z2 = &c * s;
        
        Self { a1, a2, z1, z2 }
    }
    
    /// Verify a DLEQ proof
    ///
    /// Checks:
    /// 1. g^z1 == A1 * S^c
    /// 2. R^z2 * P^{-c} == A2
    pub fn verify(
        &self,
        P: &GroupElement,
        S: &GroupElement,
        R: &GroupElement,
    ) -> bool {
        // Compute challenge
        let c = Self::compute_challenge(
            &GroupElement::generator(),
            &GroupElement::generator(),
            P,
            R,
            S,
            &self.a1,
            &self.a2,
        );
        
        // Check 1: g^z1 == A1 * S^c
        let left1 = GroupElement::generator().multiply(&self.z1);
        let right1 = &self.a1 + S.multiply(&c);
        
        // Check 2: R^z2 * P^{-c} == A2
        let left2 = R.multiply(&self.z2) + P.multiply(&c.negate());
        let right2 = &self.a2;
        
        left1.ct_eq(&right1) && left2.ct_eq(&right2)
    }
    
    /// Compute the challenge hash
    fn compute_challenge(
        g: &GroupElement,
        G: &GroupElement,
        P: &GroupElement,
        R: &GroupElement,
        S: &GroupElement,
        a1: &GroupElement,
        a2: &GroupElement,
    ) -> GroupScalar {
        let mut hasher = Sha256::new();
        hasher.update(&g.to_bytes());
        hasher.update(&G.to_bytes());
        hasher.update(&P.to_bytes());
        hasher.update(&R.to_bytes());
        hasher.update(&S.to_bytes());
        hasher.update(&a1.to_bytes());
        hasher.update(&a2.to_bytes());
        
        let hash = hasher.finalize();
        GroupScalar::from_slice(&hash).unwrap_or(GroupScalar::zero())
    }
}

/// A partial computation from a party
///
/// Each party with share s_i computes:
/// - P_i = s_i·R (their partial)
/// - proof: DLEQ proof that P_i = s_i·R AND S_i = s_i·G
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partial {
    /// Party ID
    pub party_id: usize,
    /// Partial: P_i = s_i·R
    pub partial: GroupElement,
    /// DLEQ proof
    pub proof: DLEQProof,
}

impl Partial {
    pub fn new(
        party_id: usize,
        s_i: &GroupScalar,
        S_i: &GroupElement,
        R: &GroupElement,
    ) -> Self {
        let P_i = R.multiply(s_i);
        let proof = DLEQProof::new(s_i, &P_i, S_i, R);
        
        Self {
            party_id,
            partial: P_i,
            proof,
        }
    }
    
    /// Verify the partial
    pub fn verify(
        &self,
        S_i: &GroupElement,
        R: &GroupElement,
    ) -> bool {
        self.proof.verify(&self.partial, S_i, R)
    }
}

/// Threshold Diffie-Hellman
///
/// Implements the threshold DH protocol:
/// 1. Client generates ephemeral r, computes R = r·G
/// 2. Each party with share s_i computes partial P_i = s_i·R
/// 3. Each party provides DLEQ proof for their partial
/// 4. Client verifies all proofs
/// 5. Client combines partials using Lagrange interpolation
/// 6. Result K = s·R where s is the distributed secret
pub struct ThresholdDH {
    /// DKG instance
    dkg: DKG,
    /// All party shares
    shares: Vec<GroupScalar>,
    /// All party public shares (S_i = s_i·G)
    public_shares: Vec<GroupElement>,
}

impl ThresholdDH {
    /// Create a new ThresholdDH instance
    pub fn new(
        dkg: DKG,
        shares: Vec<GroupScalar>,
        public_shares: Vec<GroupElement>,
    ) -> Result<Self, ThresholdDhError> {
        if shares.len() != public_shares.len() {
            return Err(ThresholdDhError::InvalidParameters);
        }
        
        Ok(Self {
            dkg,
            shares,
            public_shares,
        })
    }
    
    /// Compute a partial for a specific party
    pub fn compute_partial(
        &self,
        party_id: usize,
        R: &GroupElement,
    ) -> Result<Partial, ThresholdDhError> {
        let s_i = self.shares.get(party_id)
            .ok_or(ThresholdDhError::InvalidParameters)?;
        let S_i = self.public_shares.get(party_id)
            .ok_or(ThresholdDhError::InvalidParameters)?;
        
        Ok(Partial::new(party_id, s_i, S_i, R))
    }
    
    /// Verify a partial
    pub fn verify_partial(
        &self,
        partial: &Partial,
        R: &GroupElement,
    ) -> Result<bool, ThresholdDhError> {
        let S_i = self.public_shares.get(partial.party_id)
            .ok_or(ThresholdDhError::InvalidPartial)?;
        
        Ok(partial.verify(S_i, R))
    }
    
    /// Combine partials to get the final key K = s·R
    ///
    /// Uses Lagrange interpolation to combine partials:
    /// K = Σ λ_i * P_i
    /// where λ_i are Lagrange coefficients at 0
    pub fn combine_partials(
        &self,
        partials: &[Partial],
        R: &GroupElement,
    ) -> Result<GroupElement, ThresholdDhError> {
        // Verify all partials first
        for partial in partials {
            if !self.verify_partial(partial, R)? {
                return Err(ThresholdDhError::DleqVerificationFailed);
            }
        }
        
        if partials.len() < self.dkg.threshold {
            return Err(ThresholdDhError::InsufficientPartials(
                self.dkg.threshold,
                partials.len(),
            ));
        }
        
        // Extract party IDs and partials
        let party_ids: Vec<usize> = partials.iter().map(|p| p.party_id).collect();
        let partial_values: Vec<GroupElement> = partials.iter().map(|p| p.partial).collect();
        
        // Compute Lagrange coefficients at 0
        let lambdas = self.compute_lagrange_coefficients(&party_ids)?;
        
        // K = Σ λ_i * P_i
        let K = partial_values.iter()
            .zip(lambdas.iter())
            .fold(GroupElement::identity(), |acc, (P_i, &lambda)| {
                acc + P_i.multiply(&lambda)
            });
        
        Ok(K)
    }
    
    /// Compute Lagrange coefficients for parties at x=0
    fn compute_lagrange_coefficients(
        &self,
        party_ids: &[usize],
    ) -> Result<Vec<GroupScalar>, ThresholdDhError> {
        let mut lambdas = Vec::with_capacity(party_ids.len());
        
        for (i, &x_i) in party_ids.iter().enumerate() {
            let lambda = self.lagrange_coefficient(party_ids, i)?;
            lambdas.push(lambda);
        }
        
        Ok(lambdas)
    }
    
    /// Compute single Lagrange coefficient λ_i(0)
    fn lagrange_coefficient(
        &self,
        party_ids: &[usize],
        i: usize,
    ) -> Result<GroupScalar, ThresholdDhError> {
        let x_i = party_ids[i];
        let x_i_scalar = GroupScalar::from_bytes([x_i as u8; 32]).unwrap_or(GroupScalar::zero());
        
        let mut numerator = GroupScalar::one();
        let mut denominator = GroupScalar::one();
        
        for (j, &x_j) in party_ids.iter().enumerate() {
            if j == i {
                continue;
            }
            
            let x_j_scalar = GroupScalar::from_bytes([x_j as u8; 32]).unwrap_or(GroupScalar::zero());
            
            // numerator *= (0 - x_j) = -x_j
            numerator = numerator * x_j_scalar.negate();
            
            // denominator *= (x_i - x_j)
            denominator = denominator * (x_i_scalar - &x_j_scalar);
        }
        
        // λ_i(0) = numerator / denominator
        denominator.invert()
            .map(|denom_inv| numerator * denom_inv)
            .ok_or(ThresholdDhError::GroupError(GroupError::OperationFailed))
    }
    
    /// Derive a key from K using HKDF
    ///
    /// HKDF(K || R, context) -> key
    pub fn derive_key(
        K: &GroupElement,
        R: &GroupElement,
        context: &[u8],
        output_len: usize,
    ) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        
        // Extract: PRK = HMAC-SHA256(salt, IKM)
        // Using K || R as IKM, empty salt
        let mut hkdf = HmacSha256::new_from_slice(&[])
            .expect("HMAC can take key of any size");
        hkdf.update(&K.to_bytes());
        hkdf.update(&R.to_bytes());
        let prk = hkdf.finalize().into_bytes();
        
        // Expand: OKM = HMAC-SHA256(PRK, info || [0x01])
        let mut hkdf = HmacSha256::new_from_slice(&prk);
        hkdf.update(context);
        hkdf.update(&[0x01]);
        let mut okm = hkdf.finalize().into_bytes();
        
        // Truncate to desired length
        okm.truncate(output_len);
        okm
    }
    
    /// Full threshold DH protocol
    ///
    /// This is a convenience method that runs the entire protocol:
    /// 1. Client generates ephemeral
    /// 2. Parties compute partials
    /// 3. Client combines partials
    /// 4. Returns (K, key) where K = s·R and key = HKDF(K || R, context)
    pub fn run_protocol(
        &self,
        party_ids: &[usize],
        context: &[u8],
        key_len: usize,
    ) -> Result<(GroupElement, Vec<u8>), ThresholdDhError> {
        // Step 1: Client generates ephemeral
        let r = GroupScalar::random();
        let R = GroupElement::generator().multiply(&r);
        
        // Step 2: Parties compute partials
        let mut partials = Vec::new();
        for &party_id in party_ids {
            let partial = self.compute_partial(party_id, &R)?;
            partials.push(partial);
        }
        
        // Step 3: Client combines partials
        let K = self.combine_partials(&partials, &R)?;
        
        // Step 4: Derive key
        let key = Self::derive_key(&K, &R, context, key_len);
        
        Ok((K, key))
    }
}

/// Client state for threshold DH
pub struct ThresholdDhClient {
    /// Ephemeral scalar
    r: GroupScalar,
    /// Ephemeral public key R = r·G
    R: GroupElement,
    /// Collected partials
    partials: Vec<Partial>,
    /// DKG instance (for verification)
    dkg: DKG,
    /// Public shares (for verification)
    public_shares: Vec<GroupElement>,
}

impl ThresholdDhClient {
    pub fn new(
        dkg: DKG,
        public_shares: Vec<GroupElement>,
    ) -> Self {
        let r = GroupScalar::random();
        let R = GroupElement::generator().multiply(&r);
        
        Self {
            r,
            R,
            partials: Vec::new(),
            dkg,
            public_shares,
        }
    }
    
    /// Get the ephemeral public key
    pub fn get_R(&self) -> GroupElement {
        self.R
    }
    
    /// Receive a partial from a party
    pub fn receive_partial(&mut self, partial: Partial) -> Result<bool, ThresholdDhError> {
        let S_i = self.public_shares.get(partial.party_id)
            .ok_or(ThresholdDhError::InvalidPartial)?;
        
        // Verify the partial
        let is_valid = partial.verify(S_i, &self.R);
        
        if is_valid {
            self.partials.push(partial);
        }
        
        Ok(is_valid)
    }
    
    /// Check if we have enough partials
    pub fn has_enough_partials(&self) -> bool {
        self.partials.len() >= self.dkg.threshold
    }
    
    /// Combine partials to get K = s·R
    pub fn combine(&self) -> Result<GroupElement, ThresholdDhError> {
        if !self.has_enough_partials() {
            return Err(ThresholdDhError::InsufficientPartials(
                self.dkg.threshold,
                self.partials.len(),
            ));
        }
        
        // Create a temporary ThresholdDH to use combine_partials
        let threshold_dh = ThresholdDH::new(
            self.dkg.clone(),
            vec![], // We don't need shares for combination
            self.public_shares.clone(),
        )?;
        
        threshold_dh.combine_partials(&self.partials, &self.R)
    }
    
    /// Derive a key from K
    pub fn derive_key(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, ThresholdDhError> {
        let K = self.combine()?;
        Ok(ThresholdDH::derive_key(&K, &self.R, context, output_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dleq_proof_honest() {
        let s = GroupScalar::random();
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let G = GroupElement::generator();
        
        let P = R.multiply(&s);
        let S = G.multiply(&s);
        
        let proof = DLEQProof::new(&s, &P, &S, &R);
        
        assert!(proof.verify(&P, &S, &R));
    }
    
    #[test]
    fn test_dleq_proof_wrong_P() {
        let s = GroupScalar::random();
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let G = GroupElement::generator();
        
        let P = R.multiply(&s);
        let S = G.multiply(&s);
        
        let proof = DLEQProof::new(&s, &P, &S, &R);
        
        // Try to verify with wrong P
        let wrong_P = GroupElement::generator();
        assert!(!proof.verify(&wrong_P, &S, &R));
    }
    
    #[test]
    fn test_dleq_proof_wrong_S() {
        let s = GroupScalar::random();
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let G = GroupElement::generator();
        
        let P = R.multiply(&s);
        let S = G.multiply(&s);
        
        let proof = DLEQProof::new(&s, &P, &S, &R);
        
        // Try to verify with wrong S
        let wrong_S = GroupElement::generator();
        assert!(!proof.verify(&P, &wrong_S, &R));
    }
    
    #[test]
    fn test_partial_creation_and_verification() {
        let s_i = GroupScalar::random();
        let S_i = GroupElement::generator().multiply(&s_i);
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        
        let partial = Partial::new(0, &s_i, &S_i, &R);
        
        assert!(partial.verify(&S_i, &R));
    }
    
    #[test]
    fn test_threshold_dh() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contributions and final shares
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        let shares = dkg.combine_contributions(&contributions).unwrap();
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        let threshold_dh = ThresholdDH::new(dkg, shares.clone(), public_shares).unwrap();
        
        // Client picks ephemeral
        let r = GroupScalar::random();
        let R = GroupElement::generator().multiply(&r);
        
        // Parties compute partials
        let partials: Vec<Partial> = (0..3)
            .map(|i| threshold_dh.compute_partial(i, &R).unwrap())
            .collect();
        
        // Client combines
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify: K should equal s·R where s = Σ shares[i] for i in 0..3
        let s_sum: GroupScalar = (0..3).fold(GroupScalar::zero(), |acc, i| acc + shares[i]);
        let expected_K = R.multiply(&s_sum);
        
        assert!(K.ct_eq(&expected_K));
    }
    
    #[test]
    fn test_threshold_dh_invalid_partial() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contributions and final shares
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        let shares = dkg.combine_contributions(&contributions).unwrap();
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        let threshold_dh = ThresholdDH::new(dkg, shares, public_shares).unwrap();
        
        // Client picks ephemeral
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        
        // Create an invalid partial
        let invalid_partial = Partial {
            party_id: 0,
            partial: GroupElement::generator(),
            proof: DLEQProof {
                a1: GroupElement::identity(),
                a2: GroupElement::identity(),
                z1: GroupScalar::zero(),
                z2: GroupScalar::zero(),
            },
        };
        
        // Verification should fail
        let result = threshold_dh.verify_partial(&invalid_partial, &R);
        assert!(!result.unwrap());
    }
    
    #[test]
    fn test_threshold_dh_insufficient_partials() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contributions and final shares
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        let shares = dkg.combine_contributions(&contributions).unwrap();
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        let threshold_dh = ThresholdDH::new(dkg, shares, public_shares).unwrap();
        
        // Client picks ephemeral
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        
        // Only 2 partials (need 3)
        let partials: Vec<Partial> = (0..2)
            .map(|i| threshold_dh.compute_partial(i, &R).unwrap())
            .collect();
        
        // Should fail with insufficient partials
        let result = threshold_dh.combine_partials(&partials, &R);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            ThresholdDhError::InsufficientPartials(threshold, got) => {
                assert_eq!(threshold, 3);
                assert_eq!(got, 2);
            }
            _ => panic!("Expected InsufficientPartials error"),
        }
    }
    
    #[test]
    fn test_key_derivation() {
        let K = GroupElement::generator().multiply(&GroupScalar::random());
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let context = b"test context";
        
        let key1 = ThresholdDH::derive_key(&K, &R, context, 32);
        let key2 = ThresholdDH::derive_key(&K, &R, context, 32);
        
        // Same inputs should produce same output
        assert_eq!(key1, key2);
        
        // Different context should produce different output
        let key3 = ThresholdDH::derive_key(&K, &R, b"different context", 32);
        assert_ne!(key1, key3);
        
        // Different length should truncate
        let key4 = ThresholdDH::derive_key(&K, &R, context, 16);
        assert_eq!(key4.len(), 16);
        assert_eq!(&key1[..16], &key4[..]);
    }
    
    #[test]
    fn test_client_workflow() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contributions and final shares
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        let shares = dkg.combine_contributions(&contributions).unwrap();
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        // Client creates instance
        let mut client = ThresholdDhClient::new(dkg, public_shares.clone());
        
        // Get R
        let R = client.get_R();
        
        // Parties send partials
        let threshold_dh = ThresholdDH::new(
            DKG::new(5, 3).unwrap(),
            shares.clone(),
            public_shares,
        ).unwrap();
        
        for i in 0..3 {
            let partial = threshold_dh.compute_partial(i, &R).unwrap();
            let result = client.receive_partial(partial);
            assert!(result.unwrap());
        }
        
        // Client has enough partials
        assert!(client.has_enough_partials());
        
        // Client combines
        let K = client.combine().unwrap();
        
        // Verify K = s·R
        let s_sum: GroupScalar = (0..3).fold(GroupScalar::zero(), |acc, i| acc + shares[i]);
        let expected_K = R.multiply(&s_sum);
        assert!(K.ct_eq(&expected_K));
        
        // Client derives key
        let key = client.derive_key(b"test", 32).unwrap();
        assert_eq!(key.len(), 32);
    }
}
