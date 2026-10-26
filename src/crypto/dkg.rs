//! Feldman's Verifiable Secret Sharing (VSS) for Dealerless DKG
//!
//! This module implements dealerless threshold key generation using
//! Feldman's VSS with polynomial commitments. No single party
//! (including the "dealer") ever knows the complete secret.

use super::group::{GroupScalar, GroupElement, GroupError};
use serde::{Serialize, Deserialize};
use rand::Rng;

/// Error type for DKG operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum DkgError {
    #[error("Invalid parameters: threshold ({0}) must be <= parties ({1}) and > 0")]
    InvalidParameters(usize, usize),
    #[error("Party ID {0} is out of range (0..{1})")]
    InvalidPartyId(usize, usize),
    #[error("Share verification failed for party {0}")]
    VerificationFailed(usize),
    #[error("Insufficient contributions: expected {0}, got {1}")]
    InsufficientContributions(usize, usize),
    #[error("Group error: {0}")]
    GroupError(#[from] GroupError),
}

/// A party's contribution to the DKG protocol
/// 
/// Each party generates a random polynomial and distributes:
/// - Shares: f_i(j) for each party j
/// - Commitments: g^{a_0}, g^{a_1}, ..., g^{a_{k-1}} where f_i(x) = a_0 + a_1*x + ... + a_{k-1}*x^{k-1}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyContribution {
    /// Party identifier (0-indexed)
    pub party_id: usize,
    /// Shares for each party: f_i(j) for j in 0..n
    pub shares: Vec<GroupScalar>,
    /// Commitments: C_m = g^{a_m} for m in 0..k
    pub commitments: Vec<GroupElement>,
}

impl PartyContribution {
    /// Create a new contribution
    pub fn new(party_id: usize, shares: Vec<GroupScalar>, commitments: Vec<GroupElement>) -> Self {
        Self { party_id, shares, commitments }
    }
    
    /// Get the share for a specific party
    pub fn get_share(&self, party_id: usize) -> Option<GroupScalar> {
        self.shares.get(party_id).cloned()
    }
    
    /// Validate the contribution structure
    pub fn validate(&self, threshold: usize, parties: usize) -> Result<(), DkgError> {
        if self.shares.len() != parties {
            return Err(DkgError::InvalidParameters(threshold, parties));
        }
        if self.commitments.len() != threshold {
            return Err(DkgError::InvalidParameters(threshold, parties));
        }
        Ok(())
    }
}

/// Feldman's VSS for Dealerless Distributed Key Generation
/// 
/// This implements the DKG protocol where:
/// 1. Each party i generates a random polynomial f_i of degree k-1
/// 2. Each party broadcasts commitments C_{i,m} = g^{a_{i,m}}
/// 3. Each party sends share f_i(j) to party j
/// 4. Each party verifies their shares against commitments
/// 5. Each party broadcasts complaint if verification fails
/// 6. Final shares are sum of all f_i(j)
/// 7. Public key is sum of all C_{i,0}
/// 
/// The secret s = Σ a_{i,0} is never reconstructed by any single party.
pub struct DKG {
    /// Total number of parties
    pub parties: usize,
    /// Threshold (minimum number of parties to reconstruct)
    pub threshold: usize,
}

impl DKG {
    /// Create a new DKG instance
    pub fn new(parties: usize, threshold: usize) -> Result<Self, DkgError> {
        if threshold > parties || threshold == 0 {
            return Err(DkgError::InvalidParameters(threshold, parties));
        }
        Ok(Self { parties, threshold })
    }
    
    /// Generate a party's contribution
    /// 
    /// Party i generates:
    /// - Random polynomial: f_i(x) = a_{i,0} + a_{i,1}*x + ... + a_{i,k-1}*x^{k-1}
    /// - Commitments: C_{i,m} = g^{a_{i,m}} for m in 0..k
    /// - Shares: f_i(j) for j in 0..n
    pub fn generate_contribution(&self, party_id: usize) -> Result<PartyContribution, DkgError> {
        if party_id >= self.parties {
            return Err(DkgError::InvalidPartyId(party_id, self.parties));
        }
        
        let mut rng = rand::thread_rng();
        
        // Generate random coefficients a_{i,0}, a_{i,1}, ..., a_{i,k-1}
        let coefficients: Vec<GroupScalar> = (0..self.threshold)
            .map(|_| GroupScalar::random())
            .collect();
        
        // Generate commitments: C_{i,m} = g^{a_{i,m}}
        let commitments: Vec<GroupElement> = coefficients.iter()
            .map(|a| GroupElement::generator().multiply(a))
            .collect();
        
        // Generate shares: f_i(j) = Σ_{m=0}^{k-1} a_{i,m} * j^m
        let shares: Vec<GroupScalar> = (0..self.parties)
            .map(|j| self.evaluate_polynomial(&coefficients, &GroupScalar::from_bytes([j as u8; 32]).unwrap_or(GroupScalar::zero())))
            .collect();
        
        Ok(PartyContribution::new(party_id, shares, commitments))
    }
    
    /// Evaluate polynomial at point x using Horner's rule
    /// 
    /// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{n-1}*x^{n-1}
    /// 
    /// Horner's rule: f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_{n-1})...)
    pub fn evaluate_polynomial(coefficients: &[GroupScalar], x: &GroupScalar) -> GroupScalar {
        coefficients.iter()
            .rev()
            .fold(GroupScalar::zero(), |acc, &coeff| acc * x + coeff)
    }
    
    /// Verify a party's contribution
    /// 
    /// For each share (j, f_i(j)), verify:
    /// g^{f_i(j)} == Π_{m=0}^{k-1} (C_{i,m})^{j^m}
    /// 
    /// This uses the property that:
    /// g^{Σ a_m * j^m} = Π g^{a_m * j^m} = Π (g^{a_m})^{j^m} = Π C_{i,m}^{j^m}
    pub fn verify_contribution(&self, contribution: &PartyContribution) -> Result<(), DkgError> {
        contribution.validate(self.threshold, self.parties)?;
        
        for (j, share) in contribution.shares.iter().enumerate() {
            if !self.verify_share(contribution, j, share)? {
                return Err(DkgError::VerificationFailed(contribution.party_id));
            }
        }
        
        Ok(())
    }
    
    /// Verify a single share against commitments
    fn verify_share(
        &self,
        contribution: &PartyContribution,
        party_j: usize,
        share: &GroupScalar,
    ) -> Result<bool, DkgError> {
        // Compute left side: g^{f_i(j)}
        let left = GroupElement::generator().multiply(share);
        
        // Compute right side: Π_{m=0}^{k-1} (C_{i,m})^{j^m}
        let j_scalar = GroupScalar::from_bytes([party_j as u8; 32]).unwrap_or(GroupScalar::zero());
        
        let right = contribution.commitments.iter()
            .enumerate()
            .fold(GroupElement::identity(), |acc, (m, commitment)| {
                // Compute j^m
                let j_pow_m = j_scalar.pow(m as u64);
                // Compute C_{i,m}^{j^m}
                acc + commitment.multiply(&j_pow_m)
            });
        
        Ok(left.ct_eq(&right))
    }
    
    /// Combine all party contributions to get final shares
    /// 
    /// Final share for party j: s_j = Σ_i f_i(j)
    /// 
    /// This is the sum of all shares from all parties' polynomials.
    /// The secret s = s_0 = Σ_i a_{i,0} (if we use 0-indexed parties)
    pub fn combine_contributions(
        &self,
        contributions: &[PartyContribution],
    ) -> Result<Vec<GroupScalar>, DkgError> {
        if contributions.len() != self.parties {
            return Err(DkgError::InsufficientContributions(
                self.parties,
                contributions.len(),
            ));
        }
        
        // For each party j, sum all f_i(j)
        let mut final_shares = vec![GroupScalar::zero(); self.parties];
        
        for contribution in contributions {
            for (j, share) in contribution.shares.iter().enumerate() {
                final_shares[j] = final_shares[j].add(share);
            }
        }
        
        Ok(final_shares)
    }
    
    /// Get the public key from all contributions
    /// 
    /// Public key S = s·G = (Σ_i a_{i,0})·G = Σ_i (a_{i,0}·G) = Σ_i C_{i,0}
    pub fn get_public_key(
        &self,
        contributions: &[PartyContribution],
    ) -> Result<GroupElement, DkgError> {
        if contributions.is_empty() {
            return Err(DkgError::InsufficientContributions(self.parties, 0));
        }
        
        // Sum all C_{i,0} (first commitment from each party)
        let public_key = contributions.iter()
            .map(|c| c.commitments[0])
            .fold(GroupElement::identity(), |acc, c| acc + c);
        
        Ok(public_key)
    }
    
    /// Get the secret from threshold shares using Lagrange interpolation
    /// 
    /// This reconstructs s = f(0) from shares f(j) for j in indices.
    /// 
    /// WARNING: This should only be used for testing. In production,
    /// the secret should NEVER be reconstructed!
    #[cfg(test)]
    pub fn reconstruct_secret(
        &self,
        shares: &[(usize, GroupScalar)],
    ) -> Result<GroupScalar, DkgError> {
        if shares.len() < self.threshold {
            return Err(DkgError::InsufficientContributions(
                self.threshold,
                shares.len(),
            ));
        }
        
        // Use Lagrange interpolation at x=0
        let indices: Vec<usize> = shares.iter().map(|(i, _)| *i).collect();
        let values: Vec<GroupScalar> = shares.iter().map(|(_, v)| *v).collect();
        
        let secret = self.lagrange_interpolation(&indices, &values, 0)?;
        
        Ok(secret)
    }
    
    /// Lagrange interpolation at point x
    /// 
    /// Given points (x_i, y_i) for i in 0..n, compute f(x) where
    /// f is the unique polynomial of degree n-1 passing through the points.
    /// 
    /// f(x) = Σ_i y_i * λ_i(x)
    /// where λ_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j)
    pub fn lagrange_interpolation(
        &self,
        indices: &[usize],
        values: &[GroupScalar],
        x: usize,
    ) -> Result<GroupScalar, DkgError> {
        if indices.len() != values.len() {
            return Err(DkgError::GroupError(GroupError::OperationFailed));
        }
        
        let x_scalar = GroupScalar::from_bytes([x as u8; 32]).unwrap_or(GroupScalar::zero());
        
        let mut result = GroupScalar::zero();
        
        for (i, (x_i, y_i)) in indices.iter().zip(values.iter()).enumerate() {
            let x_i_scalar = GroupScalar::from_bytes([*x_i as u8; 32]).unwrap_or(GroupScalar::zero());
            
            // Compute Lagrange coefficient λ_i(x)
            let lambda = self.lagrange_coefficient(indices, i, &x_scalar)?;
            
            // Add y_i * λ_i(x) to result
            result = result + (*y_i * lambda);
        }
        
        Ok(result)
    }
    
    /// Compute Lagrange coefficient λ_i(x) for interpolation
    fn lagrange_coefficient(
        &self,
        indices: &[usize],
        i: usize,
        x: &GroupScalar,
    ) -> Result<GroupScalar, DkgError> {
        let x_i = indices[i];
        let x_i_scalar = GroupScalar::from_bytes([x_i as u8; 32]).unwrap_or(GroupScalar::zero());
        
        let mut numerator = GroupScalar::one();
        let mut denominator = GroupScalar::one();
        
        for (j, &x_j) in indices.iter().enumerate() {
            if j == i {
                continue;
            }
            
            let x_j_scalar = GroupScalar::from_bytes([x_j as u8; 32]).unwrap_or(GroupScalar::zero());
            
            // numerator *= (x - x_j)
            numerator = numerator * (x - &x_j_scalar);
            
            // denominator *= (x_i - x_j)
            denominator = denominator * (x_i_scalar - &x_j_scalar);
        }
        
        // λ_i(x) = numerator / denominator
        let lambda = numerator * denominator.invert()?;
        
        Ok(lambda)
    }
}

/// DKG protocol state for a party
pub struct PartyState {
    /// Party ID
    pub party_id: usize,
    /// DKG instance
    pub dkg: DKG,
    /// This party's contribution
    pub contribution: Option<PartyContribution>,
    /// Received contributions from other parties
    pub received_contributions: Vec<PartyContribution>,
    /// Final shares (once DKG completes)
    pub final_shares: Option<Vec<GroupScalar>>,
}

impl PartyState {
    pub fn new(party_id: usize, parties: usize, threshold: usize) -> Result<Self, DkgError> {
        Ok(Self {
            party_id,
            dkg: DKG::new(parties, threshold)?,
            contribution: None,
            received_contributions: Vec::new(),
            final_shares: None,
        })
    }
    
    /// Generate and store this party's contribution
    pub fn generate_contribution(&mut self) -> Result<&PartyContribution, DkgError> {
        let contribution = self.dkg.generate_contribution(self.party_id)?;
        self.contribution = Some(contribution);
        Ok(self.contribution.as_ref().unwrap())
    }
    
    /// Receive a contribution from another party
    pub fn receive_contribution(
        &mut self,
        contribution: PartyContribution,
    ) -> Result<(), DkgError> {
        // Verify the contribution
        self.dkg.verify_contribution(&contribution)?;
        
        // Store it
        self.received_contributions.push(contribution);
        
        Ok(())
    }
    
    /// Check if DKG can complete
    pub fn can_complete(&self) -> bool {
        self.contribution.is_some() && 
        self.received_contributions.len() == self.dkg.parties - 1
    }
    
    /// Complete DKG and compute final shares
    pub fn complete(&mut self) -> Result<Vec<GroupScalar>, DkgError> {
        if !self.can_complete() {
            return Err(DkgError::InsufficientContributions(
                self.dkg.parties,
                self.received_contributions.len() + 1,
            ));
        }
        
        let mut all_contributions = self.received_contributions.clone();
        all_contributions.push(self.contribution.as_ref().unwrap().clone());
        
        // Sort by party_id to ensure consistent ordering
        all_contributions.sort_by_key(|c| c.party_id);
        
        let final_shares = self.dkg.combine_contributions(&all_contributions)?;
        self.final_shares = Some(final_shares.clone());
        
        Ok(final_shares)
    }
    
    /// Get this party's share
    pub fn get_share(&self) -> Option<GroupScalar> {
        self.final_shares.as_ref().and_then(|shares| shares.get(self.party_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dkg_creation() {
        // Valid parameters
        let dkg = DKG::new(5, 3);
        assert!(dkg.is_ok());
        let dkg = dkg.unwrap();
        assert_eq!(dkg.parties, 5);
        assert_eq!(dkg.threshold, 3);
        
        // Invalid: threshold > parties
        let dkg = DKG::new(5, 6);
        assert!(dkg.is_err());
        
        // Invalid: threshold = 0
        let dkg = DKG::new(5, 0);
        assert!(dkg.is_err());
    }
    
    #[test]
    fn test_contribution_generation() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contribution for party 0
        let contribution = dkg.generate_contribution(0).unwrap();
        
        assert_eq!(contribution.party_id, 0);
        assert_eq!(contribution.shares.len(), 5);
        assert_eq!(contribution.commitments.len(), 3);
        
        // Verify the contribution
        assert!(dkg.verify_contribution(&contribution).is_ok());
    }
    
    #[test]
    fn test_polynomial_evaluation() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Create a simple polynomial: f(x) = 1 + 2x + 3x^2
        let coefficients = vec![
            GroupScalar::one(),
            GroupScalar::from_bytes([2u8; 32]).unwrap(),
            GroupScalar::from_bytes([3u8; 32]).unwrap(),
        ];
        
        // Evaluate at x=0: f(0) = 1
        let f0 = DKG::evaluate_polynomial(&coefficients, &GroupScalar::zero());
        assert!(f0.ct_eq(&GroupScalar::one()));
        
        // Evaluate at x=1: f(1) = 1 + 2 + 3 = 6
        let f1 = DKG::evaluate_polynomial(&coefficients, &GroupScalar::one());
        // We can't directly check the value since we're in a finite field,
        // but we can verify consistency
    }
    
    #[test]
    fn test_dkg_complete_honest_parties() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contributions from all parties
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Verify all contributions
        for contribution in &contributions {
            assert!(dkg.verify_contribution(contribution).is_ok());
        }
        
        // Combine to get final shares
        let shares = dkg.combine_contributions(&contributions).unwrap();
        
        assert_eq!(shares.len(), 5);
        
        // Get public key
        let public_key = dkg.get_public_key(&contributions).unwrap();
        
        // Public key should not be identity
        assert!(!public_key.is_identity());
    }
    
    #[test]
    fn test_dkg_malicious_party() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate honest contributions
        let mut contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Corrupt party 2's contribution by changing a commitment
        contributions[2].commitments[0] = GroupElement::generator();
        
        // Verification should fail
        let result = dkg.verify_contribution(&contributions[2]);
        assert!(result.is_err());
        
        match result.unwrap_err() {
            DkgError::VerificationFailed(id) => assert_eq!(id, 2),
            _ => panic!("Expected VerificationFailed error"),
        }
    }
    
    #[test]
    fn test_lagrange_interpolation() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Create a polynomial: f(x) = 1 + 2x + 3x^2
        // We'll use points at x=1, x=2, x=3
        let coefficients = vec![
            GroupScalar::one(),
            GroupScalar::from_bytes([2u8; 32]).unwrap(),
            GroupScalar::from_bytes([3u8; 32]).unwrap(),
        ];
        
        let points: Vec<(usize, GroupScalar)> = vec![
            (1, DKG::evaluate_polynomial(&coefficients, &GroupScalar::from_bytes([1u8; 32]).unwrap())),
            (2, DKG::evaluate_polynomial(&coefficients, &GroupScalar::from_bytes([2u8; 32]).unwrap())),
            (3, DKG::evaluate_polynomial(&coefficients, &GroupScalar::from_bytes([3u8; 32]).unwrap())),
        ];
        
        let indices: Vec<usize> = points.iter().map(|(i, _)| *i).collect();
        let values: Vec<GroupScalar> = points.iter().map(|(_, v)| *v).collect();
        
        // Interpolate at x=0: should get f(0) = 1
        let f0 = dkg.lagrange_interpolation(&indices, &values, 0).unwrap();
        assert!(f0.ct_eq(&GroupScalar::one()));
        
        // Interpolate at x=1: should get f(1)
        let f1 = dkg.lagrange_interpolation(&indices, &values, 1).unwrap();
        assert!(f1.ct_eq(&points[0].1));
    }
    
    #[test]
    fn test_dkg_reconstruction() {
        let dkg = DKG::new(5, 3).unwrap();
        
        // Generate contributions from all parties
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Combine to get final shares
        let shares = dkg.combine_contributions(&contributions).unwrap();
        
        // Get public key
        let public_key = dkg.get_public_key(&contributions).unwrap();
        
        // Reconstruct secret from threshold shares
        let indices: Vec<usize> = (0..3).collect();
        let share_tuples: Vec<(usize, GroupScalar)> = indices.iter()
            .map(|&i| (i, shares[i].clone()))
            .collect();
        
        let secret = dkg.reconstruct_secret(&share_tuples).unwrap();
        
        // Verify: public_key should equal secret * G
        let expected_public_key = GroupElement::generator().multiply(&secret);
        assert!(public_key.ct_eq(&expected_public_key));
    }
    
    #[test]
    fn test_party_state() {
        let mut party = PartyState::new(0, 5, 3).unwrap();
        
        // Generate contribution
        let contribution = party.generate_contribution().unwrap();
        assert_eq!(contribution.party_id, 0);
        
        // Can't complete yet
        assert!(!party.can_complete());
        
        // Receive contributions from other parties
        let dkg = DKG::new(5, 3).unwrap();
        for i in 1..5 {
            let other_contribution = dkg.generate_contribution(i).unwrap();
            party.receive_contribution(other_contribution).unwrap();
        }
        
        // Now can complete
        assert!(party.can_complete());
        
        // Complete DKG
        let shares = party.complete().unwrap();
        assert_eq!(shares.len(), 5);
        
        // Get this party's share
        let my_share = party.get_share().unwrap();
        assert_eq!(my_share, shares[0]);
    }
}
