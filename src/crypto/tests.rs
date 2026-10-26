//! Integration tests for crypto module
//!
//! These tests verify that all crypto components work together correctly.

#[cfg(test)]
mod tests {
    use super::super::*;
    
    #[test]
    fn test_full_dkg_workflow() {
        // Create DKG with 5 parties, threshold 3
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
        
        // Get public key
        let public_key = dkg.get_public_key(&contributions).unwrap();
        
        // Verify: public_key should equal sum of all s_i * G
        let expected_public_key = shares.iter()
            .fold(GroupElement::identity(), |acc, s| acc + GroupElement::generator().multiply(s));
        assert!(public_key.ct_eq(&expected_public_key));
    }
    
    #[test]
    fn test_threshold_dh_full_workflow() {
        // Setup DKG
        let dkg = DKG::new(5, 3).unwrap();
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        let shares = dkg.combine_contributions(&contributions).unwrap();
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        // Create threshold DH
        let threshold_dh = ThresholdDH::new(dkg, shares.clone(), public_shares).unwrap();
        
        // Client picks ephemeral
        let r = GroupScalar::random();
        let R = GroupElement::generator().multiply(&r);
        
        // Parties compute partials
        let partials: Vec<Partial> = (0..3)
            .map(|i| threshold_dh.compute_partial(i, &R).unwrap())
            .collect();
        
        // Verify all partials
        for partial in &partials {
            let S_i = &public_shares[partial.party_id];
            assert!(partial.verify(S_i, &R));
        }
        
        // Client combines partials
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify: K should equal (Σ s_i) * R
        let s_sum: GroupScalar = (0..3).fold(GroupScalar::zero(), |acc, i| acc + shares[i]);
        let expected_K = R.multiply(&s_sum);
        assert!(K.ct_eq(&expected_K));
        
        // Derive key
        let key = ThresholdDH::derive_key(&K, &R, b"test context", 32);
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_share_refresh_workflow() {
        use std::time::Duration;
        
        // Create share manager
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        // Get initial shares
        let initial_shares = manager.get_all_shares().clone();
        
        // Refresh
        manager.refresh().unwrap();
        
        // Get new shares
        let new_shares = manager.get_all_shares();
        
        // Shares should be different
        assert_ne!(&initial_shares[..], new_shares);
        
        // Can still access old shares
        for i in 0..5 {
            let old_share = manager.get_epoch_share(0, i).unwrap();
            assert!(old_share.ct_eq(&initial_shares[i]));
        }
    }
    
    #[test]
    fn test_cross_module_integration() {
        use std::time::Duration;
        
        // Create DKG
        let dkg = DKG::new(5, 3).unwrap();
        let contributions: Vec<PartyContribution> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        let shares = dkg.combine_contributions(&contributions).unwrap();
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        // Create threshold DH
        let threshold_dh = ThresholdDH::new(
            DKG::new(5, 3).unwrap(),
            shares.clone(),
            public_shares.clone(),
        ).unwrap();
        
        // Create share manager with same shares
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        ).unwrap();
        
        // Replace shares with our DKG shares
        {
            let mut manager_mut = manager;
            manager_mut.current_info.shares = shares;
        }
        
        // Run threshold DH
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let partials: Vec<Partial> = (0..3)
            .map(|i| threshold_dh.compute_partial(i, &R).unwrap())
            .collect();
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify K is correct
        let s_sum: GroupScalar = (0..3).fold(GroupScalar::zero(), |acc, i| acc + shares[i]);
        let expected_K = R.multiply(&s_sum);
        assert!(K.ct_eq(&expected_K));
    }
    
    #[test]
    fn test_serialization_roundtrip() {
        // Test GroupScalar
        let s = GroupScalar::random();
        let bytes = bincode::serialize(&s).unwrap();
        let s2: GroupScalar = bincode::deserialize(&bytes).unwrap();
        assert!(s.ct_eq(&s2));
        
        // Test GroupElement
        let g = GroupElement::generator().multiply(&GroupScalar::random());
        let bytes = bincode::serialize(&g).unwrap();
        let g2: GroupElement = bincode::deserialize(&bytes).unwrap();
        assert!(g.ct_eq(&g2));
        
        // Test PartyContribution
        let dkg = DKG::new(5, 3).unwrap();
        let contribution = dkg.generate_contribution(0).unwrap();
        let bytes = bincode::serialize(&contribution).unwrap();
        let contribution2: PartyContribution = bincode::deserialize(&bytes).unwrap();
        assert_eq!(contribution.party_id, contribution2.party_id);
        assert_eq!(contribution.shares.len(), contribution2.shares.len());
        assert_eq!(contribution.commitments.len(), contribution2.commitments.len());
        
        // Test DLEQProof
        let s = GroupScalar::random();
        let R = GroupElement::generator().multiply(&GroupScalar::random());
        let S = GroupElement::generator().multiply(&s);
        let P = R.multiply(&s);
        let proof = DLEQProof::new(&s, &P, &S, &R);
        let bytes = bincode::serialize(&proof).unwrap();
        let proof2: DLEQProof = bincode::deserialize(&bytes).unwrap();
        assert!(proof.verify(&P, &S, &R));
        assert!(proof2.verify(&P, &S, &R));
    }
}
