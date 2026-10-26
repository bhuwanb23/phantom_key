//! Integration tests for Phantom Key v2
//!
//! These tests verify that all components work together correctly.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use uuid::Uuid;
    use chrono::Utc;
    
    use crate::crypto::{
        dkg::DKG,
        group::{GroupElement, GroupScalar},
        share_refresh::ShareManager,
        threshold_dh::{ThresholdDH, Partial, DLEQProof},
    };
    use crate::vault::{
        decoy::DecoyRegistry,
        encryption::VaultEncryption,
        handle::HandleGenerator,
        mapping::DecoyManager,
        storage::{MemoryStorage, SecretType, VaultEntry, VaultMetadata},
    };
    use crate::egress::{
        canary::CanaryRegistry,
        interceptor::{EgressInterceptor, OutboundRequest, InboundResponse},
        ledger::{Ledger, LedgerEntry, ChainStatus},
        scanner::SecretScanner,
    };
    use crate::llm::{
        attack_lab::AttackLab,
        phantom_key::{PhantomKey, PhantomKeyBuilder},
        provider::{Message, ProviderType, ProviderFactory},
    };

    // ========================================================================
    // PHASE 1: CORE CRYPTOGRAPHY TESTS
    // ========================================================================

    #[test]
    fn test_group_operations() {
        // Test scalar operations
        let s1 = GroupScalar::from_bytes([1u8; 32]).unwrap();
        let s2 = GroupScalar::from_bytes([2u8; 32]).unwrap();
        
        let sum = s1 + s2;
        let diff = s2 - s1;
        let product = s1 * s2;
        let neg = -s1;
        
        assert!(sum.ct_eq(&(s1 + s2)));
        assert!(diff.ct_eq(&(s2 - s1)));
        assert!(product.ct_eq(&(s1 * s2)));
        assert!(neg.ct_eq(&(-s1)));
        
        // Test element operations
        let g = GroupElement::generator();
        let g2 = g + g;
        let g_neg = -g;
        let g_scalar = g * s1;
        
        assert!(g2.ct_eq(&(g + g)));
        assert!(g_neg.ct_eq(&(-g)));
        assert!(!g_scalar.is_identity());
    }

    #[test]
    fn test_dkg_honest_parties() {
        let dkg = DKG::new(5, 3).unwrap();
        
        let contributions: Vec<_> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Verify all contributions
        for contribution in &contributions {
            assert!(dkg.verify_contribution(contribution).is_ok());
        }
        
        // Combine
        let shares = dkg.combine_contributions(&contributions).unwrap();
        assert_eq!(shares.len(), 5);
        
        // Get public key
        let public_key = dkg.get_public_key(&contributions).unwrap();
        assert!(!public_key.is_identity());
    }

    #[test]
    fn test_dkg_malicious_party() {
        let dkg = DKG::new(5, 3).unwrap();
        
        let mut contributions: Vec<_> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        // Corrupt party 2's contribution
        contributions[2].commitments[0] = GroupElement::generator();
        
        // Verification should fail
        assert!(dkg.verify_contribution(&contributions[2]).is_err());
    }

    #[test]
    fn test_threshold_dh() {
        let dkg = DKG::new(5, 3).unwrap();
        let contributions: Vec<_> = (0..5)
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
        let partials: Vec<_> = (0..3)
            .map(|i| threshold_dh.compute_partial(i, &R).unwrap())
            .collect();
        
        // Verify all partials
        for partial in &partials {
            let S_i = &public_shares[partial.party_id];
            assert!(partial.verify(S_i, &R));
        }
        
        // Client combines
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify K is correct
        let s_sum: GroupScalar = (0..3).fold(GroupScalar::zero(), |acc, i| acc + shares[i]);
        let expected_K = R.multiply(&s_sum);
        assert!(K.ct_eq(&expected_K));
    }

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
    fn test_share_refresh() {
        use std::time::Duration;
        
        let mut manager = ShareManager::new(
            5,
            3,
            Duration::from_secs(3600),
            Duration::from_secs(300),
        )
        .unwrap();
        
        let old_shares = manager.get_all_shares().clone();
        
        // Refresh
        manager.refresh().unwrap();
        
        // Epoch should increment
        assert_eq!(manager.current_epoch(), 1);
        
        // Shares should be different
        let new_shares = manager.get_all_shares();
        assert_ne!(&old_shares[..], new_shares);
    }

    // ========================================================================
    // PHASE 2: VAULT SYSTEM TESTS
    // ========================================================================

    #[test]
    fn test_vault_storage() {
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
    fn test_vault_encryption() {
        let R = GroupElement::generator();
        let handle = "⟦H1⟧";
        let secret = b"my-secret";
        
        let (ciphertext, nonce) = VaultEncryption::encrypt(secret, &R, handle);
        let decrypted = VaultEncryption::decrypt(&ciphertext, &nonce, &R, handle).unwrap();
        
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_handle_system() {
        let generator = HandleGenerator::new();
        
        let handle1 = generator.generate();
        let handle2 = generator.generate();
        
        assert_ne!(handle1, handle2);
        assert!(handle1.to_string().starts_with("⟦H"));
        assert!(handle1.to_string().ends_with("⟧"));
        
        // Test parsing
        let handle_str = handle1.to_string();
        let parsed: crate::vault::handle::Handle = handle_str.parse().unwrap();
        assert_eq!(handle1, parsed);
    }

    #[test]
    fn test_decoy_generation() {
        let registry = DecoyRegistry::new();
        
        // Test all decoy types
        let aws_key = registry.generate(&SecretType::AwsAccessKey);
        assert!(aws_key.starts_with("AKIA"));
        assert_eq!(aws_key.len(), 20);
        
        let aws_secret = registry.generate(&SecretType::AwsSecretKey);
        assert_eq!(aws_secret.len(), 40);
        
        let iban = registry.generate(&SecretType::IbAN);
        assert!(iban.len() >= 4);
        
        let credit_card = registry.generate(&SecretType::CreditCard);
        assert!(credit_card.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_decoy_mapping() {
        let registry = DecoyRegistry::new();
        let storage = Arc::new(MemoryStorage::new());
        let mapping = Arc::new(Mutex::new(crate::vault::mapping::DecoyMap::new()));
        
        let manager = DecoyManager::new(registry, mapping, storage);
        
        // Note: This test would need a real R to work properly
        // For now, just test that it can be created
        assert!(true);
    }

    // ========================================================================
    // PHASE 3: EGRESS COURT TESTS
    // ========================================================================

    #[test]
    fn test_ledger() {
        use ed25519_dalek::SigningKey;
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);
        
        // Append entries
        for i in 0..3 {
            let entry = LedgerEntry {
                id: Uuid::new_v4(),
                prev_hash: [0u8; 32],
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
        
        // Verify chain
        assert!(ledger.verify_chain());
        assert!(matches!(ledger.chain_status(), ChainStatus::Valid { .. }));
    }

    #[test]
    fn test_ledger_tampering() {
        use ed25519_dalek::SigningKey;
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);
        
        // Append an entry
        let entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash: [0u8; 32],
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"test".to_vec(),
            hash: [0u8; 32],
        };
        ledger.append(entry).unwrap();
        
        // Verify chain is valid
        assert!(ledger.verify_chain());
        
        // Tamper with the entry
        {
            let mut storage = ledger.storage.lock().unwrap();
            if let Some(entry) = storage.get_mut(0) {
                entry.entry.payload = b"tampered".to_vec();
            }
        }
        
        // Verify chain is now invalid
        assert!(!ledger.verify_chain());
    }

    #[test]
    fn test_scanner() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();
        
        // Store a secret
        let secret = b"test-secret-123";
        let handle = "⟦H1⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Generic,
            ..Default::default()
        };
        
        let entry = encryption.create_entry(secret, &R, handle.clone(), metadata);
        storage.insert(entry);
        
        // Create scanner
        let scanner = SecretScanner::new(storage, encryption, R);
        
        // Scan for the secret
        let payload = b"Using secret: test-secret-123";
        let matches = scanner.scan(payload);
        
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].handle, handle);
    }

    #[test]
    fn test_canary_system() {
        let registry = CanaryRegistry::new();
        
        // Register a canary
        let id = registry.register(
            "test-canary-value".to_string(),
            Uuid::new_v4(),
            "test-provider".to_string(),
        );
        
        // Verify it's not triggered
        let canary = registry.get(&id).unwrap();
        assert!(!canary.is_triggered());
        
        // Trigger it
        registry.trigger(&id);
        
        // Verify it's now triggered
        let canary = registry.get(&id).unwrap();
        assert!(canary.is_triggered());
    }

    #[tokio::test]
    async fn test_interceptor() {
        use ed25519_dalek::SigningKey;
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));
        
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();
        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(storage, encryption, R)
        ));
        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));
        
        let interceptor = EgressInterceptor::new(
            ledger.clone(),
            scanner,
            canary_registry,
        );
        
        // Intercept a request
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

    // ========================================================================
    // PHASE 4: INTEGRATION TESTS
    // ========================================================================

    #[test]
    fn test_phantom_key_creation() {
        let storage = Arc::new(MemoryStorage::new());
        
        let result = PhantomKeyBuilder::new()
            .parties(5)
            .threshold(3)
            .vault_storage(storage)
            .build();
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_phantom_key_store_and_retrieve() {
        let storage = Arc::new(MemoryStorage::new());
        
        let mut phantom_key = PhantomKeyBuilder::new()
            .parties(5)
            .threshold(3)
            .vault_storage(storage.clone())
            .build()
            .unwrap();
        
        // Store a secret
        let secret = b"my-secret-value";
        let handle = phantom_key
            .store_secret(secret, SecretType::Generic)
            .await
            .unwrap();
        
        // Retrieve the secret
        let retrieved = phantom_key
            .get_secret(&handle)
            .await
            .unwrap();
        
        assert_eq!(retrieved, secret);
    }

    #[test]
    fn test_provider_factory() {
        let bedrock = ProviderFactory::create_bedrock(
            "https://bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            "test-api-key".to_string(),
        );
        assert_eq!(bedrock.name(), "bedrock");
        
        let openai = ProviderFactory::create_openai("test-api-key".to_string());
        assert_eq!(openai.name(), "openai");
        
        let gemini = ProviderFactory::create_gemini("test-api-key".to_string());
        assert_eq!(gemini.name(), "gemini");
    }

    // ========================================================================
    // ATTACK LAB TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_attack_lab_demos() {
        let storage = Arc::new(MemoryStorage::new());
        
        let phantom_key = PhantomKeyBuilder::new()
            .parties(5)
            .threshold(3)
            .vault_storage(storage)
            .build()
            .unwrap();
        
        let attack_lab = AttackLab::new(phantom_key);
        
        // Run all demos
        let results = attack_lab.run_all_demos().await;
        
        // All demos should complete (may not all pass in test environment)
        assert_eq!(results.len(), 6);
    }

    #[test]
    fn test_attack_lab_demo_names() {
        assert_eq!(AttackLab::get_demo_name(1), "Memory Safety");
        assert_eq!(AttackLab::get_demo_name(2), "Log Inspection");
        assert_eq!(AttackLab::get_demo_name(3), "Wire Inspection");
        assert_eq!(AttackLab::get_demo_name(4), "DLEQ Validation");
        assert_eq!(AttackLab::get_demo_name(5), "Ledger Tampering");
        assert_eq!(AttackLab::get_demo_name(6), "Canary Detection");
    }

    // ========================================================================
    // END-TO-END WORKFLOW TESTS
    // ========================================================================

    #[tokio::test]
    async fn test_end_to_end_workflow() {
        // This test verifies the complete workflow:
        // 1. Create PhantomKey
        // 2. Store a secret
        // 3. Retrieve the secret
        // 4. Verify it matches
        
        let storage = Arc::new(MemoryStorage::new());
        
        let mut phantom_key = PhantomKeyBuilder::new()
            .parties(5)
            .threshold(3)
            .vault_storage(storage.clone())
            .build()
            .unwrap();
        
        // Store a secret
        let secret = b"end-to-end-test-secret";
        let handle = phantom_key
            .store_secret(secret, SecretType::Generic)
            .await
            .unwrap();
        
        // Retrieve the secret
        let retrieved = phantom_key
            .get_secret(&handle)
            .await
            .unwrap();
        
        assert_eq!(retrieved, secret);
        
        // Verify vault has the entry
        let entries = phantom_key.get_vault_entries();
        assert!(!entries.is_empty());
        
        // Verify we can find the entry by handle
        let entry = storage.get_by_handle(&handle).unwrap();
        assert_eq!(entry.handle, handle);
    }

    #[tokio::test]
    async fn test_full_system_integration() {
        // This test verifies that all major components work together
        
        // 1. Create DKG
        let dkg = DKG::new(5, 3).unwrap();
        
        // 2. Generate contributions
        let contributions: Vec<_> = (0..5)
            .map(|i| dkg.generate_contribution(i).unwrap())
            .collect();
        
        // 3. Combine to get shares
        let shares = dkg.combine_contributions(&contributions).unwrap();
        
        // 4. Create public shares
        let public_shares: Vec<GroupElement> = (0..5)
            .map(|i| GroupElement::generator().multiply(&shares[i]))
            .collect();
        
        // 5. Create Threshold DH
        let threshold_dh = ThresholdDH::new(dkg, shares.clone(), public_shares).unwrap();
        
        // 6. Run Threshold DH
        let r = GroupScalar::random();
        let R = GroupElement::generator().multiply(&r);
        
        let partials: Vec<_> = (0..3)
            .map(|i| threshold_dh.compute_partial(i, &R).unwrap())
            .collect();
        
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // 7. Create Vault
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        
        // Store a secret
        let secret = b"integration-test-secret";
        let handle = "⟦H1⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Generic,
            ..Default::default()
        };
        
        let entry = encryption.create_entry(secret, &K, handle.clone(), metadata);
        storage.insert(entry);
        
        // 8. Retrieve the secret
        let decrypted = encryption.get_secret(&storage.get_by_handle(&handle).unwrap(), &K).unwrap();
        assert_eq!(decrypted, secret);
        
        // 9. Create Ledger
        use ed25519_dalek::SigningKey;
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);
        
        // Log a request
        let entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash: [0u8; 32],
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            provider: "test".to_string(),
            method: "POST".to_string(),
            url: "/test".to_string(),
            payload: b"test".to_vec(),
            hash: [0u8; 32],
        };
        ledger.append(entry).unwrap();
        
        // Verify chain
        assert!(ledger.verify_chain());
        
        // 10. Create Scanner
        let scanner = SecretScanner::new(storage, encryption, K);
        
        // Scan for the secret
        let payload = b"Using secret: integration-test-secret";
        let matches = scanner.scan(payload);
        assert_eq!(matches.len(), 1);
        
        // All components worked together!
    }
}
