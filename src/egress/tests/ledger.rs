//! Tests for ledger module

#[cfg(test)]
mod tests {
    use super::super::ledger::*;
    use ed25519_dalek::SigningKey;
    use rand::Rng;

    #[test]
    fn test_ledger_creation() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);

        assert_eq!(ledger.entries().len(), 0);
        assert_eq!(ledger.head_hash(), None);
    }

    #[test]
    fn test_ledger_genesis_hash() {
        let genesis = Ledger::genesis_hash();
        assert_eq!(genesis, [0u8; 32]);
    }

    #[test]
    fn test_ledger_append_single() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);

        let entry = LedgerEntry {
            id: uuid::Uuid::new_v4(),
            prev_hash: [0u8; 32],
            timestamp: chrono::Utc::now(),
            request_id: uuid::Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"test payload".to_vec(),
            hash: [0u8; 32],
        };

        ledger.append(entry).unwrap();

        assert_eq!(ledger.entries().len(), 1);
        assert!(ledger.head_hash().is_some());
    }

    #[test]
    fn test_ledger_append_multiple() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);

        for i in 0..5 {
            let entry = LedgerEntry {
                id: uuid::Uuid::new_v4(),
                prev_hash: [0u8; 32],
                timestamp: chrono::Utc::now(),
                request_id: uuid::Uuid::new_v4(),
                provider: format!("provider-{}", i),
                method: "POST".to_string(),
                url: format!("/endpoint-{}", i),
                payload: format!("payload-{}", i).into_bytes(),
                hash: [0u8; 32],
            };
            ledger.append(entry).unwrap();
        }

        assert_eq!(ledger.entries().len(), 5);
    }

    #[test]
    fn test_ledger_chain_verification() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);

        // Append valid entries
        for i in 0..3 {
            let entry = LedgerEntry {
                id: uuid::Uuid::new_v4(),
                prev_hash: [0u8; 32],
                timestamp: chrono::Utc::now(),
                request_id: uuid::Uuid::new_v4(),
                provider: format!("provider-{}", i),
                method: "POST".to_string(),
                url: format!("/endpoint-{}", i),
                payload: format!("payload-{}", i).into_bytes(),
                hash: [0u8; 32],
            };
            ledger.append(entry).unwrap();
        }

        assert!(ledger.verify_chain());
        assert!(matches!(ledger.chain_status(), ChainStatus::Valid { .. }));
    }

    #[test]
    fn test_ledger_get_entry() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);

        let id = uuid::Uuid::new_v4();
        let entry = LedgerEntry {
            id,
            prev_hash: [0u8; 32],
            timestamp: chrono::Utc::now(),
            request_id: uuid::Uuid::new_v4(),
            provider: "test".to_string(),
            method: "GET".to_string(),
            url: "/test".to_string(),
            payload: b"test".to_vec(),
            hash: [0u8; 32],
        };

        ledger.append(entry).unwrap();

        let retrieved = ledger.get(&id).unwrap();
        assert_eq!(retrieved.entry.id, id);
    }

    #[test]
    fn test_ledger_clear() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Ledger::new(signing_key);

        // Add some entries
        for _ in 0..3 {
            let entry = LedgerEntry {
                id: uuid::Uuid::new_v4(),
                prev_hash: [0u8; 32],
                timestamp: chrono::Utc::now(),
                request_id: uuid::Uuid::new_v4(),
                provider: "test".to_string(),
                method: "GET".to_string(),
                url: "/test".to_string(),
                payload: b"test".to_vec(),
                hash: [0u8; 32],
            };
            ledger.append(entry).unwrap();
        }

        assert_eq!(ledger.entries().len(), 3);

        ledger.clear();
        assert_eq!(ledger.entries().len(), 0);
    }

    #[test]
    fn test_ledger_entry_hash() {
        let entry = LedgerEntry {
            id: uuid::Uuid::new_v4(),
            prev_hash: [1u8; 32],
            timestamp: chrono::Utc::now(),
            request_id: uuid::Uuid::new_v4(),
            provider: "test".to_string(),
            method: "GET".to_string(),
            url: "/test".to_string(),
            payload: b"test".to_vec(),
            hash: [0u8; 32],
        };

        let computed_hash = entry.compute_hash();
        assert_ne!(computed_hash, [0u8; 32]);
        assert!(entry.verify_hash());
    }
}
