//! Tests for vault storage module

#[cfg(test)]
mod tests {
    use super::super::storage::*;
    use uuid::Uuid;

    #[test]
    fn test_vault_entry_creation() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H1⟧".to_string(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            metadata: VaultMetadata::default(),
        };

        assert_eq!(entry.handle, "⟦H1⟧");
        assert_eq!(entry.ciphertext, vec![1, 2, 3]);
    }

    #[test]
    fn test_secret_type_serialization() {
        let types = [
            SecretType::AwsAccessKey,
            SecretType::AwsSecretKey,
            SecretType::IbAN,
            SecretType::CreditCard,
            SecretType::ApiKey,
            SecretType::Password,
            SecretType::Generic,
            SecretType::Custom("test".to_string()),
        ];

        for ty in types {
            let serialized = serde_json::to_string(&ty).unwrap();
            let deserialized: SecretType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(ty, deserialized);
        }
    }

    #[test]
    fn test_vault_metadata_default() {
        let metadata = VaultMetadata::default();

        assert!(metadata.created_at <= Utc::now());
        assert!(metadata.updated_at <= Utc::now());
        assert_eq!(metadata.secret_type, SecretType::Generic);
        assert_eq!(metadata.description, None);
        assert_eq!(metadata.tags, Vec::<String>::new());
        assert_eq!(metadata.access_count, 0);
    }

    #[test]
    fn test_memory_storage_insert_get() {
        let mut storage = MemoryStorage::new();

        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H1⟧".to_string(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            metadata: VaultMetadata::default(),
        };

        let id = storage.insert(entry.clone());
        assert_eq!(id, entry.id);

        let retrieved = storage.get(&entry.id).unwrap();
        assert_eq!(retrieved.handle, entry.handle);
        assert_eq!(retrieved.ciphertext, entry.ciphertext);
    }

    #[test]
    fn test_memory_storage_get_by_handle() {
        let mut storage = MemoryStorage::new();

        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H2⟧".to_string(),
            ciphertext: vec![7, 8, 9],
            nonce: vec![10, 11, 12],
            metadata: VaultMetadata::default(),
        };

        storage.insert(entry.clone());

        let retrieved = storage.get_by_handle("⟦H2⟧").unwrap();
        assert_eq!(retrieved.id, entry.id);
        assert_eq!(retrieved.ciphertext, entry.ciphertext);
    }

    #[test]
    fn test_memory_storage_update() {
        let mut storage = MemoryStorage::new();

        let mut entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H3⟧".to_string(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            metadata: VaultMetadata::default(),
        };

        storage.insert(entry.clone());

        entry.ciphertext = vec![9, 8, 7];
        assert!(storage.update(entry.clone()));

        let retrieved = storage.get(&entry.id).unwrap();
        assert_eq!(retrieved.ciphertext, vec![9, 8, 7]);
    }

    #[test]
    fn test_memory_storage_delete() {
        let mut storage = MemoryStorage::new();

        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H4⟧".to_string(),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            metadata: VaultMetadata::default(),
        };

        let id = entry.id;
        storage.insert(entry);

        assert!(storage.delete(&id));
        assert!(storage.get(&id).is_none());
        assert!(storage.get_by_handle("⟦H4⟧").is_none());
    }

    #[test]
    fn test_memory_storage_list() {
        let mut storage = MemoryStorage::new();

        for i in 0..5 {
            let entry = VaultEntry {
                id: Uuid::new_v4(),
                handle: format!("⟦H{}⟧", i),
                ciphertext: vec![i as u8],
                nonce: vec![],
                metadata: VaultMetadata::default(),
            };
            storage.insert(entry);
        }

        let entries = storage.list();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_memory_storage_search() {
        let mut storage = MemoryStorage::new();

        let entry = VaultEntry {
            id: Uuid::new_v4(),
            handle: "⟦H_search_test⟧".to_string(),
            ciphertext: vec![],
            nonce: vec![],
            metadata: VaultMetadata {
                description: Some("test description".to_string()),
                tags: vec!["tag1".to_string(), "tag2".to_string()],
                ..Default::default()
            },
        };
        storage.insert(entry);

        // Search by handle
        let results = storage.search("H_search");
        assert_eq!(results.len(), 1);

        // Search by description
        let results = storage.search("description");
        assert_eq!(results.len(), 1);

        // Search by tag
        let results = storage.search("tag1");
        assert_eq!(results.len(), 1);
    }
}
