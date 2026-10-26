//! Tests for vault mapping module

#[cfg(test)]
mod tests {
    use super::super::mapping::*;
    use super::super::handle::Handle;
    use super::super::storage::{MemoryStorage, VaultEntry, VaultMetadata, SecretType};
    use super::super::decoy::DecoyRegistry;
    use std::sync::Arc;
    use uuid::Uuid;
    use crate::crypto::group::GroupElement;

    #[test]
    fn test_decoy_map_creation() {
        let map = DecoyMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_decoy_map_register() {
        let mut map = DecoyMap::new();
        let handle = Handle::new();
        let decoy = "AKIAIOSFODNN7EXAMPLE".to_string();

        map.register(handle.clone(), decoy.clone());

        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        assert_eq!(map.get_handle(&decoy), Some(&handle));
        assert_eq!(map.get_decoy(&handle), Some(&decoy));
    }

    #[test]
    fn test_decoy_map_multiple() {
        let mut map = DecoyMap::new();

        for i in 0..5 {
            let handle = Handle::new();
            let decoy = format!("DECOY{}", i);
            map.register(handle, decoy);
        }

        assert_eq!(map.len(), 5);
    }

    #[test]
    fn test_decoy_map_remove() {
        let mut map = DecoyMap::new();
        let handle = Handle::new();
        let decoy = "TEST_DECOY".to_string();

        map.register(handle.clone(), decoy.clone());
        assert_eq!(map.len(), 1);

        let removed = map.remove(&handle);
        assert_eq!(removed, Some(decoy));
        assert_eq!(map.len(), 0);
        assert!(map.get_handle(&decoy).is_none());
        assert!(map.get_decoy(&handle).is_none());
    }

    #[test]
    fn test_decoy_map_clear() {
        let mut map = DecoyMap::new();

        for i in 0..5 {
            let handle = Handle::new();
            let decoy = format!("DECOY{}", i);
            map.register(handle, decoy);
        }

        assert_eq!(map.len(), 5);
        map.clear();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_decoy_manager_basic() {
        let registry = DecoyRegistry::new();
        let mapping = Arc::new(Mutex::new(DecoyMap::new()));
        let storage = Arc::new(MemoryStorage::new());

        let manager = DecoyManager::new(registry, mapping.clone(), storage.clone());

        let R = GroupElement::generator();
        let handle = manager.store_secret(
            b"test-secret",
            SecretType::Generic,
            &R,
        );

        assert!(mapping.lock().unwrap().get_decoy(&handle).is_some());
    }

    #[test]
    fn test_decoy_manager_store_and_retrieve() {
        let registry = DecoyRegistry::new();
        let mapping = Arc::new(Mutex::new(DecoyMap::new()));
        let storage = Arc::new(MemoryStorage::new());

        let manager = DecoyManager::new(registry, mapping.clone(), storage.clone());

        let R = GroupElement::generator();
        let secret = b"my-secret-value";

        let handle = manager.store_secret(secret, SecretType::Generic, &R);
        let decoy = manager.get_decoy_from_handle(&handle).unwrap();

        let retrieved = manager.get_secret_from_decoy(&decoy, &R).unwrap();
        assert_eq!(retrieved, secret);
    }

    #[test]
    fn test_decoy_manager_process_prompt() {
        let registry = DecoyRegistry::new();
        let mapping = Arc::new(Mutex::new(DecoyMap::new()));
        let storage = Arc::new(MemoryStorage::new());

        let manager = DecoyManager::new(registry, mapping, storage);

        let R = GroupElement::generator();
        let prompt = "Please use AKIAIOSFODNN7EXAMPLE to access AWS";

        let (processed, handles) = manager.process_prompt(prompt, &R);

        assert_ne!(processed, prompt);
        assert!(!handles.is_empty());
    }
}
