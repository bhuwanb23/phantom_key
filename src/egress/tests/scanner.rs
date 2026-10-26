//! Tests for scanner module

#[cfg(test)]
mod tests {
    use super::super::scanner::*;
    use super::super::super::vault::storage::{MemoryStorage, VaultEntry, VaultMetadata, SecretType};
    use super::super::super::vault::encryption::VaultEncryption;
    use super::super::super::crypto::group::GroupElement;
    use std::sync::Arc;

    #[test]
    fn test_scanner_creation() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        let scanner = SecretScanner::new(storage, encryption, R);
        // Just verify it can be created
        assert!(true);
    }

    #[test]
    fn test_scanner_scan_empty() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        let scanner = SecretScanner::new(storage, encryption, R);

        let payload = b"no secrets here";
        let matches = scanner.scan(payload);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_scanner_scan_with_secret() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        // Store a secret first
        let secret = b"my-secret-password";
        let handle = "⟦H1⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Password,
            ..Default::default()
        };

        let entry = encryption.create_entry(secret, &R, handle.clone(), metadata);
        storage.insert(entry);

        // Create scanner with same R
        let scanner = SecretScanner::new(storage.clone(), encryption, R);

        // Scan for the secret
        let payload = b"Using password: my-secret-password";
        let matches = scanner.scan(payload);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].handle, handle);
        assert_eq!(matches[0].encoding, "raw");
    }

    #[test]
    fn test_scanner_detects_base64() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        let secret = b"test-secret";
        let handle = "⟦H2⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Generic,
            ..Default::default()
        };

        let entry = encryption.create_entry(secret, &R, handle.clone(), metadata);
        storage.insert(entry);

        let scanner = SecretScanner::new(storage, encryption, R);

        let base64_secret = base64::encode(secret);
        let payload = format!("Encoded: {}", base64_secret).into_bytes();
        let matches = scanner.scan(&payload);

        assert!(!matches.is_empty());
        assert_eq!(matches[0].encoding, "base64");
    }

    #[test]
    fn test_scanner_detects_hex() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        let secret = b"test-secret";
        let handle = "⟦H3⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Generic,
            ..Default::default()
        };

        let entry = encryption.create_entry(secret, &R, handle.clone(), metadata);
        storage.insert(entry);

        let scanner = SecretScanner::new(storage, encryption, R);

        let hex_secret = hex::encode(secret);
        let payload = format!("Hex: {}", hex_secret).into_bytes();
        let matches = scanner.scan(&payload);

        assert!(!matches.is_empty());
        assert_eq!(matches[0].encoding, "hex");
    }

    #[test]
    fn test_scanner_detects_url_encoded() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        let secret = b"test@secret";
        let handle = "⟦H4⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Generic,
            ..Default::default()
        };

        let entry = encryption.create_entry(secret, &R, handle.clone(), metadata);
        storage.insert(entry);

        let scanner = SecretScanner::new(storage, encryption, R);

        let url_secret = urlencoding::encode(&String::from_utf8_lossy(secret));
        let payload = format!("URL: {}", url_secret).into_bytes();
        let matches = scanner.scan(&payload);

        assert!(!matches.is_empty());
        assert_eq!(matches[0].encoding, "url");
    }

    #[test]
    fn test_scanner_no_false_positives() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        // Store a real secret
        let secret = b"real-secret";
        let handle = "⟦H5⟧".to_string();
        let metadata = VaultMetadata {
            secret_type: SecretType::Generic,
            ..Default::default()
        };

        let entry = encryption.create_entry(secret, &R, handle, metadata);
        storage.insert(entry);

        let scanner = SecretScanner::new(storage, encryption, R);

        // Scan for a similar but different string
        let payload = b"fake-secret";
        let matches = scanner.scan(payload);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_scanner_contains_secrets() {
        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        let scanner = SecretScanner::new(storage, encryption, R);

        assert!(!scanner.contains_secrets(b"no secrets"));
        assert!(scanner.contains_secrets(b"test")); // Will match if there's a secret "test"
    }
}
