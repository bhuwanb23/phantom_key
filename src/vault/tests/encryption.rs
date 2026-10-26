//! Tests for vault encryption module

#[cfg(test)]
mod tests {
    use super::super::encryption::*;
    use super::super::storage::*;
    use crate::crypto::group::GroupElement;

    #[test]
    fn test_key_derivation() {
        let R = GroupElement::generator();
        let handle = "⟦H1⟧";

        let key1 = VaultEncryption::derive_key(&R, handle, None);
        let key2 = VaultEncryption::derive_key(&R, handle, None);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_key_derivation_different_handles() {
        let R = GroupElement::generator();

        let key1 = VaultEncryption::derive_key(&R, "⟦H1⟧", None);
        let key2 = VaultEncryption::derive_key(&R, "⟦H2⟧", None);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_derivation_different_context() {
        let R = GroupElement::generator();
        let handle = "⟦H1⟧";

        let key1 = VaultEncryption::derive_key(&R, handle, None);
        let key2 = VaultEncryption::derive_key(&R, handle, Some(b"context1"));

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encryption_decryption() {
        let R = GroupElement::generator();
        let handle = "⟦H1⟧";
        let secret = b"my-secret-password";

        let (ciphertext, nonce) = VaultEncryption::encrypt(secret, &R, handle);

        let decrypted = VaultEncryption::decrypt(&ciphertext, &nonce, &R, handle).unwrap();

        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_encryption_decryption_different_keys() {
        let R1 = GroupElement::generator();
        let R2 = GroupElement::generator().double();
        let handle = "⟦H1⟧";
        let secret = b"my-secret";

        let (ciphertext, nonce) = VaultEncryption::encrypt(secret, &R1, handle);

        // Decryption with wrong R should fail
        let result = VaultEncryption::decrypt(&ciphertext, &nonce, &R2, handle);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_entry() {
        let R = GroupElement::generator();
        let handle = "⟦H1⟧";
        let secret = b"test-secret";
        let metadata = VaultMetadata::default();

        let entry = VaultEncryption::create_entry(secret, &R, handle.to_string(), metadata);

        assert_eq!(entry.handle, handle);
        assert!(!entry.ciphertext.is_empty());
        assert!(!entry.nonce.is_empty());
    }

    #[test]
    fn test_get_secret() {
        let R = GroupElement::generator();
        let handle = "⟦H1⟧";
        let secret = b"test-secret";
        let metadata = VaultMetadata::default();

        let entry = VaultEncryption::create_entry(secret, &R, handle.to_string(), metadata);

        let retrieved = VaultEncryption::get_secret(&entry, &R).unwrap();
        assert_eq!(retrieved, secret);
    }
}
