//! Per-Secret Encryption with HKDF
//!
//! This module provides HKDF-based per-secret encryption using
//! ChaCha20-Poly1305 AEAD for confidentiality and integrity.

use super::storage::{VaultEntry, VaultMetadata};
use crate::crypto::group::GroupElement;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Vault encryption/decryption
pub struct VaultEncryption;

impl VaultEncryption {
    /// Derive encryption key using HKDF
    /// K = HKDF(R, handle || context)
    pub fn derive_key(R: &GroupElement, handle: &str, context: Option<&[u8]>) -> Vec<u8> {
        let mut hkdf = HmacSha256::new_from_slice(R.to_bytes().as_ref())
            .expect("HKDF init failed");

        hkdf.update(handle.as_bytes());
        if let Some(ctx) = context {
            hkdf.update(ctx);
        }

        let mut prk = [0u8; 32];
        hkdf.finalize_into(&mut prk).expect("HKDF extract failed");

        let mut key = [0u8; 32];
        HmacSha256::new_from_slice(&prk)
            .and_then(|mut h| {
                h.update(b"phantom-key-v2-vault");
                h.finalize_into(&mut key)
            })
            .expect("HKDF expand failed");

        key.to_vec()
    }

    /// Encrypt a secret using ChaCha20-Poly1305
    pub fn encrypt(secret: &[u8], R: &GroupElement, handle: &str) -> (Vec<u8>, Vec<u8>) {
        let key = Self::derive_key(R, handle, None);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("Invalid key length");

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, secret)
            .expect("Encryption failed");

        (ciphertext, nonce.to_vec())
    }

    /// Decrypt a secret using ChaCha20-Poly1305
    pub fn decrypt(
        ciphertext: &[u8],
        nonce: &[u8],
        R: &GroupElement,
        handle: &str,
    ) -> Option<Vec<u8>> {
        let key = Self::derive_key(R, handle, None);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("Invalid key length");

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).ok()
    }

    /// Create a new encrypted vault entry
    pub fn create_entry(
        secret: &[u8],
        R: &GroupElement,
        handle: String,
        metadata: VaultMetadata,
    ) -> VaultEntry {
        let (ciphertext, nonce) = Self::encrypt(secret, R, &handle);

        VaultEntry {
            id: Uuid::new_v4(),
            handle,
            ciphertext,
            nonce,
            metadata,
        }
    }

    /// Get secret from vault entry
    pub fn get_secret(entry: &VaultEntry, R: &GroupElement) -> Option<Vec<u8>> {
        Self::decrypt(&entry.ciphertext, &entry.nonce, R, &entry.handle)
    }
}
