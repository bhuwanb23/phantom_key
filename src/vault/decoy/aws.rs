//! AWS Key Decoy Generators
//!
//! Generates fake AWS access keys and secret keys that match
//! the expected format.

use super::DecoyGenerator;
use crate::vault::storage::SecretType;
use rand::Rng;

/// AWS Access Key Generator
/// Format: AKIA + 16 uppercase alphanumeric characters
pub struct AwsAccessKeyGenerator;

impl DecoyGenerator for AwsAccessKeyGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        let random_part: String = (0..16)
            .map(|_| {
                const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                CHARSET[rng.gen_range(0..CHARSET.len())] as char
            })
            .collect();
        format!("AKIA{}", random_part)
    }

    fn validate_format(&self, value: &str) -> bool {
        value.starts_with("AKIA") && value.len() == 20
    }

    fn secret_type(&self) -> SecretType {
        SecretType::AwsAccessKey
    }
}

/// AWS Secret Key Generator
/// Format: 40-character base64-like string
pub struct AwsSecretKeyGenerator;

impl DecoyGenerator for AwsSecretKeyGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..40)
            .map(|_| {
                const CHARSET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                CHARSET[rng.gen_range(0..CHARSET.len())] as char
            })
            .collect()
    }

    fn validate_format(&self, value: &str) -> bool {
        value.len() == 40
            && value.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
            })
    }

    fn secret_type(&self) -> SecretType {
        SecretType::AwsSecretKey
    }
}

/// AWS Session Token Generator
/// Format: Similar to secret key but longer
pub struct AwsSessionTokenGenerator;

impl DecoyGenerator for AwsSessionTokenGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        (0..372) // Typical session token length
            .map(|_| {
                const CHARSET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
                CHARSET[rng.gen_range(0..CHARSET.len())] as char
            })
            .collect()
    }

    fn validate_format(&self, value: &str) -> bool {
        value.len() >= 100
            && value.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
            })
    }

    fn secret_type(&self) -> SecretType {
        SecretType::AwsSessionToken
    }
}
