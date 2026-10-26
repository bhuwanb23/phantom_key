//! Credit Card Decoy Generator
//!
//! Generates fake credit card numbers with valid Luhn checksums.

use super::DecoyGenerator;
use crate::vault::storage::SecretType;
use std::collections::HashMap;
use rand::Rng;

/// Credit Card Generator
pub struct CreditCardGenerator {
    issuer: String,
}

impl CreditCardGenerator {
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_lowercase(),
        }
    }
}

impl DecoyGenerator for CreditCardGenerator {
    fn generate(&self) -> String {
        let prefixes: HashMap<&str, &str> = [
            ("visa", "4"),
            ("mastercard", "5"),
            ("amex", "37"),
            ("discover", "6011"),
        ]
        .iter()
        .cloned()
        .collect();

        let prefix = prefixes
            .get(self.issuer.as_str())
            .unwrap_or(&"4");

        let mut rng = rand::thread_rng();
        let length = match self.issuer.as_str() {
            "amex" => 15,
            _ => 16,
        };

        let mut digits: Vec<u8> = prefix
            .chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();

        while digits.len() < length - 1 {
            digits.push(rng.gen_range(0..10) as u8);
        }

        let checksum = Self::luhn_checksum(&digits);
        digits.push(checksum);

        digits.iter().map(|&d| d.to_string()).collect()
    }

    fn validate_format(&self, value: &str) -> bool {
        value.chars().all(|c| c.is_ascii_digit())
    }

    fn secret_type(&self) -> SecretType {
        SecretType::CreditCard
    }
}

impl CreditCardGenerator {
    /// Calculate Luhn checksum digit
    fn luhn_checksum(digits: &[u8]) -> u8 {
        let mut sum = 0;

        for (i, &digit) in digits.iter().enumerate() {
            let mut d = digit as u32;
            if (digits.len() - i) % 2 == 0 {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            sum += d;
        }

        ((10 - (sum % 10)) % 10) as u8
    }
}
