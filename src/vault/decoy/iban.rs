//! IBAN Decoy Generator
//!
//! Generates fake IBANs with valid checksums.
//! Format: 2-letter country code + 2-digit checksum + BBAN

use super::DecoyGenerator;
use crate::vault::storage::SecretType;
use rand::Rng;

/// IBAN Generator
pub struct IbanGenerator {
    country_code: String,
}

impl IbanGenerator {
    pub fn new(country_code: &str) -> Self {
        Self {
            country_code: country_code.to_uppercase(),
        }
    }
}

impl DecoyGenerator for IbanGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();

        // Generate random BBAN
        let bban_length = 18;
        let bban: String = (0..bban_length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect();

        // Calculate checksum: 98 - (BBAN + country_code + "00") mod 97
        let check_input = format!("{}{}", bban, self.country_code);
        let check_num = Self::mod97(&format!("{}{}", check_input, "00"));
        let checksum = 98 - check_num;
        let checksum = format!("{:02}", checksum % 97);

        format!("{}{}{}", self.country_code, checksum, bban)
    }

    fn validate_format(&self, value: &str) -> bool {
        value.starts_with(&self.country_code) && value.len() >= 4
    }

    fn secret_type(&self) -> SecretType {
        SecretType::IbAN
    }
}

impl IbanGenerator {
    /// Calculate MOD-97-10 checksum
    fn mod97(input: &str) -> u32 {
        let mut remainder: u64 = 0;

        for c in input.chars() {
            let digit = if c.is_ascii_digit() {
                c.to_digit(10).unwrap() as u64
            } else {
                (c as u64) - ('A' as u64) + 10
            };
            remainder = (remainder * 10 + digit) % 97;
        }

        remainder as u32
    }
}
