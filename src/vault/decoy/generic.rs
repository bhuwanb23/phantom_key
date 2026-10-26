//! Generic Decoy Generator
//!
//! Generates decoys based on custom patterns.

use super::DecoyGenerator;
use crate::vault::storage::SecretType;
use rand::Rng;

/// Generic Decoy Generator for custom patterns
/// 
/// Pattern syntax:
/// - 0-9: random digit
/// - a-z: random lowercase letter
/// - A-Z: random uppercase letter
/// - x: random hex digit (lowercase)
/// - X: random hex digit (uppercase)
/// - other: literal character
pub struct GenericDecoyGenerator {
    pattern: String,
}

impl GenericDecoyGenerator {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
        }
    }
}

impl DecoyGenerator for GenericDecoyGenerator {
    fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        let mut result = String::new();

        for c in self.pattern.chars() {
            match c {
                '0'..='9' => {
                    result.push(rng.gen_range(0..10).to_string().chars().next().unwrap());
                }
                'a'..='z' => {
                    result.push(rng.gen_range(b'a'..b'z'+1) as char);
                }
                'A'..='Z' => {
                    result.push(rng.gen_range(b'A'..b'Z'+1) as char);
                }
                'x' => {
                    result.push(rng.gen_range(0..16).to_string().chars().next().unwrap());
                }
                'X' => {
                    result.push(
                        rng.gen_range(0..16)
                            .to_string()
                            .to_uppercase()
                            .chars()
                            .next()
                            .unwrap(),
                    );
                }
                c => {
                    result.push(c);
                }
            }
        }

        result
    }

    fn validate_format(&self, value: &str) -> bool {
        value.len() == self.pattern.len()
    }

    fn secret_type(&self) -> SecretType {
        SecretType::Generic
    }
}
