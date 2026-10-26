//! Decoy Generation
//!
//! This module provides format-preserving decoy generators for various
//! secret types. Decoys are fake secrets that look real but don't
//! expose actual sensitive data.

pub mod aws;
pub mod iban;
pub mod credit_card;
pub mod generic;

use super::storage::SecretType;
use std::collections::HashMap;

/// Trait for decoy generators
pub trait DecoyGenerator: Send + Sync {
    /// Generate a new decoy
    fn generate(&self) -> String;

    /// Validate that a value matches the expected format
    fn validate_format(&self, value: &str) -> bool;

    /// Get the secret type this generator produces
    fn secret_type(&self) -> SecretType;
}

/// Decoy registry for tracking generators
pub struct DecoyRegistry {
    generators: HashMap<SecretType, Box<dyn DecoyGenerator>>,
}

impl DecoyRegistry {
    pub fn new() -> Self {
        let mut generators = HashMap::new();

        generators.insert(
            SecretType::AwsAccessKey,
            Box::new(aws::AwsAccessKeyGenerator),
        );
        generators.insert(
            SecretType::AwsSecretKey,
            Box::new(aws::AwsSecretKeyGenerator),
        );
        generators.insert(
            SecretType::IbAN,
            Box::new(iban::IbanGenerator::new("DE")),
        );
        generators.insert(
            SecretType::CreditCard,
            Box::new(credit_card::CreditCardGenerator::new("visa")),
        );

        Self { generators }
    }

    /// Generate a decoy for a specific secret type
    pub fn generate(&self, secret_type: &SecretType) -> String {
        self.generators
            .get(secret_type)
            .map(|g| g.generate())
            .unwrap_or_else(|| generic::GenericDecoyGenerator::new("XXXXXXXX").generate())
    }

    /// Register a custom generator
    pub fn register_generator(
        &mut self,
        secret_type: SecretType,
        generator: Box<dyn DecoyGenerator>,
    ) {
        self.generators.insert(secret_type, generator);
    }

    /// Validate a value against its secret type
    pub fn validate(&self, value: &str, secret_type: &SecretType) -> bool {
        self.generators
            .get(secret_type)
            .map(|g| g.validate_format(value))
            .unwrap_or(false)
    }
}

impl Default for DecoyRegistry {
    fn default() -> Self {
        Self::new()
    }
}
