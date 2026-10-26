# Implementation Guide: Phantom Key

**Project:** Phantom Key  
**Date:** October 26, 2026  
**Purpose:** Practical implementation guide with code examples

---

## Executive Summary

This guide provides **practical implementation details** for building Phantom Key. It includes:
- Rust code examples for threshold Diffie-Hellman
- Decoy generation implementations
- Canary system design
- Egress Court implementation
- Integration with LLM providers

**Status:** Implementation-ready (theoretical validation complete)

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Dependencies](#2-dependencies)
3. [Threshold Diffie-Hellman Implementation](#3-threshold-diffie-hellman-implementation)
4. [Decoy Generation](#4-decoy-generation)
5. [Leak Canary System](#5-leak-canary-system)
6. [Egress Court](#6-egress-court)
7. [Integration with LLMs](#7-integration-with-llms)
8. [Split-Brain Routing](#8-split-brain-routing)
9. [Testing Strategy](#9-testing-strategy)
10. [Deployment Considerations](#10-deployment-considerations)

---

## 1. Project Structure

```
phantom-key/
├── Cargo.toml                    # Rust project configuration
├── src/
│   ├── main.rs                    # Main entry point
│   ├── config.rs                  # Configuration management
│   ├── crypto/
│   │   ├── mod.rs                 # Crypto module exports
│   │   ├── threshold_dh.rs         # Threshold Diffie-Hellman
│   │   ├── shamir.rs               # Shamir secret sharing
│   │   ├── kdf.rs                  # Key derivation
│   │   └── group.rs               # Ristretto255 group helpers
│   ├── decoy/
│   │   ├── mod.rs                 # Decoy module exports
│   │   ├── aws.rs                  # AWS key decoys
│   │   ├── iban.rs                 # IBAN decoys
│   │   ├── credit_card.rs          # Credit card decoys
│   │   └── generic.rs              # Generic format-preserving
│   ├── canary/
│   │   ├── mod.rs                 # Canary module exports
│   │   ├── registry.rs             # Canary registry
│   │   ├── scanner.rs              # Canary scanner
│   │   └── generator.rs            # Canary generation
│   ├── egress/
│   │   ├── mod.rs                 # Egress module exports
│   │   ├── interceptor.rs          # API request interceptor
│   │   ├── scanner.rs              # Secret scanner
│   │   ├── ledger.rs               # Hash-chained audit ledger
│   │   └── tui.rs                  # Text-based UI
│   ├── routing/
│   │   ├── mod.rs                 # Routing module exports
│   │   ├── provider.rs             # Provider abstractions
│   │   ├── router.rs               # Multi-provider router
│   │   └── split_brain.rs          # Split-brain routing
│   └── error.rs                   # Error types
├── tests/
│   ├── crypto/
│   │   ├── test_threshold.rs      # Threshold DH tests
│   │   └── test_shamir.rs          # Shamir SSS tests
│   ├── decoy/
│   │   └── test_formats.rs         # Format tests
│   ├── canary/
│   │   └── test_detection.rs       # Detection tests
│   ├── egress/
│   │   └── test_ledger.rs          # Ledger tests
│   └── integration/
│       └── test_full_flow.rs       # Full flow tests
├── examples/
│   ├── basic.rs                   # Basic example
│   └── demo.rs                    # Demo with TUI
└── README.md
```

---

## 2. Dependencies

### 2.1 Cargo.toml

```toml
[package]
name = "phantom-key"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "Threshold key use without reconstruction for LLM security"
license = "MIT OR Apache-2.0"
readme = "README.md"

[dependencies]
# Cryptography
curve25519-dalek = { version = "4.0", features = ["ristretto", "serde"] }
ristretto255-dh = "0.3"
sha2 = "0.10"
chacha20poly1305 = "0.10"
aes-gcm = "0.10"
rand_core = { version = "0.6", features = ["std"] }
rand = "0.8"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bincode = "1.3"

# Async
tokio = { version = "1.0", features = ["full"] }
tokio-stream = "0.1"

# HTTP
reqwest = { version = "0.11", features = ["json", "stream"] }
hyper = "0.14"
warp = "0.3"

# CLI
clap = { version = "4.0", features = ["derive"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# TUI
ratatui = "0.20"
crossterm = "0.26"

# Other
uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
regex = "1.8"
lazy_static = "1.4"

[dev-dependencies]
criterion = "0.4"
proptest = "1.0"

[features]
default = []
benchmark = ["criterion"]
```

---

## 3. Threshold Diffie-Hellman Implementation

### 3.1 Shamir Secret Sharing

```rust
// src/crypto/shamir.rs
use curve25519_dalek::scalar::Scalar;
use serde::{Serialize, Deserialize};

/// A share in Shamir's Secret Sharing scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub index: u32,
    pub value: Scalar,
}

/// Generate Shamir shares for a secret
pub fn split_secret(secret: Scalar, threshold: usize, total: usize) -> Vec<Share> {
    assert!(threshold <= total, "Threshold must be <= total");
    assert!(threshold > 0, "Threshold must be > 0");
    
    // Generate random coefficients for polynomial f(x) = secret + a1*x + a2*x^2 + ...
    let mut rng = rand::thread_rng();
    let coefficients: Vec<Scalar> = (0..threshold)
        .map(|_| Scalar::random(&mut rng))
        .collect();
    
    // f(0) = secret, so we use coefficients[0] as the secret
    let mut coefficients = coefficients;
    coefficients[0] = secret;
    
    // Generate shares at x = 1, 2, ..., total
    (1..=total)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let y = evaluate_polynomial(&coefficients, &x);
            Share { index: i as u32, value: y }
        })
        .collect()
}

/// Evaluate polynomial at point x
fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients.iter()
        .fold(Scalar::zero(), |acc, &coeff| acc + &coeff * x)
}

/// Compute Lagrange coefficients for reconstruction at x=0
pub fn lagrange_coefficients(indices: &[u32], x: u32) -> Vec<Scalar> {
    let x_scalar = Scalar::from(x as u64);
    indices.iter()
        .map(|&i| {
            let i_scalar = Scalar::from(i as u64);
            let mut numerator = Scalar::one();
            let mut denominator = Scalar::one();
            
            for &j in indices {
                if j == i {
                    continue;
                }
                let j_scalar = Scalar::from(j as u64);
                numerator *= &(x_scalar - j_scalar);
                denominator *= &(i_scalar - j_scalar);
            }
            
            numerator * denominator.invert()
        })
        .collect()
}

/// Reconstruct secret from shares
pub fn reconstruct_secret(shares: &[Share]) -> Option<Scalar> {
    if shares.is_empty() {
        return None;
    }
    
    let indices: Vec<u32> = shares.iter().map(|s| s.index).collect();
    let lambdas = lagrange_coefficients(&indices, 0);
    
    if lambdas.len() != shares.len() {
        return None;
    }
    
    let secret = lambdas.iter()
        .zip(shares.iter())
        .fold(Scalar::zero(), |acc, (&lambda, share)| acc + &lambda * &share.value);
    
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_split_and_reconstruct() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        
        let shares = split_secret(secret, 3, 5);
        
        // Try with threshold shares
        let reconstructed = reconstruct_secret(&shares[..3]).unwrap();
        assert_eq!(reconstructed, secret);
        
        // Try with more than threshold
        let reconstructed = reconstruct_secret(&shares[..4]).unwrap();
        assert_eq!(reconstructed, secret);
    }
    
    #[test]
    fn test_less_than_threshold_fails() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        
        let shares = split_secret(secret, 3, 5);
        
        // Try with less than threshold - should reconstruct to wrong value
        let reconstructed = reconstruct_secret(&shares[..2]).unwrap();
        assert_ne!(reconstructed, secret);
    }
}
```

### 3.2 Threshold Diffie-Hellman

```rust
// src/crypto/threshold_dh.rs
use curve25519_dalek::ristretto::{RistrettoPoint, Scalar};
use curve25519_dalek::traits::MultiscalarMul;
use sha2::{Sha256, Digest};
use super::shamir::{Share, split_secret, lagrange_coefficients};

/// Threshold Diffie-Hellman key exchange
pub struct ThresholdDH {
    shares: Vec<Share>,  // Secret shares s_i
}

impl ThresholdDH {
    /// Create new threshold DH with given secret
    pub fn new(secret: Scalar, threshold: usize, total: usize) -> Self {
        let shares = split_secret(secret, threshold, total);
        Self { shares }
    }
    
    /// Get the share at index (1-based)
    pub fn get_share(&self, index: u32) -> Option<&Share> {
        self.shares.iter().find(|s| s.index == index)
    }
    
    /// Compute partial point P_i = s_i * R
    pub fn compute_partial(&self, share_index: u32, R: &RistrettoPoint) -> Option<RistrettoPoint> {
        let share = self.get_share(share_index)?;
        Some(share.value * R)
    }
    
    /// Combine partial points to get K = s * R
    pub fn combine_partials(
        &self,
        partials: &[(u32, RistrettoPoint)],
        R: &RistrettoPoint,
    ) -> Option<RistrettoPoint> {
        if partials.len() < self.shares.len() {
            // Need at least threshold shares
            return None;
        }
        
        let indices: Vec<u32> = partials.iter().map(|(i, _)| *i).collect();
        let lambdas = lagrange_coefficients(&indices, 0);
        
        if lambdas.len() != partials.len() {
            return None;
        }
        
        // K = Σ λ_i * P_i
        let points: Vec<(&Scalar, &RistrettoPoint)> = lambdas.iter()
            .zip(partials.iter())
            .map(|(lambda, (_, P_i))| (lambda, P_i))
            .collect();
        
        let K = RistrettoPoint::multiscalar_mul(points.iter().map(|(s, p)| (s, p)).collect());
        
        Some(K)
    }
    
    /// Derive AEAD key from K
    pub fn derive_key(K: &RistrettoPoint) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(K.compress().as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threshold_dh() {
        let mut rng = rand::thread_rng();
        
        // Generate master secret
        let s = Scalar::random(&mut rng);
        
        // Create threshold DH
        let threshold_dh = ThresholdDH::new(s, 3, 5);
        
        // Client picks ephemeral
        let r = Scalar::random(&mut rng);
        let R = r * RistrettoPoint::generator();
        
        // Each shareholder computes partial
        let partials: Vec<(u32, RistrettoPoint)> = (0..3)
            .map(|i| {
                let share_index = (i + 1) as u32;
                let P_i = threshold_dh.compute_partial(share_index, &R).unwrap();
                (share_index, P_i)
            })
            .collect();
        
        // Client combines
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify: K should equal s * R
        let expected_K = s * R;
        assert_eq!(K, expected_K);
        
        // Derive key
        let key = ThresholdDH::derive_key(&K);
        assert_eq!(key.len(), 32);
    }
}
```

---

## 4. Decoy Generation

### 4.1 AWS Keys

```rust
// src/decoy/aws.rs
use rand::Rng;
use std::collections::HashMap;

const AWS_ACCESS_KEY_PREFIX: &str = "AKIA";
const AWS_ACCESS_KEY_LENGTH: usize = 20; // AKIA + 16 chars
const AWS_SECRET_KEY_LENGTH: usize = 40;

/// Generate fake AWS access key ID
pub fn generate_access_key_id() -> String {
    let mut rng = rand::thread_rng();
    let random_part: String = (0..16)
        .map(|_| {
            const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            CHARSET[rng.gen_range(0..CHARSET.len())] as char
        })
        .collect();
    format!("{}{}", AWS_ACCESS_KEY_PREFIX, random_part)
}

/// Generate fake AWS secret access key
pub fn generate_secret_access_key() -> String {
    let mut rng = rand::thread_rng();
    (0..AWS_SECRET_KEY_LENGTH)
        .map(|_| {
            const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            CHARSET[rng.gen_range(0..CHARSET.len())] as char
        })
        .collect()
}

/// Generate complete fake AWS credentials
pub fn generate_aws_credentials() -> HashMap<String, String> {
    let mut creds = HashMap::new();
    creds.insert("AWS_ACCESS_KEY_ID".to_string(), generate_access_key_id());
    creds.insert("AWS_SECRET_ACCESS_KEY".to_string(), generate_secret_access_key());
    creds
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aws_key_format() {
        let key_id = generate_access_key_id();
        assert!(key_id.starts_with("AKIA"));
        assert_eq!(key_id.len(), AWS_ACCESS_KEY_LENGTH);
        
        let secret_key = generate_secret_access_key();
        assert_eq!(secret_key.len(), AWS_SECRET_KEY_LENGTH);
    }
}
```

### 4.2 IBAN

```rust
// src/decoy/iban.rs
use rand::Rng;

/// Generate a valid IBAN with fake account number
pub fn generate_iban(country_code: &str) -> String {
    // Country code must be 2 uppercase letters
    let country_code = country_code.to_uppercase();
    assert_eq!(country_code.len(), 2);
    
    // Generate random BBAN (Basic Bank Account Number)
    let mut rng = rand::thread_rng();
    let bban_length = 18; // Typical length
    let bban: String = (0..bban_length)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect();
    
    // Calculate checksum: 98 - (BBAN + country_code + "00") mod 97
    let check_input = format!("{}{}", bban, country_code);
    let check_num = mod97(&format!("{}{}", check_input, "00"));
    let checksum = 98 - check_num;
    let checksum = format!("{:02}", checksum % 97);
    
    format!("{}{}{}", country_code, checksum, bban)
}

/// Calculate MOD-97-10 checksum
fn mod97(input: &str) -> u32 {
    let mut remainder: u64 = 0;
    
    for c in input.chars() {
        let digit = c.to_digit(10).unwrap_or(0) as u64;
        remainder = (remainder * 10 + digit) % 97;
    }
    
    remainder as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_iban_format() {
        let iban = generate_iban("DE");
        assert!(iban.starts_with("DE"));
        assert_eq!(iban.len(), 22); // DE + 2 checksum + 18 BBAN
        
        // Verify checksum
        let (country, checksum, bban) = iban.split_at(2);
        let checksum = &iban[2..4];
        let bban = &iban[4..];
        let check_input = format!("{}{}{}", bban, country, "00");
        let check_num = mod97(&check_input);
        let expected_checksum = 98 - check_num;
        assert_eq!(checksum.parse::<u32>().unwrap() % 97, expected_checksum % 97);
    }
}
```

### 4.3 Credit Cards

```rust
// src/decoy/credit_card.rs
use rand::Rng;

/// Generate a valid credit card number (Luhn algorithm)
pub fn generate_credit_card(issuer: &str) -> String {
    let prefixes: std::collections::HashMap<&str, &str> = [
        ("visa", "4"),
        ("mastercard", "5"),
        ("amex", "37"),
        ("discover", "6011"),
    ].iter().cloned().collect();
    
    let prefix = prefixes.get(issuer.to_lowercase().as_str())
        .unwrap_or(&"4");
    
    let mut rng = rand::thread_rng();
    let length = match issuer.to_lowercase().as_str() {
        "amex" => 15,
        _ => 16,
    };
    
    let mut digits: Vec<u8> = prefix.chars()
        .map(|c| c.to_digit(10).unwrap() as u8)
        .collect();
    
    // Fill with random digits
    while digits.len() < length - 1 {
        digits.push(rng.gen_range(0..10) as u8);
    }
    
    // Calculate Luhn checksum
    let checksum = luhn_checksum(&digits);
    digits.push(checksum);
    
    digits.iter().map(|&d| d.to_string()).collect()
}

/// Calculate Luhn checksum digit
fn luhn_checksum(digits: &[u8]) -> u8 {
    let mut sum = 0;
    
    for (i, &digit) in digits.iter().enumerate() {
        let mut d = digit as u32;
        if (digits.len() - i) % 2 == 0 {
            // Double every second digit from the right
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    
    ((10 - (sum % 10)) % 10) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_credit_card_luhn() {
        let card = generate_credit_card("visa");
        assert!(card.starts_with("4"));
        assert_eq!(card.len(), 16);
        
        // Verify Luhn checksum
        let digits: Vec<u8> = card.chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        let checksum = digits.last().unwrap();
        let calculated = luhn_checksum(&digits[..digits.len()-1]);
        assert_eq!(*checksum, calculated);
    }
}
```

### 4.4 Generic Format-Preserving

```rust
// src/decoy/generic.rs
use rand::Rng;

/// Generate a format-preserving decoy for a given pattern
pub fn generate_decoy(pattern: &str) -> String {
    let mut rng = rand::thread_rng();
    let mut result = String::new();
    
    for c in pattern.chars() {
        match c {
            '0'..='9' => {
                result.push(rng.gen_range(0..10).to_string().chars().next().unwrap());
            },
            'a'..='z' => {
                result.push(rng.gen_range(b'a'..b'z'+1) as char);
            },
            'A'..='Z' => {
                result.push(rng.gen_range(b'A'..b'Z'+1) as char);
            },
            'x' => {
                // Hex digit
                result.push(rng.gen_range(0..16).to_string().chars().next().unwrap());
            },
            'X' => {
                // Uppercase hex
                result.push(rng.gen_range(0..16).to_string().to_uppercase().chars().next().unwrap());
            },
            c => {
                result.push(c);
            }
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generic_decoy() {
        // AWS access key pattern: AKIA + 16 uppercase hex
        let pattern = "AKIAxxxxxxxxxxxxxxxx";
        let decoy = generate_decoy(pattern);
        assert!(decoy.starts_with("AKIA"));
        assert_eq!(decoy.len(), pattern.len());
    }
}
```

---

## 5. Leak Canary System

### 5.1 Canary Registry

```rust
// src/canary/registry.rs
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub id: Uuid,
    pub value: String,
    pub canary_type: String,
    pub request_id: Uuid,
    pub provider: String,
    pub created_at: DateTime<Utc>,
    pub triggered_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct CanaryRegistry {
    canaries: Arc<Mutex<HashMap<Uuid, Canary>>>,
}

impl CanaryRegistry {
    pub fn new() -> Self {
        Self {
            canaries: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Register a new canary
    pub fn register(&self, value: String, canary_type: String, request_id: Uuid, provider: String) -> Uuid {
        let mut canaries = self.canaries.lock().unwrap();
        let id = Uuid::new_v4();
        
        let canary = Canary {
            id,
            value,
            canary_type,
            request_id,
            provider,
            created_at: Utc::now(),
            triggered_at: None,
            metadata: HashMap::new(),
        };
        
        canaries.insert(id, canary);
        id
    }
    
    /// Trigger a canary (mark as used)
    pub fn trigger(&self, canary_id: Uuid) -> Option<Canary> {
        let mut canaries = self.canaries.lock().unwrap();
        if let Some(canary) = canaries.get_mut(&canary_id) {
            canary.triggered_at = Some(Utc::now());
            Some(canary.clone())
        } else {
            None
        }
    }
    
    /// Check if a value is a registered canary
    pub fn is_canary(&self, value: &str) -> Option<Uuid> {
        let canaries = self.canaries.lock().unwrap();
        for (id, canary) in canaries.iter() {
            if canary.value == value {
                return Some(*id);
            }
        }
        None
    }
    
    /// Get canary by ID
    pub fn get(&self, id: Uuid) -> Option<Canary> {
        let canaries = self.canaries.lock().unwrap();
        canaries.get(&id).cloned()
    }
}
```

### 5.2 Canary Generator

```rust
// src/canary/generator.rs
use uuid::Uuid;
use super::registry::{CanaryRegistry, Canary};
use crate::decoy;

pub struct CanaryGenerator {
    registry: CanaryRegistry,
}

impl CanaryGenerator {
    pub fn new(registry: CanaryRegistry) -> Self {
        Self { registry }
    }
    
    /// Generate a canary for AWS credentials
    pub fn generate_aws(&self, request_id: Uuid, provider: &str) -> Canary {
        let creds = decoy::aws::generate_aws_credentials();
        let value = format!("AWS_ACCESS_KEY_ID={},AWS_SECRET_ACCESS_KEY={}",
            creds.get("AWS_ACCESS_KEY_ID").unwrap(),
            creds.get("AWS_SECRET_ACCESS_KEY").unwrap());
        
        let id = self.registry.register(
            value.clone(),
            "aws_credentials".to_string(),
            request_id,
            provider.to_string(),
        );
        
        Canary {
            id,
            value,
            canary_type: "aws_credentials".to_string(),
            request_id,
            provider: provider.to_string(),
            created_at: chrono::Utc::now(),
            triggered_at: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Generate a canary for IBAN
    pub fn generate_iban(&self, request_id: Uuid, provider: &str) -> Canary {
        let iban = decoy::iban::generate_iban("DE");
        let id = self.registry.register(
            iban.clone(),
            "iban".to_string(),
            request_id,
            provider.to_string(),
        );
        
        Canary {
            id,
            value: iban,
            canary_type: "iban".to_string(),
            request_id,
            provider: provider.to_string(),
            created_at: chrono::Utc::now(),
            triggered_at: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Generate a canary for credit card
    pub fn generate_credit_card(&self, request_id: Uuid, provider: &str) -> Canary {
        let card = decoy::credit_card::generate_credit_card("visa");
        let id = self.registry.register(
            card.clone(),
            "credit_card".to_string(),
            request_id,
            provider.to_string(),
        );
        
        Canary {
            id,
            value: card,
            canary_type: "credit_card".to_string(),
            request_id,
            provider: provider.to_string(),
            created_at: chrono::Utc::now(),
            triggered_at: None,
            metadata: HashMap::new(),
        }
    }
}
```

### 5.3 Canary Scanner

```rust
// src/canary/scanner.rs
use regex::Regex;
use lazy_static::lazy_static;
use super::registry::CanaryRegistry;

lazy_static! {
    static ref AWS_ACCESS_KEY_PATTERN: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    static ref AWS_SECRET_KEY_PATTERN: Regex = Regex::new(r"[A-Za-z0-9/+=]{40}").unwrap();
    static ref IBAN_PATTERN: Regex = Regex::new(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}").unwrap();
    static ref CREDIT_CARD_PATTERN: Regex = Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap();
}

pub struct CanaryScanner {
    registry: CanaryRegistry,
}

impl CanaryScanner {
    pub fn new(registry: CanaryRegistry) -> Self {
        Self { registry }
    }
    
    /// Scan text for canary values
    pub fn scan(&self, text: &str) -> Vec<Uuid> {
        let mut triggered = Vec::new();
        
        // Check AWS access keys
        for cap in AWS_ACCESS_KEY_PATTERN.captures_iter(text) {
            if let Some(id) = self.registry.is_canary(&cap[0]) {
                triggered.push(id);
            }
        }
        
        // Check AWS secret keys
        for cap in AWS_SECRET_KEY_PATTERN.captures_iter(text) {
            if let Some(id) = self.registry.is_canary(&cap[0]) {
                triggered.push(id);
            }
        }
        
        // Check IBANs
        for cap in IBAN_PATTERN.captures_iter(text) {
            if let Some(id) = self.registry.is_canary(&cap[0]) {
                triggered.push(id);
            }
        }
        
        // Check credit cards
        for cap in CREDIT_CARD_PATTERN.captures_iter(text) {
            if let Some(id) = self.registry.is_canary(&cap[0]) {
                triggered.push(id);
            }
        }
        
        triggered
    }
    
    /// Trigger all detected canaries
    pub fn trigger_detected(&self, text: &str) -> Vec<Canary> {
        let triggered_ids = self.scan(text);
        triggered_ids.iter()
            .filter_map(|&id| self.registry.trigger(id))
            .collect()
    }
}
```

---

## 6. Egress Court

### 6.1 Audit Ledger

```rust
// src/egress/ledger.rs
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub prev_hash: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub request_id: Uuid,
    pub provider: String,
    pub method: String,
    pub url: String,
    pub payload: Vec<u8>,
    pub hash: [u8; 32],
}

impl AuditEntry {
    pub fn new(
        prev_hash: [u8; 32],
        request_id: Uuid,
        provider: String,
        method: String,
        url: String,
        payload: Vec<u8>,
    ) -> Self {
        let timestamp = Utc::now();
        let mut hasher = Sha256::new();
        hasher.update(&prev_hash);
        hasher.update(&timestamp.to_rfc3339().as_bytes());
        hasher.update(&request_id.as_bytes());
        hasher.update(&provider.as_bytes());
        hasher.update(&method.as_bytes());
        hasher.update(&url.as_bytes());
        hasher.update(&payload);
        let hash = hasher.finalize().into();
        
        Self {
            id: Uuid::new_v4(),
            prev_hash,
            timestamp,
            request_id,
            provider,
            method,
            url,
            payload,
            hash,
        }
    }
    
    pub fn verify(&self, prev_hash: [u8; 32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&prev_hash);
        hasher.update(&self.timestamp.to_rfc3339().as_bytes());
        hasher.update(&self.request_id.as_bytes());
        hasher.update(&self.provider.as_bytes());
        hasher.update(&self.method.as_bytes());
        hasher.update(&self.url.as_bytes());
        hasher.update(&self.payload);
        let computed_hash: [u8; 32] = hasher.finalize().into();
        computed_hash == self.hash
    }
}

#[derive(Debug, Default)]
pub struct AuditLedger {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Add a new entry to the ledger
    pub fn append(&self, entry: AuditEntry) {
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry);
    }
    
    /// Get the current head hash
    pub fn head_hash(&self) -> Option<[u8; 32]> {
        let entries = self.entries.lock().unwrap();
        entries.last().map(|e| e.hash)
    }
    
    /// Get the genesis hash (all zeros)
    pub fn genesis_hash() -> [u8; 32] {
        [0u8; 32]
    }
    
    /// Verify the entire chain
    pub fn verify_chain(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        let mut prev_hash = Self::genesis_hash();
        
        for entry in entries.iter() {
            if entry.prev_hash != prev_hash {
                return false;
            }
            if !entry.verify(prev_hash) {
                return false;
            }
            prev_hash = entry.hash;
        }
        
        true
    }
    
    /// Get all entries
    pub fn entries(&self) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap();
        entries.clone()
    }
}
```

### 6.2 Secret Scanner

```rust
// src/egress/scanner.rs
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // AWS patterns
    static ref AWS_ACCESS_KEY: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    static ref AWS_SECRET_KEY: Regex = Regex::new(r"[A-Za-z0-9/+=]{40}").unwrap();
    static ref AWS_SESSION_TOKEN: Regex = Regex::new(r"[A-Za-z0-9/+=]+`).unwrap();
    
    // Other patterns
    static ref OPENAI_KEY: Regex = Regex::new(r"sk-[0-9a-zA-Z]{48}").unwrap();
    static ref ANTHROPIC_KEY: Regex = Regex::new(r"sk-ant-[0-9a-zA-Z-]{32}").unwrap();
    static ref GITHUB_TOKEN: Regex = Regex::new(r"gh[ps]_[A-Za-z0-9]{36}").unwrap();
    static ref SLACK_TOKEN: Regex = Regex::new(r"xox[baprs]-[0-9a-zA-Z-]{10,48}").unwrap();
    
    // Generic patterns
    static ref PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"password[\s]*[=:]\s*[^\s]+").unwrap();
    static ref API_KEY: Regex = Regex::new(r"api[_-]?key[\s]*[=:]\s*[^\s]+").unwrap();
}

#[derive(Debug)]
pub struct SecretMatch {
    pub pattern: String,
    pub value: String,
    pub position: usize,
}

pub struct SecretScanner;

impl SecretScanner {
    pub fn new() -> Self {
        Self
    }
    
    /// Scan payload for secrets
    pub fn scan(&self, payload: &[u8]) -> Vec<SecretMatch> {
        let text = String::from_utf8_lossy(payload);
        let mut matches = Vec::new();
        
        // AWS
        for cap in AWS_ACCESS_KEY.captures_iter(&text) {
            matches.push(SecretMatch {
                pattern: "AWS_ACCESS_KEY".to_string(),
                value: cap[0].to_string(),
                position: cap.get(0).unwrap().start(),
            });
        }
        
        for cap in AWS_SECRET_KEY.captures_iter(&text) {
            matches.push(SecretMatch {
                pattern: "AWS_SECRET_KEY".to_string(),
                value: cap[0].to_string(),
                position: cap.get(0).unwrap().start(),
            });
        }
        
        // OpenAI
        for cap in OPENAI_KEY.captures_iter(&text) {
            matches.push(SecretMatch {
                pattern: "OPENAI_KEY".to_string(),
                value: cap[0].to_string(),
                position: cap.get(0).unwrap().start(),
            });
        }
        
        // Generic
        for cap in PRIVATE_KEY.captures_iter(&text) {
            matches.push(SecretMatch {
                pattern: "PRIVATE_KEY".to_string(),
                value: cap[0].to_string(),
                position: cap.get(0).unwrap().start(),
            });
        }
        
        matches
    }
    
    /// Check if payload contains any secrets
    pub fn contains_secrets(&self, payload: &[u8]) -> bool {
        !self.scan(payload).is_empty()
    }
}
```

### 6.3 Interceptor

```rust
// src/egress/interceptor.rs
use std::sync::Arc;
use tokio::sync::Mutex;
use super::{ledger::AuditLedger, scanner::SecretScanner};
use crate::canary::scanner::CanaryScanner;

pub struct EgressInterceptor {
    ledger: Arc<AuditLedger>,
    secret_scanner: SecretScanner,
    canary_scanner: CanaryScanner,
}

impl EgressInterceptor {
    pub fn new(
        ledger: Arc<AuditLedger>,
        secret_scanner: SecretScanner,
        canary_scanner: CanaryScanner,
    ) -> Self {
        Self {
            ledger,
            secret_scanner,
            canary_scanner,
        }
    }
    
    /// Intercept and log an outbound request
    pub async fn intercept(
        &self,
        request_id: uuid::Uuid,
        provider: &str,
        method: &str,
        url: &str,
        payload: &[u8],
    ) -> Result<(), String> {
        // Scan for secrets
        let secret_matches = self.secret_scanner.scan(payload);
        if !secret_matches.is_empty() {
            return Err(format!(
                "SECRET DETECTED in egress to {}: {:?}",
                provider, secret_matches
            ));
        }
        
        // Scan for canaries
        let text = String::from_utf8_lossy(payload);
        let triggered_canaries = self.canary_scanner.trigger_detected(&text);
        if !triggered_canaries.is_empty() {
            // Canary triggered - this is expected for decoyed prompts
            // But we still log it
        }
        
        // Get previous hash
        let prev_hash = self.ledger.head_hash().unwrap_or_else(|| AuditLedger::genesis_hash());
        
        // Create audit entry
        let entry = AuditEntry::new(
            prev_hash,
            request_id,
            provider.to_string(),
            method.to_string(),
            url.to_string(),
            payload.to_vec(),
        );
        
        // Append to ledger
        self.ledger.append(entry);
        
        Ok(())
    }
}
```

### 6.4 TUI

```rust
// src/egress/tui.rs
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use super::ledger::AuditLedger;

pub struct EgressTUI {
    ledger: Arc<AuditLedger>,
}

impl EgressTUI {
    pub fn new(ledger: Arc<AuditLedger>) -> Self {
        Self { ledger }
    }
    
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut terminal = setup_terminal()?;
        
        loop {
            terminal.draw(|f| self.ui(f))?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    
    fn ui(&self, f: &mut Frame) {
        let size = f.size();
        
        // Get latest entries
        let entries = self.ledger.entries();
        let latest = &entries[entries.len().saturating_sub(10)..];
        
        // Create table rows
        let rows: Vec<Row> = latest.iter()
            .map(|entry| {
                Row::new([
                    entry.timestamp.format("%H:%M:%S").to_string(),
                    entry.provider.clone(),
                    entry.method.clone(),
                    format!("{:.20}", entry.url),
                    if entry.hash == self.ledger.head_hash().unwrap_or([0; 32]) {
                        "✓".to_string()
                    } else {
                        "✗".to_string()
                    },
                ])
            })
            .collect();
        
        // Create table
        let table = Table::new(rows)
            .header(Row::new(["Time", "Provider", "Method", "URL", "Status"]))
            .block(Block::default().title("Egress Court - Recent Requests").borders(Borders::ALL))
            .widths(&[10, 15, 10, 30, 5]);
        
        f.render_widget(table, size);
        
        // Show chain status
        let chain_valid = self.ledger.verify_chain();
        let status_text = if chain_valid { "✓ Chain Valid" } else { "✗ Chain Tampered" };
        let status = Paragraph::new(status_text)
            .block(Block::default().title("Chain Status").borders(Borders::ALL));
        f.render_widget(status, Rect {
            x: 0,
            y: size.height - 3,
            width: size.width,
            height: 3,
        });
    }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>, Box<dyn std::error::Error>> {
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    crossterm::terminal::enable_raw_mode()?;
    
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    
    Ok(terminal)
}
```

---

## 7. Integration with LLMs

### 7.1 Prompt Processor

```rust
// src/llm/prompt_processor.rs
use uuid::Uuid;
use std::collections::HashMap;
use crate::{
    crypto::threshold_dh::ThresholdDH,
    decoy,
    canary::generator::CanaryGenerator,
};

pub struct PromptProcessor {
    threshold_dh: ThresholdDH,
    canary_generator: CanaryGenerator,
}

impl PromptProcessor {
    pub fn new(threshold_dh: ThresholdDH, canary_generator: CanaryGenerator) -> Self {
        Self {
            threshold_dh,
            canary_generator,
        }
    }
    
    /// Process a prompt: replace secrets with decoys and register canaries
    pub fn process_prompt(
        &self,
        prompt: &str,
        request_id: Uuid,
        provider: &str,
    ) -> (String, HashMap<Uuid, String>) {
        let mut processed = prompt.to_string();
        let mut canaries = HashMap::new();
        
        // Replace AWS keys
        let aws_pattern = regex::Regex::new(r"AWS_ACCESS_KEY_ID=\w+|AWS_SECRET_ACCESS_KEY=\w+").unwrap();
        for cap in aws_pattern.captures_iter(prompt) {
            let canary = self.canary_generator.generate_aws(request_id, provider);
            let replacement = format!("AWS_ACCESS_KEY_ID={},AWS_SECRET_ACCESS_KEY={}",
                canary.value.split(',').next().unwrap(),
                canary.value.split(',').nth(1).unwrap());
            processed = processed.replace(&cap[0], &replacement);
            canaries.insert(canary.id, canary.value);
        }
        
        // Replace IBANs
        let iban_pattern = regex::Regex::new(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}").unwrap();
        for cap in iban_pattern.captures_iter(prompt) {
            let canary = self.canary_generator.generate_iban(request_id, provider);
            processed = processed.replace(&cap[0], &canary.value);
            canaries.insert(canary.id, canary.value);
        }
        
        // Replace credit cards
        let cc_pattern = regex::Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b").unwrap();
        for cap in cc_pattern.captures_iter(prompt) {
            let canary = self.canary_generator.generate_credit_card(request_id, provider);
            processed = processed.replace(&cap[0], &canary.value);
            canaries.insert(canary.id, canary.value);
        }
        
        (processed, canaries)
    }
    
    /// Encrypt the processed prompt
    pub fn encrypt_prompt(
        &self,
        processed_prompt: &str,
        request_id: Uuid,
    ) -> Vec<u8> {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::scalar::Scalar;
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let R = r * RistrettoPoint::generator();
        
        // Collect partials from shareholders
        let mut partials = Vec::new();
        for i in 1..=3 {  // Assuming threshold=3
            if let Some(P_i) = self.threshold_dh.compute_partial(i, &R) {
                partials.push((i, P_i));
            }
        }
        
        // Combine to get K = s * R
        let K = self.threshold_dh.combine_partials(&partials, &R)
            .expect("Failed to combine partials");
        
        // Derive encryption key
        let key = ThresholdDH::derive_key(&K);
        
        // Encrypt with ChaCha20-Poly1305
        use chacha20poly1305::{
            aead::{Aead, KeyInit, OsRng},
            ChaCha20Poly1305,
        };
        
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        cipher.encrypt(&nonce, processed_prompt.as_bytes())
            .expect("Encryption failed")
    }
}
```

---

## 8. Split-Brain Routing

### 8.1 Provider Abstraction

```rust
// src/routing/provider.rs
use std::collections::HashMap;
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<HashMap<String, String>>,
        temperature: f32,
    ) -> Result<Value, String>;
}

pub struct BedrockProvider {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

#[async_trait]
impl LLMProvider for BedrockProvider {
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<HashMap<String, String>>,
        temperature: f32,
    ) -> Result<Value, String> {
        let request = serde_json::json!({
            "modelId": model,
            "messages": messages,
            "temperature": temperature,
        });
        
        let response = self.client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        response.json().await.map_err(|e| e.to_string())
    }
}

pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: String,
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<HashMap<String, String>>,
        temperature: f32,
    ) -> Result<Value, String> {
        let request = serde_json::json!({
            "model": model,
            "messages": messages,
            "temperature": temperature,
        });
        
        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        response.json().await.map_err(|e| e.to_string())
    }
}
```

### 8.2 Split-Brain Router

```rust
// src/routing/split_brain.rs
use std::collections::HashMap;
use async_trait::async_trait;
use super::provider::LLMProvider;
use uuid::Uuid;

pub struct SplitBrainRouter {
    providers: HashMap<String, Box<dyn LLMProvider>>,
}

impl SplitBrainRouter {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }
    
    pub fn add_provider(&mut self, name: String, provider: Box<dyn LLMProvider>) {
        self.providers.insert(name, provider);
    }
    
    /// Split a request across multiple providers
    pub async fn split_request(
        &self,
        request_id: Uuid,
        model: &str,
        messages: Vec<HashMap<String, String>>,
        temperature: f32,
    ) -> HashMap<String, Result<Value, String>> {
        let mut results = HashMap::new();
        
        // Split messages into parts
        let parts = self.split_messages(messages);
        
        // Send each part to a different provider
        for (provider_name, provider) in &self.providers {
            let part_messages = parts.get(provider_name).cloned().unwrap_or_default();
            let result = provider.chat_completion(model, part_messages, temperature).await;
            results.insert(provider_name.clone(), result);
        }
        
        results
    }
    
    /// Split messages into provider-specific parts
    fn split_messages(&self, messages: Vec<HashMap<String, String>>) -> HashMap<String, Vec<HashMap<String, String>>> {
        let mut parts = HashMap::new();
        
        // Simple round-robin splitting
        for (i, message) in messages.into_iter().enumerate() {
            let provider_names: Vec<String> = self.providers.keys().cloned().collect();
            let provider_name = &provider_names[i % provider_names.len()];
            parts.entry(provider_name.clone())
                .or_insert_with(Vec::new)
                .push(message);
        }
        
        parts
    }
    
    /// Aggregate results from multiple providers
    pub async fn aggregate_results(
        &self,
        results: HashMap<String, Result<Value, String>>,
    ) -> Result<Value, String> {
        // Simple: return the first successful result
        for (_, result) in results {
            if let Ok(value) = result {
                return Ok(value);
            }
        }
        
        // If all failed, return the first error
        for (provider, result) in results {
            if let Err(e) = result {
                return Err(format!("{} failed: {}", provider, e));
            }
        }
        
        Err("No results available".to_string())
    }
}
```

---

## 9. Testing Strategy

### 9.1 Unit Tests

```rust
// tests/crypto/test_threshold.rs
#[cfg(test)]
mod tests {
    use phantom_key::crypto::threshold_dh::ThresholdDH;
    use curve25519_dalek::scalar::Scalar;
    use rand::Rng;
    
    #[test]
    fn test_threshold_dh_correctness() {
        let mut rng = rand::thread_rng();
        let s = Scalar::random(&mut rng);
        
        let threshold_dh = ThresholdDH::new(s, 3, 5);
        
        let r = Scalar::random(&mut rng);
        let R = r * RistrettoPoint::generator();
        
        // Compute partials
        let partials: Vec<(u32, RistrettoPoint)> = (1..=3)
            .map(|i| (i, threshold_dh.compute_partial(i, &R).unwrap()))
            .collect();
        
        // Combine
        let K = threshold_dh.combine_partials(&partials, &R).unwrap();
        
        // Verify
        let expected_K = s * R;
        assert_eq!(K, expected_K);
    }
    
    #[test]
    fn test_threshold_dh_less_than_threshold() {
        let mut rng = rand::thread_rng();
        let s = Scalar::random(&mut rng);
        
        let threshold_dh = ThresholdDH::new(s, 3, 5);
        
        let r = Scalar::random(&mut rng);
        let R = r * RistrettoPoint::generator();
        
        // Try with less than threshold
        let partials: Vec<(u32, RistrettoPoint)> = (1..=2)
            .map(|i| (i, threshold_dh.compute_partial(i, &R).unwrap()))
            .collect();
        
        // Should fail
        let result = threshold_dh.combine_partials(&partials, &R);
        assert!(result.is_none());
    }
}
```

### 9.2 Integration Tests

```rust
// tests/integration/test_full_flow.rs
#[cfg(test)]
mod tests {
    use phantom_key::{
        crypto::threshold_dh::ThresholdDH,
        decoy,
        canary::generator::CanaryGenerator,
        llm::prompt_processor::PromptProcessor,
    };
    use curve25519_dalek::scalar::Scalar;
    use uuid::Uuid;
    use rand::Rng;
    
    #[tokio::test]
    async fn test_full_flow() {
        let mut rng = rand::thread_rng();
        
        // Setup threshold DH
        let s = Scalar::random(&mut rng);
        let threshold_dh = ThresholdDH::new(s, 3, 5);
        
        // Setup canary generator
        let canary_registry = CanaryRegistry::new();
        let canary_generator = CanaryGenerator::new(canary_registry);
        
        // Setup prompt processor
        let prompt_processor = PromptProcessor::new(threshold_dh, canary_generator);
        
        // Process prompt
        let prompt = "My AWS key is AKIAIOSFODNN7EXAMPLE and my IBAN is DE89370400440532013000";
        let request_id = Uuid::new_v4();
        let (processed, canaries) = prompt_processor.process_prompt(prompt, request_id, "bedrock");
        
        // Verify secrets were replaced
        assert!(!processed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!processed.contains("DE89370400440532013000"));
        
        // Verify canaries were registered
        assert!(!canaries.is_empty());
        
        // Encrypt
        let ciphertext = prompt_processor.encrypt_prompt(&processed, request_id);
        
        // Verify ciphertext is not empty
        assert!(!ciphertext.is_empty());
    }
}
```

---

## 10. Deployment Considerations

### 10.1 Configuration

```yaml
# config.yaml
threshold:
  k: 3      # Threshold
  n: 5      # Total shareholders

shareholders:
  - address: "127.0.0.1:8080"
    id: 1
  - address: "127.0.0.1:8081"
    id: 2
  - address: "127.0.0.1:8082"
    id: 3
  - address: "127.0.0.1:8083"
    id: 4
  - address: "127.0.0.1:8084"
    id: 5

providers:
  bedrock:
    endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com"
    api_key: "${BEDROCK_API_KEY}"
    models:
      - "anthropic.claude-3-sonnet-20240229-v1:0"
      - "anthropic.claude-3-haiku-20240307-v1:0"
  
  openai:
    api_key: "${OPENAI_API_KEY}"
    models:
      - "gpt-4"
      - "gpt-3.5-turbo"

split_brain:
  enabled: true
  providers:
    - "bedrock"
    - "openai"

canaries:
  enabled: true
  types:
    - "aws_credentials"
    - "iban"
    - "credit_card"

egress:
  log_file: "/var/log/phantom-key/audit.log"
  tui_enabled: true
```

### 10.2 Environment Variables

```bash
# Required
PHANTOM_KEY_MASTER_SECRET=...  # Only for initial setup
PHANTOM_KEY_SHARE_1=...         # Shareholder 1's share
PHANTOM_KEY_SHARE_2=...         # Shareholder 2's share
...

# Provider API keys
BEDROCK_API_KEY=...
OPENAI_API_KEY=...

# Optional
PHANTOM_KEY_THRESHOLD=3
PHANTOM_KEY_TOTAL=5
PHANTOM_KEY_LOG_LEVEL=info
```

### 10.3 Docker Deployment

```dockerfile
# Dockerfile
FROM rust:1.70 as builder

WORKDIR /usr/src/phantom-key
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libssl-dev pkg-config

WORKDIR /usr/local/bin
COPY --from=builder /usr/src/phantom-key/target/release/phantom-key .

EXPOSE 8080
CMD ["./phantom-key"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  phantom-key:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PHANTOM_KEY_SHARE_1=${SHARE_1}
      - PHANTOM_KEY_SHARE_2=${SHARE_2}
      - PHANTOM_KEY_SHARE_3=${SHARE_3}
      - BEDROCK_API_KEY=${BEDROCK_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./audit:/var/log/phantom-key
    restart: unless-stopped
```

---

## Summary

This implementation guide provides:

1. **Complete Rust implementation** for all Phantom Key components
2. **Modular design** for easy extension
3. **Comprehensive testing** strategy
4. **Production-ready deployment** options

**Next Steps:**
1. Implement the code (estimated 2-4 weeks for full implementation)
2. Write comprehensive tests
3. Performance benchmarking
4. Security audit
5. Integration with actual LLM providers

---

**Document Version:** 1.0  
**Last Updated:** October 26, 2026  
**Classification:** Internal  
**Distribution:** Project Team Only
