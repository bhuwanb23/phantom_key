//! Cryptographic primitives for Phantom Key v2
//!
//! This module contains:
//! - Group operations (Scalar, GroupElement)
//! - Distributed Key Generation (DKG) with Feldman commitments
//! - Threshold Diffie-Hellman with DLEQ proofs
//! - Proactive share refresh

pub mod group;
pub mod dkg;
pub mod threshold_dh;
pub mod share_refresh;

// Re-export main types
pub use group::{GroupScalar, GroupElement};
pub use dkg::{DKG, PartyContribution};
pub use threshold_dh::{ThresholdDH, DLEQProof};
pub use share_refresh::ShareManager;

/// Cryptography error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid group operation")]
    InvalidGroupOperation,
    #[error("DKG error: {0}")]
    DkgError(String),
    #[error("Threshold DH error: {0}")]
    ThresholdDhError(String),
    #[error("Share refresh error: {0}")]
    ShareRefreshError(String),
}
