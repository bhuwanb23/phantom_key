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
pub use group::{GroupScalar, GroupElement, GroupError, sum_elements, sum_scalars, multi_scalar_multiply};
pub use dkg::{DKG, PartyContribution, DkgError};
pub use threshold_dh::{ThresholdDH, DLEQProof, Partial, ThresholdDhClient, ThresholdDhError};
pub use share_refresh::{ShareManager, SyncShareManager, AutoRefresh, EpochInfo, EpochKeyDerivation, ShareRefreshError};

/// Cryptography error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Group error: {0}")]
    Group(#[from] GroupError),
    #[error("DKG error: {0}")]
    Dkg(#[from] DkgError),
    #[error("Threshold DH error: {0}")]
    ThresholdDh(#[from] ThresholdDhError),
    #[error("Share refresh error: {0}")]
    ShareRefresh(#[from] ShareRefreshError),
}

/// Cryptography result type
pub type Result<T> = std::result::Result<T, Error>;
