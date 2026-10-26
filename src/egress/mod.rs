//! Egress Court for Phantom Key v2
//!
//! This module contains:
//! - Signed, hash-chained ledger
//! - Secret scanner (exact vault value matching)
//! - Canary system with detection
//! - Request/response interceptor
//! - Textual TUI

pub mod ledger;
pub mod scanner;
pub mod canary;
pub mod interceptor;
pub mod tui;

// Re-export main types
pub use ledger::{Ledger, LedgerEntry, SignedLedgerEntry, ChainStatus, LedgerError};
pub use scanner::{SecretScanner, SecretMatch};
pub use canary::{Canary, CanaryRegistry};
pub use interceptor::{EgressInterceptor, OutboundRequest, InboundResponse, InterceptionError};
pub use tui::App;

/// Egress error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Ledger error: {0}")]
    LedgerError(#[from] LedgerError),
    #[error("Scanner error: {0}")]
    ScannerError(String),
    #[error("Canary error: {0}")]
    CanaryError(String),
    #[error("Interceptor error: {0}")]
    InterceptorError(#[from] InterceptionError),
    #[error("TUI error: {0}")]
    TuiError(String),
}
