//! Textual User Interface for Egress Court
//!
//! Provides real-time monitoring of:
//! - Chat/LLM conversation
//! - Egress ledger with chain status
//! - Shareholder status
//! - Vault entries

pub mod app;
pub mod panels;

pub use app::App;
pub use panels::*;
