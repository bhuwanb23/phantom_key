//! LLM Integration for Phantom Key v2
//!
//! This module provides:
//! - Provider abstraction (LLMProvider trait)
//! - Bedrock, OpenAI, and Gemini implementations
//! - PhantomKey main system
//! - Attack Lab for demonstrations

pub mod provider;
pub mod phantom_key;
pub mod attack_lab;
pub mod server;

// Re-export main types
pub use provider::{LLMProvider, LLMResponse, Message, ProviderFactory};
pub use phantom_key::PhantomKey;
pub use attack_lab::AttackLab;
pub use server::create_router;

/// LLM error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Phantom Key error: {0}")]
    PhantomKeyError(String),
    #[error("Attack Lab error: {0}")]
    AttackLabError(String),
}

/// LLM result type
pub type Result<T> = std::result::Result<T, Error>;
