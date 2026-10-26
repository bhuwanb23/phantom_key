//! LLM integration for Phantom Key v2
//!
//! This module contains:
//! - Provider abstraction (LLMProvider trait)
//! - Bedrock, OpenAI, and Gemini implementations
//! - Attack Lab for demonstrations
//! - Main PhantomKey system

pub mod provider;
pub mod server;
pub mod attack_lab;
pub mod phantom_key;

// Re-export main types
pub use provider::{LLMProvider, LLMResponse, Message, BedrockProvider, OpenAIProvider, GeminiProvider, ProviderFactory};
pub use server::create_router;
pub use attack_lab::AttackLab;
pub use phantom_key::PhantomKey;

/// LLM error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Server error: {0}")]
    ServerError(String),
    #[error("Attack Lab error: {0}")]
    AttackLabError(#[from] attack_lab::AttackLabError),
    #[error("Phantom Key error: {0}")]
    PhantomKeyError(String),
}
