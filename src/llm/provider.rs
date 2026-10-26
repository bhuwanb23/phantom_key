//! LLM Provider Abstraction
//!
//! Provides a common interface for Bedrock, OpenAI, and Gemini providers.

use async_trait::async_trait;
use serde_json::{Value, json};
use std::error::Error;

/// Message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    pub fn new(role: &str, content: &str) -> Self {
        Self {
            role: role.to_string(),
            content: content.to_string(),
        }
    }
}

/// LLM response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    pub content: String,
    pub model: String,
    pub usage: Value,
}

/// Trait for LLM providers
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Send a chat completion request
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<Message>,
        temperature: f32,
        max_tokens: Option<u32>,
    ) -> Result<LLMResponse, Box<dyn Error>>;

    /// Get provider name
    fn name(&self) -> &str;

    /// Get provider type
    fn provider_type(&self) -> ProviderType;
}

/// Provider type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderType {
    Bedrock,
    OpenAI,
    Gemini,
}

/// Provider factory
pub struct ProviderFactory;

impl ProviderFactory {
    /// Create a Bedrock provider
    pub fn create_bedrock(endpoint: String, api_key: String) -> Box<dyn LLMProvider> {
        Box::new(BedrockProvider::new(endpoint, api_key))
    }

    /// Create an OpenAI provider
    pub fn create_openai(api_key: String) -> Box<dyn LLMProvider> {
        Box::new(OpenAIProvider::new(api_key))
    }

    /// Create a Gemini provider
    pub fn create_gemini(api_key: String) -> Box<dyn LLMProvider> {
        Box::new(GeminiProvider::new(api_key))
    }
}

/// Bedrock provider
pub struct BedrockProvider {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

impl BedrockProvider {
    pub fn new(endpoint: String, api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint,
            api_key,
        }
    }
}

#[async_trait]
impl LLMProvider for BedrockProvider {
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<Message>,
        temperature: f32,
        max_tokens: Option<u32>,
    ) -> Result<LLMResponse, Box<dyn Error>> {
        let bedrock_messages: Vec<Value> = messages
            .into_iter()
            .map(|m| json!({
                "role": m.role,
                "content": [{"text": m.content}],
            }))
            .collect();

        let request = json!({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens.unwrap_or(4096),
            "messages": bedrock_messages,
            "temperature": temperature,
        });

        let url = format!(
            "{}/model/{}/invoke",
            self.endpoint.trim_end_matches('/'),
            model
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Bedrock API error: {} - {}",
                status, body
            )
            .into());
        }

        let response_json: Value = response.json().await?;

        let content = response_json["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let usage = response_json["usage"].clone();

        Ok(LLMResponse {
            content,
            model: model.to_string(),
            usage,
        })
    }

    fn name(&self) -> &str {
        "bedrock"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Bedrock
    }
}

/// OpenAI provider
pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            base_url: "https://api.openai.com/v1".to_string(),
        }
    }

    pub fn with_base_url(api_key: String, base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            base_url,
        }
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<Message>,
        temperature: f32,
        max_tokens: Option<u32>,
    ) -> Result<LLMResponse, Box<dyn Error>> {
        let openai_messages: Vec<Value> = messages
            .into_iter()
            .map(|m| json!({
                "role": m.role,
                "content": m.content,
            }))
            .collect();

        let request = json!({
            "model": model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens.unwrap_or(4096),
        });

        let url = format!("{}/chat/completions", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "OpenAI API error: {} - {}",
                status, body
            )
            .into());
        }

        let response_json: Value = response.json().await?;

        let content = response_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let usage = response_json["usage"].clone();

        Ok(LLMResponse {
            content,
            model: model.to_string(),
            usage,
        })
    }

    fn name(&self) -> &str {
        "openai"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::OpenAI
    }
}

/// Gemini provider
pub struct GeminiProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl GeminiProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
        }
    }

    pub fn with_base_url(api_key: String, base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            base_url,
        }
    }
}

#[async_trait]
impl LLMProvider for GeminiProvider {
    async fn chat_completion(
        &self,
        model: &str,
        messages: Vec<Message>,
        temperature: f32,
        max_tokens: Option<u32>,
    ) -> Result<LLMResponse, Box<dyn Error>> {
        let gemini_messages: Vec<Value> = messages
            .into_iter()
            .map(|m| json!({
                "role": m.role,
                "parts": [{"text": m.content}],
            }))
            .collect();

        let request = json!({
            "model": model,
            "messages": gemini_messages,
            "temperature": temperature,
            "maxOutputTokens": max_tokens.unwrap_or(4096),
        });

        let url = format!(
            "{}/models/{}:generateContent",
            self.base_url,
            model
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", &self.api_key)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Gemini API error: {} - {}",
                status, body
            )
            .into());
        }

        let response_json: Value = response.json().await?;

        let content = response_json["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let usage = response_json["usageMetadata"].clone();

        Ok(LLMResponse {
            content,
            model: model.to_string(),
            usage,
        })
    }

    fn name(&self) -> &str {
        "gemini"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Gemini
    }
}
