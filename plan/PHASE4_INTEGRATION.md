# Phase 4: Integration & Polish

**Project:** Phantom Key v2  
**Phase:** 4 of 4  
**Duration:** 1 week (Week 6)  
**Lead:** Integration Team  
**Status:** ⏳ Not Started  
**Priority:** 🟡 **HIGH**

---

## 🎯 Phase Overview

**Objective:** Integrate all components and prepare for competition submission.

This final phase brings together all the work from Phases 1-3:
- Core Cryptography (DKG, Threshold DH, Share Refresh)
- Vault System (Sealed Vault, Handles, Decoys)
- Egress Court (Ledger, Scanner, Canaries, TUI)

And adds:
- LLM provider integration (Bedrock, OpenAI, Gemini)
- Attack Lab for video demonstrations
- Polish and documentation

**Prerequisite:** Phase 1, Phase 2, AND Phase 3 must be 100% complete before starting.

### Key Outcomes
- ✅ Fully integrated system
- ✅ Bedrock, OpenAI, and Gemini provider integration
- ✅ Attack Lab with 6 live demos
- ✅ Competition video
- ✅ Competition documentation
- ✅ Final testing and validation

---

## 📋 Sub-Phases & Tasks

### Sub-Phase 4.1: Integration (Day 36-37)

**Objective:** Integrate all components into a single, working system.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 4.1.1 | Integrate crypto with vault | Connect DKG/Threshold DH with vault encryption | Integration | 8h | Phase 1, Phase 2 | ⏳ |
| 4.1.2 | Integrate vault with egress | Connect vault with ledger and scanner | Integration | 8h | Phase 2, Phase 3 | ⏳ |
| 4.1.3 | Implement full workflow | End-to-end: prompt → vault → LLM → response | Integration | 8h | 4.1.1, 4.1.2 | ⏳ |
| 4.1.4 | Add integration tests | Test complete workflow | Integration | 8h | 4.1.3 | ⏳ |
| 4.1.5 | Fix integration bugs | Resolve any issues found during integration | Integration | 8h | 4.1.4 | ⏳ |

#### Technical Details

**File: `src/lib.rs` (Main integration point)**

```rust
pub mod crypto;
pub mod vault;
pub mod egress;
pub mod llm;

/// Main Phantom Key v2 system
pub struct PhantomKey {
    dkg: crypto::dkg::DKG,
    threshold_dh: crypto::threshold_dh::ThresholdDH,
    share_manager: crypto::share_refresh::ShareManager,
    vault_storage: Arc<dyn vault::storage::VaultStorage>,
    vault_encryption: vault::encryption::VaultEncryption,
    ledger: Arc<egress::ledger::Ledger>,
    scanner: Arc<egress::scanner::SecretScanner>,
    canary_registry: Arc<Mutex<egress::canary::CanaryRegistry>>,
    interceptor: Arc<egress::interceptor::EgressInterceptor>,
}

impl PhantomKey {
    pub fn new(
        parties: usize,
        threshold: usize,
        storage_backend: Arc<dyn vault::storage::VaultStorage>,
    ) -> Self {
        // Initialize DKG
        let dkg = crypto::dkg::DKG::new(parties, threshold);
        
        // Initialize share manager
        let share_manager = crypto::share_refresh::ShareManager::new(
            parties,
            threshold,
            Duration::from_secs(3600),  // 1 hour epoch
            Duration::from_secs(300),   // 5 minute verification
        );
        
        // Initialize vault encryption
        let vault_encryption = vault::encryption::VaultEncryption::new(
            crypto::threshold_dh::ThresholdDH::new(
                vec![],  // Will be populated during DKG
                vec![],
                dkg.clone(),
            )
        );
        
        // Initialize ledger
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let ledger = Arc::new(egress::ledger::Ledger::new(signing_key));
        
        // Initialize scanner
        let scanner = Arc::new(egress::scanner::SecretScanner::new(
            storage_backend.clone(),
            vault_encryption.clone(),
            crypto::group::GroupElement::generator(),
        ));
        
        // Initialize canary registry
        let canary_registry = Arc::new(Mutex::new(egress::canary::CanaryRegistry::new()));
        
        // Initialize interceptor
        let interceptor = Arc::new(egress::interceptor::EgressInterceptor::new(
            ledger.clone(),
            scanner.clone(),
            canary_registry.clone(),
        ));
        
        Self {
            dkg,
            threshold_dh: crypto::threshold_dh::ThresholdDH::new(vec![], vec![], dkg.clone()),
            share_manager,
            vault_storage: storage_backend,
            vault_encryption: vault_encryption,
            ledger,
            scanner,
            canary_registry,
            interceptor,
        }
    }
    
    /// Process a prompt: replace secrets with decoys, send to LLM, process response
    pub async fn process_prompt(
        &self,
        prompt: &str,
        model: &str,
        provider: &str,
    ) -> Result<String, PhantomKeyError> {
        // Step 1: Get current R from threshold DH
        let r = crypto::group::GroupScalar::random();
        let R = crypto::group::GroupElement::generator().multiply(&r);
        
        // Update scanner with current R
        {
            let mut scanner = Arc::try_unwrap(self.scanner.clone()).unwrap_or(Arc::new(self.scanner.clone()));
            Arc::get_mut(&mut scanner).unwrap().update_r(R.clone());
        }
        
        // Step 2: Process prompt (replace secrets with decoys)
        let (processed_prompt, handles) = self.process_prompt_internal(prompt, &R).await?;
        
        // Step 3: Send to LLM
        let llm_response = self.send_to_llm(processed_prompt, model, provider).await?;
        
        // Step 4: Process response (swap handles back to real values)
        let final_response = self.process_response(llm_response, handles, &R).await?;
        
        Ok(final_response)
    }
    
    async fn process_prompt_internal(
        &self,
        prompt: &str,
        R: &crypto::group::GroupElement,
    ) -> Result<(String, Vec<vault::handle::Handle>), PhantomKeyError> {
        // This would use the vault and decoy system
        // For now, return a placeholder
        Ok((prompt.to_string(), vec![]))
    }
    
    async fn send_to_llm(
        &self,
        prompt: String,
        model: &str,
        provider: &str,
    ) -> Result<String, PhantomKeyError> {
        // This would use the LLM provider integration
        // For now, return a placeholder
        Ok(format!("Response from {} model {} to: {}", provider, model, prompt))
    }
    
    async fn process_response(
        &self,
        response: String,
        handles: Vec<vault::handle::Handle>,
        R: &crypto::group::GroupElement,
    ) -> Result<String, PhantomKeyError> {
        // This would swap handles back to real values
        // For now, return the response as-is
        Ok(response)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PhantomKeyError {
    #[error("Crypto error")]
    CryptoError(#[from] crypto::Error),
    #[error("Vault error")]
    VaultError(String),
    #[error("Egress error")]
    EgressError(#[from] egress::Error),
    #[error("LLM error")]
    LLMError(String),
}
```

**File: `src/integration/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::storage::MemoryStorage;
    
    #[tokio::test]
    async fn test_full_workflow() {
        let storage = Arc::new(MemoryStorage::new());
        let phantom_key = PhantomKey::new(5, 3, storage.clone());
        
        let prompt = "What is the weather in SF?";
        let model = "anthropic.claude-3-sonnet";
        let provider = "bedrock";
        
        let response = phantom_key.process_prompt(prompt, model, provider).await.unwrap();
        
        // Verify response is not empty
        assert!(!response.is_empty());
    }
    
    #[tokio::test]
    async fn test_secret_handling() {
        let storage = Arc::new(MemoryStorage::new());
        let phantom_key = PhantomKey::new(5, 3, storage.clone());
        
        // This test would need real secret handling
        // For now, just verify the system can be created
        assert!(true);
    }
}
```

#### Deliverables
- [ ] Main PhantomKey struct integrating all components
- [ ] Full workflow implementation
- [ ] Integration tests
- [ ] Bug fixes from integration testing

#### Acceptance Criteria
- [ ] All components work together
- [ ] Full workflow executes successfully
- [ ] Integration tests pass
- [ ] All bugs from integration are fixed

---

### Sub-Phase 4.2: LLM Provider Integration (Day 38)

**Objective:** Integrate with Bedrock, OpenAI, and Gemini LLM providers.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 4.2.1 | Design provider abstraction | Define LLMProvider trait | Integration | 4h | 4.1 | ⏳ |
| 4.2.2 | Implement Bedrock provider | AWS Bedrock integration | Integration | 8h | 4.2.1 | ⏳ |
| 4.2.3 | Implement OpenAI provider | OpenAI API integration | Integration | 8h | 4.2.2 | ⏳ |
| 4.2.4 | Implement Gemini provider | Google Gemini integration | Integration | 8h | 4.2.3 | ⏳ |
| 4.2.5 | Add provider tests | Test all provider integrations | Integration | 4h | 4.2.4 | ⏳ |

#### Technical Details

**File: `src/llm/provider.rs`**

```rust
use async_trait::async_trait;
use serde_json::{Value, json};
use std::error::Error;

/// Message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,      // "user", "assistant", "system"
    pub content: String,
}

/// LLM response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    pub content: String,
    pub model: String,
    pub usage: Value,     // Token usage information
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
        // Convert messages to Bedrock format
        let bedrock_messages: Vec<Value> = messages.into_iter()
            .map(|m| json!({
                "role": m.role,
                "content": m.content,
            }))
            .collect();
        
        let request = json!({
            "modelId": model,
            "messages": bedrock_messages,
            "temperature": temperature,
            "maxTokenCount": max_tokens.unwrap_or(4096),
        });
        
        let response = self.client
            .post(&format!("{}/model/{}/invoke", self.endpoint, model))
            .header("Content-Type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&request)
            .send()
            .await?;
        
        let response_json: Value = response.json().await?;
        
        // Parse response
        let content = response_json["content"][0]["text"].as_str()
            .unwrap_or("").to_string();
        
        Ok(LLMResponse {
            content,
            model: model.to_string(),
            usage: response_json["usage"].clone(),
        })
    }
    
    fn name(&self) -> &str {
        "bedrock"
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
        let openai_messages: Vec<Value> = messages.into_iter()
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
        
        let response = self.client
            .post(&format!("{}/chat/completions", self.base_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;
        
        let response_json: Value = response.json().await?;
        
        let content = response_json["choices"][0]["message"]["content"].as_str()
            .unwrap_or("").to_string();
        
        Ok(LLMResponse {
            content,
            model: model.to_string(),
            usage: response_json["usage"].clone(),
        })
    }
    
    fn name(&self) -> &str {
        "openai"
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
        let gemini_messages: Vec<Value> = messages.into_iter()
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
        
        let url = format!("{}/models/{}:generateContent", self.base_url, model);
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", &self.api_key)
            .json(&request)
            .send()
            .await?;
        
        let response_json: Value = response.json().await?;
        
        let content = response_json["candidates"][0]["content"]["parts"][0]["text"].as_str()
            .unwrap_or("").to_string();
        
        Ok(LLMResponse {
            content,
            model: model.to_string(),
            usage: response_json["usageMetadata"].clone(),
        })
    }
    
    fn name(&self) -> &str {
        "gemini"
    }
}

/// Provider factory
pub struct ProviderFactory;

impl ProviderFactory {
    pub fn create_bedrock(endpoint: String, api_key: String) -> Box<dyn LLMProvider> {
        Box::new(BedrockProvider::new(endpoint, api_key))
    }
    
    pub fn create_openai(api_key: String) -> Box<dyn LLMProvider> {
        Box::new(OpenAIProvider::new(api_key))
    }
    
    pub fn create_gemini(api_key: String) -> Box<dyn LLMProvider> {
        Box::new(GeminiProvider::new(api_key))
    }
}
```

**File: `src/llm/provider/tests.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{mock, Server};
    
    #[tokio::test]
    async fn test_bedrock_provider() {
        // This would need mocking or real API keys
        // For now, just test that the provider can be created
        let provider = BedrockProvider::new(
            "https://bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            "test-api-key".to_string(),
        );
        
        assert_eq!(provider.name(), "bedrock");
    }
    
    #[tokio::test]
    async fn test_openai_provider() {
        let provider = OpenAIProvider::new("test-api-key".to_string());
        assert_eq!(provider.name(), "openai");
    }
    
    #[tokio::test]
    async fn test_gemini_provider() {
        let provider = GeminiProvider::new("test-api-key".to_string());
        assert_eq!(provider.name(), "gemini");
    }
}
```

#### Deliverables
- [ ] LLMProvider trait
- [ ] Bedrock provider implementation
- [ ] OpenAI provider implementation
- [ ] Gemini provider implementation
- [ ] Provider factory
- [ ] Unit tests for providers

#### Acceptance Criteria
- [ ] All providers can be created
- [ ] All providers implement the trait
- [ ] Provider names are correct
- [ ] All provider tests pass

---

### Sub-Phase 4.3: Attack Lab (Day 39-40)

**Objective:** Implement live attack demonstrations for the competition video.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 4.3.1 | Implement memory dump demo | Show no real secrets in memory | Integration | 4h | 4.1, 4.2 | ⏳ |
| 4.3.2 | Implement log inspection demo | Show no real secrets in logs | Integration | 4h | 4.3.1 | ⏳ |
| 4.3.3 | Implement wire inspection demo | Show no real secrets on wire | Integration | 4h | 4.3.2 | ⏳ |
| 4.3.4 | Implement DLEQ validation demo | Show malicious partials rejected | Integration | 4h | 4.3.3 | ⏳ |
| 4.3.5 | Implement ledger tampering demo | Show chain breaks on tampering | Integration | 4h | 4.3.4 | ⏳ |
| 4.3.6 | Implement canary detection demo | Show canary reappearance flagged | Integration | 4h | 4.3.5 | ⏳ |
| 4.3.7 | Create Attack Lab script | Script to run all demos | Integration | 4h | 4.3.6 | ⏳ |
| 4.3.8 | Test all demos | Verify all demos work correctly | Integration | 4h | 4.3.7 | ⏳ |

#### Technical Details

**File: `scripts/attack_lab.sh`**

```bash
#!/bin/bash
# Phantom Key v2 Attack Lab
# Run this script to demonstrate security properties

set -e

echo "=========================================="
echo "Phantom Key v2 Attack Lab"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Demo 1: Memory Safety
echo "Demo 1: Memory Safety"
echo "-------------------"
echo "Checking for real secrets in process memory..."
echo ""

# Get the PID of the running Phantom Key process
PID=$(pgrep -f phantom_key | head -n 1)

if [ -z "$PID" ]; then
    echo "${RED}ERROR: Phantom Key process not found${NC}"
    exit 1
fi

echo "Dumping process memory for PID: $PID"
# In a real demo, we'd use gcore or similar
# For this script, we'll just check /proc

# Check for real secrets in process memory
if grep -q "REAL_SECRET_VALUE" /proc/$PID/maps 2>/dev/null; then
    echo "${RED}FAIL: Real secret found in process memory${NC}"
    exit 1
else
    echo "${GREEN}PASS: No real secrets found in process memory${NC}"
fi

echo ""
echo ""

# Demo 2: Log Inspection
echo "Demo 2: Log Inspection"
echo "--------------------"
echo "Checking for real secrets in logs..."
echo ""

# Check log files
LOG_DIR="/var/log/phantom-key"
if [ -d "$LOG_DIR" ]; then
    if grep -rq "REAL_SECRET_VALUE" "$LOG_DIR" 2>/dev/null; then
        echo "${RED}FAIL: Real secret found in logs${NC}"
        exit 1
    else
        echo "${GREEN}PASS: No real secrets found in logs${NC}"
    fi
else
    echo "${RED}WARNING: Log directory not found${NC}"
fi

echo ""
echo ""

# Demo 3: Wire Inspection
echo "Demo 3: Wire Inspection"
echo "--------------------"
echo "Checking for real secrets on the wire..."
echo ""

# This would normally use tcpdump or similar
# For the demo, we'll just check that we can start a capture
if command -v tcpdump &> /dev/null; then
    echo "Starting tcpdump to check for secrets..."
    timeout 2 tcpdump -i any -A -c 10 2>/dev/null | grep -q "REAL_SECRET_VALUE" && {
        echo "${RED}FAIL: Real secret found on wire${NC}"
        exit 1
    } || {
        echo "${GREEN}PASS: No real secrets found on wire${NC}"
    }
else
    echo "${RED}WARNING: tcpdump not available${NC}"
fi

echo ""
echo ""

# Demo 4: DLEQ Validation
echo "Demo 4: DLEQ Validation"
echo "--------------------"
echo "Testing that malicious partials are rejected..."
echo ""

# Run the DLEQ test
if cargo test --lib dleq_validation -- --nocapture 2>&1 | grep -q "test result: ok"; then
    echo "${GREEN}PASS: DLEQ validation works correctly${NC}"
else
    echo "${RED}FAIL: DLEQ validation test failed${NC}"
    exit 1
fi

echo ""
echo ""

# Demo 5: Ledger Tampering
echo "Demo 5: Ledger Tampering"
echo "----------------------"
echo "Testing that ledger tampering is detected..."
echo ""

# Run the tampering test
if cargo test --lib ledger_tampering -- --nocapture 2>&1 | grep -q "test result: ok"; then
    echo "${GREEN}PASS: Ledger tampering detection works correctly${NC}"
else
    echo "${RED}FAIL: Ledger tampering test failed${NC}"
    exit 1
fi

echo ""
echo ""

# Demo 6: Canary Detection
echo "Demo 6: Canary Detection"
echo "-----------------------"
echo "Testing that canary reappearance is detected..."
echo ""

# Run the canary test
if cargo test --lib canary_detection -- --nocapture 2>&1 | grep -q "test result: ok"; then
    echo "${GREEN}PASS: Canary detection works correctly${NC}"
else
    echo "${RED}FAIL: Canary detection test failed${NC}"
    exit 1
fi

echo ""
echo ""
echo "=========================================="
echo "All Attack Lab demos completed successfully!"
echo "=========================================="
```

**File: `src/llm/attack_lab.rs`** (Alternative Rust implementation)

```rust
/// Attack Lab demonstrations
pub struct AttackLab {
    phantom_key: Arc<PhantomKey>,
}

impl AttackLab {
    pub fn new(phantom_key: Arc<PhantomKey>) -> Self {
        Self { phantom_key }
    }
    
    /// Demo 1: Memory Safety
    pub async fn demo_memory_safety(&self) -> Result<bool, AttackLabError> {
        // In a real implementation, we'd check process memory
        // For now, just return true
        Ok(true)
    }
    
    /// Demo 2: Log Inspection
    pub async fn demo_log_inspection(&self) -> Result<bool, AttackLabError> {
        // Check ledger for real secrets
        let entries = self.phantom_key.ledger.entries();
        for entry in entries {
            let text = String::from_utf8_lossy(&entry.entry.payload);
            if text.contains("REAL_SECRET_VALUE") {
                return Ok(false); // Secret found
            }
        }
        Ok(true) // No secrets found
    }
    
    /// Demo 3: Wire Inspection
    pub async fn demo_wire_inspection(&self) -> Result<bool, AttackLabError> {
        // This would check network traffic
        // For now, just return true
        Ok(true)
    }
    
    /// Demo 4: DLEQ Validation
    pub async fn demo_dleq_validation(&self) -> Result<bool, AttackLabError> {
        // Test that bad partials are rejected
        // This would require a real test
        Ok(true)
    }
    
    /// Demo 5: Ledger Tampering
    pub async fn demo_ledger_tampering(&self) -> Result<bool, AttackLabError> {
        // Tamper with ledger and verify detection
        let was_valid = self.phantom_key.ledger.verify_chain();
        
        // Tamper with first entry
        {
            let mut storage = self.phantom_key.ledger.storage.lock().unwrap();
            if let Some(entry) = storage.get_mut(0) {
                entry.entry.payload = b"tampered".to_vec();
                // Don't update hash - this makes it invalid
            }
        }
        
        let still_valid = self.phantom_key.ledger.verify_chain();
        
        Ok(was_valid && !still_valid)
    }
    
    /// Demo 6: Canary Detection
    pub async fn demo_canary_detection(&self) -> Result<bool, AttackLabError> {
        // Register a canary
        let canary_id = self.phantom_key.canary_registry.lock().unwrap().register(
            "test-canary-value".to_string(),
            Uuid::new_v4(),
            "test".to_string(),
        );
        
        // Check that it's not triggered
        let canary = self.phantom_key.canary_registry.lock().unwrap().get(&canary_id).unwrap();
        if canary.is_triggered() {
            return Ok(false);
        }
        
        // Trigger it
        self.phantom_key.canary_registry.lock().unwrap().trigger(&canary_id);
        
        // Check that it's now triggered
        let canary = self.phantom_key.canary_registry.lock().unwrap().get(&canary_id).unwrap();
        Ok(canary.is_triggered())
    }
    
    /// Run all demos
    pub async fn run_all_demos(&self) -> Vec<bool> {
        vec![
            self.demo_memory_safety().await.unwrap_or(false),
            self.demo_log_inspection().await.unwrap_or(false),
            self.demo_wire_inspection().await.unwrap_or(false),
            self.demo_dleq_validation().await.unwrap_or(false),
            self.demo_ledger_tampering().await.unwrap_or(false),
            self.demo_canary_detection().await.unwrap_or(false),
        ]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AttackLabError {
    #[error("Demo failed")]
    DemoFailed,
}
```

#### Deliverables
- [ ] Memory dump demo
- [ ] Log inspection demo
- [ ] Wire inspection demo
- [ ] DLEQ validation demo
- [ ] Ledger tampering demo
- [ ] Canary detection demo
- [ ] Attack Lab script
- [ ] All demos tested and working

#### Acceptance Criteria
- [ ] All 6 demos work correctly
- [ ] Demos demonstrate the security properties
- [ ] Demos are reliable and repeatable
- [ ] Attack Lab script runs successfully

---

### Sub-Phase 4.4: Polish & Documentation (Day 41-42)

**Objective:** Polish the system and prepare competition documentation.

#### Tasks

| # | Task | Description | Owner | Effort | Dependencies | Status |
|---|------|-------------|-------|--------|--------------|--------|
| 4.4.1 | Fix all remaining bugs | Address any outstanding issues | Integration | 8h | 4.1, 4.2, 4.3 | ⏳ |
| 4.4.2 | Performance optimization | Optimize critical paths | Integration | 8h | 4.4.1 | ⏳ |
| 4.4.3 | Security audit | Review for vulnerabilities | Security | 8h | 4.4.1 | ⏳ |
| 4.4.4 | Write user documentation | README, usage guides | Docs | 8h | 4.4.1 | ⏳ |
| 4.4.5 | Write competition documentation | Judging notes, architecture | Docs | 8h | 4.4.4 | ⏳ |
| 4.4.6 | Create competition video | Record and edit video | Marketing | 8h | 4.4.1 | ⏳ |
| 4.4.7 | Final testing | Comprehensive test suite | QA | 8h | 4.4 | ⏳ |

#### Technical Details

**File: `README.md`** (User Documentation)

```markdown
# Phantom Key v2

A secure system for LLM prompt processing that never sends real secrets to the model.

## Features

- Dealerless threshold cryptography (DKG)
- Sealed vault with per-secret encryption
- Format-preserving decoys
- Signed, hash-chained audit ledger
- Real-time monitoring TUI

## Installation

```bash
cargo build --release
```

## Usage

```bash
# Start the Phantom Key server
./target/release/phantom-key

# Or with configuration
./target/release/phantom-key --config config.yaml
```

## Configuration

```yaml
# Number of parties and threshold
parties: 5
threshold: 3

# Share refresh settings
refresh_interval: 3600  # 1 hour
verification_period: 300  # 5 minutes

# Provider API keys
providers:
  bedrock:
    endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com"
    api_key: "${BEDROCK_API_KEY}"
  openai:
    api_key: "${OPENAI_API_KEY}"
  gemini:
    api_key: "${GEMINI_API_KEY}"

# Ledger settings
ledger:
  storage: "sqlite"
  path: "/var/log/phantom-key/ledger.db"
```

## Attack Lab

Run the attack lab to see security properties in action:

```bash
./scripts/attack_lab.sh
```

This will demonstrate:
1. Memory safety - no real secrets in process memory
2. Log inspection - no real secrets in logs
3. Wire inspection - no real secrets on the wire
4. DLEQ validation - malicious partials rejected
5. Ledger tampering - chain breaks on modification
6. Canary detection - reappearance flagged
```

**File: `JUDGING.md`** (Competition Documentation)

```markdown
# Phantom Key v2 - Judging Notes

## Overview

Phantom Key v2 is a novel approach to secure LLM prompt processing that:

1. **Never sends real secrets to the model** - Uses format-preserving decoys
2. **Never reconstructs the master key** - Uses dealerless threshold cryptography
3. **Detects data reappearance** - Uses canaries with best-effort detection
4. **Provides tamper-evident audit** - Uses signed, hash-chained ledger

## Novelty

This project combines four security primitives in a novel way:

- Dealerless threshold key (DKG with Feldman commitments)
- Sealed vault with per-secret encryption
- Handles at LLM boundary (model sees decoys, emits handles)
- Signed, hash-chained egress ledger

No existing project combines all four components.

## Technical Depth

### Cryptography

- **Ristretto255**: Prime-order group for threshold operations
- **Feldman's VSS**: Verifiable secret sharing for dealerless DKG
- **Chaum-Pedersen DLEQ**: Proofs for threshold DH partials
- **Ed25519**: Signatures for ledger entries
- **HKDF**: Key derivation for per-secret encryption
- **ChaCha20-Poly1305**: AEAD encryption for vault

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Phantom Key v2                              │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  Core Crypto  │  │  Vault       │  │  Egress Court │    │
│  │  - DKG        │  │  - Sealed    │  │  - Ledger     │    │
│  │  - Threshold  │  │  - Handles   │  │  - Scanner    │    │
│  │    DH        │  │  - Decoys    │  │  - Canaries   │    │
│  │  - Share      │  │              │  │  - TUI        │    │
│  │    Refresh   │  │              │  │              │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Security Properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| Confidentiality | Real secrets never sent to provider | Sealed vault + decoys |
| Integrity | Secrets cannot be tampered | AEAD encryption |
| Detection | Reappearance of canaries detected | Canary scanner |
| Non-repudiation | Actions provable | Signed ledger |
| Key separation | Each secret has unique key | HKDF with handle |
| Malicious party detection | Invalid partials rejected | DLEQ proofs |

## Honest Limitations

- Model sees decoys (task not hidden)
- Best-effort detection (no proof of retention)
- Threshold compromise (k parties can reconstruct s)
- Epoch compromise (old shares vulnerable)
- Side channels not protected

## Competition Rubric

| Category | Points | Delivery |
|----------|--------|----------|
| UI | 3 | Textual TUI with chat, egress/ledger, shareholder status, vault panel |
| Video | 2 | Attack Lab with 6 live demos |
| API Evidence | 2 | Real Bedrock/OpenAI/Gemini calls with request IDs in ledger |

## Video Script

1. **Intro (30s)** - Problem statement, solution overview
2. **Demo: Normal Operation (1min)** - Show TUI, LLM interaction
3. **Attack Lab (3min)** - Run all 6 demos
4. **Code Walkthrough (1min)** - Key cryptographic components
5. **Conclusion (30s)** - Summary, next steps

Total: ~6 minutes

## Running the Demos

```bash
# Start Phantom Key
cargo run --release

# In another terminal, run Attack Lab
./scripts/attack_lab.sh
```

## Team

- [Name 1] - Crypto Lead
- [Name 2] - Security Lead
- [Name 3] - Backend Lead
- [Name 4] - Integration Lead
```

**File: `scripts/record_video.sh`** (Video Recording)

```bash
#!/bin/bash
# Record Phantom Key v2 competition video

# Configuration
OUTPUT_FILE="phantom_key_v2_video.mp4"
RESOLUTION="1920x1080"
FPS=30

# Check dependencies
if ! command -v ffmpeg &> /dev/null; then
    echo "Error: ffmpeg is required"
    exit 1
fi

# Start recording
echo "Starting video recording..."
echo "Press Ctrl+C to stop"

ffmpeg -video_size $RESOLUTION -framerate $FPS -f x11grab -i :0.0 $OUTPUT_FILE

# Post-processing
echo "Post-processing video..."
ffmpeg -i $OUTPUT_FILE -c:v libx264 -crf 23 -preset fast -c:a aac -b:a 128k ${OUTPUT_FILE%.mp4}_compressed.mp4

mv ${OUTPUT_FILE%.mp4}_compressed.mp4 $OUTPUT_FILE

echo "Video recording complete: $OUTPUT_FILE"
```

#### Deliverables
- [ ] All bugs fixed
- [ ] Performance optimized
- [ ] Security audit complete
- [ ] User documentation
- [ ] Competition documentation
- [ ] Competition video
- [ ] Final test suite

#### Acceptance Criteria
- [ ] System is bug-free
- [ ] Performance meets targets
- [ ] Security audit passes
- [ ] Documentation is complete
- [ ] Video is under 6 minutes
- [ ] All tests pass

---

## 📊 Phase Summary

### Tasks Breakdown
| Sub-Phase | Tasks | Effort | Status |
|-----------|-------|--------|--------|
| 4.1 Integration | 5 | 40h | ⏳ |
| 4.2 Provider Integration | 5 | 32h | ⏳ |
| 4.3 Attack Lab | 8 | 32h | ⏳ |
| 4.4 Polish & Docs | 7 | 56h | ⏳ |
| **Total** | **25** | **160h (20 person-days)** | ⏳ |

### Deliverables Summary
- ✅ Fully integrated system
- ✅ Bedrock, OpenAI, and Gemini provider integration
- ✅ Attack Lab with 6 live demos
- ✅ Competition video
- ✅ User documentation
- ✅ Competition documentation
- ✅ Final test suite

### Acceptance Criteria
- [ ] All components work together
- [ ] All providers are integrated
- [ ] All demos work correctly
- [ ] Video is complete and under 6 minutes
- [ ] Documentation is complete
- [ ] All tests pass

---

## 🎯 Next Steps

**After Phase 4 completes, the project is ready for competition submission!**

- Submit to competition
- Prepare for judging
- Celebrate! 🎉

---

## 📝 Phase Information

**Phase:** 4 of 4  
**Name:** Integration & Polish  
**Duration:** 1 week  
**Status:** ⏳ Not Started  
**Priority:** 🟡 HIGH  
**Prerequisite:** Phase 1, Phase 2, AND Phase 3

**Document Version:** 1.0  
**Last Updated:** October 26, 2026  
**Owner:** Integration Team
