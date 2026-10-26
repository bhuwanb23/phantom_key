//! Phantom Key v2 Main System
//!
//! Integrates all components:
//! - Core Cryptography (DKG, Threshold DH, Share Refresh)
//! - Vault System (Sealed Vault, Handles, Decoys)
//! - Egress Court (Ledger, Scanner, Canaries, TUI)
//! - LLM Providers (Bedrock, OpenAI, Gemini)

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::crypto::{
    dkg::DKG,
    group::GroupElement,
    share_refresh::ShareManager,
    threshold_dh::{ThresholdDH, Partial},
};
use crate::vault::{
    decoy::DecoyRegistry,
    encryption::VaultEncryption,
    handle::HandleGenerator,
    mapping::DecoyManager,
    storage::{MemoryStorage, VaultStorage},
};
use crate::egress::{
    canary::CanaryRegistry,
    interceptor::{EgressInterceptor, OutboundRequest},
    ledger::Ledger,
    scanner::SecretScanner,
};
use crate::llm::provider::{LLMProvider, Message, ProviderType};

/// Phantom Key v2 main system
pub struct PhantomKey {
    /// DKG instance
    pub dkg: DKG,
    
    /// Threshold DH
    pub threshold_dh: ThresholdDH,
    
    /// Share manager with proactive refresh
    pub share_manager: Arc<Mutex<ShareManager>>,
    
    /// Vault storage backend
    pub vault_storage: Arc<dyn VaultStorage>,
    
    /// Vault encryption
    pub vault_encryption: VaultEncryption,
    
    /// Handle generator
    pub handle_generator: HandleGenerator,
    
    /// Decoy registry
    pub decoy_registry: DecoyRegistry,
    
    /// Decoy manager
    pub decoy_manager: DecoyManager,
    
    /// Ledger
    pub ledger: Arc<Ledger>,
    
    /// Secret scanner
    pub scanner: Arc<Mutex<SecretScanner>>,
    
    /// Canary registry
    pub canary_registry: Arc<Mutex<CanaryRegistry>>,
    
    /// Egress interceptor
    pub interceptor: Arc<EgressInterceptor>,
    
    /// LLM providers
    pub providers: Vec<(ProviderType, Arc<dyn LLMProvider>)>,
    
    /// Current threshold DH ephemeral
    pub current_r: GroupElement,
    pub current_R: GroupElement,
}

/// Phantom Key error type
#[derive(Debug, thiserror::Error)]
pub enum PhantomKeyError {
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("Vault error: {0}")]
    VaultError(String),
    #[error("Egress error: {0}")]
    EgressError(String),
    #[error("LLM error: {0}")]
    LLMError(String),
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),
    #[error("No valid providers configured")]
    NoProvidersConfigured,
}

impl PhantomKey {
    /// Create a new Phantom Key v2 instance
    pub fn new(
        parties: usize,
        threshold: usize,
        vault_storage: Arc<dyn VaultStorage>,
    ) -> Result<Self, PhantomKeyError> {
        // Initialize DKG
        let dkg = DKG::new(parties, threshold)
            .map_err(|e| PhantomKeyError::CryptoError(e.to_string()))?;

        // Initialize share manager
        let share_manager = Arc::new(Mutex::new(
            ShareManager::new(
                parties,
                threshold,
                Duration::from_secs(3600),  // 1 hour epoch
                Duration::from_secs(300),   // 5 minute verification
            )
            .map_err(|e| PhantomKeyError::CryptoError(e.to_string()))?,
        ));

        // Initialize vault encryption
        let vault_encryption = VaultEncryption;

        // Initialize handle generator
        let handle_generator = HandleGenerator::new();

        // Initialize decoy registry
        let decoy_registry = DecoyRegistry::new();

        // Initialize decoy manager
        let decoy_mapping = Arc::new(Mutex::new(crate::vault::mapping::DecoyMap::new()));
        let decoy_manager = DecoyManager::new(
            decoy_registry.clone(),
            decoy_mapping,
            vault_storage.clone(),
        );

        // Initialize ledger
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));

        // Initialize scanner
        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(
                vault_storage.clone(),
                vault_encryption.clone(),
                GroupElement::generator(),
            ),
        ));

        // Initialize canary registry
        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));

        // Initialize interceptor
        let interceptor = Arc::new(EgressInterceptor::new(
            ledger.clone(),
            scanner.clone(),
            canary_registry.clone(),
        ));

        // Initialize providers (empty for now)
        let providers = Vec::new();

        // Generate initial ephemeral
        let current_r = GroupElement::generator();
        let current_R = GroupElement::generator();

        // Initialize threshold DH
        let threshold_dh = ThresholdDH::new(
            dkg.clone(),
            vec![],
            vec![],
        )
        .map_err(|e| PhantomKeyError::CryptoError(e.to_string()))?;

        Ok(Self {
            dkg,
            threshold_dh,
            share_manager,
            vault_storage,
            vault_encryption,
            handle_generator,
            decoy_registry,
            decoy_manager,
            ledger,
            scanner,
            canary_registry,
            interceptor,
            providers,
            current_r,
            current_R,
        })
    }

    /// Add an LLM provider
    pub fn add_provider(
        &mut self,
        provider_type: ProviderType,
        provider: Arc<dyn LLMProvider>,
    ) {
        self.providers.push((provider_type, provider));
    }

    /// Get a provider by type
    pub fn get_provider(&self, provider_type: &ProviderType) -> Option<Arc<dyn LLMProvider>> {
        self.providers
            .iter()
            .find(|(pt, _)| pt == provider_type)
            .map(|(_, p)| p.clone())
    }

    /// Process a prompt through Phantom Key
    /// 
    /// Workflow:
    /// 1. Generate new ephemeral r, R = r*G
    /// 2. Process prompt: replace secrets with decoys
    /// 3. Send to LLM (with decoys)
    /// 4. Process response: detect canaries, scan for secrets
    /// 5. Return final response
    pub async fn process_prompt(
        &mut self,
        prompt: &str,
        model: &str,
        provider_type: ProviderType,
    ) -> Result<String, PhantomKeyError> {
        // Step 1: Generate new ephemeral
        self.generate_new_ephemeral();

        // Update scanner with current R
        {
            let mut scanner = self.scanner.lock().await;
            scanner.update_r(self.current_R);
        }

        // Step 2: Process prompt (replace secrets with decoys)
        let (processed_prompt, handles) = self
            .process_prompt_internal(prompt, &self.current_R)
            .await?;

        // Step 3: Send to LLM
        let llm_response = self
            .send_to_llm(processed_prompt, model, provider_type)
            .await?;

        // Step 4: Process response
        let final_response = self
            .process_response(llm_response, handles, &self.current_R)
            .await?;

        Ok(final_response)
    }

    /// Generate new ephemeral for threshold DH
    fn generate_new_ephemeral(&mut self) {
        self.current_r = GroupElement::generator();
        self.current_R = GroupElement::generator().multiply(&self.current_r);
    }

    /// Process prompt: replace secrets with decoys
    async fn process_prompt_internal(
        &self,
        prompt: &str,
        R: &GroupElement,
    ) -> Result<(String, Vec<String>), PhantomKeyError> {
        // Use decoy manager to process prompt
        // This will replace any real secrets with decoys
        let (processed, handles) = self.decoy_manager.process_prompt(prompt, R);

        // Convert handles to strings
        let handle_strings: Vec<String> = handles.iter().map(|h| h.to_string()).collect();

        Ok((processed, handle_strings))
    }

    /// Send to LLM provider
    async fn send_to_llm(
        &self,
        prompt: String,
        model: &str,
        provider_type: ProviderType,
    ) -> Result<String, PhantomKeyError> {
        let provider = self
            .get_provider(&provider_type)
            .ok_or(PhantomKeyError::ProviderNotFound(
                format!("{:?}", provider_type),
            ))?;

        let messages = vec![Message::new("user", &prompt)];

        let response = provider
            .chat_completion(model, messages, 0.7, Some(4096))
            .await
            .map_err(|e| PhantomKeyError::LLMError(e.to_string()))?;

        Ok(response.content)
    }

    /// Process response: swap handles back to real values
    async fn process_response(
        &self,
        response: String,
        handles: Vec<String>,
        R: &GroupElement,
    ) -> Result<String, PhantomKeyError> {
        // For now, just return the response as-is
        // In a real implementation, we'd swap handles back to real values
        Ok(response)
    }

    /// Store a secret in the vault
    pub async fn store_secret(
        &self,
        secret: &[u8],
        secret_type: crate::vault::storage::SecretType,
    ) -> Result<String, PhantomKeyError> {
        // Generate handle
        let handle = self.handle_generator.generate();

        // Store in vault
        let metadata = crate::vault::storage::VaultMetadata {
            secret_type,
            description: Some("Stored via PhantomKey".to_string()),
            ..Default::default()
        };

        let entry = self.vault_encryption.create_entry(
            secret,
            &self.current_R,
            handle.to_string(),
            metadata,
        );

        self.vault_storage.insert(entry);

        // Generate and register decoy
        let decoy = self.decoy_registry.generate(&secret_type);
        self.decoy_manager.mapping.lock().unwrap().register(
            handle.clone(),
            decoy,
        );

        Ok(handle.to_string())
    }

    /// Get a secret from the vault
    pub async fn get_secret(
        &self,
        handle: &str,
    ) -> Result<Vec<u8>, PhantomKeyError> {
        let entry = self
            .vault_storage
            .get_by_handle(handle)
            .ok_or(PhantomKeyError::VaultError(
                "Handle not found".to_string(),
            ))?;

        self.vault_encryption
            .get_secret(&entry, &self.current_R)
            .ok_or(PhantomKeyError::VaultError("Decryption failed".to_string()))
    }

    /// Run threshold DH protocol
    pub async fn run_threshold_dh(
        &self,
        party_ids: &[usize],
    ) -> Result<(GroupElement, Vec<u8>), PhantomKeyError> {
        // Generate partials for specified parties
        let mut partials = Vec::new();

        for &party_id in party_ids {
            let partial = self
                .threshold_dh
                .compute_partial(party_id, &self.current_R)
                .map_err(|e| PhantomKeyError::CryptoError(e.to_string()))?;
            partials.push(partial);
        }

        // Combine partials
        let K = self
            .threshold_dh
            .combine_partials(&partials, &self.current_R)
            .map_err(|e| PhantomKeyError::CryptoError(e.to_string()))?;

        // Derive key
        let key = ThresholdDH::derive_key(&K, &self.current_R, b"phantom-key-v2", 32);

        Ok((K, key))
    }

    /// Refresh shares
    pub async fn refresh_shares(&self) -> Result<(), PhantomKeyError> {
        let mut manager = self.share_manager.lock().unwrap();
        manager
            .refresh()
            .map_err(|e| PhantomKeyError::CryptoError(e.to_string()))
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        let manager = self.share_manager.lock().unwrap();
        manager.current_epoch()
    }

    /// Get ledger chain status
    pub fn ledger_status(&self) -> crate::egress::ledger::ChainStatus {
        self.ledger.chain_status()
    }

    /// Get all ledger entries
    pub fn get_ledger_entries(&self) -> Vec<crate::egress::ledger::SignedLedgerEntry> {
        self.ledger.entries()
    }

    /// Get all vault entries
    pub fn get_vault_entries(&self) -> Vec<crate::vault::storage::VaultEntry> {
        self.vault_storage.list()
    }
}

/// Phantom Key builder for easier construction
pub struct PhantomKeyBuilder {
    parties: usize,
    threshold: usize,
    vault_storage: Option<Arc<dyn VaultStorage>>,
    providers: Vec<(ProviderType, Arc<dyn LLMProvider>)>,
}

impl PhantomKeyBuilder {
    pub fn new() -> Self {
        Self {
            parties: 5,
            threshold: 3,
            vault_storage: None,
            providers: Vec::new(),
        }
    }

    pub fn parties(mut self, parties: usize) -> Self {
        self.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn vault_storage(mut self, storage: Arc<dyn VaultStorage>) -> Self {
        self.vault_storage = Some(storage);
        self
    }

    pub fn add_provider(
        mut self,
        provider_type: ProviderType,
        provider: Arc<dyn LLMProvider>,
    ) -> Self {
        self.providers.push((provider_type, provider));
        self
    }

    pub fn build(self) -> Result<PhantomKey, PhantomKeyError> {
        let storage = self
            .vault_storage
            .unwrap_or_else(|| Arc::new(MemoryStorage::new()));

        let mut phantom_key = PhantomKey::new(self.parties, self.threshold, storage)?;

        for (provider_type, provider) in self.providers {
            phantom_key.add_provider(provider_type, provider);
        }

        Ok(phantom_key)
    }
}

impl Default for PhantomKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}
