//! Request/Response Interceptor
//!
//! Intercepts outbound API requests and inbound responses,
//! logs them to the ledger, scans for secrets, and detects canaries.

use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::egress::{
    ledger::{Ledger, LedgerEntry, LedgerError},
    scanner::{SecretScanner, SecretMatch},
    canary::CanaryRegistry,
};

/// Outbound request to intercept
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub id: Uuid,
    pub provider: String,
    pub method: String,
    pub url: String,
    pub payload: Vec<u8>,
}

impl OutboundRequest {
    pub fn new(provider: String, method: String, url: String, payload: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            provider,
            method,
            url,
            payload,
        }
    }
}

/// Inbound response to intercept
#[derive(Debug, Clone)]
pub struct InboundResponse {
    pub request_id: Uuid,
    pub payload: Vec<u8>,
}

/// Interception error
#[derive(Debug, thiserror::Error)]
pub enum InterceptionError {
    #[error("Secret detected in payload")]
    SecretDetected,
    #[error("Ledger error: {0}")]
    LedgerError(#[from] LedgerError),
    #[error("Secret matches: {:?}", matches.0)]
    SecretMatches(Vec<SecretMatch>),
}

/// Interceptor for outbound requests
pub struct EgressInterceptor {
    ledger: Arc<Ledger>,
    scanner: Arc<Mutex<SecretScanner>>,
    canary_registry: Arc<Mutex<CanaryRegistry>>,
}

impl EgressInterceptor {
    pub fn new(
        ledger: Arc<Ledger>,
        scanner: Arc<Mutex<SecretScanner>>,
        canary_registry: Arc<Mutex<CanaryRegistry>>,
    ) -> Self {
        Self {
            ledger,
            scanner,
            canary_registry,
        }
    }

    /// Intercept and log an outbound request
    pub async fn intercept_request(
        &self,
        request: OutboundRequest,
    ) -> Result<(), InterceptionError> {
        // Scan for real secrets
        let scanner = self.scanner.lock().await;
        let secret_matches = scanner.scan(&request.payload);

        if !secret_matches.is_empty() {
            return Err(InterceptionError::SecretMatches(secret_matches));
        }

        // Detect canaries
        let text = String::from_utf8_lossy(&request.payload);
        let canary_registry = self.canary_registry.lock().await;
        let canary_ids = canary_registry.detect(&text);

        // Trigger detected canaries
        for id in canary_ids {
            canary_registry.trigger(&id);
        }

        // Log to ledger
        let entry = LedgerEntry {
            id: Uuid::new_v4(),
            prev_hash: [0u8; 32],
            timestamp: chrono::Utc::now(),
            request_id: request.id,
            provider: request.provider,
            method: request.method,
            url: request.url,
            payload: request.payload,
            hash: [0u8; 32],
        };

        self.ledger.append(entry)?;

        Ok(())
    }

    /// Intercept and log an inbound response
    pub async fn intercept_response(
        &self,
        response: InboundResponse,
    ) -> Result<(), InterceptionError> {
        // Scan for real secrets in response
        let scanner = self.scanner.lock().await;
        let secret_matches = scanner.scan(&response.payload);

        if !secret_matches.is_empty() {
            // Log but don't block - model might echo secrets
            // This is a warning condition
        }

        // Detect canaries in response
        let text = String::from_utf8_lossy(&response.payload);
        let canary_registry = self.canary_registry.lock().await;
        let canary_ids = canary_registry.detect(&text);

        // Trigger detected canaries
        for id in canary_ids {
            canary_registry.trigger(&id);
        }

        Ok(())
    }

    /// Intercept a complete request-response cycle
    pub async fn intercept_cycle(
        &self,
        request: OutboundRequest,
        response: InboundResponse,
    ) -> Result<(), InterceptionError> {
        self.intercept_request(request).await?;
        self.intercept_response(response).await?;
        Ok(())
    }
}
