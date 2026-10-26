//! Tests for interceptor module

#[cfg(test)]
mod tests {
    use super::super::interceptor::*;
    use super::super::ledger::{Ledger, LedgerEntry};
    use super::super::scanner::{SecretScanner, SecretMatch};
    use super::super::canary::CanaryRegistry;
    use super::super::super::vault::storage::MemoryStorage;
    use super::super::super::vault::encryption::VaultEncryption;
    use super::super::super::crypto::group::GroupElement;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use ed25519_dalek::SigningKey;
    use rand::Rng;

    #[tokio::test]
    async fn test_interceptor_creation() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));

        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();
        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(storage, encryption, R)
        ));

        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));

        let interceptor = EgressInterceptor::new(
            ledger,
            scanner,
            canary_registry,
        );

        // Just verify it can be created
        assert!(true);
    }

    #[tokio::test]
    async fn test_interceptor_request_no_secrets() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));

        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();
        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(storage, encryption, R)
        ));

        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));

        let interceptor = EgressInterceptor::new(
            ledger.clone(),
            scanner,
            canary_registry,
        );

        let request = OutboundRequest {
            id: uuid::Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"safe payload".to_vec(),
        };

        interceptor.intercept_request(request).await.unwrap();

        // Verify entry was logged
        assert_eq!(ledger.entries().len(), 1);
    }

    #[tokio::test]
    async fn test_interceptor_request_with_secret() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));

        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();

        // Store a secret first
        let secret = b"my-secret";
        let handle = "⟦H1⟧".to_string();
        let metadata = super::super::super::vault::storage::VaultMetadata {
            secret_type: super::super::super::vault::storage::SecretType::Generic,
            ..Default::default()
        };
        let entry = encryption.create_entry(secret, &R, handle, metadata);
        storage.insert(entry);

        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(storage, encryption, R)
        ));

        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));

        let interceptor = EgressInterceptor::new(
            ledger.clone(),
            scanner,
            canary_registry,
        );

        let request = OutboundRequest {
            id: uuid::Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"Using secret: my-secret".to_vec(),
        };

        let result = interceptor.intercept_request(request).await;
        assert!(result.is_err());

        // Entry should NOT be logged when secret is detected
        assert_eq!(ledger.entries().len(), 0);
    }

    #[tokio::test]
    async fn test_interceptor_response() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));

        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();
        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(storage, encryption, R)
        ));

        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));

        let interceptor = EgressInterceptor::new(
            ledger.clone(),
            scanner,
            canary_registry,
        );

        let response = InboundResponse {
            request_id: uuid::Uuid::new_v4(),
            payload: b"response payload".to_vec(),
        };

        interceptor.intercept_response(response).await.unwrap();
        // Response interception doesn't log to ledger
        assert_eq!(ledger.entries().len(), 0);
    }

    #[tokio::test]
    async fn test_interceptor_cycle() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let ledger = Arc::new(Ledger::new(signing_key));

        let storage = Arc::new(MemoryStorage::new());
        let encryption = VaultEncryption;
        let R = GroupElement::generator();
        let scanner = Arc::new(Mutex::new(
            SecretScanner::new(storage, encryption, R)
        ));

        let canary_registry = Arc::new(Mutex::new(CanaryRegistry::new()));

        let interceptor = EgressInterceptor::new(
            ledger.clone(),
            scanner,
            canary_registry,
        );

        let request = OutboundRequest {
            id: uuid::Uuid::new_v4(),
            provider: "bedrock".to_string(),
            method: "POST".to_string(),
            url: "/model/test".to_string(),
            payload: b"safe payload".to_vec(),
        };

        let response = InboundResponse {
            request_id: request.id,
            payload: b"response payload".to_vec(),
        };

        interceptor.intercept_cycle(request, response).await.unwrap();

        // Request should be logged
        assert_eq!(ledger.entries().len(), 1);
    }

    #[test]
    fn test_outbound_request_creation() {
        let request = OutboundRequest::new(
            "bedrock".to_string(),
            "POST".to_string(),
            "/model/test".to_string(),
            b"payload".to_vec(),
        );

        assert_eq!(request.provider, "bedrock");
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "/model/test");
        assert_eq!(request.payload, b"payload");
    }

    #[test]
    fn test_inbound_response_creation() {
        let request_id = uuid::Uuid::new_v4();
        let response = InboundResponse {
            request_id,
            payload: b"response".to_vec(),
        };

        assert_eq!(response.request_id, request_id);
        assert_eq!(response.payload, b"response");
    }
}
