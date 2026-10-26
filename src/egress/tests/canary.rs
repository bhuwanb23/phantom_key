//! Tests for canary module

#[cfg(test)]
mod tests {
    use super::super::canary::*;
    use uuid::Uuid;

    #[test]
    fn test_canary_creation() {
        let value = "test-canary-value".to_string();
        let request_id = Uuid::new_v4();
        let provider = "bedrock".to_string();

        let canary = Canary::new(value.clone(), request_id, provider.clone());

        assert_eq!(canary.value, value);
        assert_eq!(canary.request_id, request_id);
        assert_eq!(canary.provider, provider);
        assert!(!canary.is_triggered());
    }

    #[test]
    fn test_canary_trigger() {
        let mut canary = Canary::new(
            "value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );

        assert!(!canary.is_triggered());

        canary.trigger();

        assert!(canary.is_triggered());
        assert!(canary.triggered_at.is_some());
    }

    #[test]
    fn test_canary_add_metadata() {
        let mut canary = Canary::new(
            "value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );

        canary.add_metadata("key1".to_string(), "value1".to_string());
        canary.add_metadata("key2".to_string(), "value2".to_string());

        assert_eq!(canary.metadata.get("key1"), Some(&"value1".to_string()));
        assert_eq!(canary.metadata.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_canary_registry_creation() {
        let registry = CanaryRegistry::new();
        assert!(registry.all().is_empty());
    }

    #[test]
    fn test_canary_registry_register() {
        let registry = CanaryRegistry::new();

        let id = registry.register(
            "test-value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );

        assert!(registry.get(&id).is_some());
        assert_eq!(registry.get_id_by_value("test-value"), Some(id));
    }

    #[test]
    fn test_canary_registry_get() {
        let registry = CanaryRegistry::new();

        let id = registry.register(
            "test-value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );

        let canary = registry.get(&id).unwrap();
        assert_eq!(canary.value, "test-value");
    }

    #[test]
    fn test_canary_registry_trigger() {
        let registry = CanaryRegistry::new();

        let id = registry.register(
            "test-value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );

        let canary_before = registry.get(&id).unwrap();
        assert!(!canary_before.is_triggered());

        let triggered = registry.trigger(&id).unwrap();
        assert!(triggered.is_triggered());

        let canary_after = registry.get(&id).unwrap();
        assert!(canary_after.is_triggered());
    }

    #[test]
    fn test_canary_registry_trigger_by_value() {
        let registry = CanaryRegistry::new();

        let id = registry.register(
            "test-value".to_string(),
            Uuid::new_v4(),
            "bedrock".to_string(),
        );

        let triggered = registry.trigger_by_value("test-value").unwrap();
        assert!(triggered.is_triggered());
    }

    #[test]
    fn test_canary_registry_detect() {
        let registry = CanaryRegistry::new();

        let id1 = registry.register("value1".to_string(), Uuid::new_v4(), "bedrock".to_string());
        let id2 = registry.register("value2".to_string(), Uuid::new_v4(), "openai".to_string());

        let detected = registry.detect("This contains value1 and value2");
        assert!(detected.contains(&id1));
        assert!(detected.contains(&id2));

        let detected2 = registry.detect("Only value1 here");
        assert!(detected2.contains(&id1));
        assert!(!detected2.contains(&id2));
    }

    #[test]
    fn test_canary_registry_active_and_triggered() {
        let registry = CanaryRegistry::new();

        let id1 = registry.register("value1".to_string(), Uuid::new_v4(), "bedrock".to_string());
        let id2 = registry.register("value2".to_string(), Uuid::new_v4(), "openai".to_string());

        // Trigger one
        registry.trigger(&id1);

        let active = registry.active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id2);

        let triggered = registry.triggered();
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].id, id1);
    }

    #[test]
    fn test_canary_registry_remove() {
        let registry = CanaryRegistry::new();

        let id = registry.register("value".to_string(), Uuid::new_v4(), "bedrock".to_string());

        let removed = registry.remove(&id).unwrap();
        assert_eq!(removed.value, "value");

        assert!(registry.get(&id).is_none());
        assert!(registry.get_id_by_value("value").is_none());
    }

    #[test]
    fn test_canary_registry_clear() {
        let registry = CanaryRegistry::new();

        registry.register("value1".to_string(), Uuid::new_v4(), "bedrock".to_string());
        registry.register("value2".to_string(), Uuid::new_v4(), "openai".to_string());

        assert_eq!(registry.all().len(), 2);

        registry.clear();

        assert!(registry.all().is_empty());
    }

    #[test]
    fn test_canary_registry_default() {
        let registry: CanaryRegistry = Default::default();
        assert!(registry.all().is_empty());
    }
}
