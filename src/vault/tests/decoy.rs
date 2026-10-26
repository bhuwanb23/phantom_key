//! Tests for vault decoy module

#[cfg(test)]
mod tests {
    use super::super::decoy::*;
    use super::super::storage::SecretType;

    #[test]
    fn test_decoy_registry_creation() {
        let registry = DecoyRegistry::new();
        assert!(!registry.generators.is_empty());
    }

    #[test]
    fn test_decoy_registry_generate_aws_access_key() {
        let registry = DecoyRegistry::new();
        let decoy = registry.generate(&SecretType::AwsAccessKey);

        assert!(decoy.starts_with("AKIA"));
        assert_eq!(decoy.len(), 20);
    }

    #[test]
    fn test_decoy_registry_generate_aws_secret_key() {
        let registry = DecoyRegistry::new();
        let decoy = registry.generate(&SecretType::AwsSecretKey);

        assert_eq!(decoy.len(), 40);
    }

    #[test]
    fn test_decoy_registry_generate_iban() {
        let registry = DecoyRegistry::new();
        let decoy = registry.generate(&SecretType::IbAN);

        assert!(decoy.starts_with("DE"));
        assert!(decoy.len() >= 4);
    }

    #[test]
    fn test_decoy_registry_generate_credit_card() {
        let registry = DecoyRegistry::new();
        let decoy = registry.generate(&SecretType::CreditCard);

        assert!(decoy.starts_with("4"));
        assert!(decoy.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_decoy_registry_validate() {
        let registry = DecoyRegistry::new();

        let decoy = registry.generate(&SecretType::AwsAccessKey);
        assert!(registry.validate(&decoy, &SecretType::AwsAccessKey));

        assert!(!registry.validate("invalid", &SecretType::AwsAccessKey));
    }

    #[test]
    fn test_decoy_registry_custom_generator() {
        let mut registry = DecoyRegistry::new();

        let custom_generator = super::super::decoy::generic::GenericDecoyGenerator::new("TESTXXXX");
        registry.register_generator(
            SecretType::Custom("test".to_string()),
            Box::new(custom_generator),
        );

        let decoy = registry.generate(&SecretType::Custom("test".to_string()));
        assert!(decoy.starts_with("TEST"));
        assert_eq!(decoy.len(), 8);
    }

    #[test]
    fn test_decoy_registry_default() {
        let registry: DecoyRegistry = Default::default();
        assert!(!registry.generators.is_empty());
    }
}
