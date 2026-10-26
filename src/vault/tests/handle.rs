//! Tests for vault handle module

#[cfg(test)]
mod tests {
    use super::super::handle::*;
    use uuid::Uuid;

    #[test]
    fn test_handle_creation() {
        let handle = Handle::new();

        assert!(handle.to_string().starts_with("⟦H"));
        assert!(handle.to_string().ends_with("⟧"));
    }

    #[test]
    fn test_handle_from_uuid() {
        let uuid = Uuid::new_v4();
        let handle = Handle::from_uuid(uuid);

        assert_eq!(handle.uuid(), Some(uuid));
    }

    #[test]
    fn test_handle_uuid_roundtrip() {
        let uuid = Uuid::new_v4();
        let handle = Handle::from_uuid(uuid);
        let retrieved_uuid = handle.uuid().unwrap();

        assert_eq!(uuid, retrieved_uuid);
    }

    #[test]
    fn test_handle_is_valid() {
        assert!(Handle::is_valid("⟦H12345678-1234-1234-1234-123456789012⟧"));
        assert!(Handle::is_valid("⟦H00000000-0000-0000-0000-000000000000⟧"));

        assert!(!Handle::is_valid("H123⟧"));
        assert!(!Handle::is_valid("⟦H123"));
        assert!(!Handle::is_valid("⟦X123⟧"));
        assert!(!Handle::is_valid(""));
    }

    #[test]
    fn test_handle_parsing() {
        let uuid = Uuid::new_v4();
        let handle = Handle::from_uuid(uuid);
        let handle_str = handle.to_string();

        let parsed: Handle = handle_str.parse().unwrap();
        assert_eq!(handle, parsed);
        assert_eq!(parsed.uuid(), Some(uuid));
    }

    #[test]
    fn test_handle_parse_error() {
        let result: Result<Handle, _> = "invalid".parse();
        assert!(result.is_err());

        let result: Result<Handle, _> = "⟦X123⟧".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_display() {
        let uuid = Uuid::new_v4();
        let handle = Handle::from_uuid(uuid);

        let display = format!("{}", handle);
        assert!(display.starts_with("⟦H"));
        assert!(display.ends_with("⟧"));
    }

    #[test]
    fn test_handle_equality() {
        let uuid = Uuid::new_v4();
        let handle1 = Handle::from_uuid(uuid);
        let handle2 = Handle::from_uuid(uuid);

        assert_eq!(handle1, handle2);
    }

    #[test]
    fn test_handle_inequality() {
        let handle1 = Handle::new();
        let handle2 = Handle::new();

        assert_ne!(handle1, handle2);
    }

    #[test]
    fn test_handle_generator() {
        let generator = HandleGenerator::new();

        let handle1 = generator.generate();
        let handle2 = generator.generate();

        assert_ne!(handle1, handle2);
        assert!(handle1.to_string().starts_with("⟦H"));
        assert!(handle2.to_string().starts_with("⟦H"));
    }

    #[test]
    fn test_handle_generator_from_uuid() {
        let generator = HandleGenerator::new();
        let uuid = Uuid::new_v4();

        let handle = generator.generate_from_uuid(uuid);
        assert_eq!(handle.uuid(), Some(uuid));
    }
}
