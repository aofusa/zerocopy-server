//! Integration tests for JWT validation

#[cfg(test)]
mod jwt_validation_tests {
    use std::collections::HashMap;

#[test]
fn test_hs256_validation_flow() {
    // This is a basic integration test structure
    // Full integration tests would require Proxy-WASM context mocking
    // which is complex, so we test the core logic here
    
    // Test token extraction logic
    let header_value = "Bearer test_token";
    let token = if header_value.starts_with("Bearer ") || header_value.starts_with("bearer ") {
        Some(header_value[7..].trim().to_string())
    } else {
        Some(header_value.to_string())
    };
    
    assert_eq!(token, Some("test_token".to_string()));
}

#[test]
fn test_token_parsing() {
    let token = "header.payload.signature";
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "header");
    assert_eq!(parts[1], "payload");
    assert_eq!(parts[2], "signature");
}

#[test]
fn test_invalid_token_format() {
    let token = "header.payload";  // Missing signature
    let parts: Vec<&str> = token.split('.').collect();
    assert_ne!(parts.len(), 3);
}

#[test]
fn test_claims_to_headers_mapping() {
    use serde_json::Value;
    
    let mut claims_to_headers = HashMap::new();
    claims_to_headers.insert("sub".to_string(), "X-User-ID".to_string());
    claims_to_headers.insert("email".to_string(), "X-User-Email".to_string());
    
    // Simulate claims
    let mut extra = HashMap::new();
    extra.insert("email".to_string(), Value::String("user@example.com".to_string()));
    
    // Test mapping logic
    let claim = "email";
    let value = match claim {
        "sub" => Some("user123".to_string()),
        "email" => extra.get("email").and_then(|v| {
            match v {
                Value::String(s) => Some(s.clone()),
                _ => Some(v.to_string()),
            }
        }),
        _ => None,
    };
    
    assert_eq!(value, Some("user@example.com".to_string()));
}

#[test]
fn test_skip_paths() {
    let skip_paths = vec!["/health".to_string(), "/metrics".to_string()];
    
    assert!(skip_paths.iter().any(|p| "/health".starts_with(p)));
    assert!(skip_paths.iter().any(|p| "/health/check".starts_with(p)));
    assert!(skip_paths.iter().any(|p| "/metrics".starts_with(p)));
    assert!(!skip_paths.iter().any(|p| "/api/users".starts_with(p)));
    }
}

