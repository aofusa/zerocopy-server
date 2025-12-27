//! Common test utilities and mocks

/// Mock time provider for testing
pub struct MockTimeProvider {
    pub now: u64,
}

impl MockTimeProvider {
    pub fn new(now: u64) -> Self {
        Self { now }
    }
    
    pub fn now_nanos(&self) -> u64 {
        self.now
    }
}

/// Test helper functions
pub mod helpers {
    use super::*;
    
    /// Create a test JWT header (base64url encoded)
    pub fn create_test_header(alg: &str, kid: Option<&str>) -> String {
        let header = if let Some(kid) = kid {
            format!(r#"{{"alg":"{}","typ":"JWT","kid":"{}"}}"#, alg, kid)
        } else {
            format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg)
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header.as_bytes())
    }
    
    /// Create a test JWT claims (base64url encoded)
    pub fn create_test_claims(claims: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claims.as_bytes())
    }
    
    /// Create a test JWT token
    pub fn create_test_token(header: &str, claims: &str, signature: &str) -> String {
        format!("{}.{}.{}", header, claims, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mock_time_provider() {
        let provider = MockTimeProvider::new(1000);
        assert_eq!(provider.now_nanos(), 1000);
    }
    
    #[test]
    fn test_create_test_header() {
        let header = helpers::create_test_header("HS256", None);
        assert!(!header.is_empty());
    }
}

