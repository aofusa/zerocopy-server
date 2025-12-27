//! Integration tests for JWKS cache

// In integration tests, crate name with hyphens becomes underscores
// The crate name is "jwt-filter" but we reference it as "jwt_filter"
use jwt_filter::jwks::{Jwks, JwksCache, Jwk};

fn create_test_jwk(kid: Option<&str>) -> Jwk {
    Jwk {
        kty: "RSA".to_string(),
        kid: kid.map(|s| s.to_string()),
        alg: Some("RS256".to_string()),
        use_type: Some("sig".to_string()),
        n: Some("test_n".to_string()),
        e: Some("AQAB".to_string()),
    }
}

fn create_test_jwks() -> Jwks {
    Jwks {
        keys: vec![
            create_test_jwk(Some("key1")),
            create_test_jwk(Some("key2")),
        ],
    }
}

#[test]
fn test_jwks_cache_integration() {
    let jwks = create_test_jwks();
    let url = "https://example.com/jwks".to_string();
    
    // Set in global cache
    JwksCache::set_global(url.clone(), jwks.clone(), 3600);
    
    // Get from global cache
    let cached = JwksCache::get_global(&url);
    assert!(cached.is_some());
    let cached_jwks = cached.unwrap();
    assert_eq!(cached_jwks.keys.len(), 2);
    
    // Verify keys are accessible
    assert!(cached_jwks.find_key("key1").is_some());
    assert!(cached_jwks.find_key("key2").is_some());
}

#[test]
fn test_jwks_cache_multiple_urls() {
    let jwks1 = create_test_jwks();
    let jwks2 = Jwks {
        keys: vec![create_test_jwk(Some("different_key"))],
    };
    
    let url1 = "https://example.com/jwks1".to_string();
    let url2 = "https://example.com/jwks2".to_string();
    
    JwksCache::set_global(url1.clone(), jwks1, 3600);
    JwksCache::set_global(url2.clone(), jwks2, 3600);
    
    let cached1 = JwksCache::get_global(&url1);
    let cached2 = JwksCache::get_global(&url2);
    
    assert!(cached1.is_some());
    assert!(cached2.is_some());
    assert_eq!(cached1.unwrap().keys.len(), 2);
    assert_eq!(cached2.unwrap().keys.len(), 1);
}

#[test]
fn test_jwks_cache_needs_refresh() {
    // Use a unique URL to avoid conflicts with other tests
    let url = "https://test-needs-refresh.example.com/jwks".to_string();
    
    // Initially needs refresh (if not cached by previous test)
    // Note: This test may be flaky if run after other tests that use the same URL
    // In practice, we'd use a mock time provider or clear the cache between tests
    
    // Set cache
    let jwks = create_test_jwks();
    JwksCache::set_global(url.clone(), jwks, 3600);
    
    // Should not need refresh immediately
    assert!(!JwksCache::needs_refresh_global(&url));
    
    // Verify we can get it
    let cached = JwksCache::get_global(&url);
    assert!(cached.is_some());
}

