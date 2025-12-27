//! JWKS (JSON Web Key Set) handling
//!
//! Supports fetching and caching JWKS from external URLs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWKS response from OIDC provider
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (RSA, EC, etc.)
    pub kty: String,
    /// Key ID
    #[serde(default)]
    pub kid: Option<String>,
    /// Algorithm
    #[serde(default)]
    pub alg: Option<String>,
    /// Key use: sig or enc
    #[serde(default)]
    pub use_type: Option<String>,
    
    // RSA parameters
    /// RSA modulus (base64url)
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url)
    #[serde(default)]
    pub e: Option<String>,
}

impl Jwks {
    /// Parse JWKS from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
    
    /// Find key by kid
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
    
    /// Get first RSA key (fallback when no kid specified)
    pub fn first_rsa_key(&self) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kty == "RSA")
    }
}

/// JWKS cache with TTL tracking
pub struct JwksCache {
    /// Cached JWKS keyed by URL
    entries: HashMap<String, CacheEntry>,
}

struct CacheEntry {
    jwks: Jwks,
    fetched_at: u64,  // nanoseconds since epoch
    ttl_secs: u64,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
    
    /// Get cached JWKS if still valid
    pub fn get(&self, url: &str, now_nanos: u64) -> Option<&Jwks> {
        if let Some(entry) = self.entries.get(url) {
            let age_secs = (now_nanos - entry.fetched_at) / 1_000_000_000;
            if age_secs < entry.ttl_secs {
                return Some(&entry.jwks);
            }
        }
        None
    }
    
    /// Store JWKS in cache
    pub fn set(&mut self, url: String, jwks: Jwks, now_nanos: u64, ttl_secs: u64) {
        self.entries.insert(url, CacheEntry {
            jwks,
            fetched_at: now_nanos,
            ttl_secs,
        });
    }
    
    /// Check if URL needs refresh
    pub fn needs_refresh(&self, url: &str, now_nanos: u64) -> bool {
        self.get(url, now_nanos).is_none()
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}
