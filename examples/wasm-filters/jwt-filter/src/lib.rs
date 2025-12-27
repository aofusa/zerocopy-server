//! JWT Authentication Proxy-Wasm Filter
//!
//! Validates JWT tokens with support for:
//! - HS256 (HMAC-SHA256) with static secrets
//! - RS256 (RSA-SHA256) with JWKS URL fetching
//! - Claims validation (exp, iss, aud)
//! - Claims-to-headers mapping

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod crypto;
mod jwks;

use crypto::VerifyResult;
use jwks::{Jwks, JwksCache};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(JwtFilterRoot::new())
    });
}}

/// JWT Filter Configuration
#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Expected issuer (iss claim)
    #[serde(default)]
    pub issuer: Option<String>,
    
    /// Expected audience (aud claim)
    #[serde(default)]
    pub audience: Option<String>,
    
    /// JWKS URL for RS256 keys
    #[serde(default)]
    pub jwks_url: Option<String>,
    
    /// JWKS cache TTL in seconds
    #[serde(default = "default_jwks_ttl")]
    pub jwks_cache_ttl_secs: u64,
    
    /// Allowed algorithms
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    
    /// Static secrets for HS256 (kid -> base64 secret)
    #[serde(default)]
    pub static_keys: HashMap<String, String>,
    
    /// Header name for token extraction
    #[serde(default = "default_header_name")]
    pub header_name: String,
    
    /// Claims to forward as headers (claim -> header name)
    #[serde(default)]
    pub claims_to_headers: HashMap<String, String>,
    
    /// Skip authentication for these paths
    #[serde(default)]
    pub skip_paths: Vec<String>,
    
    /// Upstream name for JWKS fetching
    #[serde(default = "default_jwks_upstream")]
    pub jwks_upstream: String,
}

fn default_jwks_ttl() -> u64 { 3600 }
fn default_algorithms() -> Vec<String> { vec!["RS256".to_string(), "HS256".to_string()] }
fn default_header_name() -> String { "Authorization".to_string() }
fn default_jwks_upstream() -> String { "jwks".to_string() }

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            jwks_url: None,
            jwks_cache_ttl_secs: 3600,
            algorithms: vec!["RS256".to_string(), "HS256".to_string()],
            static_keys: HashMap::new(),
            header_name: "Authorization".to_string(),
            claims_to_headers: HashMap::new(),
            skip_paths: vec!["/health".to_string(), "/metrics".to_string()],
            jwks_upstream: "jwks".to_string(),
        }
    }
}

impl JwtConfig {
    pub fn should_skip(&self, path: &str) -> bool {
        self.skip_paths.iter().any(|p| path.starts_with(p))
    }
}

/// JWT Header
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// JWT Claims
#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

struct JwtFilterRoot {
    config: JwtConfig,
    jwks_cache: JwksCache,
}

impl JwtFilterRoot {
    fn new() -> Self {
        Self {
            config: JwtConfig::default(),
            jwks_cache: JwksCache::new(),
        }
    }
}

impl Context for JwtFilterRoot {}

impl RootContext for JwtFilterRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        if plugin_configuration_size == 0 {
            log::info!("[jwt] Using default configuration");
            return true;
        }

        if let Some(config_bytes) = self.get_plugin_configuration() {
            match serde_json::from_slice::<JwtConfig>(&config_bytes) {
                Ok(config) => {
                    log::info!(
                        "[jwt] Configuration loaded: issuer={:?}, jwks_url={:?}, algorithms={:?}",
                        config.issuer,
                        config.jwks_url,
                        config.algorithms
                    );
                    self.config = config;
                }
                Err(e) => {
                    log::error!("[jwt] Failed to parse configuration: {}", e);
                    return false;
                }
            }
        }
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(JwtFilter {
            context_id,
            config: self.config.clone(),
            pending_jwks_fetch: false,
            cached_token: None,
        }))
    }
}

struct JwtFilter {
    context_id: u32,
    config: JwtConfig,
    pending_jwks_fetch: bool,
    cached_token: Option<String>,
}

impl Context for JwtFilter {
    fn on_http_call_response(&mut self, _token_id: u32, _num_headers: usize, body_size: usize, _num_trailers: usize) {
        self.pending_jwks_fetch = false;
        
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            if let Some(jwks) = Jwks::from_bytes(&body) {
                log::info!("[jwt:{}] JWKS fetched with {} keys", self.context_id, jwks.keys.len());
                
                // Re-verify token with new JWKS
                if let Some(ref token) = self.cached_token.take() {
                    if self.verify_token_with_jwks(token, &jwks).is_ok() {
                        self.resume_http_request();
                        return;
                    }
                }
            } else {
                log::error!("[jwt:{}] Failed to parse JWKS response", self.context_id);
            }
        }
        
        // Failed to verify
        self.send_unauthorized("Invalid token");
    }
}

impl HttpContext for JwtFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Check skip paths
        if let Some(path) = self.get_http_request_header(":path") {
            if self.config.should_skip(&path) {
                log::debug!("[jwt:{}] Path skipped: {}", self.context_id, path);
                return Action::Continue;
            }
        }

        // Extract token
        let token = match self.extract_token() {
            Some(t) => t,
            None => {
                self.send_unauthorized("Missing authentication token");
                return Action::Pause;
            }
        };

        // Parse JWT
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            self.send_unauthorized("Invalid token format");
            return Action::Pause;
        }

        // Decode header
        let header = match self.decode_header(parts[0]) {
            Some(h) => h,
            None => {
                self.send_unauthorized("Invalid token header");
                return Action::Pause;
            }
        };

        // Check algorithm
        if !self.config.algorithms.contains(&header.alg) {
            self.send_unauthorized("Unsupported algorithm");
            return Action::Pause;
        }

        // Decode claims
        let claims = match self.decode_claims(parts[1]) {
            Some(c) => c,
            None => {
                self.send_unauthorized("Invalid token claims");
                return Action::Pause;
            }
        };

        // Validate claims
        if let Err(msg) = self.validate_claims(&claims) {
            self.send_unauthorized(&msg);
            return Action::Pause;
        }

        // Verify signature
        let header_payload = format!("{}.{}", parts[0], parts[1]);
        
        match header.alg.as_str() {
            "HS256" => {
                if let Some(result) = self.verify_hs256(&header, &header_payload, parts[2]) {
                    if !matches!(result, VerifyResult::Valid) {
                        self.send_unauthorized("Invalid signature");
                        return Action::Pause;
                    }
                } else {
                    self.send_unauthorized("Key not found");
                    return Action::Pause;
                }
            }
            "RS256" => {
                // Check if we need to fetch JWKS
                if self.config.jwks_url.is_some() {
                    self.cached_token = Some(token.clone());
                    
                    // Try to fetch JWKS
                    if self.fetch_jwks() {
                        self.pending_jwks_fetch = true;
                        return Action::Pause;
                    } else {
                        self.send_unauthorized("Failed to fetch JWKS");
                        return Action::Pause;
                    }
                } else {
                    self.send_unauthorized("RS256 requires JWKS URL");
                    return Action::Pause;
                }
            }
            _ => {
                self.send_unauthorized("Unsupported algorithm");
                return Action::Pause;
            }
        }

        // Add claims as headers
        self.add_claims_headers(&claims);

        Action::Continue
    }

    fn on_log(&mut self) {
        log::debug!("[jwt:{}] Request completed", self.context_id);
    }
}

impl JwtFilter {
    fn extract_token(&self) -> Option<String> {
        let header_value = self.get_http_request_header(&self.config.header_name)?;
        
        // Support "Bearer <token>" format
        if header_value.starts_with("Bearer ") || header_value.starts_with("bearer ") {
            Some(header_value[7..].trim().to_string())
        } else {
            Some(header_value)
        }
    }

    fn decode_header(&self, header_b64: &str) -> Option<JwtHeader> {
        let bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn decode_claims(&self, claims_b64: &str) -> Option<JwtClaims> {
        let bytes = URL_SAFE_NO_PAD.decode(claims_b64).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn validate_claims(&self, claims: &JwtClaims) -> Result<(), String> {
        // Check expiration
        if let Some(exp) = claims.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if now > exp {
                return Err("Token expired".to_string());
            }
        }

        // Check issuer
        if let Some(ref expected_iss) = self.config.issuer {
            match &claims.iss {
                Some(iss) if iss == expected_iss => {}
                _ => return Err("Invalid issuer".to_string()),
            }
        }

        // Check audience
        if let Some(ref expected_aud) = self.config.audience {
            let aud_matches = match &claims.aud {
                Some(serde_json::Value::String(s)) => s == expected_aud,
                Some(serde_json::Value::Array(arr)) => {
                    arr.iter().any(|v| v.as_str() == Some(expected_aud.as_str()))
                }
                _ => false,
            };
            
            if !aud_matches {
                return Err("Invalid audience".to_string());
            }
        }

        Ok(())
    }

    fn verify_hs256(&self, header: &JwtHeader, header_payload: &str, signature: &str) -> Option<VerifyResult> {
        // Find key by kid or use first available
        let secret_b64 = if let Some(ref kid) = header.kid {
            self.config.static_keys.get(kid)?
        } else {
            self.config.static_keys.values().next()?
        };

        let secret = URL_SAFE_NO_PAD.decode(secret_b64).ok()?;
        Some(crypto::verify_hs256(header_payload, signature, &secret))
    }

    fn verify_token_with_jwks(&self, token: &str, jwks: &Jwks) -> Result<(), String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid format".to_string());
        }

        let header = self.decode_header(parts[0]).ok_or("Invalid header")?;
        let header_payload = format!("{}.{}", parts[0], parts[1]);

        // Find key
        let jwk = if let Some(ref kid) = header.kid {
            jwks.find_key(kid)
        } else {
            jwks.first_rsa_key()
        }.ok_or("Key not found")?;

        // Verify
        match crypto::verify_rs256(&header_payload, parts[2], jwk) {
            VerifyResult::Valid => Ok(()),
            _ => Err("Invalid signature".to_string()),
        }
    }

    fn fetch_jwks(&self) -> bool {
        let jwks_url = match &self.config.jwks_url {
            Some(url) => url,
            None => return false,
        };

        // Parse URL to get host and path
        let url_without_scheme = if jwks_url.starts_with("https://") {
            &jwks_url[8..]
        } else if jwks_url.starts_with("http://") {
            &jwks_url[7..]
        } else {
            jwks_url.as_str()
        };

        let (host, path) = match url_without_scheme.find('/') {
            Some(pos) => (&url_without_scheme[..pos], &url_without_scheme[pos..]),
            None => (url_without_scheme, "/"),
        };

        let headers = vec![
            (":method", "GET"),
            (":path", path),
            (":authority", host),
            ("accept", "application/json"),
        ];

        match self.dispatch_http_call(
            &self.config.jwks_upstream,
            headers,
            None,
            vec![],
            Duration::from_secs(5),
        ) {
            Ok(_) => {
                log::debug!("[jwt:{}] JWKS fetch dispatched to {}", self.context_id, jwks_url);
                true
            }
            Err(e) => {
                log::error!("[jwt:{}] Failed to dispatch JWKS fetch: {:?}", self.context_id, e);
                false
            }
        }
    }

    fn add_claims_headers(&self, claims: &JwtClaims) {
        for (claim, header) in &self.config.claims_to_headers {
            let value = match claim.as_str() {
                "sub" => claims.sub.as_ref().map(|s| s.to_string()),
                "email" => claims.email.as_ref().map(|s| s.to_string()),
                "iss" => claims.iss.as_ref().map(|s| s.to_string()),
                _ => claims.extra.get(claim).and_then(|v| {
                    match v {
                        serde_json::Value::String(s) => Some(s.clone()),
                        _ => Some(v.to_string()),
                    }
                }),
            };

            if let Some(v) = value {
                self.add_http_request_header(header, &v);
            }
        }
    }

    fn send_unauthorized(&self, message: &str) {
        log::warn!("[jwt:{}] Unauthorized: {}", self.context_id, message);
        self.send_http_response(
            401,
            vec![
                ("content-type", "application/json"),
                ("www-authenticate", "Bearer"),
            ],
            Some(format!(r#"{{"error":"unauthorized","message":"{}"}}"#, message).as_bytes()),
        );
    }
}
