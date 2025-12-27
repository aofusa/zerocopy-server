//! Distributed Cache Proxy-Wasm Filter
//!
//! Caches HTTP GET responses using external backends:
//! - Redis via Webdis HTTP API
//! - Memcached via HTTP API
//!
//! Features:
//! - Configurable backend selection
//! - Cache key generation from URL and headers
//! - Cache-Control header support
//! - Cache bypass header

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::time::Duration;

mod memcached;
mod redis;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CacheFilterRoot::new())
    });
}}

/// Cache backend type
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    Redis,
    Memcached,
}

impl Default for CacheBackend {
    fn default() -> Self {
        CacheBackend::Redis
    }
}

/// Cache filter configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Cache backend to use
    #[serde(default)]
    pub backend: CacheBackend,
    
    /// Redis configuration
    #[serde(default)]
    pub redis: RedisConfig,
    
    /// Memcached configuration
    #[serde(default)]
    pub memcached: MemcachedConfig,
    
    /// Default TTL in seconds
    #[serde(default = "default_ttl")]
    pub default_ttl_secs: u64,
    
    /// HTTP methods to cache
    #[serde(default = "default_cache_methods")]
    pub cache_methods: Vec<String>,
    
    /// Headers to include in cache key
    #[serde(default)]
    pub key_headers: Vec<String>,
    
    /// Header to bypass cache
    #[serde(default = "default_bypass_header")]
    pub bypass_header: String,
    
    /// Paths to skip caching
    #[serde(default)]
    pub skip_paths: Vec<String>,
    
    /// Upstream cluster name for cache backend
    #[serde(default = "default_upstream")]
    pub upstream: String,
    
    /// Timeout for cache GET operations (seconds)
    #[serde(default = "default_get_timeout")]
    pub get_timeout_secs: u64,
    
    /// Timeout for cache SET operations (seconds)
    #[serde(default = "default_set_timeout")]
    pub set_timeout_secs: u64,
    
    /// Headers to save in cache (empty = save important headers only)
    #[serde(default)]
    pub save_headers: Vec<String>,
    
    /// Headers to exclude from cache (always excluded)
    #[serde(default = "default_exclude_headers")]
    pub exclude_headers: Vec<String>,
    
    /// Header to trigger cache invalidation
    #[serde(default = "default_invalidate_header")]
    pub invalidate_header: String,
    
    /// Enable cache invalidation
    #[serde(default = "default_invalidate_enabled")]
    pub invalidate_enabled: bool,
    
    /// Automatically include Vary headers in cache key
    #[serde(default = "default_vary_enabled")]
    pub vary_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Webdis URL base (just the host, path is built dynamically)
    #[serde(default = "default_redis_host")]
    pub host: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemcachedConfig {
    /// Memcached HTTP API host
    #[serde(default = "default_memcached_host")]
    pub host: String,
}

fn default_ttl() -> u64 { 300 }
fn default_cache_methods() -> Vec<String> { vec!["GET".to_string(), "HEAD".to_string()] }
fn default_bypass_header() -> String { "X-Cache-Bypass".to_string() }
fn default_upstream() -> String { "cache".to_string() }
fn default_redis_host() -> String { "webdis".to_string() }
fn default_memcached_host() -> String { "memcached-http".to_string() }
fn default_get_timeout() -> u64 { 1 }
fn default_set_timeout() -> u64 { 1 }
fn default_exclude_headers() -> Vec<String> {
    vec![
        "connection".to_string(),
        "transfer-encoding".to_string(),
        "content-length".to_string(),
    ]
}
fn default_invalidate_header() -> String { "X-Cache-Invalidate".to_string() }
fn default_invalidate_enabled() -> bool { false }
fn default_vary_enabled() -> bool { true }

impl Default for RedisConfig {
    fn default() -> Self {
        Self { host: "webdis".to_string() }
    }
}

impl Default for MemcachedConfig {
    fn default() -> Self {
        Self { host: "memcached-http".to_string() }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::Redis,
            redis: RedisConfig::default(),
            memcached: MemcachedConfig::default(),
            default_ttl_secs: 300,
            cache_methods: vec!["GET".to_string(), "HEAD".to_string()],
            key_headers: vec!["Accept".to_string(), "Accept-Encoding".to_string()],
            bypass_header: "X-Cache-Bypass".to_string(),
            skip_paths: vec!["/health".to_string(), "/metrics".to_string()],
            upstream: "cache".to_string(),
            get_timeout_secs: 1,
            set_timeout_secs: 1,
            save_headers: vec![],
            exclude_headers: default_exclude_headers(),
            invalidate_header: "X-Cache-Invalidate".to_string(),
            invalidate_enabled: false,
            vary_enabled: true,
        }
    }
}

impl CacheConfig {
    pub fn should_skip(&self, path: &str) -> bool {
        self.skip_paths.iter().any(|p| path.starts_with(p))
    }

    pub fn should_cache_method(&self, method: &str) -> bool {
        self.cache_methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }
}

/// Cache operation type
#[derive(Debug, Clone, Copy, PartialEq)]
enum CacheOp {
    Get,
    #[allow(dead_code)]
    Set, // Fire-and-forgetで使用されるため、pending_opには設定されない
}

struct CacheFilterRoot {
    config: CacheConfig,
}

impl CacheFilterRoot {
    fn new() -> Self {
        Self {
            config: CacheConfig::default(),
        }
    }
}

impl Context for CacheFilterRoot {}

impl RootContext for CacheFilterRoot {
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        if plugin_configuration_size == 0 {
            log::info!("[cache] Using default configuration (Redis backend)");
            return true;
        }

        if let Some(config_bytes) = self.get_plugin_configuration() {
            match serde_json::from_slice::<CacheConfig>(&config_bytes) {
                Ok(config) => {
                    log::info!(
                        "[cache] Configuration loaded: backend={:?}, ttl={}s",
                        config.backend,
                        config.default_ttl_secs
                    );
                    self.config = config;
                }
                Err(e) => {
                    log::error!("[cache] Failed to parse configuration: {}", e);
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
        Some(Box::new(CacheFilter {
            context_id,
            config: self.config.clone(),
            cache_key: None,
            pending_op: None,
            cached_response: None,
            if_none_match: None,
            cache_ttl: None,
            vary_headers: None,
        }))
    }
}

struct CacheFilter {
    context_id: u32,
    config: CacheConfig,
    cache_key: Option<String>,
    pending_op: Option<CacheOp>,
    #[allow(dead_code)]
    cached_response: Option<CachedResponse>, // 将来の拡張用に保持
    if_none_match: Option<String>,
    cache_ttl: Option<u64>,
    vary_headers: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String, // Base64エンコードされた文字列として保存
    #[serde(skip_serializing_if = "Option::is_none")]
    vary_headers: Option<Vec<String>>,
}

impl Context for CacheFilter {
    fn on_http_call_response(&mut self, _token_id: u32, _num_headers: usize, body_size: usize, _num_trailers: usize) {
        let op = self.pending_op.take();
        
        match op {
            Some(CacheOp::Get) => {
                if let Some(body) = self.get_http_call_response_body(0, body_size) {
                    let cached_value = match self.config.backend {
                        CacheBackend::Redis => redis::parse_get_response(&body),
                        CacheBackend::Memcached => memcached::parse_get_response(&body),
                    };

                    if let Some(value) = cached_value {
                        log::info!("[cache:{}] Cache HIT for key {:?}", 
                            self.context_id, self.cache_key);
                        
                        // Parse cached response and serve it
                        if let Some(cached) = self.parse_cached_response(&value) {
                            // ETagを取得
                            let cached_etag = cached.headers.iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
                                .map(|(_, v)| v.clone());
                            
                            // If-None-Match と比較
                            if let (Some(ref if_none_match), Some(ref cached_etag)) = 
                                (&self.if_none_match, &cached_etag) {
                                
                                // ETagの比較
                                if Self::etag_matches(if_none_match, cached_etag) {
                                    // 304 Not Modified を返却
                                    self.add_http_response_header("X-Cache", "HIT");
                                    self.add_http_response_header("ETag", cached_etag);
                                    
                                    // 他のキャッシュ関連ヘッダも追加
                                    if let Some(last_modified) = cached.headers.iter()
                                        .find(|(k, _)| k.eq_ignore_ascii_case("last-modified"))
                                        .map(|(_, v)| v.clone()) {
                                        self.add_http_response_header("Last-Modified", &last_modified);
                                    }
                                    
                                    self.send_http_response(304, vec![], None);
                                    return;
                                }
                            }
                            
                            // 通常のキャッシュヒット処理
                            self.add_http_response_header("X-Cache", "HIT");
                            
                            // ボディをデコード
                            let body_bytes = base64_decode(&cached.body).unwrap_or_default();
                            
                            self.send_http_response(
                                cached.status as u32,
                                cached.headers.iter()
                                    .map(|(k, v)| (k.as_str(), v.as_str()))
                                    .collect(),
                                Some(&body_bytes),
                            );
                            return;
                        }
                    }

                    log::debug!("[cache:{}] Cache MISS for key {:?}", 
                        self.context_id, self.cache_key);
                }
                
                // Cache miss - continue to upstream
                self.resume_http_request();
            }
            Some(CacheOp::Set) => {
                log::debug!("[cache:{}] Cache SET completed for key {:?}", 
                    self.context_id, self.cache_key);
            }
            None => {}
        }
    }
}

impl HttpContext for CacheFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Get method and path
        let method = self.get_http_request_header(":method").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();

        // キャッシュ無効化のチェック
        if self.config.invalidate_enabled {
            if let Some(invalidate_value) = self.get_http_request_header(&self.config.invalidate_header) {
                if self.invalidate_cache(&invalidate_value) {
                    log::info!("[cache:{}] Cache invalidated for pattern: {}", 
                        self.context_id, invalidate_value);
                }
            }
        }

        // Check if cacheable
        if !self.config.should_cache_method(&method) {
            return Action::Continue;
        }

        if self.config.should_skip(&path) {
            return Action::Continue;
        }

        // Check bypass header
        if self.get_http_request_header(&self.config.bypass_header).is_some() {
            log::debug!("[cache:{}] Cache bypassed via header", self.context_id);
            return Action::Continue;
        }

        // If-None-Match ヘッダを保存
        self.if_none_match = self.get_http_request_header("if-none-match");

        // Generate cache key
        let cache_key = self.generate_cache_key(&method, &path);
        self.cache_key = Some(cache_key.clone());

        // Try to get from cache
        if self.fetch_from_cache(&cache_key) {
            self.pending_op = Some(CacheOp::Get);
            return Action::Pause;
        }

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Add cache status header
        self.add_http_response_header("X-Cache", "MISS");
        
        // Check if response is cacheable
        if let Some(cache_control) = self.get_http_response_header("cache-control") {
            if cache_control.contains("no-store") || cache_control.contains("private") {
                log::debug!("[cache:{}] Response not cacheable (Cache-Control)", self.context_id);
                self.cache_key = None;
                return Action::Continue;
            }
            
            // TTLを計算（Cache-Controlから抽出）
            let ttl = Self::parse_cache_control(&cache_control)
                .unwrap_or(self.config.default_ttl_secs);
            self.cache_ttl = Some(ttl);
        } else {
            self.cache_ttl = Some(self.config.default_ttl_secs);
        }

        // Varyヘッダを解析
        if self.config.vary_enabled {
            if let Some(vary_value) = self.get_http_response_header("vary") {
                let vary_headers = Self::parse_vary_header(&vary_value);
                self.vary_headers = Some(vary_headers);
            }
        }

        // Only cache successful responses
        if let Some(status) = self.get_http_response_header(":status") {
            if let Ok(code) = status.parse::<u16>() {
                if code < 200 || code >= 300 {
                    self.cache_key = None;
                }
            }
        }

        Action::Continue
    }

    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream {
            return Action::Continue;
        }

        // Cache the response if we have a key
        if let Some(ref cache_key) = self.cache_key.clone() {
            if let Some(body) = self.get_http_response_body(0, body_size) {
                // Get status and headers
                let status = self.get_http_response_header(":status")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200);
                
                // すべての重要なヘッダを収集
                let headers = self.collect_response_headers();
                
                // BodyをBase64エンコード
                let body_b64 = base64_encode(&body);

                let cached = CachedResponse { 
                    status, 
                    headers, 
                    body: body_b64,
                    vary_headers: self.vary_headers.clone(),
                };
                
                // Store in cache
                let ttl = self.cache_ttl.unwrap_or(self.config.default_ttl_secs);
                if let Ok(serialized) = self.serialize_cached_response(&cached) {
                    self.store_in_cache(cache_key, &serialized, ttl);
                } else {
                    log::error!("[cache:{}] Failed to serialize cached response", self.context_id);
                }
            }
        }

        Action::Continue
    }

    fn on_log(&mut self) {
        log::debug!("[cache:{}] Request completed", self.context_id);
    }
}

impl CacheFilter {
    /// Parse Cache-Control header to extract TTL
    fn parse_cache_control(header_value: &str) -> Option<u64> {
        // Cache-Control: max-age=3600, public, no-cache
        // s-maxage を優先
        for directive in header_value.split(',') {
            let directive = directive.trim();
            if let Some(ttl) = Self::parse_directive(directive, "s-maxage") {
                return Some(ttl);
            }
        }
        
        // max-age を次にチェック
        for directive in header_value.split(',') {
            let directive = directive.trim();
            if let Some(ttl) = Self::parse_directive(directive, "max-age") {
                return Some(ttl);
            }
        }
        
        None
    }
    
    fn parse_directive(directive: &str, name: &str) -> Option<u64> {
        if directive.starts_with(name) {
            if let Some(equals_pos) = directive.find('=') {
                let value = directive[equals_pos + 1..].trim();
                value.parse::<u64>().ok()
            } else {
                None
            }
        } else {
            None
        }
    }
    
    /// Compare ETag values (supports weak ETags)
    fn etag_matches(if_none_match: &str, etag: &str) -> bool {
        for tag in if_none_match.split(',') {
            let tag = tag.trim().trim_matches('"');
            let etag_clean = etag.trim().trim_matches('"');
            
            // 弱いETagの処理（W/プレフィックスを無視）
            let tag_stripped = tag.strip_prefix("W/").unwrap_or(tag);
            let etag_stripped = etag_clean.strip_prefix("W/").unwrap_or(etag_clean);
            
            if tag_stripped == etag_stripped {
                return true;
            }
        }
        
        false
    }
    
    /// Parse Vary header
    fn parse_vary_header(vary_value: &str) -> Vec<String> {
        vary_value.split(',')
            .map(|s| s.trim().to_lowercase())
            .collect()
    }
    
    /// Collect response headers to save in cache
    fn collect_response_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        
        // 重要なヘッダを優先的に取得
        let important_headers = vec![
            "content-type",
            "cache-control",
            "etag",
            "last-modified",
            "expires",
            "vary",
        ];
        
        for header_name in &important_headers {
            if let Some(value) = self.get_http_response_header(header_name) {
                // 除外リストに含まれていないかチェック
                if !self.config.exclude_headers.iter()
                    .any(|h| h.eq_ignore_ascii_case(header_name)) {
                    headers.push((header_name.to_string(), value));
                }
            }
        }
        
        // 設定で指定された追加ヘッダを取得
        for header_name in &self.config.save_headers {
            if !important_headers.contains(&header_name.as_str()) {
                if let Some(value) = self.get_http_response_header(header_name) {
                    if !self.config.exclude_headers.iter()
                        .any(|h| h.eq_ignore_ascii_case(header_name)) {
                        headers.push((header_name.clone(), value));
                    }
                }
            }
        }
        
        headers
    }
    
    /// Generate cache key from request (with collision prevention)
    fn generate_cache_key(&self, method: &str, path: &str) -> String {
        let mut key_parts = vec![method.to_string(), path.to_string()];
        
        // Add configured headers to key
        for header_name in &self.config.key_headers {
            if let Some(value) = self.get_http_request_header(header_name) {
                // ヘッダ値が長すぎる場合は切り詰める
                let truncated_value = if value.len() > 100 {
                    &value[..100]
                } else {
                    &value
                };
                key_parts.push(format!("{}={}", header_name, truncated_value));
            }
        }
        
        let key_str = key_parts.join("|");
        let hash = simple_hash(&key_str);
        
        // ハッシュとキー文字列の短縮版を組み合わせ（衝突対策）
        let key_suffix = if key_str.len() > 50 {
            base64_encode(&key_str.as_bytes()[..50])
                .chars()
                .take(20)
                .collect::<String>()
        } else {
            base64_encode(key_str.as_bytes())
                .chars()
                .take(20)
                .collect::<String>()
        };
        
        format!("veil:cache:{}:{}", hash, key_suffix)
    }

    /// Fetch from cache backend
    fn fetch_from_cache(&self, key: &str) -> bool {
        let path = match self.config.backend {
            CacheBackend::Redis => redis::build_get_path(key),
            CacheBackend::Memcached => memcached::build_get_path(key),
        };

        let headers = vec![
            (":method", "GET"),
            (":path", &path),
            (":authority", match self.config.backend {
                CacheBackend::Redis => &self.config.redis.host,
                CacheBackend::Memcached => &self.config.memcached.host,
            }),
        ];

        match self.dispatch_http_call(
            &self.config.upstream,
            headers,
            None,
            vec![],
            Duration::from_secs(self.config.get_timeout_secs),
        ) {
            Ok(_) => true,
            Err(e) => {
                log::error!("[cache:{}] Failed to fetch from cache: {:?}", self.context_id, e);
                false
            }
        }
    }

    /// Store in cache backend
    fn store_in_cache(&self, key: &str, value: &str, ttl_secs: u64) {
        let (path, body) = match self.config.backend {
            CacheBackend::Redis => (
                redis::build_set_path(key, value, Some(ttl_secs)),
                None,
            ),
            CacheBackend::Memcached => (
                "/set".to_string(),
                Some(memcached::build_set_body(key, value, ttl_secs)),
            ),
        };

        let method = match self.config.backend {
            CacheBackend::Redis => "GET",
            CacheBackend::Memcached => "POST",
        };

        let headers = vec![
            (":method", method),
            (":path", &path),
            (":authority", match self.config.backend {
                CacheBackend::Redis => &self.config.redis.host,
                CacheBackend::Memcached => &self.config.memcached.host,
            }),
            ("content-type", "application/json"),
        ];

        if let Err(e) = self.dispatch_http_call(
            &self.config.upstream,
            headers,
            body.as_deref(),
            vec![],
            Duration::from_secs(self.config.set_timeout_secs),
        ) {
            log::error!("[cache:{}] Failed to store in cache: {:?}", self.context_id, e);
        }
        // Note: Store is fire-and-forget, no need to track pending_op
    }
    
    /// Invalidate cache for a pattern
    fn invalidate_cache(&self, pattern: &str) -> bool {
        // シンプルな実装: 特定のキーを削除
        // 将来的にワイルドカードパターンをサポート可能
        let cache_key = if pattern.starts_with("veil:cache:") {
            pattern.to_string()
        } else {
            // パターンからキーを生成（簡易実装）
            format!("veil:cache:{}", simple_hash(pattern))
        };
        
        match self.config.backend {
            CacheBackend::Redis => {
                let path = redis::build_delete_path(&cache_key);
                self.delete_from_cache(&path)
            }
            CacheBackend::Memcached => {
                let path = memcached::build_delete_path(&cache_key);
                self.delete_from_cache(&path)
            }
        }
    }
    
    /// Delete from cache backend
    fn delete_from_cache(&self, path: &str) -> bool {
        let headers = vec![
            (":method", "GET"), // WebdisはGET /DEL/{key}を使用
            (":path", path),
            (":authority", match self.config.backend {
                CacheBackend::Redis => &self.config.redis.host,
                CacheBackend::Memcached => &self.config.memcached.host,
            }),
        ];
        
        // 注意: DELETE操作は非同期だが、fire-and-forgetで実行
        match self.dispatch_http_call(
            &self.config.upstream,
            headers,
            None,
            vec![],
            Duration::from_secs(self.config.get_timeout_secs),
        ) {
            Ok(_) => {
                log::debug!("[cache:{}] Cache deletion dispatched", self.context_id);
                true
            }
            Err(e) => {
                log::error!("[cache:{}] Failed to delete cache: {:?}", self.context_id, e);
                false
            }
        }
    }

    /// Serialize cached response using serde_json
    fn serialize_cached_response(&self, cached: &CachedResponse) -> Result<String, serde_json::Error> {
        serde_json::to_string(cached)
    }

    /// Parse cached response from serialized format
    fn parse_cached_response(&self, value: &str) -> Option<CachedResponse> {
        let parsed: CachedResponse = serde_json::from_str(value).ok()?;
        Some(parsed)
    }
}

/// Simple hash function for cache keys
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    }
    hash
}

/// Base64 encoding using standard library
fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Base64 decoding using standard library
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}
