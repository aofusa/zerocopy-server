use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use httparse::{Request, Status, Header};
use monoio::fs::OpenOptions;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use monoio::RuntimeBuilder;
use monoio::time::timeout;
use monoio_rustls::{TlsAcceptor, TlsConnector, ServerTlsStream, ClientTlsStream};
use rustls::{ServerConfig, ClientConfig, RootCertStore};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls_pemfile::{certs, private_key};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use ftlog::{info, error, warn};
use time::OffsetDateTime;

// ====================
// 定数定義（パフォーマンスチューニング済み）
// ====================

// エラーレスポンス用静的バッファ
static ERR_MSG_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static ERR_MSG_FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static ERR_MSG_NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static ERR_MSG_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static ERR_MSG_REQUEST_TOO_LARGE: &[u8] = b"HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static ERR_MSG_GATEWAY_TIMEOUT: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

// HTTP ヘッダー部品（事前計算）
static HTTP_200_PREFIX: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: ";
static CONTENT_LENGTH_HEADER: &[u8] = b"\r\nContent-Length: ";
static CONNECTION_KEEP_ALIVE: &[u8] = b"\r\nConnection: keep-alive\r\n\r\n";
static CONNECTION_CLOSE: &[u8] = b"\r\nConnection: close\r\n\r\n";

// バッファサイズ（ページアライン・L2キャッシュ最適化）
const BUF_SIZE: usize = 65536;           // 64KB - io_uring最適サイズ
const HEADER_BUF_CAPACITY: usize = 512;  // HTTPヘッダー用

// セキュリティ制限
const MAX_HEADER_SIZE: usize = 8192;     // 8KB - ヘッダーサイズ上限
const MAX_BODY_SIZE: usize = 10485760;   // 10MB - ボディサイズ上限

// タイムアウト設定
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

// バックエンドコネクションプール設定
const BACKEND_POOL_MAX_IDLE_PER_HOST: usize = 8;    // ホストあたりの最大アイドル接続数
const BACKEND_POOL_IDLE_TIMEOUT_SECS: u64 = 30;     // アイドル接続のタイムアウト（秒）

// ====================
// Graceful Shutdown フラグ
// ====================

static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

// ====================
// TLSコネクタ（スレッドローカル）
// ====================

thread_local! {
    static TLS_CONNECTOR: TlsConnector = {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        TlsConnector::from(Arc::new(client_config))
    };
}

// ====================
// バックエンドコネクションプール
// ====================
//
// スレッドローカルなコネクションプールにより、バックエンドへの接続を再利用します。
// HTTP用とHTTPS用で別々のプールを管理し、ホスト:ポートをキーにしています。
// ====================

/// プールされた接続のエントリ
struct PooledConnection<T> {
    stream: T,
    created_at: std::time::Instant,
}

impl<T> PooledConnection<T> {
    fn new(stream: T) -> Self {
        Self {
            stream,
            created_at: std::time::Instant::now(),
        }
    }
    
    /// 接続がまだ有効かどうかを判定（タイムアウトチェック）
    fn is_valid(&self) -> bool {
        self.created_at.elapsed().as_secs() < BACKEND_POOL_IDLE_TIMEOUT_SECS
    }
}

/// HTTPバックエンド用コネクションプール（TcpStream）
struct HttpConnectionPool {
    connections: HashMap<String, VecDeque<PooledConnection<TcpStream>>>,
}

impl HttpConnectionPool {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }
    
    /// プールから接続を取得（有効な接続がなければNone）
    fn get(&mut self, key: &str) -> Option<TcpStream> {
        if let Some(queue) = self.connections.get_mut(key) {
            while let Some(entry) = queue.pop_front() {
                if entry.is_valid() {
                    return Some(entry.stream);
                }
                // 無効な接続は破棄
            }
        }
        None
    }
    
    /// 接続をプールに返却
    fn put(&mut self, key: String, stream: TcpStream) {
        let queue = self.connections.entry(key).or_insert_with(VecDeque::new);
        
        // 古い接続を削除
        while queue.len() >= BACKEND_POOL_MAX_IDLE_PER_HOST {
            queue.pop_front();
        }
        
        queue.push_back(PooledConnection::new(stream));
    }
}

/// HTTPSバックエンド用コネクションプール（ClientTlsStream<TcpStream>）
struct HttpsConnectionPool {
    connections: HashMap<String, VecDeque<PooledConnection<ClientTlsStream<TcpStream>>>>,
}

impl HttpsConnectionPool {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }
    
    /// プールから接続を取得（有効な接続がなければNone）
    fn get(&mut self, key: &str) -> Option<ClientTlsStream<TcpStream>> {
        if let Some(queue) = self.connections.get_mut(key) {
            while let Some(entry) = queue.pop_front() {
                if entry.is_valid() {
                    return Some(entry.stream);
                }
                // 無効な接続は破棄
            }
        }
        None
    }
    
    /// 接続をプールに返却
    fn put(&mut self, key: String, stream: ClientTlsStream<TcpStream>) {
        let queue = self.connections.entry(key).or_insert_with(VecDeque::new);
        
        // 古い接続を削除
        while queue.len() >= BACKEND_POOL_MAX_IDLE_PER_HOST {
            queue.pop_front();
        }
        
        queue.push_back(PooledConnection::new(stream));
    }
}

thread_local! {
    static HTTP_POOL: RefCell<HttpConnectionPool> = RefCell::new(HttpConnectionPool::new());
    static HTTPS_POOL: RefCell<HttpsConnectionPool> = RefCell::new(HttpsConnectionPool::new());
}

// ====================
// バッファプール
// ====================
//
// 注意: monoioのAsyncWriteRentExtはバッファの所有権を取るため、
// 完全なゼロコピーは実現できません。バッファプールによりアロケーション
// コストを削減していますが、Arc<Vec<u8>>からのコピーは避けられません。
// ====================

thread_local! {
    static BUF_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(
        (0..32).map(|_| vec![0u8; BUF_SIZE]).collect()
    );
}

/// バッファ取得ヘルパー
#[inline(always)]
fn buf_get() -> Vec<u8> {
    BUF_POOL.with(|p| {
        p.borrow_mut().pop().unwrap_or_else(|| vec![0u8; BUF_SIZE])
    })
}

/// バッファ返却ヘルパー（安全化済み）
/// 
/// # Safety considerations
/// 以前は `unsafe { buf.set_len(BUF_SIZE) }` を使用していましたが、
/// これは未初期化メモリへのアクセスリスク（Heartbleed類似の脆弱性）があるため、
/// `resize(BUF_SIZE, 0)` によるゼロ初期化に変更しました。
/// 
/// パフォーマンスへの影響:
/// - 64KBのゼロ初期化は最新CPUでは数マイクロ秒程度
/// - セキュリティとのトレードオフとして許容可能
#[inline(always)]
fn buf_put(mut buf: Vec<u8>) {
    BUF_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        if pool.len() < 128 {
            // 安全のため、長さをクリアしてからゼロ初期化
            // これにより前回のリクエストデータが残らない
            buf.clear();
            buf.resize(BUF_SIZE, 0);
            pool.push(buf);
        }
    });
}

// ====================
// 設定構造体
// ====================

#[derive(Deserialize)]
struct Config {
    server: ServerConfigSection,
    tls: TlsConfigSection,
    host_routes: Option<HashMap<String, BackendConfig>>,
    path_routes: Option<HashMap<String, HashMap<String, BackendConfig>>>,
}

#[derive(Deserialize)]
struct ServerConfigSection {
    listen: String,
}

#[derive(Deserialize)]
struct TlsConfigSection {
    cert_path: String,
    key_path: String,
}

#[derive(Clone)]
enum BackendConfig {
    Proxy { url: String },
    File { path: String, mode: String },
}

impl<'de> serde::Deserialize<'de> for BackendConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        
        struct BackendConfigVisitor;
        
        impl<'de> Visitor<'de> for BackendConfigVisitor {
            type Value = BackendConfig;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a backend configuration object")
            }
            
            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut backend_type: Option<String> = None;
                let mut url: Option<String> = None;
                let mut path: Option<String> = None;
                let mut mode: Option<String> = None;
                
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => backend_type = Some(map.next_value()?),
                        "url" => url = Some(map.next_value()?),
                        "path" => path = Some(map.next_value()?),
                        "mode" => mode = Some(map.next_value()?),
                        _ => { let _: serde::de::IgnoredAny = map.next_value()?; }
                    }
                }
                
                let backend_type = backend_type.unwrap_or_else(|| "File".to_string());
                
                match backend_type.as_str() {
                    "Proxy" => {
                        let url = url.ok_or_else(|| serde::de::Error::missing_field("url"))?;
                        Ok(BackendConfig::Proxy { url })
                    }
                    "File" | _ => {
                        let path = path.ok_or_else(|| serde::de::Error::missing_field("path"))?;
                        let mode = mode.unwrap_or_else(|| "sendfile".to_string());
                        Ok(BackendConfig::File { path, mode })
                    }
                }
            }
        }
        
        deserializer.deserialize_map(BackendConfigVisitor)
    }
}

// ====================
// ランタイムBackend
// ====================

#[derive(Clone)]
enum Backend {
    Proxy(Arc<ProxyTarget>),
    MemoryFile(Arc<Vec<u8>>, Arc<str>),  // (content, mime_type)
    SendFile(Arc<PathBuf>, bool),         // (path, is_directory)
}

#[derive(Clone)]
struct ProxyTarget {
    host: String,
    port: u16,
    use_tls: bool,
    path_prefix: String,
}

impl ProxyTarget {
    fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = if url.starts_with("https://") {
            (true, &url[8..])
        } else if url.starts_with("http://") {
            (false, &url[7..])
        } else {
            return None;
        };

        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        let (host, port) = match host_port.find(':') {
            Some(idx) => {
                let h = &host_port[..idx];
                let p = host_port[idx + 1..].parse().ok()?;
                (h.to_string(), p)
            }
            None => (host_port.to_string(), if scheme { 443 } else { 80 }),
        };

        Some(ProxyTarget {
            host,
            port,
            use_tls: scheme,
            path_prefix: path.to_string(),
        })
    }
    
    /// デフォルトポートかどうかを判定
    #[inline]
    fn is_default_port(&self) -> bool {
        if self.use_tls {
            self.port == 443
        } else {
            self.port == 80
        }
    }
}

// ソート済みプレフィックスマップ
#[derive(Clone)]
struct SortedPathMap {
    prefixes: Vec<Arc<[u8]>>,
    backends: Vec<Backend>,
}

impl SortedPathMap {
    fn find_longest(&self, path: &[u8]) -> Option<(&[u8], &Backend)> {
        for (i, prefix) in self.prefixes.iter().enumerate() {
            if path.starts_with(prefix.as_ref()) {
                return Some((prefix.as_ref(), &self.backends[i]));
            }
        }
        None
    }
}

// ====================
// 非同期I/Oトレイト（コード重複解消）
// ====================

/// 非同期読み込みトレイト
trait AsyncReader {
    async fn read_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>);
}

/// 非同期書き込みトレイト
trait AsyncWriter {
    async fn write_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>);
}

// TcpStream用の実装
impl AsyncReader for TcpStream {
    async fn read_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        self.read(buf).await
    }
}

impl AsyncWriter for TcpStream {
    async fn write_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        self.write_all(buf).await
    }
}

// ServerTlsStream用の実装
impl AsyncReader for ServerTlsStream<TcpStream> {
    async fn read_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        self.read(buf).await
    }
}

impl AsyncWriter for ServerTlsStream<TcpStream> {
    async fn write_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        self.write_all(buf).await
    }
}

// ClientTlsStream用の実装
impl AsyncReader for ClientTlsStream<TcpStream> {
    async fn read_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        self.read(buf).await
    }
}

impl AsyncWriter for ClientTlsStream<TcpStream> {
    async fn write_buf(&mut self, buf: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        self.write_all(buf).await
    }
}

// ====================
// 設定読み込み
// ====================

fn load_tls_config(tls_config: &TlsConfigSection) -> io::Result<Arc<ServerConfig>> {
    let cert_file = File::open(&tls_config.cert_path)?;
    let key_file = File::open(&tls_config.key_path)?;

    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let mut key_reader = BufReader::new(key_file);
    let keys = private_key(&mut key_reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Private key not found"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Arc::new(config))
}

fn load_config(path: &Path) -> io::Result<(String, Arc<ServerConfig>, Arc<HashMap<Box<[u8]>, Backend>>, Arc<HashMap<Box<[u8]>, SortedPathMap>>)> {
    let config_str = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TOML parse error: {}", e)))?;

    let tls_config = load_tls_config(&config.tls)?;

    let mut host_routes_bytes: HashMap<Box<[u8]>, Backend> = HashMap::new();
    if let Some(host_routes) = config.host_routes {
        for (k, v) in host_routes {
            let backend = load_backend(&v)?;
            host_routes_bytes.insert(k.into_bytes().into_boxed_slice(), backend);
        }
    }

    let mut path_routes_bytes: HashMap<Box<[u8]>, SortedPathMap> = HashMap::new();
    if let Some(path_routes) = config.path_routes {
        for (host, path_map) in path_routes {
            let mut entries: Vec<(String, Backend)> = Vec::with_capacity(path_map.len());
            for (k, v) in path_map {
                entries.push((k, load_backend(&v)?));
            }
            entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
            
            let prefixes: Vec<Arc<[u8]>> = entries.iter()
                .map(|(k, _)| Arc::from(k.as_bytes()))
                .collect();
            let backends: Vec<Backend> = entries.into_iter().map(|(_, v)| v).collect();
            
            path_routes_bytes.insert(
                host.into_bytes().into_boxed_slice(),
                SortedPathMap { prefixes, backends }
            );
        }
    }

    Ok((config.server.listen, tls_config, Arc::new(host_routes_bytes), Arc::new(path_routes_bytes)))
}

fn load_backend(config: &BackendConfig) -> io::Result<Backend> {
    match config {
        BackendConfig::Proxy { url } => {
            let target = ProxyTarget::parse(url)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid proxy URL"))?;
            Ok(Backend::Proxy(Arc::new(target)))
        }
        BackendConfig::File { path, mode } => {
            let metadata = fs::metadata(path)?;
            let is_dir = metadata.is_dir();
            match mode.as_str() {
                "memory" => {
                    if is_dir {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Memory mode not supported for directories"));
                    }
                    let data = fs::read(path)?;
                    let mime_type = mime_guess::from_path(path).first_or_octet_stream();
                    
                    Ok(Backend::MemoryFile(Arc::new(data), Arc::from(mime_type.as_ref())))
                }
                "sendfile" | "" => Ok(Backend::SendFile(Arc::new(PathBuf::from(path)), is_dir)),
                _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid mode")),
            }
        }
    }
}

// ====================
// メイン関数
// ====================

fn main() {
    // rustls 0.23+: プロセスレベルで暗号プロバイダーをインストール（ring使用）
    CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("Failed to install rustls crypto provider");
    
    let _guard = ftlog::Builder::new().try_init().unwrap();

    let (listen_addr_str, tls_config, host_routes, path_routes) = match load_config(Path::new("config.toml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config load error: {}", e);
            return;
        }
    };
    
    let acceptor = TlsAcceptor::from(tls_config);
    let listen_addr = listen_addr_str.parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 443)));

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());
    
    info!("============================================");
    info!("High-Performance Reverse Proxy Server");
    info!("Hostname: {}", hostname);
    info!("Listen Address: {}", listen_addr);
    info!("Threads: {}", num_cpus::get());
    info!("Read Timeout: {:?}", READ_TIMEOUT);
    info!("Write Timeout: {:?}", WRITE_TIMEOUT);
    info!("Connect Timeout: {:?}", CONNECT_TIMEOUT);
    info!("Idle Timeout: {:?}", IDLE_TIMEOUT);
    info!("============================================");

    // Graceful Shutdown用のシグナルハンドラを設定
    setup_signal_handler();

    let num_threads = num_cpus::get();
    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let acceptor_clone = acceptor.clone();
        let host_routes_clone = host_routes.clone();
        let path_routes_clone = path_routes.clone();
        let addr = listen_addr;

        let handle = thread::spawn(move || {
            let mut rt = RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .expect("Failed to create runtime");
            rt.block_on(async move {
                let listener = match create_listener(addr) {
                    Ok(l) => l,
                    Err(e) => {
                        error!("[Thread {}] Bind error: {}", thread_id, e);
                        return;
                    }
                };

                info!("[Thread {}] Worker started", thread_id);

                loop {
                    // Shutdown チェック
                    if SHUTDOWN_FLAG.load(Ordering::Relaxed) {
                        info!("[Thread {}] Shutting down...", thread_id);
                        break;
                    }

                    // タイムアウト付きaccept（Graceful Shutdown対応）
                    let accept_result = timeout(Duration::from_secs(1), listener.accept()).await;
                    
                    let (stream, peer_addr) = match accept_result {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            error!("[Thread {}] Accept error: {}", thread_id, e);
                            continue;
                        }
                        Err(_) => {
                            // タイムアウト - ループを継続してshutdownチェック
                            continue;
                        }
                    };
                    
                    let _ = stream.set_nodelay(true);
                    
                    let acceptor = acceptor_clone.clone();
                    let host_routes = host_routes_clone.clone();
                    let path_routes = path_routes_clone.clone();
                    
                    monoio::spawn(async move {
                        handle_connection(stream, acceptor, host_routes, path_routes, peer_addr).await;
                    });
                }
                
                info!("[Thread {}] Worker stopped", thread_id);
            });
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }
    
    info!("Server shutdown complete");
}

/// シグナルハンドラのセットアップ
fn setup_signal_handler() {
    // SIGINT, SIGTERM をキャッチしてシャットダウンフラグを設定
    ctrlc::set_handler(move || {
        info!("Received shutdown signal, initiating graceful shutdown...");
        SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
    }).expect("Failed to set signal handler");
}

fn create_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let config = monoio::net::ListenerConfig::default()
        .reuse_port(true)
        .backlog(8192);
    TcpListener::bind_with_config(addr, &config)
}

// ====================
// 接続処理
// ====================

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    host_routes: Arc<HashMap<Box<[u8]>, Backend>>,
    path_routes: Arc<HashMap<Box<[u8]>, SortedPathMap>>,
    _peer_addr: SocketAddr,
) {
    // TLSハンドシェイクにタイムアウトを設定
    let tls_result = timeout(CONNECT_TIMEOUT, acceptor.accept(stream)).await;
    
    let tls_stream = match tls_result {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            warn!("TLS handshake error: {}", e);
            return;
        }
        Err(_) => {
            warn!("TLS handshake timeout");
            return;
        }
    };

    handle_requests(tls_stream, &host_routes, &path_routes).await;
}

// ====================
// リクエスト処理ループ
// ====================

async fn handle_requests(
    mut tls_stream: ServerTlsStream<TcpStream>,
    host_routes: &Arc<HashMap<Box<[u8]>, Backend>>,
    path_routes: &Arc<HashMap<Box<[u8]>, SortedPathMap>>,
) {
    let mut accumulated = Vec::with_capacity(BUF_SIZE);

    loop {
        // 読み込み（アイドルタイムアウト付き）
        let read_buf = buf_get();
        let read_result = timeout(IDLE_TIMEOUT, tls_stream.read(read_buf)).await;
        
        let (res, returned_buf) = match read_result {
            Ok(result) => result,
            Err(_) => {
                // アイドルタイムアウト - 接続を閉じる
                return;
            }
        };
        
        let n = match res {
            Ok(0) => {
                buf_put(returned_buf);
                return;
            }
            Ok(n) => n,
            Err(_) => {
                buf_put(returned_buf);
                return;
            }
        };
        
        // 読み込んだデータを蓄積
        accumulated.extend_from_slice(&returned_buf[..n]);
        buf_put(returned_buf);

        // ヘッダーサイズ制限チェック
        if accumulated.len() > MAX_HEADER_SIZE {
            let err_buf = ERR_MSG_REQUEST_TOO_LARGE.to_vec();
            let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
            return;
        }

        // HTTPリクエストをパース
        let mut headers_storage = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers_storage);
        
        match req.parse(&accumulated) {
            Ok(Status::Complete(header_len)) => {
                // HTTPメソッド取得
                let method_bytes: Box<[u8]> = req.method
                    .map(|m| m.as_bytes().into())
                    .unwrap_or_else(|| Box::from(b"GET" as &[u8]));
                
                // ヘッダー情報抽出
                let host_bytes: Box<[u8]> = req.headers.iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .map(|h| Box::from(h.value))
                    .unwrap_or_else(|| Box::from([] as [u8; 0]));
                
                let path_bytes: Box<[u8]> = req.path
                    .map(|p| p.as_bytes().into())
                    .unwrap_or_else(|| Box::from(b"/" as &[u8]));
                
                let user_agent: Box<[u8]> = req.headers.iter()
                    .find(|h| h.name.eq_ignore_ascii_case("user-agent"))
                    .map(|h| Box::from(h.value))
                    .unwrap_or_else(|| Box::from([] as [u8; 0]));
                
                let content_length: usize = req.headers.iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                
                // Transfer-Encoding: chunked チェック（改善版）
                let is_chunked: bool = req.headers.iter()
                    .find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
                    .map(|h| is_chunked_encoding(h.value))
                    .unwrap_or(false);
                
                // Connection: close チェック（Keep-Alive対応）
                let client_wants_close: bool = req.headers.iter()
                    .find(|h| h.name.eq_ignore_ascii_case("connection"))
                    .map(|h| h.value.eq_ignore_ascii_case(b"close"))
                    .unwrap_or(false);

                // ボディサイズ制限
                if !is_chunked && content_length > MAX_BODY_SIZE {
                    drop(req);
                    let err_buf = ERR_MSG_REQUEST_TOO_LARGE.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
                    return;
                }

                let headers_for_proxy: Vec<(Box<[u8]>, Box<[u8]>)> = req.headers.iter()
                    .filter(|h| !h.name.is_empty())
                    .map(|h| (h.name.as_bytes().into(), h.value.into()))
                    .collect();
                
                drop(req);

                // Backend選択
                let backend_result = find_backend(
                    &host_bytes,
                    &path_bytes,
                    host_routes,
                    path_routes,
                );

                let (prefix, backend) = match backend_result {
                    Some(b) => b,
                    None => {
                        let err_buf = ERR_MSG_BAD_REQUEST.to_vec();
                        let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
                        return;
                    }
                };

                let start_time = OffsetDateTime::now_utc();
                
                // 初期ボディ（ヘッダー後のデータ）
                let initial_body: Vec<u8> = if header_len < accumulated.len() {
                    accumulated[header_len..].to_vec()
                } else {
                    Vec::new()
                };

                // バッファクリア（次のリクエストに備える）
                accumulated.clear();

                // Backend処理
                let result = handle_backend(
                    tls_stream,
                    backend,
                    &method_bytes,
                    &path_bytes,
                    prefix,
                    content_length,
                    is_chunked,
                    &headers_for_proxy,
                    &initial_body,
                    client_wants_close,
                ).await;

                match result {
                    Some((stream_back, status, resp_size, should_close)) => {
                        log_access(&path_bytes, &user_agent, content_length as u64, status, resp_size, start_time);
                        tls_stream = stream_back;
                        
                        // Connection: close が要求された場合、またはエラー時は接続を閉じる
                        if should_close {
                            return;
                        }
                        // Keep-Alive: ループを継続して次のリクエストを待機
                    }
                    None => {
                        return;
                    }
                }
            }
            Ok(Status::Partial) => {
                // データ不足、次の読み込みを待つ
                continue;
            }
            Err(_) => {
                let err_buf = ERR_MSG_BAD_REQUEST.to_vec();
                let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
                return;
            }
        }
    }
}

// ====================
// HTTPヘッダー検証（Header Injection防止）
// ====================
//
// httparseがパースしたヘッダーを再検証し、不正な文字を含む
// ヘッダーを除外することで、HTTP Request Smuggling攻撃を防止します。
// 多層防御（Defense in Depth）の原則に基づく追加チェックです。
// ====================

/// ヘッダー名が有効か検証（RFC 7230 token準拠）
/// 
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
#[inline]
fn is_valid_header_name(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    for &b in name {
        let is_tchar = matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
            b'^' | b'_' | b'`' | b'|' | b'~' |
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        );
        if !is_tchar {
            return false;
        }
    }
    true
}

/// ヘッダー値が有効か検証（Header Injection防止）
/// 
/// RFC 7230 field-value に基づき、以下を禁止:
/// - CR (\r): ヘッダーインジェクションの主要ベクトル
/// - LF (\n): ヘッダーインジェクションの主要ベクトル
/// - NUL (0x00): セキュリティ上の理由
/// 
/// obs-fold（折り返しヘッダー）は許容しない方針とする。
/// これにより、プロキシとバックエンド間の解釈の違いを悪用した
/// HTTP Request Smuggling攻撃を防止する。
#[inline]
fn is_valid_header_value(value: &[u8]) -> bool {
    for &b in value {
        // CR, LF, NULは絶対に禁止
        if b == b'\r' || b == b'\n' || b == 0 {
            return false;
        }
    }
    true
}

// ====================
// Transfer-Encoding: chunked 検出（改善版）
// ====================

/// Transfer-Encoding ヘッダー値から chunked かどうかを正確に判定
#[inline]
fn is_chunked_encoding(value: &[u8]) -> bool {
    // カンマ区切りの各値をチェック
    for part in value.split(|&b| b == b',') {
        // 空白をトリム
        let trimmed: Vec<u8> = part.iter()
            .skip_while(|&&b| b == b' ' || b == b'\t')
            .copied()
            .collect();
        let trimmed: Vec<u8> = trimmed.iter()
            .rev()
            .skip_while(|&&b| b == b' ' || b == b'\t')
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        
        if trimmed.eq_ignore_ascii_case(b"chunked") {
            return true;
        }
    }
    false
}

// ====================
// Backend選択
// ====================

fn find_backend(
    host: &[u8],
    path: &[u8],
    host_routes: &Arc<HashMap<Box<[u8]>, Backend>>,
    path_routes: &Arc<HashMap<Box<[u8]>, SortedPathMap>>,
) -> Option<(Box<[u8]>, Backend)> {
    if let Some(backend) = host_routes.get(host) {
        return Some((Box::new([]), backend.clone()));
    }
    
    if let Some(sorted_map) = path_routes.get(host) {
        if let Some((prefix, backend)) = sorted_map.find_longest(path) {
            return Some((prefix.into(), backend.clone()));
        }
    }
    
    None
}

// ====================
// Backend処理
// ====================

async fn handle_backend(
    mut tls_stream: ServerTlsStream<TcpStream>,
    backend: Backend,
    method: &[u8],
    req_path: &[u8],
    prefix: Box<[u8]>,
    content_length: usize,
    is_chunked: bool,
    headers: &[(Box<[u8]>, Box<[u8]>)],
    initial_body: &[u8],
    client_wants_close: bool,
) -> Option<(ServerTlsStream<TcpStream>, u16, u64, bool)> {
    match backend {
        Backend::Proxy(target) => {
            handle_proxy(tls_stream, &target, method, req_path, &prefix, content_length, is_chunked, headers, initial_body, client_wants_close).await
        }
        Backend::MemoryFile(data, mime_type) => {
            // Keep-Alive対応: クライアントの要求に応じてConnectionヘッダーを動的に生成
            let mut header = Vec::with_capacity(HEADER_BUF_CAPACITY);
            header.extend_from_slice(HTTP_200_PREFIX);
            header.extend_from_slice(mime_type.as_bytes());
            header.extend_from_slice(CONTENT_LENGTH_HEADER);
            let mut num_buf = itoa::Buffer::new();
            header.extend_from_slice(num_buf.format(data.len()).as_bytes());
            if client_wants_close {
                header.extend_from_slice(CONNECTION_CLOSE);
            } else {
                header.extend_from_slice(CONNECTION_KEEP_ALIVE);
            }
            
            // ヘッダー送信（タイムアウト付き）
            let write_result = timeout(WRITE_TIMEOUT, tls_stream.write_all(header)).await;
            match write_result {
                Ok((Ok(_), _)) => {}
                _ => return None,
            }
            
            // ボディ送信（タイムアウト付き）
            let data_len = data.len() as u64;
            let data_buf = data.to_vec();
            let write_result = timeout(WRITE_TIMEOUT, tls_stream.write_all(data_buf)).await;
            match write_result {
                Ok((Ok(_), _)) => {
                    Some((tls_stream, 200, data_len, client_wants_close))
                }
                _ => None,
            }
        }
        Backend::SendFile(base_path, is_dir) => {
            handle_sendfile(tls_stream, &base_path, is_dir, req_path, &prefix, client_wants_close).await
        }
    }
}

// ====================
// HTTPレスポンスパーサー（httparse使用）
// ====================

/// httparseを使用したレスポンス解析結果
struct ParsedResponse {
    /// ステータスコード
    status_code: u16,
    /// ヘッダー終端位置（ボディ開始位置）
    header_len: usize,
    /// Content-Length（存在する場合）
    content_length: Option<usize>,
    /// Transfer-Encoding: chunked かどうか
    is_chunked: bool,
    /// Connection: close かどうか（HTTP/1.1ではデフォルトはkeep-alive）
    is_connection_close: bool,
}

/// HTTPレスポンスをhttparseで解析
/// 
/// httparseを使用することで以下のメリットがある:
/// - RFC準拠の堅牢なパース
/// - \r\n と \n の両方に対応
/// - ヘッダー折り返し（obs-fold）の処理
/// - 不正なHTTPレスポンスの検出
fn parse_http_response(data: &[u8]) -> Option<ParsedResponse> {
    let mut headers_storage = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers_storage);
    
    match response.parse(data) {
        Ok(Status::Complete(header_len)) => {
            let status_code = response.code.unwrap_or(502);
            
            // Content-Length を取得
            let content_length = response.headers.iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .and_then(|s| s.trim().parse().ok());
            
            // Transfer-Encoding: chunked をチェック
            let is_chunked = response.headers.iter()
                .find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
                .map(|h| is_chunked_encoding(h.value))
                .unwrap_or(false);
            
            // Connection: close をチェック（HTTP/1.1ではデフォルトはkeep-alive）
            let is_connection_close = response.headers.iter()
                .find(|h| h.name.eq_ignore_ascii_case("connection"))
                .map(|h| {
                    // 値をトリムして比較
                    let value = h.value;
                    let trimmed: Vec<u8> = value.iter()
                        .skip_while(|&&b| b == b' ' || b == b'\t')
                        .copied()
                        .collect();
                    trimmed.eq_ignore_ascii_case(b"close")
                })
                .unwrap_or(false);
            
            Some(ParsedResponse {
                status_code,
                header_len,
                content_length,
                is_chunked,
                is_connection_close,
            })
        }
        Ok(Status::Partial) => None, // データ不足
        Err(_) => None, // パースエラー
    }
}

/// HTTPレスポンスヘッダーが完全に受信されているかチェック
/// 
/// httparseを使用して、ヘッダーが完全に受信されたかを判定します。
/// 完全な場合はヘッダー終端位置（ボディ開始位置）を返します。
#[inline]
#[allow(dead_code)]
fn check_response_header_complete(data: &[u8]) -> Option<usize> {
    let mut headers_storage = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers_storage);
    
    match response.parse(data) {
        Ok(Status::Complete(header_len)) => Some(header_len),
        _ => None,
    }
}

// ====================
// Chunked Transfer Encoding パーサー（RFC 7230 Section 4.1 準拠）
// ====================
//
// Chunked-Bodyの構文:
//   chunked-body   = *chunk last-chunk trailer-part CRLF
//   chunk          = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
//   chunk-size     = 1*HEXDIG
//   last-chunk     = 1*("0") [ chunk-ext ] CRLF
//   trailer-part   = *( header-field CRLF )
//
// トレーラーが存在する場合でも正確に終端を検出するために
// ステートマシンベースのパーサーを使用します。
// ====================

/// Chunkedデコーダの状態
#[derive(Debug, Clone, Copy, PartialEq)]
enum ChunkedState {
    /// チャンクサイズの16進数を読み取り中
    ReadingChunkSize,
    /// チャンク拡張（;以降）を読み取り中（サイズ行の終わりまでスキップ）
    ReadingChunkExtension,
    /// チャンクサイズ行の\r後、\nを期待
    ExpectingChunkSizeLF,
    /// チャンクデータを読み取り中（残りバイト数をchunk_remainingで追跡）
    ReadingChunkData,
    /// チャンクデータ後の\rを期待
    ExpectingChunkDataCR,
    /// チャンクデータ後の\nを期待
    ExpectingChunkDataLF,
    /// トレーラーヘッダーまたは終端の空行を読み取り中
    /// 空行（\r\n）で完了、それ以外はトレーラーヘッダー
    ReadingTrailerLine,
    /// トレーラー行または終端の\r後、\nを期待
    ExpectingTrailerLF,
    /// 転送完了
    Complete,
}

/// Chunked転送デコーダ（ステートマシン）
/// 
/// RFC 7230 Section 4.1に準拠し、トレーラーの有無にかかわらず
/// 正確に終端を検出します。
#[derive(Debug, Clone)]
struct ChunkedDecoder {
    /// 現在の状態
    state: ChunkedState,
    /// 現在のチャンクの残りバイト数
    chunk_remaining: u64,
    /// チャンクサイズの解析中に蓄積する16進数値
    size_accumulator: u64,
    /// サイズに少なくとも1文字は含まれているか
    size_has_digit: bool,
    /// トレーラー行が空かどうか（終端検出用）
    trailer_line_empty: bool,
}

impl ChunkedDecoder {
    /// 新しいChunkedDecoderを作成
    fn new() -> Self {
        Self {
            state: ChunkedState::ReadingChunkSize,
            chunk_remaining: 0,
            size_accumulator: 0,
            size_has_digit: false,
            trailer_line_empty: true,
        }
    }
    
    /// データをフィードして状態を更新
    /// 完了した場合はtrueを返す
    fn feed(&mut self, data: &[u8]) -> bool {
        for &byte in data {
            if self.feed_byte(byte) {
                return true;
            }
        }
        false
    }
    
    /// 1バイトを処理して状態を更新
    /// 完了した場合はtrueを返す
    #[inline]
    fn feed_byte(&mut self, byte: u8) -> bool {
        match self.state {
            ChunkedState::ReadingChunkSize => {
                match byte {
                    b'0'..=b'9' => {
                        self.size_accumulator = self.size_accumulator.saturating_mul(16)
                            .saturating_add((byte - b'0') as u64);
                        self.size_has_digit = true;
                    }
                    b'a'..=b'f' => {
                        self.size_accumulator = self.size_accumulator.saturating_mul(16)
                            .saturating_add((byte - b'a' + 10) as u64);
                        self.size_has_digit = true;
                    }
                    b'A'..=b'F' => {
                        self.size_accumulator = self.size_accumulator.saturating_mul(16)
                            .saturating_add((byte - b'A' + 10) as u64);
                        self.size_has_digit = true;
                    }
                    b';' => {
                        // チャンク拡張の開始
                        self.state = ChunkedState::ReadingChunkExtension;
                    }
                    b'\r' => {
                        self.state = ChunkedState::ExpectingChunkSizeLF;
                    }
                    _ => {
                        // 不正な文字 - 回復のためスキップ（緩い解析）
                    }
                }
            }
            
            ChunkedState::ReadingChunkExtension => {
                // チャンク拡張はCRまでスキップ
                if byte == b'\r' {
                    self.state = ChunkedState::ExpectingChunkSizeLF;
                }
            }
            
            ChunkedState::ExpectingChunkSizeLF => {
                if byte == b'\n' {
                    if !self.size_has_digit {
                        // サイズが解析できなかった場合、リセット
                        self.state = ChunkedState::ReadingChunkSize;
                    } else if self.size_accumulator == 0 {
                        // 最後のチャンク（サイズ0）- トレーラーセクションへ
                        self.state = ChunkedState::ReadingTrailerLine;
                        self.trailer_line_empty = true;
                    } else {
                        // 通常のチャンク - データセクションへ
                        self.chunk_remaining = self.size_accumulator;
                        self.state = ChunkedState::ReadingChunkData;
                    }
                    // 次のチャンクのためにリセット
                    self.size_accumulator = 0;
                    self.size_has_digit = false;
                } else {
                    // LFが来なかった - リセット（緩い解析）
                    self.state = ChunkedState::ReadingChunkSize;
                    self.size_accumulator = 0;
                    self.size_has_digit = false;
                }
            }
            
            ChunkedState::ReadingChunkData => {
                self.chunk_remaining = self.chunk_remaining.saturating_sub(1);
                if self.chunk_remaining == 0 {
                    self.state = ChunkedState::ExpectingChunkDataCR;
                }
            }
            
            ChunkedState::ExpectingChunkDataCR => {
                if byte == b'\r' {
                    self.state = ChunkedState::ExpectingChunkDataLF;
                } else {
                    // 不正な形式 - 次のチャンクを探す（緩い解析）
                    self.state = ChunkedState::ReadingChunkSize;
                }
            }
            
            ChunkedState::ExpectingChunkDataLF => {
                if byte == b'\n' {
                    self.state = ChunkedState::ReadingChunkSize;
                } else {
                    // 不正な形式 - リセット
                    self.state = ChunkedState::ReadingChunkSize;
                }
            }
            
            ChunkedState::ReadingTrailerLine => {
                match byte {
                    b'\r' => {
                        self.state = ChunkedState::ExpectingTrailerLF;
                    }
                    _ => {
                        // トレーラーヘッダーの内容
                        self.trailer_line_empty = false;
                    }
                }
            }
            
            ChunkedState::ExpectingTrailerLF => {
                if byte == b'\n' {
                    if self.trailer_line_empty {
                        // 空行 = 転送完了
                        self.state = ChunkedState::Complete;
                        return true;
                    } else {
                        // トレーラーヘッダー行が完了、次の行へ
                        self.state = ChunkedState::ReadingTrailerLine;
                        self.trailer_line_empty = true;
                    }
                } else {
                    // 不正な形式だが、トレーラー読み取りを継続
                    self.state = ChunkedState::ReadingTrailerLine;
                    self.trailer_line_empty = false;
                }
            }
            
            ChunkedState::Complete => {
                return true;
            }
        }
        false
    }
    
    /// 転送が完了したかどうかを返す
    #[inline]
    #[allow(dead_code)]
    fn is_complete(&self) -> bool {
        self.state == ChunkedState::Complete
    }
}

// ====================
// プロキシ処理
// ====================
//
// バックエンドコネクションプールを使用して、接続を再利用します。
// Connection: keep-alive をバックエンドに送信し、レスポンスの
// Connection ヘッダーに基づいて接続をプールに返却します。
// ====================

async fn handle_proxy(
    client_stream: ServerTlsStream<TcpStream>,
    target: &ProxyTarget,
    method: &[u8],
    req_path: &[u8],
    prefix: &[u8],
    content_length: usize,
    is_chunked: bool,
    headers: &[(Box<[u8]>, Box<[u8]>)],
    initial_body: &[u8],
    client_wants_close: bool,
) -> Option<(ServerTlsStream<TcpStream>, u16, u64, bool)> {
    let pool_key = format!("{}:{}", target.host, target.port);
    
    // リクエストパス構築
    let path_str = std::str::from_utf8(req_path).unwrap_or("/");
    let sub_path = if prefix.is_empty() {
        path_str.to_string()
    } else {
        let prefix_str = std::str::from_utf8(prefix).unwrap_or("");
        if path_str.starts_with(prefix_str) {
            let remaining = &path_str[prefix_str.len()..];
            let base = target.path_prefix.trim_end_matches('/');
            
            if remaining.is_empty() {
                if base.is_empty() {
                    "/".to_string()
                } else {
                    format!("{}/", base)
                }
            } else if remaining.starts_with('/') {
                if base.is_empty() {
                    remaining.to_string()
                } else {
                    format!("{}{}", base, remaining)
                }
            } else {
                if base.is_empty() {
                    format!("/{}", remaining)
                } else {
                    format!("{}/{}", base, remaining)
                }
            }
        } else {
            path_str.to_string()
        }
    };
    
    let final_path = if sub_path.is_empty() { "/" } else { &sub_path };

    // HTTPリクエスト構築（Connection: keep-alive を使用）
    let mut request = Vec::with_capacity(1024);
    request.extend_from_slice(method);
    request.extend_from_slice(b" ");
    request.extend_from_slice(final_path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(target.host.as_bytes());
    
    if !target.is_default_port() {
        request.extend_from_slice(b":");
        let mut port_buf = itoa::Buffer::new();
        request.extend_from_slice(port_buf.format(target.port).as_bytes());
    }
    
    request.extend_from_slice(b"\r\n");
    
    for (name, value) in headers {
        // host と connection ヘッダーは別途処理済みのためスキップ
        if name.eq_ignore_ascii_case(b"host") || name.eq_ignore_ascii_case(b"connection") {
            continue;
        }
        
        // Header Injection防止: ヘッダー名と値の検証
        // httparseによるパース後も、多層防御として再検証を行う
        // 不正な文字（CR, LF, NUL等）を含むヘッダーは除外
        if !is_valid_header_name(name) {
            warn!("Invalid header name detected, skipping: {:?}", 
                  String::from_utf8_lossy(name));
            continue;
        }
        if !is_valid_header_value(value) {
            warn!("Invalid header value detected (possible header injection), skipping header: {:?}", 
                  String::from_utf8_lossy(name));
            continue;
        }
        
        request.extend_from_slice(name);
        request.extend_from_slice(b": ");
        request.extend_from_slice(value);
        request.extend_from_slice(b"\r\n");
    }
    // バックエンドにはKeep-Aliveを要求
    request.extend_from_slice(b"Connection: keep-alive\r\n\r\n");

    if target.use_tls {
        proxy_https_pooled(client_stream, target, &pool_key, request, content_length, is_chunked, initial_body, client_wants_close).await
    } else {
        proxy_http_pooled(client_stream, target, &pool_key, request, content_length, is_chunked, initial_body, client_wants_close).await
    }
}

// ====================
// HTTP プロキシ（コネクションプール対応）
// ====================

async fn proxy_http_pooled(
    mut client_stream: ServerTlsStream<TcpStream>,
    target: &ProxyTarget,
    pool_key: &str,
    request: Vec<u8>,
    content_length: usize,
    is_chunked: bool,
    initial_body: &[u8],
    client_wants_close: bool,
) -> Option<(ServerTlsStream<TcpStream>, u16, u64, bool)> {
    // プールから接続を取得、または新規作成
    let mut backend_stream = match HTTP_POOL.with(|p| p.borrow_mut().get(pool_key)) {
        Some(stream) => stream,
        None => {
            // 新規接続を作成
            let addr = format!("{}:{}", target.host, target.port);
            let connect_result = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await;
            
            match connect_result {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    stream
                }
                Ok(Err(e)) => {
                    error!("Proxy connect error to {}: {}", addr, e);
                    let err_buf = ERR_MSG_BAD_GATEWAY.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 502, 0, true));
                }
                Err(_) => {
                    error!("Proxy connect timeout to {}", addr);
                    let err_buf = ERR_MSG_GATEWAY_TIMEOUT.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 504, 0, true));
                }
            }
        }
    };

    // リクエスト送信とレスポンス受信
    let result = proxy_http_request(
        &mut client_stream,
        &mut backend_stream,
        request,
        content_length,
        is_chunked,
        initial_body,
    ).await;

    match result {
        Some((status_code, total, backend_wants_keep_alive)) => {
            // バックエンドがKeep-Aliveを許可している場合、プールに返却
            if backend_wants_keep_alive {
                HTTP_POOL.with(|p| p.borrow_mut().put(pool_key.to_string(), backend_stream));
            }
            Some((client_stream, status_code, total, client_wants_close))
        }
        None => {
            // エラー発生時は接続を破棄
            let err_buf = ERR_MSG_BAD_GATEWAY.to_vec();
            let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
            Some((client_stream, 502, 0, true))
        }
    }
}

/// HTTPリクエストを送信してレスポンスを受信（内部関数）
/// 戻り値: Option<(status_code, response_size, backend_wants_keep_alive)>
async fn proxy_http_request(
    client_stream: &mut ServerTlsStream<TcpStream>,
    backend_stream: &mut TcpStream,
    request: Vec<u8>,
    content_length: usize,
    is_chunked: bool,
    initial_body: &[u8],
) -> Option<(u16, u64, bool)> {
    // 1. リクエストヘッダー送信（タイムアウト付き）
    let write_result = timeout(WRITE_TIMEOUT, backend_stream.write_all(request)).await;
    if !matches!(write_result, Ok((Ok(_), _))) {
        return None;
    }

    // 2. リクエストボディ送信
    if !initial_body.is_empty() {
        let body_buf = initial_body.to_vec();
        let write_result = timeout(WRITE_TIMEOUT, backend_stream.write_all(body_buf)).await;
        if !matches!(write_result, Ok((Ok(_), _))) {
            return None;
        }
    }

    // 3. 残りのリクエストボディを転送
    if is_chunked {
        // Chunked転送の場合
        if !transfer_chunked_body(client_stream, backend_stream, initial_body).await {
            return None;
        }
    } else {
        // Content-Length転送の場合
        let remaining = content_length.saturating_sub(initial_body.len());
        if remaining > 0 {
            let transferred = transfer_exact_bytes(client_stream, backend_stream, remaining).await;
            if transferred < remaining as u64 {
                return None;
            }
        }
    }

    // 4. レスポンスを受信して転送（Connectionヘッダーも取得）
    let (total, status_code, backend_wants_keep_alive) = transfer_response_with_keepalive(backend_stream, client_stream).await;

    Some((status_code, total, backend_wants_keep_alive))
}

// ====================
// HTTPS プロキシ（コネクションプール対応）
// ====================

async fn proxy_https_pooled(
    mut client_stream: ServerTlsStream<TcpStream>,
    target: &ProxyTarget,
    pool_key: &str,
    request: Vec<u8>,
    content_length: usize,
    is_chunked: bool,
    initial_body: &[u8],
    client_wants_close: bool,
) -> Option<(ServerTlsStream<TcpStream>, u16, u64, bool)> {
    // プールから接続を取得、または新規作成
    let mut backend_stream = match HTTPS_POOL.with(|p| p.borrow_mut().get(pool_key)) {
        Some(stream) => stream,
        None => {
            // 新規TCP接続を作成
            let addr = format!("{}:{}", target.host, target.port);
            let connect_result = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await;
            
            let backend_tcp = match connect_result {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    stream
                }
                Ok(Err(e)) => {
                    error!("Proxy connect error to {}: {}", addr, e);
                    let err_buf = ERR_MSG_BAD_GATEWAY.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 502, 0, true));
                }
                Err(_) => {
                    error!("Proxy connect timeout to {}", addr);
                    let err_buf = ERR_MSG_GATEWAY_TIMEOUT.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 504, 0, true));
                }
            };
            
            // TLS接続（タイムアウト付き）
            let server_name = match ServerName::try_from(target.host.clone()) {
                Ok(name) => name,
                Err(e) => {
                    error!("Invalid server name {}: {}", target.host, e);
                    let err_buf = ERR_MSG_BAD_GATEWAY.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 502, 0, true));
                }
            };

            let connector = TLS_CONNECTOR.with(|c| c.clone());
            let tls_result = timeout(CONNECT_TIMEOUT, connector.connect(server_name, backend_tcp)).await;
            
            match tls_result {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    error!("TLS connect error to {}: {}", target.host, e);
                    let err_buf = ERR_MSG_BAD_GATEWAY.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 502, 0, true));
                }
                Err(_) => {
                    error!("TLS connect timeout to {}", target.host);
                    let err_buf = ERR_MSG_GATEWAY_TIMEOUT.to_vec();
                    let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
                    return Some((client_stream, 504, 0, true));
                }
            }
        }
    };

    // リクエスト送信とレスポンス受信
    let result = proxy_https_request(
        &mut client_stream,
        &mut backend_stream,
        request,
        content_length,
        is_chunked,
        initial_body,
    ).await;

    match result {
        Some((status_code, total, backend_wants_keep_alive)) => {
            // バックエンドがKeep-Aliveを許可している場合、プールに返却
            if backend_wants_keep_alive {
                HTTPS_POOL.with(|p| p.borrow_mut().put(pool_key.to_string(), backend_stream));
            }
            Some((client_stream, status_code, total, client_wants_close))
        }
        None => {
            // エラー発生時は接続を破棄
            let err_buf = ERR_MSG_BAD_GATEWAY.to_vec();
            let _ = timeout(WRITE_TIMEOUT, client_stream.write_all(err_buf)).await;
            Some((client_stream, 502, 0, true))
        }
    }
}

/// HTTPSリクエストを送信してレスポンスを受信（内部関数）
/// 戻り値: Option<(status_code, response_size, backend_wants_keep_alive)>
async fn proxy_https_request(
    client_stream: &mut ServerTlsStream<TcpStream>,
    backend_stream: &mut ClientTlsStream<TcpStream>,
    request: Vec<u8>,
    content_length: usize,
    is_chunked: bool,
    initial_body: &[u8],
) -> Option<(u16, u64, bool)> {
    // 1. リクエストヘッダー送信
    let write_result = timeout(WRITE_TIMEOUT, backend_stream.write_all(request)).await;
    if !matches!(write_result, Ok((Ok(_), _))) {
        return None;
    }

    // 2. リクエストボディ送信
    if !initial_body.is_empty() {
        let body_buf = initial_body.to_vec();
        let write_result = timeout(WRITE_TIMEOUT, backend_stream.write_all(body_buf)).await;
        if !matches!(write_result, Ok((Ok(_), _))) {
            return None;
        }
    }

    // 3. 残りのリクエストボディを転送
    if is_chunked {
        if !transfer_chunked_body(client_stream, backend_stream, initial_body).await {
            return None;
        }
    } else {
        let remaining = content_length.saturating_sub(initial_body.len());
        if remaining > 0 {
            let transferred = transfer_exact_bytes(client_stream, backend_stream, remaining).await;
            if transferred < remaining as u64 {
                return None;
            }
        }
    }

    // 4. レスポンスを受信して転送（Connectionヘッダーも取得）
    let (total, status_code, backend_wants_keep_alive) = transfer_response_with_keepalive(backend_stream, client_stream).await;

    Some((status_code, total, backend_wants_keep_alive))
}

// ====================
// 転送ヘルパー関数（ジェネリック版）
// ====================

/// 正確なバイト数を転送
async fn transfer_exact_bytes<R: AsyncReader, W: AsyncWriter>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: usize,
) -> u64 {
    let mut total = 0u64;
    
    while remaining > 0 {
        let buf = buf_get();
        let read_result = timeout(READ_TIMEOUT, reader.read_buf(buf)).await;
        
        let (res, returned_buf) = match read_result {
            Ok(result) => result,
            Err(_) => return total,
        };
        
        let n = match res {
            Ok(0) => {
                buf_put(returned_buf);
                break;
            }
            Ok(n) => n.min(remaining),
            Err(_) => {
                buf_put(returned_buf);
                break;
            }
        };
        
        let mut write_buf = returned_buf;
        write_buf.truncate(n);
        
        let write_result = timeout(WRITE_TIMEOUT, writer.write_buf(write_buf)).await;
        match write_result {
            Ok((Ok(_), returned)) => {
                buf_put(returned);
            }
            Ok((Err(_), returned)) => {
                buf_put(returned);
                break;
            }
            Err(_) => break,
        }
        
        total += n as u64;
        remaining -= n;
    }
    
    total
}

/// Chunkedボディを転送（ステートマシンベース）
/// 
/// RFC 7230準拠のChunkedDecoderを使用して、トレーラーの有無に
/// かかわらず正確に終端を検出します。
async fn transfer_chunked_body<R: AsyncReader, W: AsyncWriter>(
    reader: &mut R,
    writer: &mut W,
    initial_body: &[u8],
) -> bool {
    let mut decoder = ChunkedDecoder::new();
    
    // 初期ボディが既に終端を含んでいるかチェック
    if !initial_body.is_empty() && decoder.feed(initial_body) {
        return true;
    }
    
    loop {
        let buf = buf_get();
        let read_result = timeout(READ_TIMEOUT, reader.read_buf(buf)).await;
        
        let (res, returned_buf) = match read_result {
            Ok(result) => result,
            Err(_) => return false,
        };
        
        let n = match res {
            Ok(0) => {
                buf_put(returned_buf);
                break;
            }
            Ok(n) => n,
            Err(_) => {
                buf_put(returned_buf);
                return false;
            }
        };
        
        // ステートマシンにデータをフィード
        let is_complete = decoder.feed(&returned_buf[..n]);
        
        // バックエンドに転送
        let mut write_buf = returned_buf;
        write_buf.truncate(n);
        
        let write_result = timeout(WRITE_TIMEOUT, writer.write_buf(write_buf)).await;
        match write_result {
            Ok((Ok(_), returned)) => {
                buf_put(returned);
            }
            Ok((Err(_), returned)) => {
                buf_put(returned);
                return false;
            }
            Err(_) => return false,
        }
        
        // 終端チェック
        if is_complete {
            return true;
        }
    }
    
    false
}

/// レスポンスを受信して転送（ジェネリック版）
/// 注: 現在は transfer_response_with_keepalive を使用
#[allow(dead_code)]
async fn transfer_response<R: AsyncReader, W: AsyncWriter>(
    backend: &mut R,
    client: &mut W,
) -> (u64, u16) {
    let mut total = 0u64;
    let mut status_code = 502u16;
    let mut header_parsed = false;
    let mut accumulated = Vec::with_capacity(4096);
    let mut is_chunked = false;
    let mut body_remaining: Option<usize> = None;
    // ステートマシンベースのChunkedデコーダを使用
    let mut chunked_decoder = ChunkedDecoder::new();
    
    loop {
        let buf = buf_get();
        let read_result = timeout(READ_TIMEOUT, backend.read_buf(buf)).await;
        
        let (res, returned_buf) = match read_result {
            Ok(result) => result,
            Err(_) => {
                // タイムアウト
                if !accumulated.is_empty() {
                    let data = std::mem::take(&mut accumulated);
                    let len = data.len();
                    let _ = timeout(WRITE_TIMEOUT, client.write_buf(data)).await;
                    total += len as u64;
                }
                break;
            }
        };
        
        let n = match res {
            Ok(0) => {
                buf_put(returned_buf);
                // EOFに達した
                if !accumulated.is_empty() {
                    let data = std::mem::take(&mut accumulated);
                    let len = data.len();
                    let _ = timeout(WRITE_TIMEOUT, client.write_buf(data)).await;
                    total += len as u64;
                }
                break;
            }
            Ok(n) => n,
            Err(_) => {
                buf_put(returned_buf);
                break;
            }
        };
        
        if !header_parsed {
            accumulated.extend_from_slice(&returned_buf[..n]);
            buf_put(returned_buf);
            
            // httparseを使用してレスポンスヘッダーを解析
            if let Some(parsed) = parse_http_response(&accumulated) {
                header_parsed = true;
                status_code = parsed.status_code;
                is_chunked = parsed.is_chunked;
                
                let header_len = parsed.header_len;
                let header_with_body = std::mem::take(&mut accumulated);
                let data_len = header_with_body.len();
                
                // ボディ開始部分の長さを計算
                let body_start_len = data_len.saturating_sub(header_len);
                
                // Content-Lengthがある場合、残りのボディサイズを計算
                if let Some(cl) = parsed.content_length {
                    body_remaining = Some(cl.saturating_sub(body_start_len));
                }
                
                // Chunked の場合、初期ボディ部分をデコーダにフィード
                if is_chunked && body_start_len > 0 {
                    chunked_decoder.feed(&header_with_body[header_len..]);
                }
                
                let write_result = timeout(WRITE_TIMEOUT, client.write_buf(header_with_body)).await;
                match write_result {
                    Ok((Ok(_), returned)) => {
                        buf_put(returned);
                    }
                    Ok((Err(_), returned)) => {
                        buf_put(returned);
                        break;
                    }
                    Err(_) => break,
                }
                total += data_len as u64;
            }
        } else {
            // ヘッダー解析済み
            if is_chunked {
                // Chunked転送 - デコーダにデータをフィード
                let is_complete = chunked_decoder.feed(&returned_buf[..n]);
                
                let mut write_buf = returned_buf;
                write_buf.truncate(n);
                
                let write_result = timeout(WRITE_TIMEOUT, client.write_buf(write_buf)).await;
                match write_result {
                    Ok((Ok(_), returned)) => {
                        buf_put(returned);
                    }
                    Ok((Err(_), returned)) => {
                        buf_put(returned);
                        break;
                    }
                    Err(_) => break,
                }
                
                total += n as u64;
                
                // ステートマシンによる終端チェック
                if is_complete {
                    break;
                }
            } else {
                // Content-Length転送
                let bytes_to_send = if let Some(remaining) = body_remaining {
                    let to_send = n.min(remaining);
                    body_remaining = Some(remaining - to_send);
                    to_send
                } else {
                    n
                };
                
                if bytes_to_send > 0 {
                    let mut write_buf = returned_buf;
                    write_buf.truncate(bytes_to_send);
                    
                    let write_result = timeout(WRITE_TIMEOUT, client.write_buf(write_buf)).await;
                    match write_result {
                        Ok((Ok(_), returned)) => {
                            buf_put(returned);
                        }
                        Ok((Err(_), returned)) => {
                            buf_put(returned);
                            break;
                        }
                        Err(_) => break,
                    }
                    
                    total += bytes_to_send as u64;
                } else {
                    buf_put(returned_buf);
                }
                
                if let Some(remaining) = body_remaining {
                    if remaining == 0 {
                        break;
                    }
                }
            }
        }
    }
    
    (total, status_code)
}

/// レスポンスを受信して転送（Keep-Aliveサポート版）
/// バックエンドがKeep-Aliveを許可しているかどうかも返す
async fn transfer_response_with_keepalive<R: AsyncReader, W: AsyncWriter>(
    backend: &mut R,
    client: &mut W,
) -> (u64, u16, bool) {
    let mut total = 0u64;
    let mut status_code = 502u16;
    let mut header_parsed = false;
    let mut accumulated = Vec::with_capacity(4096);
    let mut is_chunked = false;
    let mut body_remaining: Option<usize> = None;
    // ステートマシンベースのChunkedデコーダを使用
    let mut chunked_decoder = ChunkedDecoder::new();
    let mut backend_wants_keep_alive = false;  // デフォルトはfalse（安全側）
    
    loop {
        let buf = buf_get();
        let read_result = timeout(READ_TIMEOUT, backend.read_buf(buf)).await;
        
        let (res, returned_buf) = match read_result {
            Ok(result) => result,
            Err(_) => {
                // タイムアウト
                if !accumulated.is_empty() {
                    let data = std::mem::take(&mut accumulated);
                    let len = data.len();
                    let _ = timeout(WRITE_TIMEOUT, client.write_buf(data)).await;
                    total += len as u64;
                }
                break;
            }
        };
        
        let n = match res {
            Ok(0) => {
                buf_put(returned_buf);
                // EOFに達した
                if !accumulated.is_empty() {
                    let data = std::mem::take(&mut accumulated);
                    let len = data.len();
                    let _ = timeout(WRITE_TIMEOUT, client.write_buf(data)).await;
                    total += len as u64;
                }
                break;
            }
            Ok(n) => n,
            Err(_) => {
                buf_put(returned_buf);
                break;
            }
        };
        
        if !header_parsed {
            accumulated.extend_from_slice(&returned_buf[..n]);
            buf_put(returned_buf);
            
            // httparseを使用してレスポンスヘッダーを解析
            if let Some(parsed) = parse_http_response(&accumulated) {
                header_parsed = true;
                status_code = parsed.status_code;
                is_chunked = parsed.is_chunked;
                
                // HTTP/1.1 ではデフォルトでkeep-alive、Connection: closeが明示されていなければOK
                backend_wants_keep_alive = !parsed.is_connection_close;
                
                let header_len = parsed.header_len;
                let header_with_body = std::mem::take(&mut accumulated);
                let data_len = header_with_body.len();
                
                // ボディ開始部分の長さを計算
                let body_start_len = data_len.saturating_sub(header_len);
                
                // Content-Lengthがある場合、残りのボディサイズを計算
                if let Some(cl) = parsed.content_length {
                    body_remaining = Some(cl.saturating_sub(body_start_len));
                }
                
                // Chunked の場合、初期ボディ部分をデコーダにフィード
                if is_chunked && body_start_len > 0 {
                    chunked_decoder.feed(&header_with_body[header_len..]);
                }
                
                let write_result = timeout(WRITE_TIMEOUT, client.write_buf(header_with_body)).await;
                match write_result {
                    Ok((Ok(_), returned)) => {
                        buf_put(returned);
                    }
                    Ok((Err(_), returned)) => {
                        buf_put(returned);
                        backend_wants_keep_alive = false;
                        break;
                    }
                    Err(_) => {
                        backend_wants_keep_alive = false;
                        break;
                    }
                }
                total += data_len as u64;
            }
        } else {
            // ヘッダー解析済み
            if is_chunked {
                // Chunked転送 - デコーダにデータをフィード
                let is_complete = chunked_decoder.feed(&returned_buf[..n]);
                
                let mut write_buf = returned_buf;
                write_buf.truncate(n);
                
                let write_result = timeout(WRITE_TIMEOUT, client.write_buf(write_buf)).await;
                match write_result {
                    Ok((Ok(_), returned)) => {
                        buf_put(returned);
                    }
                    Ok((Err(_), returned)) => {
                        buf_put(returned);
                        backend_wants_keep_alive = false;
                        break;
                    }
                    Err(_) => {
                        backend_wants_keep_alive = false;
                        break;
                    }
                }
                
                total += n as u64;
                
                // ステートマシンによる終端チェック
                if is_complete {
                    break;
                }
            } else {
                // Content-Length転送
                let bytes_to_send = if let Some(remaining) = body_remaining {
                    let to_send = n.min(remaining);
                    body_remaining = Some(remaining - to_send);
                    to_send
                } else {
                    n
                };
                
                if bytes_to_send > 0 {
                    let mut write_buf = returned_buf;
                    write_buf.truncate(bytes_to_send);
                    
                    let write_result = timeout(WRITE_TIMEOUT, client.write_buf(write_buf)).await;
                    match write_result {
                        Ok((Ok(_), returned)) => {
                            buf_put(returned);
                        }
                        Ok((Err(_), returned)) => {
                            buf_put(returned);
                            backend_wants_keep_alive = false;
                            break;
                        }
                        Err(_) => {
                            backend_wants_keep_alive = false;
                            break;
                        }
                    }
                    
                    total += bytes_to_send as u64;
                } else {
                    buf_put(returned_buf);
                }
                
                if let Some(remaining) = body_remaining {
                    if remaining == 0 {
                        break;
                    }
                }
            }
        }
    }
    
    (total, status_code, backend_wants_keep_alive)
}

// ====================
// SendFile処理
// ====================

async fn handle_sendfile(
    mut tls_stream: ServerTlsStream<TcpStream>,
    base_path: &Path,
    is_dir: bool,
    req_path: &[u8],
    prefix: &[u8],
    client_wants_close: bool,
) -> Option<(ServerTlsStream<TcpStream>, u16, u64, bool)> {
    let full_path = if is_dir {
        let path_str = std::str::from_utf8(req_path).unwrap_or("/");
        let prefix_str = std::str::from_utf8(prefix).unwrap_or("");
        let sub_path = path_str.strip_prefix(prefix_str).unwrap_or(path_str);
        let sub_path = sub_path.trim_start_matches('/');
        
        // パストラバーサル防止
        if sub_path.contains("..") {
            let err_buf = ERR_MSG_FORBIDDEN.to_vec();
            let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
            return Some((tls_stream, 403, 0, true));  // エラー時は接続を閉じる
        }
        
        let mut path = base_path.to_path_buf();
        if !sub_path.is_empty() {
            path.push(sub_path);
        }
        path
    } else {
        base_path.to_path_buf()
    };

    let full_path_canonical = match full_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            let err_buf = ERR_MSG_NOT_FOUND.to_vec();
            let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
            return Some((tls_stream, 404, 0, true));  // エラー時は接続を閉じる
        }
    };

    if is_dir {
        if let Ok(base) = base_path.canonicalize() {
            if !full_path_canonical.starts_with(&base) {
                let err_buf = ERR_MSG_FORBIDDEN.to_vec();
                let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
                return Some((tls_stream, 403, 0, true));  // エラー時は接続を閉じる
            }
        }
    }

    // ディレクトリの場合はindex.htmlを試す
    let final_path = if full_path_canonical.is_dir() {
        let index_path = full_path_canonical.join("index.html");
        if index_path.exists() {
            index_path
        } else {
            let err_buf = ERR_MSG_FORBIDDEN.to_vec();
            let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
            return Some((tls_stream, 403, 0, true));  // エラー時は接続を閉じる
        }
    } else {
        full_path_canonical
    };

    let file = match OpenOptions::new().read(true).open(&final_path).await {
        Ok(f) => f,
        Err(_) => {
            let err_buf = ERR_MSG_NOT_FOUND.to_vec();
            let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
            return Some((tls_stream, 404, 0, true));  // エラー時は接続を閉じる
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => {
            let err_buf = ERR_MSG_NOT_FOUND.to_vec();
            let _ = timeout(WRITE_TIMEOUT, tls_stream.write_all(err_buf)).await;
            return Some((tls_stream, 404, 0, true));  // エラー時は接続を閉じる
        }
    };

    let file_size = metadata.len();
    let mime_type = mime_guess::from_path(&final_path).first_or_octet_stream();
    
    // ヘッダー構築（Keep-Alive対応）
    let mut header_buf = Vec::with_capacity(HEADER_BUF_CAPACITY);
    header_buf.extend_from_slice(HTTP_200_PREFIX);
    header_buf.extend_from_slice(mime_type.as_ref().as_bytes());
    header_buf.extend_from_slice(CONTENT_LENGTH_HEADER);
    
    let mut num_buf = itoa::Buffer::new();
    header_buf.extend_from_slice(num_buf.format(file_size).as_bytes());
    if client_wants_close {
        header_buf.extend_from_slice(CONNECTION_CLOSE);
    } else {
        header_buf.extend_from_slice(CONNECTION_KEEP_ALIVE);
    }

    // ヘッダー送信（タイムアウト付き）
    let write_result = timeout(WRITE_TIMEOUT, tls_stream.write_all(header_buf)).await;
    if !matches!(write_result, Ok((Ok(_), _))) {
        return None;
    }

    // ファイル転送
    let mut total_sent = 0u64;
    let mut offset = 0u64;
    
    while offset < file_size {
        let read_buf = buf_get();
        let (res, returned_buf) = file.read_at(read_buf, offset).await;
        
        let n = match res {
            Ok(0) => {
                buf_put(returned_buf);
                break;
            }
            Ok(n) => n,
            Err(e) => {
                buf_put(returned_buf);
                error!("File read error: {}", e);
                break;
            }
        };
        
        let mut write_buf = returned_buf;
        write_buf.truncate(n);
        
        let write_result = timeout(WRITE_TIMEOUT, tls_stream.write_all(write_buf)).await;
        match write_result {
            Ok((Ok(_), returned)) => {
                buf_put(returned);
                total_sent += n as u64;
                offset += n as u64;
            }
            Ok((Err(_), returned)) => {
                buf_put(returned);
                break;
            }
            Err(_) => break,
        }
    }

    Some((tls_stream, 200, total_sent, client_wants_close))
}

// ====================
// ロギング
// ====================

fn log_access(path: &[u8], ua: &[u8], req_body_size: u64, status: u16, resp_body_size: u64, start_time: OffsetDateTime) {
    let end_time = OffsetDateTime::now_utc();
    let duration_ms = (end_time - start_time).whole_milliseconds();
    let path_str = std::str::from_utf8(path).unwrap_or("-");
    let ua_str = std::str::from_utf8(ua).unwrap_or("-");
    
    info!("Access: time={} duration={}ms path={} ua={} req_body_size={} status={} resp_body_size={}",
        start_time, duration_ms, path_str, ua_str, req_body_size, status, resp_body_size);
}

#[allow(dead_code)]
fn find_header<'a>(headers: &'a [Header<'a>], name: &str) -> Option<&'a [u8]> {
    headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
}
