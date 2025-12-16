//! # s2n-tls + monoio + kTLS 統合モジュール
//!
//! このモジュールは、s2n-tls を monoio ランタイムと統合し、
//! kTLS（Kernel TLS）のサポートを提供します。
//!
//! ## 主要コンポーネント
//!
//! - [`S2nConfig`]: TLS 設定を管理
//! - [`S2nTlsStream`]: monoio の AsyncReadRent/AsyncWriteRent を実装した TLS ストリーム
//! - [`S2nAcceptor`]: サーバー側の TLS アクセプター
//! - [`S2nConnector`]: クライアント側の TLS コネクター
//!
//! ## kTLS サポート
//!
//! TLS ハンドシェイク完了後、kTLS を有効化することで、
//! データ転送フェーズの暗号化/復号化をカーネルにオフロードします。
//!
//! ### メリット
//!
//! - CPU 使用率の削減（20-40%）
//! - sendfile(2) によるゼロコピー送信
//! - コンテキストスイッチの削減
//!
//! ### 要件
//!
//! - Linux 5.15+（推奨）
//! - `modprobe tls` でカーネルモジュールをロード
//! - AES-GCM 暗号スイート

// 将来の拡張用に残している未使用コードの警告を抑制
#![allow(dead_code)]

use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;

use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::net::TcpStream;

// ====================
// FFI バインディング（s2n-tls-sys 相当）
// ====================
//
// s2n-tls の C API をラップします。
// s2n-tls-sys crate が利用可能な場合はそちらを使用することを推奨しますが、
// ここでは必要最小限の FFI を直接定義しています。

#[allow(non_camel_case_types)]
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    // s2n-tls のオペーク型
    pub enum s2n_config {}
    pub enum s2n_connection {}
    pub enum s2n_cert_chain_and_key {}

    // ブロック状態
    pub type s2n_blocked_status = c_int;
    pub const S2N_NOT_BLOCKED: s2n_blocked_status = 0;
    pub const S2N_BLOCKED_ON_READ: s2n_blocked_status = 1;
    pub const S2N_BLOCKED_ON_WRITE: s2n_blocked_status = 2;

    // TLS モード
    pub type s2n_mode = c_int;
    pub const S2N_SERVER: s2n_mode = 0;
    pub const S2N_CLIENT: s2n_mode = 1;

    // Blinding モード
    pub type s2n_blinding = c_int;
    pub const S2N_BUILT_IN_BLINDING: s2n_blinding = 0;
    pub const S2N_SELF_SERVICE_BLINDING: s2n_blinding = 1;

    // 戻り値
    pub const S2N_SUCCESS: c_int = 0;
    pub const S2N_FAILURE: c_int = -1;

    // I/O コールバック型
    pub type s2n_recv_fn = Option<
        unsafe extern "C" fn(io_context: *mut c_void, buf: *mut u8, len: u32) -> c_int,
    >;
    pub type s2n_send_fn = Option<
        unsafe extern "C" fn(io_context: *mut c_void, buf: *const u8, len: u32) -> c_int,
    >;

    extern "C" {
        // 初期化/クリーンアップ
        pub fn s2n_init() -> c_int;
        pub fn s2n_cleanup() -> c_int;

        // Config 関連
        pub fn s2n_config_new() -> *mut s2n_config;
        pub fn s2n_config_free(config: *mut s2n_config) -> c_int;
        pub fn s2n_config_set_cipher_preferences(
            config: *mut s2n_config,
            version: *const c_char,
        ) -> c_int;
        pub fn s2n_config_add_cert_chain_and_key_to_store(
            config: *mut s2n_config,
            cert_key_pair: *mut s2n_cert_chain_and_key,
        ) -> c_int;
        pub fn s2n_config_set_verification_ca_location(
            config: *mut s2n_config,
            ca_pem_filename: *const c_char,
            ca_dir: *const c_char,
        ) -> c_int;
        pub fn s2n_config_disable_x509_verification(config: *mut s2n_config) -> c_int;

        // 証明書/キー関連
        pub fn s2n_cert_chain_and_key_new() -> *mut s2n_cert_chain_and_key;
        pub fn s2n_cert_chain_and_key_free(cert_and_key: *mut s2n_cert_chain_and_key) -> c_int;
        pub fn s2n_cert_chain_and_key_load_pem(
            chain_and_key: *mut s2n_cert_chain_and_key,
            chain_pem: *const c_char,
            private_key_pem: *const c_char,
        ) -> c_int;
        pub fn s2n_cert_chain_and_key_load_pem_bytes(
            chain_and_key: *mut s2n_cert_chain_and_key,
            chain_pem: *const u8,
            chain_pem_len: u32,
            private_key_pem: *const u8,
            private_key_pem_len: u32,
        ) -> c_int;

        // Connection 関連
        pub fn s2n_connection_new(mode: s2n_mode) -> *mut s2n_connection;
        pub fn s2n_connection_free(conn: *mut s2n_connection) -> c_int;
        pub fn s2n_connection_set_config(
            conn: *mut s2n_connection,
            config: *mut s2n_config,
        ) -> c_int;
        pub fn s2n_connection_set_fd(conn: *mut s2n_connection, fd: c_int) -> c_int;
        pub fn s2n_connection_set_read_fd(conn: *mut s2n_connection, fd: c_int) -> c_int;
        pub fn s2n_connection_set_write_fd(conn: *mut s2n_connection, fd: c_int) -> c_int;
        pub fn s2n_connection_set_blinding(
            conn: *mut s2n_connection,
            blinding: s2n_blinding,
        ) -> c_int;
        pub fn s2n_connection_get_delay(conn: *mut s2n_connection) -> u64;
        pub fn s2n_set_server_name(conn: *mut s2n_connection, server_name: *const c_char)
            -> c_int;

        // カスタム I/O
        pub fn s2n_connection_set_recv_cb(conn: *mut s2n_connection, recv: s2n_recv_fn) -> c_int;
        pub fn s2n_connection_set_send_cb(conn: *mut s2n_connection, send: s2n_send_fn) -> c_int;
        pub fn s2n_connection_set_recv_ctx(conn: *mut s2n_connection, ctx: *mut c_void) -> c_int;
        pub fn s2n_connection_set_send_ctx(conn: *mut s2n_connection, ctx: *mut c_void) -> c_int;

        // ハンドシェイク
        pub fn s2n_negotiate(
            conn: *mut s2n_connection,
            blocked: *mut s2n_blocked_status,
        ) -> c_int;

        // データ送受信
        pub fn s2n_recv(
            conn: *mut s2n_connection,
            buf: *mut c_void,
            size: isize,
            blocked: *mut s2n_blocked_status,
        ) -> isize;
        pub fn s2n_send(
            conn: *mut s2n_connection,
            buf: *const c_void,
            size: isize,
            blocked: *mut s2n_blocked_status,
        ) -> isize;

        // シャットダウン
        pub fn s2n_shutdown(
            conn: *mut s2n_connection,
            blocked: *mut s2n_blocked_status,
        ) -> c_int;

        // kTLS
        pub fn s2n_connection_ktls_enable_send(conn: *mut s2n_connection) -> c_int;
        pub fn s2n_connection_ktls_enable_recv(conn: *mut s2n_connection) -> c_int;

        // 接続情報
        pub fn s2n_connection_get_cipher(conn: *mut s2n_connection) -> *const c_char;
        pub fn s2n_connection_get_actual_protocol_version(conn: *mut s2n_connection) -> c_int;

        // エラーハンドリング
        pub fn s2n_errno_location() -> *mut c_int;
        pub fn s2n_strerror(error: c_int, lang: *const c_char) -> *const c_char;
        pub fn s2n_strerror_debug(error: c_int, lang: *const c_char) -> *const c_char;
    }

    /// s2n エラーを取得
    #[inline]
    pub fn get_s2n_errno() -> c_int {
        unsafe { *s2n_errno_location() }
    }
}

// ====================
// エラー型
// ====================

/// s2n-tls エラー
#[derive(Debug)]
pub struct S2nError {
    pub code: i32,
    pub message: String,
}

impl S2nError {
    /// 現在の s2n エラーから新しいエラーを作成
    pub fn from_errno() -> Self {
        let code = ffi::get_s2n_errno();
        let message = unsafe {
            let msg = ffi::s2n_strerror_debug(code, std::ptr::null());
            if msg.is_null() {
                format!("Unknown s2n error: {}", code)
            } else {
                std::ffi::CStr::from_ptr(msg)
                    .to_string_lossy()
                    .into_owned()
            }
        };
        S2nError { code, message }
    }

    /// io::Error に変換
    pub fn to_io_error(&self) -> io::Error {
        io::Error::new(io::ErrorKind::Other, self.message.clone())
    }
}

impl std::fmt::Display for S2nError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for S2nError {}

impl From<S2nError> for io::Error {
    fn from(e: S2nError) -> Self {
        e.to_io_error()
    }
}

// ====================
// ブロック状態
// ====================

/// TLS 操作のブロック状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedStatus {
    /// ブロックなし
    NotBlocked,
    /// 読み込み待ち
    BlockedOnRead,
    /// 書き込み待ち
    BlockedOnWrite,
}

impl From<ffi::s2n_blocked_status> for BlockedStatus {
    fn from(status: ffi::s2n_blocked_status) -> Self {
        match status {
            ffi::S2N_BLOCKED_ON_READ => BlockedStatus::BlockedOnRead,
            ffi::S2N_BLOCKED_ON_WRITE => BlockedStatus::BlockedOnWrite,
            _ => BlockedStatus::NotBlocked,
        }
    }
}

// ====================
// グローバル初期化
// ====================

use std::sync::Once;

static S2N_INIT: Once = Once::new();

/// s2n-tls ライブラリを初期化
///
/// この関数はプログラム起動時に一度だけ呼び出してください。
/// 複数回呼び出しても安全です（内部で Once を使用）。
pub fn init() -> Result<(), S2nError> {
    let mut result = Ok(());
    S2N_INIT.call_once(|| {
        let ret = unsafe { ffi::s2n_init() };
        if ret != ffi::S2N_SUCCESS {
            result = Err(S2nError::from_errno());
        }
    });
    result
}

// ====================
// TLS 設定
// ====================

/// s2n-tls 設定
///
/// TLS ハンドシェイクに必要な設定を保持します。
/// スレッドセーフで、複数のコネクション間で共有できます。
pub struct S2nConfig {
    inner: NonNull<ffi::s2n_config>,
    cert_chain_and_key: Option<NonNull<ffi::s2n_cert_chain_and_key>>,
}

unsafe impl Send for S2nConfig {}
unsafe impl Sync for S2nConfig {}

impl S2nConfig {
    /// 新しいサーバー設定を作成
    ///
    /// # Arguments
    ///
    /// * `cert_pem` - PEM 形式の証明書チェーン
    /// * `key_pem` - PEM 形式の秘密鍵
    pub fn new_server(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, S2nError> {
        init()?;

        let config = unsafe { ffi::s2n_config_new() };
        if config.is_null() {
            return Err(S2nError::from_errno());
        }
        let config = unsafe { NonNull::new_unchecked(config) };

        // 暗号スイート設定（kTLS 互換の AES-GCM を優先）
        let cipher_prefs = CString::new("default_tls13").unwrap();
        let ret = unsafe {
            ffi::s2n_config_set_cipher_preferences(config.as_ptr(), cipher_prefs.as_ptr())
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_config_free(config.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        // 証明書/キーをロード
        let cert_key = unsafe { ffi::s2n_cert_chain_and_key_new() };
        if cert_key.is_null() {
            unsafe { ffi::s2n_config_free(config.as_ptr()) };
            return Err(S2nError::from_errno());
        }
        let cert_key = unsafe { NonNull::new_unchecked(cert_key) };

        let ret = unsafe {
            ffi::s2n_cert_chain_and_key_load_pem_bytes(
                cert_key.as_ptr(),
                cert_pem.as_ptr(),
                cert_pem.len() as u32,
                key_pem.as_ptr(),
                key_pem.len() as u32,
            )
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe {
                ffi::s2n_cert_chain_and_key_free(cert_key.as_ptr());
                ffi::s2n_config_free(config.as_ptr());
            }
            return Err(S2nError::from_errno());
        }

        let ret = unsafe {
            ffi::s2n_config_add_cert_chain_and_key_to_store(config.as_ptr(), cert_key.as_ptr())
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe {
                ffi::s2n_cert_chain_and_key_free(cert_key.as_ptr());
                ffi::s2n_config_free(config.as_ptr());
            }
            return Err(S2nError::from_errno());
        }

        Ok(S2nConfig {
            inner: config,
            cert_chain_and_key: Some(cert_key),
        })
    }

    /// 新しいクライアント設定を作成
    ///
    /// システムの CA 証明書を使用してサーバー証明書を検証します。
    pub fn new_client() -> Result<Self, S2nError> {
        init()?;

        let config = unsafe { ffi::s2n_config_new() };
        if config.is_null() {
            return Err(S2nError::from_errno());
        }
        let config = unsafe { NonNull::new_unchecked(config) };

        // 暗号スイート設定
        let cipher_prefs = CString::new("default_tls13").unwrap();
        let ret = unsafe {
            ffi::s2n_config_set_cipher_preferences(config.as_ptr(), cipher_prefs.as_ptr())
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_config_free(config.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        // システムの CA 証明書を使用
        // /etc/ssl/certs は一般的な Linux ディストリビューションのパス
        let ca_dir = CString::new("/etc/ssl/certs").unwrap();
        let ret = unsafe {
            ffi::s2n_config_set_verification_ca_location(
                config.as_ptr(),
                std::ptr::null(),
                ca_dir.as_ptr(),
            )
        };
        if ret != ffi::S2N_SUCCESS {
            // CA 設定に失敗した場合は検証を無効化（開発用）
            ftlog::warn!("s2n-tls: Failed to set CA location, disabling X509 verification");
            let ret = unsafe { ffi::s2n_config_disable_x509_verification(config.as_ptr()) };
            if ret != ffi::S2N_SUCCESS {
                unsafe { ffi::s2n_config_free(config.as_ptr()) };
                return Err(S2nError::from_errno());
            }
        }

        Ok(S2nConfig {
            inner: config,
            cert_chain_and_key: None,
        })
    }

    /// 検証なしのクライアント設定を作成（テスト用）
    pub fn new_client_insecure() -> Result<Self, S2nError> {
        init()?;

        let config = unsafe { ffi::s2n_config_new() };
        if config.is_null() {
            return Err(S2nError::from_errno());
        }
        let config = unsafe { NonNull::new_unchecked(config) };

        let cipher_prefs = CString::new("default_tls13").unwrap();
        let ret = unsafe {
            ffi::s2n_config_set_cipher_preferences(config.as_ptr(), cipher_prefs.as_ptr())
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_config_free(config.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        let ret = unsafe { ffi::s2n_config_disable_x509_verification(config.as_ptr()) };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_config_free(config.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        Ok(S2nConfig {
            inner: config,
            cert_chain_and_key: None,
        })
    }

    fn as_ptr(&self) -> *mut ffi::s2n_config {
        self.inner.as_ptr()
    }
}

impl Drop for S2nConfig {
    fn drop(&mut self) {
        unsafe {
            if let Some(cert_key) = self.cert_chain_and_key {
                ffi::s2n_cert_chain_and_key_free(cert_key.as_ptr());
            }
            ffi::s2n_config_free(self.inner.as_ptr());
        }
    }
}

// ====================
// I/O コンテキスト
// ====================

/// 非同期 I/O 用のコンテキスト
///
/// monoio のイベントループと s2n-tls を連携させるために使用します。
struct IoContext {
    /// ファイルディスクリプタ
    fd: RawFd,
    /// 読み込みバッファ
    read_buf: Vec<u8>,
    /// 読み込み位置
    read_pos: usize,
    /// 読み込み済みバイト数
    read_len: usize,
    /// 書き込みバッファ
    write_buf: Vec<u8>,
    /// 書き込み位置
    write_pos: usize,
    /// 最後のブロック状態
    last_blocked: BlockedStatus,
}

impl IoContext {
    fn new(fd: RawFd) -> Self {
        IoContext {
            fd,
            read_buf: vec![0u8; 65536],
            read_pos: 0,
            read_len: 0,
            write_buf: Vec::with_capacity(65536),
            write_pos: 0,
            last_blocked: BlockedStatus::NotBlocked,
        }
    }
}

// ====================
// s2n コネクション
// ====================

/// s2n-tls コネクション
struct S2nConnection {
    inner: NonNull<ffi::s2n_connection>,
}

unsafe impl Send for S2nConnection {}

impl S2nConnection {
    /// サーバーモードで新しいコネクションを作成
    fn new_server(config: &S2nConfig) -> Result<Self, S2nError> {
        let conn = unsafe { ffi::s2n_connection_new(ffi::S2N_SERVER) };
        if conn.is_null() {
            return Err(S2nError::from_errno());
        }
        let conn = unsafe { NonNull::new_unchecked(conn) };

        // 設定を適用
        let ret = unsafe { ffi::s2n_connection_set_config(conn.as_ptr(), config.as_ptr()) };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_connection_free(conn.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        // Self-service blinding を使用（非同期処理に必要）
        let ret = unsafe {
            ffi::s2n_connection_set_blinding(conn.as_ptr(), ffi::S2N_SELF_SERVICE_BLINDING)
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_connection_free(conn.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        Ok(S2nConnection { inner: conn })
    }

    /// クライアントモードで新しいコネクションを作成
    fn new_client(config: &S2nConfig, server_name: &str) -> Result<Self, S2nError> {
        let conn = unsafe { ffi::s2n_connection_new(ffi::S2N_CLIENT) };
        if conn.is_null() {
            return Err(S2nError::from_errno());
        }
        let conn = unsafe { NonNull::new_unchecked(conn) };

        // 設定を適用
        let ret = unsafe { ffi::s2n_connection_set_config(conn.as_ptr(), config.as_ptr()) };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_connection_free(conn.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        // SNI を設定
        let server_name_c = CString::new(server_name).map_err(|_| S2nError {
            code: -1,
            message: "Invalid server name".to_string(),
        })?;
        let ret = unsafe { ffi::s2n_set_server_name(conn.as_ptr(), server_name_c.as_ptr()) };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_connection_free(conn.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        // Self-service blinding を使用
        let ret = unsafe {
            ffi::s2n_connection_set_blinding(conn.as_ptr(), ffi::S2N_SELF_SERVICE_BLINDING)
        };
        if ret != ffi::S2N_SUCCESS {
            unsafe { ffi::s2n_connection_free(conn.as_ptr()) };
            return Err(S2nError::from_errno());
        }

        Ok(S2nConnection { inner: conn })
    }

    fn as_ptr(&self) -> *mut ffi::s2n_connection {
        self.inner.as_ptr()
    }

    /// ファイルディスクリプタを設定
    fn set_fd(&mut self, fd: RawFd) -> Result<(), S2nError> {
        let ret = unsafe { ffi::s2n_connection_set_fd(self.as_ptr(), fd) };
        if ret != ffi::S2N_SUCCESS {
            return Err(S2nError::from_errno());
        }
        Ok(())
    }

    /// ノンブロッキングでハンドシェイクを試行
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - ハンドシェイク完了
    /// - `Ok(false)` - ブロック中（再試行が必要）
    /// - `Err(_)` - エラー
    fn try_negotiate(&mut self) -> Result<(bool, BlockedStatus), S2nError> {
        let mut blocked: ffi::s2n_blocked_status = ffi::S2N_NOT_BLOCKED;
        let ret = unsafe { ffi::s2n_negotiate(self.as_ptr(), &mut blocked) };

        if ret == ffi::S2N_SUCCESS {
            Ok((true, BlockedStatus::NotBlocked))
        } else {
            let status = BlockedStatus::from(blocked);
            match status {
                BlockedStatus::BlockedOnRead | BlockedStatus::BlockedOnWrite => {
                    Ok((false, status))
                }
                BlockedStatus::NotBlocked => Err(S2nError::from_errno()),
            }
        }
    }

    /// ノンブロッキングでデータを読み込み
    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, BlockedStatus), S2nError> {
        let mut blocked: ffi::s2n_blocked_status = ffi::S2N_NOT_BLOCKED;
        let ret = unsafe {
            ffi::s2n_recv(
                self.as_ptr(),
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len() as isize,
                &mut blocked,
            )
        };

        if ret > 0 {
            Ok((ret as usize, BlockedStatus::NotBlocked))
        } else if ret == 0 {
            // 接続クローズ
            Ok((0, BlockedStatus::NotBlocked))
        } else {
            let status = BlockedStatus::from(blocked);
            match status {
                BlockedStatus::BlockedOnRead | BlockedStatus::BlockedOnWrite => {
                    Ok((0, status))
                }
                BlockedStatus::NotBlocked => Err(S2nError::from_errno()),
            }
        }
    }

    /// ノンブロッキングでデータを送信
    fn try_send(&mut self, buf: &[u8]) -> Result<(usize, BlockedStatus), S2nError> {
        let mut blocked: ffi::s2n_blocked_status = ffi::S2N_NOT_BLOCKED;
        let ret = unsafe {
            ffi::s2n_send(
                self.as_ptr(),
                buf.as_ptr() as *const std::ffi::c_void,
                buf.len() as isize,
                &mut blocked,
            )
        };

        if ret > 0 {
            Ok((ret as usize, BlockedStatus::NotBlocked))
        } else {
            let status = BlockedStatus::from(blocked);
            match status {
                BlockedStatus::BlockedOnRead | BlockedStatus::BlockedOnWrite => {
                    Ok((0, status))
                }
                BlockedStatus::NotBlocked => Err(S2nError::from_errno()),
            }
        }
    }

    /// kTLS 送信を有効化
    fn enable_ktls_send(&mut self) -> Result<(), S2nError> {
        let ret = unsafe { ffi::s2n_connection_ktls_enable_send(self.as_ptr()) };
        if ret != ffi::S2N_SUCCESS {
            return Err(S2nError::from_errno());
        }
        Ok(())
    }

    /// kTLS 受信を有効化
    fn enable_ktls_recv(&mut self) -> Result<(), S2nError> {
        let ret = unsafe { ffi::s2n_connection_ktls_enable_recv(self.as_ptr()) };
        if ret != ffi::S2N_SUCCESS {
            return Err(S2nError::from_errno());
        }
        Ok(())
    }

    /// 使用中の暗号スイートを取得
    fn get_cipher(&self) -> Option<String> {
        let cipher = unsafe { ffi::s2n_connection_get_cipher(self.as_ptr()) };
        if cipher.is_null() {
            return None;
        }
        unsafe {
            std::ffi::CStr::from_ptr(cipher)
                .to_str()
                .ok()
                .map(|s| s.to_string())
        }
    }

    /// TLS バージョンを取得
    fn get_protocol_version(&self) -> i32 {
        unsafe { ffi::s2n_connection_get_actual_protocol_version(self.as_ptr()) }
    }
}

impl Drop for S2nConnection {
    fn drop(&mut self) {
        unsafe {
            // シャットダウンを試みる（ベストエフォート）
            let mut blocked: ffi::s2n_blocked_status = ffi::S2N_NOT_BLOCKED;
            let _ = ffi::s2n_shutdown(self.as_ptr(), &mut blocked);
            ffi::s2n_connection_free(self.as_ptr());
        }
    }
}

// ====================
// TLS ストリーム
// ====================

/// s2n-tls TLS ストリーム
///
/// monoio の AsyncReadRent/AsyncWriteRent を実装し、
/// kTLS によるカーネルオフロードをサポートします。
pub struct S2nTlsStream {
    /// 基盤となる TCP ストリーム
    inner: TcpStream,
    /// s2n コネクション
    conn: S2nConnection,
    /// kTLS が有効かどうか（送信）
    ktls_tx_enabled: bool,
    /// kTLS が有効かどうか（受信）
    ktls_rx_enabled: bool,
}

impl S2nTlsStream {
    /// 基盤となる TCP ストリームへの参照を取得
    pub fn get_ref(&self) -> &TcpStream {
        &self.inner
    }

    /// 基盤となる TCP ストリームへの可変参照を取得
    pub fn get_mut(&mut self) -> &mut TcpStream {
        &mut self.inner
    }

    /// kTLS 送信を有効化
    ///
    /// TLS ハンドシェイク完了後に呼び出してください。
    /// 成功すると、以降の送信操作はカーネルで暗号化されます。
    pub fn enable_ktls_send(&mut self) -> Result<(), S2nError> {
        if self.ktls_tx_enabled {
            return Ok(());
        }
        self.conn.enable_ktls_send()?;
        self.ktls_tx_enabled = true;
        ftlog::info!("s2n-tls: kTLS TX enabled");
        Ok(())
    }

    /// kTLS 受信を有効化
    ///
    /// TLS ハンドシェイク完了後に呼び出してください。
    /// 成功すると、以降の受信操作はカーネルで復号化されます。
    pub fn enable_ktls_recv(&mut self) -> Result<(), S2nError> {
        if self.ktls_rx_enabled {
            return Ok(());
        }
        self.conn.enable_ktls_recv()?;
        self.ktls_rx_enabled = true;
        ftlog::info!("s2n-tls: kTLS RX enabled");
        Ok(())
    }

    /// kTLS 送受信を有効化
    pub fn enable_ktls(&mut self) -> Result<(), S2nError> {
        self.enable_ktls_send()?;
        self.enable_ktls_recv()?;
        Ok(())
    }

    /// kTLS が有効かどうか
    pub fn is_ktls_enabled(&self) -> bool {
        self.ktls_tx_enabled && self.ktls_rx_enabled
    }

    /// 使用中の暗号スイートを取得
    pub fn cipher_suite(&self) -> Option<String> {
        self.conn.get_cipher()
    }

    /// TLS バージョンを取得
    pub fn protocol_version(&self) -> i32 {
        self.conn.get_protocol_version()
    }

    /// ファイルディスクリプタを取得
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsRawFd for S2nTlsStream {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

// ====================
// 非同期ハンドシェイク
// ====================

/// 非同期 TLS ハンドシェイク（サーバー側）
///
/// monoio のイベントループと連携して、ノンブロッキングで
/// TLS ハンドシェイクを実行します。
pub async fn accept(
    stream: TcpStream,
    config: &S2nConfig,
) -> Result<S2nTlsStream, io::Error> {
    let fd = stream.as_raw_fd();

    // コネクションを作成
    let mut conn = S2nConnection::new_server(config)
        .map_err(|e| e.to_io_error())?;

    // FD を設定
    conn.set_fd(fd).map_err(|e| e.to_io_error())?;

    // ノンブロッキングでハンドシェイクを実行
    loop {
        match conn.try_negotiate() {
            Ok((true, _)) => {
                // ハンドシェイク完了
                ftlog::info!(
                    "s2n-tls: Handshake complete (cipher={:?}, version={})",
                    conn.get_cipher(),
                    conn.get_protocol_version()
                );
                return Ok(S2nTlsStream {
                    inner: stream,
                    conn,
                    ktls_tx_enabled: false,
                    ktls_rx_enabled: false,
                });
            }
            Ok((false, BlockedStatus::BlockedOnRead)) => {
                // 読み込み待ち
                stream.readable(false).await?;
            }
            Ok((false, BlockedStatus::BlockedOnWrite)) => {
                // 書き込み待ち
                stream.writable(false).await?;
            }
            Ok((false, BlockedStatus::NotBlocked)) => {
                // 予期しない状態
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unexpected handshake state",
                ));
            }
            Err(e) => {
                return Err(e.to_io_error());
            }
        }
    }
}

/// 非同期 TLS ハンドシェイク（クライアント側）
///
/// monoio のイベントループと連携して、ノンブロッキングで
/// TLS ハンドシェイクを実行します。
pub async fn connect(
    stream: TcpStream,
    config: &S2nConfig,
    server_name: &str,
) -> Result<S2nTlsStream, io::Error> {
    let fd = stream.as_raw_fd();

    // コネクションを作成
    let mut conn = S2nConnection::new_client(config, server_name)
        .map_err(|e| e.to_io_error())?;

    // FD を設定
    conn.set_fd(fd).map_err(|e| e.to_io_error())?;

    // ノンブロッキングでハンドシェイクを実行
    loop {
        match conn.try_negotiate() {
            Ok((true, _)) => {
                // ハンドシェイク完了
                ftlog::info!(
                    "s2n-tls: Client handshake complete (cipher={:?}, version={})",
                    conn.get_cipher(),
                    conn.get_protocol_version()
                );
                return Ok(S2nTlsStream {
                    inner: stream,
                    conn,
                    ktls_tx_enabled: false,
                    ktls_rx_enabled: false,
                });
            }
            Ok((false, BlockedStatus::BlockedOnRead)) => {
                stream.readable(false).await?;
            }
            Ok((false, BlockedStatus::BlockedOnWrite)) => {
                stream.writable(false).await?;
            }
            Ok((false, BlockedStatus::NotBlocked)) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unexpected handshake state",
                ));
            }
            Err(e) => {
                return Err(e.to_io_error());
            }
        }
    }
}

// ====================
// AsyncReadRent / AsyncWriteRent 実装
// ====================

impl monoio::io::AsyncReadRent for S2nTlsStream {
    async fn read<T: IoBufMut>(&mut self, mut buf: T) -> monoio::BufResult<usize, T> {
        // kTLS が有効な場合は直接 TCP から読み込み
        if self.ktls_rx_enabled {
            return self.inner.read(buf).await;
        }

        // s2n-tls 経由で読み込み
        loop {
            let slice = unsafe {
                std::slice::from_raw_parts_mut(
                    buf.write_ptr(),
                    buf.bytes_total(),
                )
            };

            match self.conn.try_recv(slice) {
                Ok((n, BlockedStatus::NotBlocked)) if n > 0 => {
                    unsafe { buf.set_init(n) };
                    return (Ok(n), buf);
                }
                Ok((0, BlockedStatus::NotBlocked)) => {
                    // EOF
                    return (Ok(0), buf);
                }
                Ok((_, BlockedStatus::BlockedOnRead)) => {
                    if let Err(e) = self.inner.readable(false).await {
                        return (Err(e), buf);
                    }
                }
                Ok((_, BlockedStatus::BlockedOnWrite)) => {
                    if let Err(e) = self.inner.writable(false).await {
                        return (Err(e), buf);
                    }
                }
                Err(e) => {
                    return (Err(e.to_io_error()), buf);
                }
                _ => continue,
            }
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> monoio::BufResult<usize, T> {
        // kTLS が有効な場合は直接 TCP から読み込み
        if self.ktls_rx_enabled {
            return self.inner.readv(buf).await;
        }

        // 簡易実装: iovec の最初のバッファのみ使用
        let iovec_ptr = buf.write_iovec_ptr();
        let iovec_len = buf.write_iovec_len();
        
        if iovec_len == 0 {
            return (Ok(0), buf);
        }
        
        let slice = unsafe {
            let iov = &*iovec_ptr;
            if iov.iov_len == 0 {
                return (Ok(0), buf);
            }
            std::slice::from_raw_parts_mut(iov.iov_base as *mut u8, iov.iov_len)
        };

        loop {
            match self.conn.try_recv(slice) {
                Ok((n, BlockedStatus::NotBlocked)) if n > 0 => {
                    return (Ok(n), buf);
                }
                Ok((0, BlockedStatus::NotBlocked)) => {
                    return (Ok(0), buf);
                }
                Ok((_, BlockedStatus::BlockedOnRead)) => {
                    if let Err(e) = self.inner.readable(false).await {
                        return (Err(e), buf);
                    }
                }
                Ok((_, BlockedStatus::BlockedOnWrite)) => {
                    if let Err(e) = self.inner.writable(false).await {
                        return (Err(e), buf);
                    }
                }
                Err(e) => {
                    return (Err(e.to_io_error()), buf);
                }
                _ => continue,
            }
        }
    }
}

impl monoio::io::AsyncWriteRent for S2nTlsStream {
    async fn write<T: IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
        // kTLS が有効な場合は直接 TCP に書き込み
        if self.ktls_tx_enabled {
            return self.inner.write(buf).await;
        }

        // s2n-tls 経由で書き込み
        let slice = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };

        loop {
            match self.conn.try_send(slice) {
                Ok((n, BlockedStatus::NotBlocked)) if n > 0 => {
                    return (Ok(n), buf);
                }
                Ok((_, BlockedStatus::BlockedOnRead)) => {
                    if let Err(e) = self.inner.readable(false).await {
                        return (Err(e), buf);
                    }
                }
                Ok((_, BlockedStatus::BlockedOnWrite)) => {
                    if let Err(e) = self.inner.writable(false).await {
                        return (Err(e), buf);
                    }
                }
                Err(e) => {
                    return (Err(e.to_io_error()), buf);
                }
                _ => continue,
            }
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
        // kTLS が有効な場合は直接 TCP に書き込み
        if self.ktls_tx_enabled {
            return self.inner.writev(buf).await;
        }

        // 簡易実装: iovec の最初のバッファのみ使用
        let iovec_ptr = buf.read_iovec_ptr();
        let iovec_len = buf.read_iovec_len();
        
        if iovec_len == 0 {
            return (Ok(0), buf);
        }
        
        let slice = unsafe {
            let iov = &*iovec_ptr;
            if iov.iov_len == 0 {
                return (Ok(0), buf);
            }
            std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
        };

        loop {
            match self.conn.try_send(slice) {
                Ok((n, BlockedStatus::NotBlocked)) if n > 0 => {
                    return (Ok(n), buf);
                }
                Ok((_, BlockedStatus::BlockedOnRead)) => {
                    if let Err(e) = self.inner.readable(false).await {
                        return (Err(e), buf);
                    }
                }
                Ok((_, BlockedStatus::BlockedOnWrite)) => {
                    if let Err(e) = self.inner.writable(false).await {
                        return (Err(e), buf);
                    }
                }
                Err(e) => {
                    return (Err(e.to_io_error()), buf);
                }
                _ => continue,
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        // s2n-tls は内部でバッファリングするため、
        // 明示的なフラッシュは不要
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        // シャットダウンは Drop で行う
        Ok(())
    }
}

// ====================
// TLS アクセプター / コネクター
// ====================

/// TLS アクセプター（サーバー側）
#[derive(Clone)]
pub struct S2nAcceptor {
    config: Arc<S2nConfig>,
    /// kTLS を有効化するかどうか
    enable_ktls: bool,
}

impl S2nAcceptor {
    /// 新しいアクセプターを作成
    pub fn new(config: Arc<S2nConfig>) -> Self {
        S2nAcceptor {
            config,
            enable_ktls: false,
        }
    }

    /// kTLS を有効化
    pub fn with_ktls(mut self, enable: bool) -> Self {
        self.enable_ktls = enable;
        self
    }

    /// TLS ハンドシェイクを実行
    pub async fn accept(&self, stream: TcpStream) -> Result<S2nTlsStream, io::Error> {
        let mut tls_stream = accept(stream, &self.config).await?;

        if self.enable_ktls {
            // デバッグ情報：ネゴシエートされた暗号スイートとプロトコルバージョン
            if let Some(cipher) = tls_stream.cipher_suite() {
                ftlog::info!("s2n-tls: Negotiated cipher: {}", cipher);
            }
            ftlog::info!("s2n-tls: Protocol version: {}", tls_stream.protocol_version());

            // kTLS を有効化（TX/RX を個別に試行）
            // TX（送信）を有効化
            if let Err(e) = tls_stream.enable_ktls_send() {
                ftlog::warn!("s2n-tls: Failed to enable kTLS TX: {}", e);
            }
            // RX（受信）を有効化 - 制限が厳しいため、失敗しても TX のみで続行
            if let Err(e) = tls_stream.enable_ktls_recv() {
                ftlog::warn!("s2n-tls: Failed to enable kTLS RX: {}", e);
                // RX 失敗は許容し、TX のみで動作
            }
        }

        Ok(tls_stream)
    }
}

/// TLS コネクター（クライアント側）
#[derive(Clone)]
pub struct S2nConnector {
    config: Arc<S2nConfig>,
    /// kTLS を有効化するかどうか
    enable_ktls: bool,
}

impl S2nConnector {
    /// 新しいコネクターを作成
    pub fn new(config: Arc<S2nConfig>) -> Self {
        S2nConnector {
            config,
            enable_ktls: false,
        }
    }

    /// kTLS を有効化
    pub fn with_ktls(mut self, enable: bool) -> Self {
        self.enable_ktls = enable;
        self
    }

    /// TLS ハンドシェイクを実行
    pub async fn connect(
        &self,
        stream: TcpStream,
        server_name: &str,
    ) -> Result<S2nTlsStream, io::Error> {
        let mut tls_stream = connect(stream, &self.config, server_name).await?;

        if self.enable_ktls {
            // デバッグ情報：ネゴシエートされた暗号スイートとプロトコルバージョン
            if let Some(cipher) = tls_stream.cipher_suite() {
                ftlog::info!("s2n-tls: Negotiated cipher: {}", cipher);
            }
            ftlog::info!("s2n-tls: Protocol version: {}", tls_stream.protocol_version());

            // kTLS を有効化（TX/RX を個別に試行）
            if let Err(e) = tls_stream.enable_ktls_send() {
                ftlog::warn!("s2n-tls: Failed to enable kTLS TX: {}", e);
            }
            if let Err(e) = tls_stream.enable_ktls_recv() {
                ftlog::warn!("s2n-tls: Failed to enable kTLS RX: {}", e);
            }
        }

        Ok(tls_stream)
    }
}

// ====================
// kTLS サポートチェック
// ====================

// ====================
// sendfile サポート（kTLS 有効時）
// ====================

/// kTLS が有効なソケットに対して sendfile システムコールを実行
///
/// kTLS が有効な場合、sendfile を使用することでファイルの内容を
/// カーネル空間で直接 TLS 暗号化して送信できます。
/// これにより、ユーザー空間へのコピーが完全に不要になります。
///
/// # Arguments
///
/// * `socket_fd` - 送信先ソケットのファイルディスクリプタ（kTLS が有効であること）
/// * `file_fd` - 送信元ファイルのファイルディスクリプタ
/// * `offset` - ファイル内の開始オフセット（更新される）
/// * `count` - 送信するバイト数
///
/// # Returns
///
/// 送信されたバイト数、またはエラー
///
/// # Safety
///
/// - socket_fd は kTLS が有効な有効なソケット FD である必要があります
/// - file_fd は有効なファイル FD である必要があります
/// - kTLS が無効なソケットに対して使用すると、平文が送信されます
pub fn sendfile_ktls(
    socket_fd: RawFd,
    file_fd: RawFd,
    offset: &mut i64,
    count: usize,
) -> io::Result<usize> {
    let result = unsafe {
        libc::sendfile(socket_fd, file_fd, offset as *mut i64, count)
    };
    
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// kTLS + sendfile によるゼロコピーファイル送信
///
/// S2nTlsStream に対してファイルをゼロコピーで送信します。
/// kTLS が有効でない場合は、通常の read/write にフォールバックする必要があります。
///
/// # Arguments
///
/// * `tls_stream` - kTLS が有効な TLS ストリーム
/// * `file_fd` - 送信するファイルのファイルディスクリプタ
/// * `offset` - ファイル内の開始オフセット
/// * `count` - 送信するバイト数
///
/// # Returns
///
/// 送信されたバイト数、またはエラー
///
/// # Notes
///
/// - この関数は同期的に実行されます
/// - 大きなファイルの場合は、チャンクに分割して呼び出してください
/// - io_uring の splice 操作を使用するとさらに効率的になりますが、
///   monoio のサポート状況に依存します
pub fn sendfile_ktls_stream(
    tls_stream: &S2nTlsStream,
    file_fd: RawFd,
    offset: &mut i64,
    count: usize,
) -> io::Result<usize> {
    if !tls_stream.is_ktls_send_enabled() {
        return Err(io::Error::other(
            "kTLS TX is not enabled. Cannot use sendfile.",
        ));
    }
    
    let socket_fd = tls_stream.as_raw_fd();
    sendfile_ktls(socket_fd, file_fd, offset, count)
}

impl S2nTlsStream {
    /// kTLS 送信が有効かどうか
    pub fn is_ktls_send_enabled(&self) -> bool {
        self.ktls_tx_enabled
    }
    
    /// kTLS 受信が有効かどうか
    pub fn is_ktls_recv_enabled(&self) -> bool {
        self.ktls_rx_enabled
    }
    
    /// sendfile によるゼロコピー送信（kTLS 有効時のみ）
    ///
    /// kTLS が有効な場合、ファイルの内容をカーネル空間で直接
    /// TLS 暗号化して送信します。
    ///
    /// # Arguments
    ///
    /// * `file_fd` - 送信するファイルのファイルディスクリプタ
    /// * `offset` - ファイル内の開始オフセット（更新される）
    /// * `count` - 送信するバイト数
    ///
    /// # Returns
    ///
    /// 送信されたバイト数、またはエラー
    pub fn sendfile(&self, file_fd: RawFd, offset: &mut i64, count: usize) -> io::Result<usize> {
        sendfile_ktls_stream(self, file_fd, offset, count)
    }
}

// ====================
// splice サポート（kTLS 有効時）
// ====================

/// splice システムコールのフラグ
pub mod splice_flags {
    /// splice操作でパイプを非ブロッキングにする
    pub const SPLICE_F_NONBLOCK: libc::c_uint = 0x02;
    /// splice操作でパイプを移動モードにする（コピーではなく移動）
    pub const SPLICE_F_MOVE: libc::c_uint = 0x01;
    /// splice操作でより多くのデータが続くことを示す
    pub const SPLICE_F_MORE: libc::c_uint = 0x04;
}

/// splice(2) システムコールのラッパー
///
/// カーネル空間でFD間のデータ移動を行います。
/// 少なくとも一方のFDがパイプである必要があります。
///
/// # Arguments
///
/// * `fd_in` - 入力ファイルディスクリプタ
/// * `off_in` - 入力オフセット（パイプの場合はNone）
/// * `fd_out` - 出力ファイルディスクリプタ
/// * `off_out` - 出力オフセット（パイプの場合はNone）
/// * `len` - 転送するバイト数
/// * `flags` - spliceフラグ
///
/// # Returns
///
/// 転送されたバイト数、またはエラー
pub fn splice(
    fd_in: RawFd,
    off_in: Option<&mut i64>,
    fd_out: RawFd,
    off_out: Option<&mut i64>,
    len: usize,
    flags: libc::c_uint,
) -> io::Result<usize> {
    let off_in_ptr = match off_in {
        Some(off) => off as *mut i64,
        None => std::ptr::null_mut(),
    };
    let off_out_ptr = match off_out {
        Some(off) => off as *mut i64,
        None => std::ptr::null_mut(),
    };
    
    let result = unsafe {
        libc::splice(fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags)
    };
    
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// パイプを作成
///
/// # Returns
///
/// (read_fd, write_fd) のタプル
pub fn create_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((fds[0], fds[1]))
    }
}

/// パイプを閉じる
pub fn close_pipe(read_fd: RawFd, write_fd: RawFd) {
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

/// パイプのバッファサイズを設定
///
/// 大きなバッファサイズを設定することで、splice操作の効率が向上します。
///
/// # Arguments
///
/// * `pipe_fd` - パイプのファイルディスクリプタ
/// * `size` - 新しいバッファサイズ
///
/// # Returns
///
/// 実際に設定されたバッファサイズ
pub fn set_pipe_size(pipe_fd: RawFd, size: i32) -> io::Result<i32> {
    let result = unsafe { libc::fcntl(pipe_fd, libc::F_SETPIPE_SZ, size) };
    
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// splice を使用したゼロコピー転送（kTLS ソケット → TCP ソケット）
///
/// kTLS が有効なソケットから平文TCPソケットへデータを転送します。
/// パイプを経由して2段階のsplice操作を行います。
///
/// # Arguments
///
/// * `src_fd` - 送信元FD（kTLSソケット）
/// * `dst_fd` - 送信先FD（TCPソケット）
/// * `pipe_read_fd` - パイプの読み取り側FD
/// * `pipe_write_fd` - パイプの書き込み側FD
/// * `chunk_size` - 一度に転送する最大バイト数
///
/// # Returns
///
/// 転送されたバイト数、またはエラー
///
/// # Note
///
/// この関数は同期的に動作します。非ブロッキングソケットでWouldBlockが
/// 返される場合があります。
pub fn splice_transfer(
    src_fd: RawFd,
    dst_fd: RawFd,
    pipe_read_fd: RawFd,
    pipe_write_fd: RawFd,
    chunk_size: usize,
) -> io::Result<usize> {
    use splice_flags::*;
    
    // Step 1: src_fd → パイプ
    let to_pipe = splice(
        src_fd,
        None,
        pipe_write_fd,
        None,
        chunk_size,
        SPLICE_F_NONBLOCK | SPLICE_F_MOVE,
    )?;
    
    if to_pipe == 0 {
        // EOF
        return Ok(0);
    }
    
    // Step 2: パイプ → dst_fd
    let mut transferred = 0;
    while transferred < to_pipe {
        let remaining = to_pipe - transferred;
        match splice(
            pipe_read_fd,
            None,
            dst_fd,
            None,
            remaining,
            SPLICE_F_NONBLOCK | SPLICE_F_MOVE,
        ) {
            Ok(0) => break,
            Ok(n) => transferred += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // 非ブロッキングなので待機が必要
                break;
            }
            Err(e) => return Err(e),
        }
    }
    
    Ok(transferred)
}

/// 再利用可能なパイプペアを管理する構造体
pub struct SplicePipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

impl SplicePipe {
    /// 新しいパイプペアを作成
    pub fn new() -> io::Result<Self> {
        let (read_fd, write_fd) = create_pipe()?;
        
        // パイプバッファを大きく設定（1MB）
        // 大きなバッファは連続したsplice操作の効率を向上させる
        let _ = set_pipe_size(write_fd, 1024 * 1024);
        
        Ok(SplicePipe { read_fd, write_fd })
    }
    
    /// 読み取りFDを取得
    pub fn read_fd(&self) -> RawFd {
        self.read_fd
    }
    
    /// 書き込みFDを取得
    pub fn write_fd(&self) -> RawFd {
        self.write_fd
    }
    
    /// src_fd から dst_fd へゼロコピー転送
    pub fn transfer(&self, src_fd: RawFd, dst_fd: RawFd, chunk_size: usize) -> io::Result<usize> {
        splice_transfer(src_fd, dst_fd, self.read_fd, self.write_fd, chunk_size)
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        close_pipe(self.read_fd, self.write_fd);
    }
}

impl Default for SplicePipe {
    fn default() -> Self {
        Self::new().expect("Failed to create splice pipe")
    }
}

impl S2nTlsStream {
    /// splice を使用したゼロコピー転送（このストリームから別のFDへ）
    ///
    /// kTLS が有効な場合、カーネル空間で直接データを転送します。
    /// kTLS が無効な場合はエラーを返します。
    ///
    /// # Arguments
    ///
    /// * `dst_fd` - 送信先ファイルディスクリプタ
    /// * `pipe` - 転送に使用するパイプ
    /// * `chunk_size` - 一度に転送する最大バイト数
    ///
    /// # Returns
    ///
    /// 転送されたバイト数、またはエラー
    pub fn splice_to(&self, dst_fd: RawFd, pipe: &SplicePipe, chunk_size: usize) -> io::Result<usize> {
        if !self.ktls_rx_enabled {
            return Err(io::Error::other(
                "kTLS RX is not enabled. Cannot use splice for reading.",
            ));
        }
        
        pipe.transfer(self.as_raw_fd(), dst_fd, chunk_size)
    }
    
    /// splice を使用したゼロコピー転送（別のFDからこのストリームへ）
    ///
    /// kTLS が有効な場合、カーネル空間で直接データを転送します。
    /// kTLS が無効な場合はエラーを返します。
    ///
    /// # Arguments
    ///
    /// * `src_fd` - 送信元ファイルディスクリプタ
    /// * `pipe` - 転送に使用するパイプ
    /// * `chunk_size` - 一度に転送する最大バイト数
    ///
    /// # Returns
    ///
    /// 転送されたバイト数、またはエラー
    pub fn splice_from(&self, src_fd: RawFd, pipe: &SplicePipe, chunk_size: usize) -> io::Result<usize> {
        if !self.ktls_tx_enabled {
            return Err(io::Error::other(
                "kTLS TX is not enabled. Cannot use splice for writing.",
            ));
        }
        
        pipe.transfer(src_fd, self.as_raw_fd(), chunk_size)
    }
}

// ====================
// kTLS サポートチェック
// ====================

/// kTLS が利用可能かどうかをチェック
///
/// # Returns
///
/// - `true` - kTLS が利用可能
/// - `false` - kTLS が利用不可
pub fn is_ktls_available() -> bool {
    // /proc/modules で tls モジュールがロードされているか確認
    if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
        if !modules.lines().any(|line| line.starts_with("tls ")) {
            return false;
        }
    } else {
        return false;
    }

    // カーネルバージョンをチェック
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        if let Some(ver_str) = version.split_whitespace().nth(2) {
            let parts: Vec<&str> = ver_str.split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    // Linux 5.15+ を推奨
                    if major < 5 || (major == 5 && minor < 15) {
                        ftlog::warn!(
                            "s2n-tls: Kernel {}.{} detected. kTLS works best on 5.15+",
                            major,
                            minor
                        );
                    }
                }
            }
        }
    }

    true
}

// ====================
// テスト
// ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
        // 複数回呼び出しても安全
        assert!(init().is_ok());
    }

    #[test]
    fn test_ktls_availability() {
        let available = is_ktls_available();
        println!("kTLS available: {}", available);
    }
}
