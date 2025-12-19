//! # HTTP/3 エラー定義
//!
//! RFC 9114 Section 8 で定義されたエラーコードと、
//! QUIC 関連のエラーを提供します。

use std::fmt;
use std::io;

/// HTTP/3 エラーコード (RFC 9114 Section 8.1)
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3ErrorCode {
    /// 正常終了
    NoError = 0x100,
    /// 一般的なプロトコルエラー
    GeneralProtocolError = 0x101,
    /// 内部エラー
    InternalError = 0x102,
    /// ストリームクリエイションエラー
    StreamCreationError = 0x103,
    /// クローズ済みクリティカルストリーム
    ClosedCriticalStream = 0x104,
    /// フレームの予期しないタイプ
    FrameUnexpected = 0x105,
    /// フレームエラー
    FrameError = 0x106,
    /// 過剰な負荷
    ExcessiveLoad = 0x107,
    /// 設定エラー
    SettingsError = 0x109,
    /// リクエストが拒否された
    RequestRejected = 0x10b,
    /// リクエストがキャンセルされた
    RequestCancelled = 0x10c,
    /// リクエストが不完全
    RequestIncomplete = 0x10d,
    /// メッセージエラー
    MessageError = 0x10e,
    /// 接続クローズ
    ConnectError = 0x10f,
    /// バージョンフォールバック
    VersionFallback = 0x110,
}

impl Http3ErrorCode {
    /// u64 から変換
    pub fn from_u64(code: u64) -> Self {
        match code {
            0x100 => Self::NoError,
            0x101 => Self::GeneralProtocolError,
            0x102 => Self::InternalError,
            0x103 => Self::StreamCreationError,
            0x104 => Self::ClosedCriticalStream,
            0x105 => Self::FrameUnexpected,
            0x106 => Self::FrameError,
            0x107 => Self::ExcessiveLoad,
            0x109 => Self::SettingsError,
            0x10b => Self::RequestRejected,
            0x10c => Self::RequestCancelled,
            0x10d => Self::RequestIncomplete,
            0x10e => Self::MessageError,
            0x10f => Self::ConnectError,
            0x110 => Self::VersionFallback,
            _ => Self::GeneralProtocolError,
        }
    }
}

impl fmt::Display for Http3ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::NoError => "H3_NO_ERROR",
            Self::GeneralProtocolError => "H3_GENERAL_PROTOCOL_ERROR",
            Self::InternalError => "H3_INTERNAL_ERROR",
            Self::StreamCreationError => "H3_STREAM_CREATION_ERROR",
            Self::ClosedCriticalStream => "H3_CLOSED_CRITICAL_STREAM",
            Self::FrameUnexpected => "H3_FRAME_UNEXPECTED",
            Self::FrameError => "H3_FRAME_ERROR",
            Self::ExcessiveLoad => "H3_EXCESSIVE_LOAD",
            Self::SettingsError => "H3_SETTINGS_ERROR",
            Self::RequestRejected => "H3_REQUEST_REJECTED",
            Self::RequestCancelled => "H3_REQUEST_CANCELLED",
            Self::RequestIncomplete => "H3_REQUEST_INCOMPLETE",
            Self::MessageError => "H3_MESSAGE_ERROR",
            Self::ConnectError => "H3_CONNECT_ERROR",
            Self::VersionFallback => "H3_VERSION_FALLBACK",
        };
        write!(f, "{}", name)
    }
}

/// QUIC エラーコード (RFC 9000 Section 20)
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicErrorCode {
    /// 正常終了
    NoError = 0x0,
    /// 内部エラー
    InternalError = 0x1,
    /// 接続拒否
    ConnectionRefused = 0x2,
    /// フロー制御エラー
    FlowControlError = 0x3,
    /// ストリーム制限エラー
    StreamLimitError = 0x4,
    /// ストリーム状態エラー
    StreamStateError = 0x5,
    /// 最終サイズエラー
    FinalSizeError = 0x6,
    /// フレームエンコーディングエラー
    FrameEncodingError = 0x7,
    /// トランスポートパラメータエラー
    TransportParameterError = 0x8,
    /// 接続ID制限エラー
    ConnectionIdLimitError = 0x9,
    /// プロトコル違反
    ProtocolViolation = 0xa,
    /// 無効なトークン
    InvalidToken = 0xb,
    /// アプリケーションエラー
    ApplicationError = 0xc,
    /// 暗号バッファ超過
    CryptoBufferExceeded = 0xd,
    /// キー更新エラー
    KeyUpdateError = 0xe,
    /// AEAD制限到達
    AeadLimitReached = 0xf,
    /// 接続クローズ不要
    NoViablePathError = 0x10,
}

/// HTTP/3 エラー
#[derive(Debug)]
pub enum Http3Error {
    /// HTTP/3 プロトコルエラー
    Http3(Http3ErrorCode, String),
    /// QUIC エラー
    Quic(QuicErrorCode, String),
    /// I/O エラー
    Io(io::Error),
    /// QPACK エラー
    Qpack(String),
    /// タイムアウト
    Timeout,
    /// 接続クローズ
    ConnectionClosed,
    /// フレームエラー
    InvalidFrame(String),
}

impl fmt::Display for Http3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http3(code, msg) => write!(f, "HTTP/3 error {}: {}", code, msg),
            Self::Quic(code, msg) => write!(f, "QUIC error {:?}: {}", code, msg),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Qpack(msg) => write!(f, "QPACK error: {}", msg),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::InvalidFrame(msg) => write!(f, "Invalid frame: {}", msg),
        }
    }
}

impl std::error::Error for Http3Error {}

impl From<io::Error> for Http3Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// HTTP/3 処理結果
pub type Http3Result<T> = Result<T, Http3Error>;
