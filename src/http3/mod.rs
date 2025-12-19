//! # HTTP/3 プロトコル実装
//!
//! RFC 9114 (HTTP/3) と RFC 9000 (QUIC) の実装。
//! monoio 非同期ランタイムと統合して動作します。
//!
//! ## 注意
//!
//! HTTP/3 は QUIC (UDP) ベースのため、kTLS は使用できません。
//! 代わりに rustls の QUIC サポートを使用します。
//!
//! ## モジュール構成
//!
//! - `quic`: QUIC プロトコル実装
//! - `qpack`: QPACK ヘッダー圧縮
//! - `frame`: HTTP/3 フレーム
//! - `connection`: HTTP/3 コネクション管理

pub mod quic;
pub mod qpack;
pub mod frame;
pub mod connection;
pub mod error;

pub use error::{Http3Error, Http3ErrorCode};
pub use connection::Http3Connection;
