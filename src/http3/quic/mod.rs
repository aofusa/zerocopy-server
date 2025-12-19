//! # QUIC プロトコル実装 (RFC 9000)
//!
//! HTTP/3 の基盤となる QUIC プロトコルを実装します。
//! monoio の io_uring と統合して動作します。

pub mod packet;
pub mod crypto;
pub mod stream;
pub mod connection;

pub use packet::{PacketType, LongHeader, ShortHeader};
pub use stream::{QuicStream, StreamId, StreamType};
pub use connection::QuicConnection;

/// QUIC バージョン (RFC 9000)
pub const QUIC_VERSION_1: u32 = 0x00000001;

/// 接続 ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    /// 新しい接続 ID を生成
    pub fn generate(len: usize) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let mut id = vec![0u8; len];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = ((now >> (i * 8)) & 0xFF) as u8;
        }
        
        Self(id)
    }

    /// 空の接続 ID
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// 長さ
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空かどうか
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 暗号化レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionLevel {
    /// 初期 (Initial)
    Initial,
    /// ハンドシェイク (Handshake)
    Handshake,
    /// 1-RTT
    OneRtt,
}

/// トランスポートパラメータ
#[derive(Debug, Clone)]
pub struct TransportParameters {
    /// 初期最大データ
    pub initial_max_data: u64,
    /// 初期最大ストリームデータ (双方向)
    pub initial_max_stream_data_bidi_local: u64,
    /// 初期最大ストリームデータ (双方向リモート)
    pub initial_max_stream_data_bidi_remote: u64,
    /// 初期最大ストリームデータ (単方向)
    pub initial_max_stream_data_uni: u64,
    /// 初期最大双方向ストリーム
    pub initial_max_streams_bidi: u64,
    /// 初期最大単方向ストリーム
    pub initial_max_streams_uni: u64,
    /// アイドルタイムアウト (ms)
    pub max_idle_timeout: u64,
    /// 最大 UDP ペイロードサイズ
    pub max_udp_payload_size: u64,
    /// ACK 遅延指数
    pub ack_delay_exponent: u64,
    /// 最大 ACK 遅延
    pub max_ack_delay: u64,
    /// アクティブ接続 ID 制限
    pub active_connection_id_limit: u64,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            initial_max_data: 10 * 1024 * 1024, // 10 MB
            initial_max_stream_data_bidi_local: 1024 * 1024, // 1 MB
            initial_max_stream_data_bidi_remote: 1024 * 1024,
            initial_max_stream_data_uni: 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_idle_timeout: 30000, // 30 秒
            max_udp_payload_size: 65527,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            active_connection_id_limit: 8,
        }
    }
}

impl TransportParameters {
    /// エンコード
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // initial_max_data (0x04)
        encode_transport_param(&mut buf, 0x04, self.initial_max_data);
        // initial_max_stream_data_bidi_local (0x05)
        encode_transport_param(&mut buf, 0x05, self.initial_max_stream_data_bidi_local);
        // initial_max_stream_data_bidi_remote (0x06)
        encode_transport_param(&mut buf, 0x06, self.initial_max_stream_data_bidi_remote);
        // initial_max_stream_data_uni (0x07)
        encode_transport_param(&mut buf, 0x07, self.initial_max_stream_data_uni);
        // initial_max_streams_bidi (0x08)
        encode_transport_param(&mut buf, 0x08, self.initial_max_streams_bidi);
        // initial_max_streams_uni (0x09)
        encode_transport_param(&mut buf, 0x09, self.initial_max_streams_uni);
        // max_idle_timeout (0x01)
        encode_transport_param(&mut buf, 0x01, self.max_idle_timeout);
        // max_udp_payload_size (0x03)
        encode_transport_param(&mut buf, 0x03, self.max_udp_payload_size);

        buf
    }
}

fn encode_transport_param(buf: &mut Vec<u8>, id: u64, value: u64) {
    super::frame::encode_varint(buf, id);
    
    // 値のエンコード
    let mut value_buf = Vec::new();
    super::frame::encode_varint(&mut value_buf, value);
    
    super::frame::encode_varint(buf, value_buf.len() as u64);
    buf.extend(value_buf);
}
