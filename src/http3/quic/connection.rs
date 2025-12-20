//! # QUIC コネクション (RFC 9000)

use std::collections::HashMap;
use std::net::SocketAddr;

use super::{ConnectionId, EncryptionLevel, TransportParameters};
use super::stream::{QuicStream, StreamId};
use super::crypto::QuicCrypto;
use crate::http3::error::{Http3Error, Http3Result, QuicErrorCode};

/// QUIC コネクション状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// 初期
    Initial,
    /// ハンドシェイク中
    Handshaking,
    /// 確立済み
    Established,
    /// クロージング
    Closing,
    /// ドレイン中
    Draining,
    /// クローズ済み
    Closed,
}

/// QUIC コネクション
#[allow(dead_code)]
pub struct QuicConnection {
    /// ローカル接続 ID
    pub local_cid: ConnectionId,
    /// リモート接続 ID
    pub remote_cid: ConnectionId,
    /// リモートアドレス
    pub remote_addr: SocketAddr,
    /// 状態
    pub state: ConnectionState,
    /// ストリーム
    streams: HashMap<u64, QuicStream>,
    /// 暗号化
    crypto: QuicCrypto,
    /// ローカルトランスポートパラメータ
    local_params: TransportParameters,
    /// リモートトランスポートパラメータ
    remote_params: Option<TransportParameters>,
    /// 次のクライアントストリーム ID (双方向)
    next_client_bidi_stream: u64,
    /// 次のクライアントストリーム ID (単方向)
    next_client_uni_stream: u64,
    /// 次のサーバーストリーム ID (双方向)
    next_server_bidi_stream: u64,
    /// 次のサーバーストリーム ID (単方向)
    next_server_uni_stream: u64,
    /// 送信パケット番号
    send_pn: u64,
    /// 最大受信パケット番号
    max_recv_pn: u64,
    /// アイドルタイムアウト (ms)
    idle_timeout: u64,
    /// 最終アクティビティ時刻
    last_activity: std::time::Instant,
}

impl QuicConnection {
    /// 新しいサーバーコネクションを作成
    pub fn new_server(
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        remote_addr: SocketAddr,
    ) -> Self {
        let mut crypto = QuicCrypto::new();
        crypto.derive_initial_secrets(remote_cid.as_ref());

        Self {
            local_cid,
            remote_cid,
            remote_addr,
            state: ConnectionState::Initial,
            streams: HashMap::new(),
            crypto,
            local_params: TransportParameters::default(),
            remote_params: None,
            next_client_bidi_stream: 0,
            next_client_uni_stream: 2,
            next_server_bidi_stream: 1,
            next_server_uni_stream: 3,
            send_pn: 0,
            max_recv_pn: 0,
            idle_timeout: 30000,
            last_activity: std::time::Instant::now(),
        }
    }

    /// ストリームを取得または作成
    pub fn get_or_create_stream(&mut self, id: u64) -> Http3Result<&mut QuicStream> {
        if !self.streams.contains_key(&id) {
            let stream = QuicStream::new(
                StreamId(id),
                self.local_params.initial_max_stream_data_bidi_local,
                self.local_params.initial_max_stream_data_bidi_remote,
            );
            self.streams.insert(id, stream);
        }
        Ok(self.streams.get_mut(&id).unwrap())
    }

    /// ストリームを取得
    pub fn get_stream(&self, id: u64) -> Option<&QuicStream> {
        self.streams.get(&id)
    }

    /// ストリームを可変で取得
    pub fn get_stream_mut(&mut self, id: u64) -> Option<&mut QuicStream> {
        self.streams.get_mut(&id)
    }

    /// 新しいサーバー双方向ストリームを作成
    pub fn create_server_bidi_stream(&mut self) -> Http3Result<u64> {
        let id = self.next_server_bidi_stream;
        self.next_server_bidi_stream += 4;

        let stream = QuicStream::new(
            StreamId(id),
            self.local_params.initial_max_stream_data_bidi_local,
            self.local_params.initial_max_stream_data_bidi_remote,
        );
        self.streams.insert(id, stream);

        Ok(id)
    }

    /// 新しいサーバー単方向ストリームを作成
    pub fn create_server_uni_stream(&mut self) -> Http3Result<u64> {
        let id = self.next_server_uni_stream;
        self.next_server_uni_stream += 4;

        let stream = QuicStream::new(
            StreamId(id),
            self.local_params.initial_max_stream_data_uni,
            0,
        );
        self.streams.insert(id, stream);

        Ok(id)
    }

    /// パケットを処理
    pub fn process_packet(&mut self, packet: &[u8]) -> Http3Result<()> {
        if packet.is_empty() {
            return Err(Http3Error::Quic(QuicErrorCode::ProtocolViolation, "Empty packet".into()));
        }

        self.last_activity = std::time::Instant::now();

        // ヘッダー形式を判定
        let is_long_header = packet[0] & 0x80 != 0;

        if is_long_header {
            self.process_long_header_packet(packet)
        } else {
            self.process_short_header_packet(packet)
        }
    }

    /// Long Header パケットを処理
    fn process_long_header_packet(&mut self, _packet: &[u8]) -> Http3Result<()> {
        // パケットタイプに応じて処理
        match self.state {
            ConnectionState::Initial => {
                self.state = ConnectionState::Handshaking;
            }
            ConnectionState::Handshaking => {
                // ハンドシェイク処理
                self.crypto.advance_level(EncryptionLevel::Handshake);
            }
            _ => {}
        }

        Ok(())
    }

    /// Short Header パケットを処理
    fn process_short_header_packet(&mut self, _packet: &[u8]) -> Http3Result<()> {
        if self.state == ConnectionState::Handshaking {
            self.state = ConnectionState::Established;
            self.crypto.advance_level(EncryptionLevel::OneRtt);
        }

        Ok(())
    }

    /// コネクションを閉じる
    pub fn close(&mut self, error: QuicErrorCode, reason: &str) -> Http3Result<Vec<u8>> {
        self.state = ConnectionState::Closing;

        // CONNECTION_CLOSE フレームを生成
        let mut frame = Vec::new();
        frame.push(0x1c); // CONNECTION_CLOSE (type=0x1c)
        crate::http3::frame::encode_varint(&mut frame, error as u64);
        crate::http3::frame::encode_varint(&mut frame, 0); // Frame Type (0 = not specific)
        crate::http3::frame::encode_varint(&mut frame, reason.len() as u64);
        frame.extend_from_slice(reason.as_bytes());

        Ok(frame)
    }

    /// アイドルタイムアウトをチェック
    pub fn check_idle_timeout(&self) -> bool {
        self.last_activity.elapsed().as_millis() > self.idle_timeout as u128
    }

    /// 次の送信パケット番号を取得
    pub fn next_pn(&mut self) -> u64 {
        let pn = self.send_pn;
        self.send_pn += 1;
        pn
    }

    /// ストリームをイテレート
    pub fn streams(&self) -> impl Iterator<Item = (&u64, &QuicStream)> {
        self.streams.iter()
    }

    /// 可変でストリームをイテレート
    pub fn streams_mut(&mut self) -> impl Iterator<Item = (&u64, &mut QuicStream)> {
        self.streams.iter_mut()
    }

    /// トランスポートパラメータを設定
    pub fn set_transport_params(&mut self, params: TransportParameters) {
        self.local_params = params;
    }

    /// リモートトランスポートパラメータを設定
    pub fn set_remote_transport_params(&mut self, params: TransportParameters) {
        self.idle_timeout = params.max_idle_timeout;
        self.remote_params = Some(params);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_new() {
        let local_cid = ConnectionId::generate(8);
        let remote_cid = ConnectionId::generate(8);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let conn = QuicConnection::new_server(local_cid, remote_cid, remote_addr);

        assert_eq!(conn.state, ConnectionState::Initial);
    }

    #[test]
    fn test_create_streams() {
        let local_cid = ConnectionId::generate(8);
        let remote_cid = ConnectionId::generate(8);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut conn = QuicConnection::new_server(local_cid, remote_cid, remote_addr);

        let id1 = conn.create_server_bidi_stream().unwrap();
        let id2 = conn.create_server_bidi_stream().unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 5);
    }
}
