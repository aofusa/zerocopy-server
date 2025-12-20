//! # HTTP/3 コネクション管理 (RFC 9114)
//!
//! HTTP/3 コネクションの確立とフレーム処理を行います。

use std::collections::HashMap;

use crate::http3::error::{Http3Error, Http3ErrorCode, Http3Result};
use crate::http3::frame::{H3Frame, settings};
use crate::http3::qpack::{QpackEncoder, QpackDecoder, HeaderField};
use crate::http3::quic::QuicConnection;
use crate::http3::quic::stream::StreamId;

/// HTTP/3 ストリームタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3StreamType {
    /// 制御ストリーム
    Control,
    /// QPACK エンコーダストリーム
    QpackEncoder,
    /// QPACK デコーダストリーム
    QpackDecoder,
    /// リクエストストリーム
    Request,
}

/// HTTP/3 設定
#[derive(Debug, Clone)]
pub struct Http3Settings {
    /// QPACK 最大テーブル容量
    pub qpack_max_table_capacity: u64,
    /// QPACK 最大ブロックストリーム
    pub qpack_blocked_streams: u64,
}

impl Default for Http3Settings {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        }
    }
}

/// HTTP/3 コネクション
pub struct Http3Connection {
    /// 基盤の QUIC コネクション
    quic: QuicConnection,
    /// ローカル設定
    local_settings: Http3Settings,
    /// リモート設定
    remote_settings: Option<Http3Settings>,
    /// QPACK エンコーダ
    qpack_encoder: QpackEncoder,
    /// QPACK デコーダ
    qpack_decoder: QpackDecoder,
    /// 制御ストリーム ID (ローカル)
    local_control_stream: Option<u64>,
    /// 制御ストリーム ID (リモート)
    remote_control_stream: Option<u64>,
    /// QPACK エンコーダストリーム ID (ローカル)
    local_encoder_stream: Option<u64>,
    /// QPACK デコーダストリーム ID (ローカル)
    local_decoder_stream: Option<u64>,
    /// リクエストストリームのヘッダー
    request_headers: HashMap<u64, Vec<HeaderField>>,
    /// リクエストストリームのボディ
    request_bodies: HashMap<u64, Vec<u8>>,
    /// GOAWAY 送信済み
    goaway_sent: bool,
    /// GOAWAY 受信済み
    goaway_received: bool,
}

impl Http3Connection {
    /// 新しい HTTP/3 コネクションを作成
    pub fn new(quic: QuicConnection, settings: Http3Settings) -> Self {
        Self {
            quic,
            local_settings: settings.clone(),
            remote_settings: None,
            qpack_encoder: QpackEncoder::new(
                settings.qpack_max_table_capacity as usize,
                settings.qpack_blocked_streams as usize,
            ),
            qpack_decoder: QpackDecoder::new(
                settings.qpack_max_table_capacity as usize,
                settings.qpack_blocked_streams as usize,
            ),
            local_control_stream: None,
            remote_control_stream: None,
            local_encoder_stream: None,
            local_decoder_stream: None,
            request_headers: HashMap::new(),
            request_bodies: HashMap::new(),
            goaway_sent: false,
            goaway_received: false,
        }
    }

    /// HTTP/3 ハンドシェイク (制御ストリームと SETTINGS の交換)
    pub fn handshake(&mut self) -> Http3Result<Vec<u8>> {
        let mut output = Vec::new();

        // 制御ストリームを作成
        let control_id = self.quic.create_server_uni_stream()
            .map_err(|e| Http3Error::Http3(Http3ErrorCode::StreamCreationError, e.to_string()))?;
        self.local_control_stream = Some(control_id);

        // 制御ストリームタイプを送信 (0x00)
        output.push(0x00);

        // SETTINGS フレームを送信
        let settings_frame = H3Frame::Settings(vec![
            (settings::QPACK_MAX_TABLE_CAPACITY, self.local_settings.qpack_max_table_capacity),
            (settings::QPACK_BLOCKED_STREAMS, self.local_settings.qpack_blocked_streams),
        ]);
        output.extend(settings_frame.encode());

        // QPACK エンコーダストリームを作成
        let encoder_id = self.quic.create_server_uni_stream()
            .map_err(|e| Http3Error::Http3(Http3ErrorCode::StreamCreationError, e.to_string()))?;
        self.local_encoder_stream = Some(encoder_id);

        // QPACK デコーダストリームを作成
        let decoder_id = self.quic.create_server_uni_stream()
            .map_err(|e| Http3Error::Http3(Http3ErrorCode::StreamCreationError, e.to_string()))?;
        self.local_decoder_stream = Some(decoder_id);

        Ok(output)
    }

    /// フレームを処理
    pub fn process_frame(&mut self, stream_id: u64, data: &[u8]) -> Http3Result<Option<ProcessedRequest>> {
        if data.is_empty() {
            return Ok(None);
        }

        // ストリームタイプを判定
        let stream_type = self.get_stream_type(stream_id);

        match stream_type {
            H3StreamType::Control => self.process_control_frame(stream_id, data),
            H3StreamType::QpackEncoder | H3StreamType::QpackDecoder => {
                // QPACK ストリームの処理
                Ok(None)
            }
            H3StreamType::Request => self.process_request_frame(stream_id, data),
        }
    }

    /// ストリームタイプを取得
    fn get_stream_type(&self, stream_id: u64) -> H3StreamType {
        if Some(stream_id) == self.remote_control_stream {
            H3StreamType::Control
        } else if StreamId(stream_id).is_bidirectional() {
            H3StreamType::Request
        } else {
            // 単方向ストリーム - 最初のバイトで判定
            H3StreamType::Control
        }
    }

    /// 制御フレームを処理
    fn process_control_frame(&mut self, stream_id: u64, data: &[u8]) -> Http3Result<Option<ProcessedRequest>> {
        let (frame, _) = H3Frame::decode(data)?;

        match frame {
            H3Frame::Settings(settings) => {
                let mut remote = Http3Settings::default();
                for (id, value) in settings {
                    match id {
                        s if s == settings::QPACK_MAX_TABLE_CAPACITY => {
                            remote.qpack_max_table_capacity = value;
                        }
                        s if s == settings::QPACK_BLOCKED_STREAMS => {
                            remote.qpack_blocked_streams = value;
                        }
                        _ => {
                            // 未知の設定は無視
                        }
                    }
                }
                self.remote_settings = Some(remote);
                self.remote_control_stream = Some(stream_id);
            }
            H3Frame::GoAway(_stream_id) => {
                self.goaway_received = true;
            }
            _ => {
                // その他の制御フレームは無視
            }
        }

        Ok(None)
    }

    /// リクエストフレームを処理
    fn process_request_frame(&mut self, stream_id: u64, data: &[u8]) -> Http3Result<Option<ProcessedRequest>> {
        let (frame, consumed) = H3Frame::decode(data)?;

        match frame {
            H3Frame::Headers(header_block) => {
                // QPACK デコード
                let headers = self.qpack_decoder.decode(&header_block)
                    .map_err(|e| Http3Error::Qpack(e.to_string()))?;
                self.request_headers.insert(stream_id, headers);

                // ボディがなければリクエスト完了
                if consumed >= data.len() {
                    return Ok(Some(ProcessedRequest { stream_id }));
                }
            }
            H3Frame::Data(body) => {
                let entry = self.request_bodies.entry(stream_id).or_insert_with(Vec::new);
                entry.extend(body);

                // FIN を受信したらリクエスト完了
                if let Some(stream) = self.quic.get_stream(stream_id) {
                    if stream.fin_received {
                        return Ok(Some(ProcessedRequest { stream_id }));
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }

    /// レスポンスを送信
    pub fn send_response(
        &mut self,
        _stream_id: u64,
        status: u16,
        headers: &[(&[u8], &[u8])],
        body: Option<&[u8]>,
    ) -> Http3Result<Vec<u8>> {
        let mut output = Vec::new();

        // ステータスとヘッダーを準備
        let mut header_list: Vec<(&[u8], &[u8])> = Vec::with_capacity(headers.len() + 1);
        let status_bytes = match status {
            200 => b"200".as_slice(),
            204 => b"204".as_slice(),
            304 => b"304".as_slice(),
            400 => b"400".as_slice(),
            404 => b"404".as_slice(),
            500 => b"500".as_slice(),
            _ => b"200".as_slice(),
        };
        header_list.push((b":status", status_bytes));
        header_list.extend_from_slice(headers);

        // QPACK エンコード
        let header_block = self.qpack_encoder.encode_static(&header_list)
            .map_err(|e| Http3Error::Qpack(e.to_string()))?;

        // HEADERS フレーム
        let headers_frame = H3Frame::Headers(header_block);
        output.extend(headers_frame.encode());

        // DATA フレーム
        if let Some(body) = body {
            if !body.is_empty() {
                let data_frame = H3Frame::Data(body.to_vec());
                output.extend(data_frame.encode());
            }
        }

        Ok(output)
    }

    /// GOAWAY を送信
    pub fn send_goaway(&mut self) -> Http3Result<Vec<u8>> {
        if self.goaway_sent {
            return Ok(Vec::new());
        }

        self.goaway_sent = true;

        // 最後に受け入れたストリーム ID
        let last_stream_id = 0u64; // 簡略化

        let frame = H3Frame::GoAway(last_stream_id);
        Ok(frame.encode())
    }

    /// リクエストヘッダーを取得
    pub fn get_request_headers(&self, stream_id: u64) -> Option<&Vec<HeaderField>> {
        self.request_headers.get(&stream_id)
    }

    /// リクエストボディを取得
    pub fn get_request_body(&self, stream_id: u64) -> Option<&Vec<u8>> {
        self.request_bodies.get(&stream_id)
    }

    /// QUIC コネクションへの参照
    pub fn quic(&self) -> &QuicConnection {
        &self.quic
    }

    /// QUIC コネクションへの可変参照
    pub fn quic_mut(&mut self) -> &mut QuicConnection {
        &mut self.quic
    }
}

/// 処理済みリクエスト
#[derive(Debug)]
pub struct ProcessedRequest {
    /// ストリーム ID
    pub stream_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::quic::ConnectionId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_handshake() {
        let local_cid = ConnectionId::generate(8);
        let remote_cid = ConnectionId::generate(8);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        let quic = QuicConnection::new_server(local_cid, remote_cid, remote_addr);
        let settings = Http3Settings::default();
        let mut conn = Http3Connection::new(quic, settings);

        let output = conn.handshake().unwrap();
        assert!(!output.is_empty());
        assert!(conn.local_control_stream.is_some());
    }
}
