//! # QUIC ストリーム (RFC 9000 Section 2)

use std::collections::VecDeque;

/// ストリーム ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    /// ストリームタイプを取得
    pub fn stream_type(&self) -> StreamType {
        match self.0 & 0x03 {
            0x00 => StreamType::BidiClient,
            0x01 => StreamType::BidiServer,
            0x02 => StreamType::UniClient,
            0x03 => StreamType::UniServer,
            _ => unreachable!(),
        }
    }

    /// クライアント開始かどうか
    pub fn is_client_initiated(&self) -> bool {
        self.0 & 0x01 == 0
    }

    /// 双方向かどうか
    pub fn is_bidirectional(&self) -> bool {
        self.0 & 0x02 == 0
    }
}

/// ストリームタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// クライアント開始双方向
    BidiClient,
    /// サーバー開始双方向
    BidiServer,
    /// クライアント開始単方向
    UniClient,
    /// サーバー開始単方向
    UniServer,
}

/// ストリーム状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// 準備完了
    Ready,
    /// 送信中
    Send,
    /// データ送信済み
    DataSent,
    /// リセット送信済み
    ResetSent,
    /// リセット受信済み
    ResetRecvd,
    /// 受信中
    Recv,
    /// サイズ既知
    SizeKnown,
    /// データ受信済み
    DataRecvd,
    /// データ読み取り済み
    DataRead,
    /// リセット読み取り済み
    ResetRead,
}

/// QUIC ストリーム
#[derive(Debug)]
pub struct QuicStream {
    /// ストリーム ID
    pub id: StreamId,
    /// 状態
    pub state: StreamState,
    /// 送信バッファ
    pub send_buf: VecDeque<u8>,
    /// 受信バッファ
    pub recv_buf: VecDeque<u8>,
    /// 送信オフセット
    pub send_offset: u64,
    /// 受信オフセット
    pub recv_offset: u64,
    /// 最大送信データ
    pub max_send_data: u64,
    /// 最大受信データ
    pub max_recv_data: u64,
    /// FIN 送信済み
    pub fin_sent: bool,
    /// FIN 受信済み
    pub fin_received: bool,
}

impl QuicStream {
    /// 新しいストリームを作成
    pub fn new(id: StreamId, max_send_data: u64, max_recv_data: u64) -> Self {
        Self {
            id,
            state: StreamState::Ready,
            send_buf: VecDeque::new(),
            recv_buf: VecDeque::new(),
            send_offset: 0,
            recv_offset: 0,
            max_send_data,
            max_recv_data,
            fin_sent: false,
            fin_received: false,
        }
    }

    /// データを送信バッファに追加
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let available = self.max_send_data.saturating_sub(self.send_offset + self.send_buf.len() as u64);
        let to_write = (data.len() as u64).min(available) as usize;

        if to_write == 0 && !data.is_empty() {
            return Err("Flow control limit reached");
        }

        self.send_buf.extend(&data[..to_write]);
        Ok(to_write)
    }

    /// 受信バッファからデータを読み取り
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.recv_buf.len());
        for (i, byte) in self.recv_buf.drain(..to_read).enumerate() {
            buf[i] = byte;
        }
        to_read
    }

    /// 受信データを追加
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), &'static str> {
        // オフセットチェック
        if offset != self.recv_offset + self.recv_buf.len() as u64 {
            // 順序外のデータ - 簡略化のため拒否
            return Err("Out of order data");
        }

        if self.recv_offset + self.recv_buf.len() as u64 + data.len() as u64 > self.max_recv_data {
            return Err("Flow control limit exceeded");
        }

        self.recv_buf.extend(data);

        if fin {
            self.fin_received = true;
            self.state = StreamState::SizeKnown;
        }

        Ok(())
    }

    /// 送信するデータを取得
    pub fn poll_send(&mut self, max_len: usize) -> Option<(Vec<u8>, u64, bool)> {
        if self.send_buf.is_empty() {
            if self.fin_sent {
                return None;
            }
            return Some((Vec::new(), self.send_offset, false));
        }

        let to_send = max_len.min(self.send_buf.len());
        let data: Vec<u8> = self.send_buf.drain(..to_send).collect();
        let offset = self.send_offset;
        self.send_offset += to_send as u64;

        let fin = self.send_buf.is_empty() && self.fin_sent;

        Some((data, offset, fin))
    }

    /// FIN を設定
    pub fn set_fin(&mut self) {
        self.fin_sent = true;
    }

    /// 読み取り可能なデータがあるか
    pub fn is_readable(&self) -> bool {
        !self.recv_buf.is_empty() || self.fin_received
    }

    /// 書き込み可能か
    pub fn is_writable(&self) -> bool {
        let pending = self.send_buf.len() as u64;
        self.send_offset + pending < self.max_send_data && !self.fin_sent
    }

    /// ストリームが完了したか
    pub fn is_finished(&self) -> bool {
        self.fin_sent && self.fin_received && self.send_buf.is_empty() && self.recv_buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_write_read() {
        let mut stream = QuicStream::new(StreamId(0), 1024, 1024);

        // Write
        let written = stream.write(b"Hello, World!").unwrap();
        assert_eq!(written, 13);

        // Poll send
        let (data, offset, fin) = stream.poll_send(100).unwrap();
        assert_eq!(data, b"Hello, World!");
        assert_eq!(offset, 0);
        assert!(!fin);
    }

    #[test]
    fn test_stream_receive() {
        let mut stream = QuicStream::new(StreamId(0), 1024, 1024);

        stream.receive(0, b"Hello", false).unwrap();
        assert_eq!(stream.recv_buf.len(), 5);

        let mut buf = [0u8; 10];
        let read = stream.read(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"Hello");
    }

    #[test]
    fn test_stream_id_type() {
        assert!(StreamId(0).is_client_initiated());
        assert!(StreamId(0).is_bidirectional());

        assert!(!StreamId(1).is_client_initiated());
        assert!(StreamId(1).is_bidirectional());

        assert!(StreamId(2).is_client_initiated());
        assert!(!StreamId(2).is_bidirectional());
    }
}
