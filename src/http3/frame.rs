//! # HTTP/3 フレーム (RFC 9114 Section 7)
//!
//! HTTP/3 フレームのエンコードとデコードを提供します。

use super::error::{Http3Error, Http3Result};

/// HTTP/3 フレームタイプ (RFC 9114 Section 7.2)
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3FrameType {
    /// DATA フレーム
    Data = 0x00,
    /// HEADERS フレーム
    Headers = 0x01,
    /// CANCEL_PUSH フレーム (非推奨)
    CancelPush = 0x03,
    /// SETTINGS フレーム
    Settings = 0x04,
    /// PUSH_PROMISE フレーム
    PushPromise = 0x05,
    /// GOAWAY フレーム
    GoAway = 0x07,
    /// MAX_PUSH_ID フレーム
    MaxPushId = 0x0d,
}

impl H3FrameType {
    /// u64 から変換
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::CancelPush),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x07 => Some(Self::GoAway),
            0x0d => Some(Self::MaxPushId),
            _ => None,
        }
    }
}

/// HTTP/3 フレーム
#[derive(Debug, Clone)]
pub enum H3Frame {
    /// DATA フレーム
    Data(Vec<u8>),
    /// HEADERS フレーム (QPACK エンコード済み)
    Headers(Vec<u8>),
    /// SETTINGS フレーム
    Settings(Vec<(u64, u64)>),
    /// GOAWAY フレーム
    GoAway(u64),
    /// CANCEL_PUSH フレーム
    CancelPush(u64),
    /// PUSH_PROMISE フレーム
    PushPromise {
        push_id: u64,
        header_block: Vec<u8>,
    },
    /// MAX_PUSH_ID フレーム
    MaxPushId(u64),
    /// 未知のフレーム
    Unknown(u64, Vec<u8>),
}

impl H3Frame {
    /// フレームをデコード
    pub fn decode(data: &[u8]) -> Http3Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Http3Error::InvalidFrame("Empty frame".into()));
        }

        let (frame_type, type_len) = decode_varint(data)?;
        let (length, len_len) = decode_varint(&data[type_len..])?;

        let header_len = type_len + len_len;
        if data.len() < header_len + length as usize {
            return Err(Http3Error::InvalidFrame("Frame too short".into()));
        }

        let payload = &data[header_len..header_len + length as usize];

        let frame = match H3FrameType::from_u64(frame_type) {
            Some(H3FrameType::Data) => H3Frame::Data(payload.to_vec()),
            Some(H3FrameType::Headers) => H3Frame::Headers(payload.to_vec()),
            Some(H3FrameType::Settings) => Self::decode_settings(payload)?,
            Some(H3FrameType::GoAway) => {
                let (stream_id, _) = decode_varint(payload)?;
                H3Frame::GoAway(stream_id)
            }
            Some(H3FrameType::CancelPush) => {
                let (push_id, _) = decode_varint(payload)?;
                H3Frame::CancelPush(push_id)
            }
            Some(H3FrameType::PushPromise) => {
                let (push_id, id_len) = decode_varint(payload)?;
                H3Frame::PushPromise {
                    push_id,
                    header_block: payload[id_len..].to_vec(),
                }
            }
            Some(H3FrameType::MaxPushId) => {
                let (push_id, _) = decode_varint(payload)?;
                H3Frame::MaxPushId(push_id)
            }
            None => H3Frame::Unknown(frame_type, payload.to_vec()),
        };

        Ok((frame, header_len + length as usize))
    }

    /// SETTINGS フレームをデコード
    fn decode_settings(payload: &[u8]) -> Http3Result<Self> {
        let mut settings = Vec::new();
        let mut pos = 0;

        while pos < payload.len() {
            let (id, id_len) = decode_varint(&payload[pos..])?;
            pos += id_len;
            let (value, value_len) = decode_varint(&payload[pos..])?;
            pos += value_len;
            settings.push((id, value));
        }

        Ok(H3Frame::Settings(settings))
    }

    /// フレームをエンコード
    pub fn encode(&self) -> Vec<u8> {
        match self {
            H3Frame::Data(payload) => {
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::Data as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(payload);
                buf
            }
            H3Frame::Headers(payload) => {
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::Headers as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(payload);
                buf
            }
            H3Frame::Settings(settings) => {
                let mut payload = Vec::new();
                for &(id, value) in settings {
                    encode_varint(&mut payload, id);
                    encode_varint(&mut payload, value);
                }
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::Settings as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend(payload);
                buf
            }
            H3Frame::GoAway(stream_id) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, *stream_id);
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::GoAway as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend(payload);
                buf
            }
            H3Frame::CancelPush(push_id) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, *push_id);
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::CancelPush as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend(payload);
                buf
            }
            H3Frame::PushPromise { push_id, header_block } => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, *push_id);
                payload.extend_from_slice(header_block);
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::PushPromise as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend(payload);
                buf
            }
            H3Frame::MaxPushId(push_id) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, *push_id);
                let mut buf = Vec::new();
                encode_varint(&mut buf, H3FrameType::MaxPushId as u64);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend(payload);
                buf
            }
            H3Frame::Unknown(frame_type, payload) => {
                let mut buf = Vec::new();
                encode_varint(&mut buf, *frame_type);
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(payload);
                buf
            }
        }
    }
}

/// QUIC Variable-Length Integer デコード (RFC 9000 Section 16)
pub fn decode_varint(data: &[u8]) -> Http3Result<(u64, usize)> {
    if data.is_empty() {
        return Err(Http3Error::InvalidFrame("Buffer too short for varint".into()));
    }

    let first = data[0];
    let prefix = first >> 6;

    match prefix {
        0b00 => Ok(((first & 0x3f) as u64, 1)),
        0b01 => {
            if data.len() < 2 {
                return Err(Http3Error::InvalidFrame("Buffer too short for 2-byte varint".into()));
            }
            let val = ((first as u64 & 0x3f) << 8) | data[1] as u64;
            Ok((val, 2))
        }
        0b10 => {
            if data.len() < 4 {
                return Err(Http3Error::InvalidFrame("Buffer too short for 4-byte varint".into()));
            }
            let val = ((first as u64 & 0x3f) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | data[3] as u64;
            Ok((val, 4))
        }
        0b11 => {
            if data.len() < 8 {
                return Err(Http3Error::InvalidFrame("Buffer too short for 8-byte varint".into()));
            }
            let val = ((first as u64 & 0x3f) << 56)
                | ((data[1] as u64) << 48)
                | ((data[2] as u64) << 40)
                | ((data[3] as u64) << 32)
                | ((data[4] as u64) << 24)
                | ((data[5] as u64) << 16)
                | ((data[6] as u64) << 8)
                | data[7] as u64;
            Ok((val, 8))
        }
        _ => unreachable!(),
    }
}

/// QUIC Variable-Length Integer エンコード (RFC 9000 Section 16)
pub fn encode_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0x40 {
        buf.push(val as u8);
    } else if val < 0x4000 {
        buf.push(0x40 | ((val >> 8) as u8));
        buf.push(val as u8);
    } else if val < 0x40000000 {
        buf.push(0x80 | ((val >> 24) as u8));
        buf.push((val >> 16) as u8);
        buf.push((val >> 8) as u8);
        buf.push(val as u8);
    } else {
        buf.push(0xc0 | ((val >> 56) as u8));
        buf.push((val >> 48) as u8);
        buf.push((val >> 40) as u8);
        buf.push((val >> 32) as u8);
        buf.push((val >> 24) as u8);
        buf.push((val >> 16) as u8);
        buf.push((val >> 8) as u8);
        buf.push(val as u8);
    }
}

/// HTTP/3 SETTINGS ID (RFC 9114 Section 7.2.4.1)
pub mod settings {
    /// QPACK 最大テーブル容量
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    /// QPACK 最大ブロックストリーム
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encode_decode() {
        let test_cases: Vec<u64> = vec![0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824];

        for val in test_cases {
            let mut buf = Vec::new();
            encode_varint(&mut buf, val);
            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, val, "Failed for {}", val);
        }
    }

    #[test]
    fn test_data_frame() {
        let frame = H3Frame::Data(b"Hello, World!".to_vec());
        let encoded = frame.encode();
        let (decoded, _) = H3Frame::decode(&encoded).unwrap();

        match decoded {
            H3Frame::Data(data) => assert_eq!(data, b"Hello, World!"),
            _ => panic!("Expected DATA frame"),
        }
    }

    #[test]
    fn test_settings_frame() {
        let settings = vec![(0x01, 4096), (0x07, 100)];
        let frame = H3Frame::Settings(settings.clone());
        let encoded = frame.encode();
        let (decoded, _) = H3Frame::decode(&encoded).unwrap();

        match decoded {
            H3Frame::Settings(decoded_settings) => {
                assert_eq!(decoded_settings, settings);
            }
            _ => panic!("Expected SETTINGS frame"),
        }
    }
}
