//! # QUIC パケット (RFC 9000 Section 17)

use super::ConnectionId;

/// QUIC パケットタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial パケット
    Initial,
    /// 0-RTT パケット
    ZeroRtt,
    /// Handshake パケット
    Handshake,
    /// Retry パケット
    Retry,
    /// 1-RTT パケット (Short Header)
    OneRtt,
}

impl PacketType {
    /// Long Header のタイプビットから変換
    pub fn from_long_header_type(type_bits: u8) -> Option<Self> {
        match type_bits {
            0x00 => Some(Self::Initial),
            0x01 => Some(Self::ZeroRtt),
            0x02 => Some(Self::Handshake),
            0x03 => Some(Self::Retry),
            _ => None,
        }
    }
}

/// Long Header (RFC 9000 Section 17.2)
///
/// ```text
/// Long Header Packet {
///   Header Form (1) = 1,
///   Fixed Bit (1) = 1,
///   Long Packet Type (2),
///   Type-Specific Bits (4),
///   Version (32),
///   Destination Connection ID Length (8),
///   Destination Connection ID (0..160),
///   Source Connection ID Length (8),
///   Source Connection ID (0..160),
///   Type-Specific Payload (..),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// パケットタイプ
    pub packet_type: PacketType,
    /// バージョン
    pub version: u32,
    /// 宛先接続 ID
    pub dcid: ConnectionId,
    /// 送信元接続 ID
    pub scid: ConnectionId,
}

impl LongHeader {
    /// デコード
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 7 {
            return None;
        }

        let first_byte = data[0];
        
        // Header Form (1) must be 1 for long header
        if first_byte & 0x80 == 0 {
            return None;
        }

        // Long Packet Type
        let type_bits = (first_byte >> 4) & 0x03;
        let packet_type = PacketType::from_long_header_type(type_bits)?;

        // Version
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        // DCID Length
        let dcid_len = data[5] as usize;
        if dcid_len > 20 || data.len() < 6 + dcid_len + 1 {
            return None;
        }

        let dcid = ConnectionId(data[6..6 + dcid_len].to_vec());

        // SCID Length
        let scid_len = data[6 + dcid_len] as usize;
        if scid_len > 20 || data.len() < 7 + dcid_len + scid_len {
            return None;
        }

        let scid = ConnectionId(data[7 + dcid_len..7 + dcid_len + scid_len].to_vec());

        let header_len = 7 + dcid_len + scid_len;

        Some((
            Self {
                packet_type,
                version,
                dcid,
                scid,
            },
            header_len,
        ))
    }

    /// エンコード
    pub fn encode(&self, type_specific_bits: u8) -> Vec<u8> {
        let mut buf = Vec::new();

        // First byte: Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type-Specific (4)
        let type_bits = match self.packet_type {
            PacketType::Initial => 0x00,
            PacketType::ZeroRtt => 0x01,
            PacketType::Handshake => 0x02,
            PacketType::Retry => 0x03,
            PacketType::OneRtt => 0x00, // Not used for long header
        };
        let first_byte = 0xC0 | (type_bits << 4) | (type_specific_bits & 0x0F);
        buf.push(first_byte);

        // Version
        buf.extend_from_slice(&self.version.to_be_bytes());

        // DCID
        buf.push(self.dcid.len() as u8);
        buf.extend_from_slice(self.dcid.as_ref());

        // SCID
        buf.push(self.scid.len() as u8);
        buf.extend_from_slice(self.scid.as_ref());

        buf
    }
}

/// Short Header (RFC 9000 Section 17.3)
///
/// ```text
/// 1-RTT Packet {
///   Header Form (1) = 0,
///   Fixed Bit (1) = 1,
///   Spin Bit (1),
///   Reserved Bits (2),
///   Key Phase (1),
///   Packet Number Length (2),
///   Destination Connection ID (0..160),
///   Packet Number (8..32),
///   Packet Payload (..),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ShortHeader {
    /// スピンビット
    pub spin: bool,
    /// キーフェーズ
    pub key_phase: bool,
    /// パケット番号長 (1-4)
    pub pn_length: u8,
    /// 宛先接続 ID
    pub dcid: ConnectionId,
}

impl ShortHeader {
    /// デコード (接続 ID 長が既知の場合)
    pub fn decode(data: &[u8], dcid_len: usize) -> Option<(Self, usize)> {
        if data.is_empty() || data.len() < 1 + dcid_len {
            return None;
        }

        let first_byte = data[0];

        // Header Form (1) must be 0 for short header
        if first_byte & 0x80 != 0 {
            return None;
        }

        // Fixed Bit should be 1
        if first_byte & 0x40 == 0 {
            return None;
        }

        let spin = first_byte & 0x20 != 0;
        let key_phase = first_byte & 0x04 != 0;
        let pn_length = (first_byte & 0x03) + 1;

        let dcid = ConnectionId(data[1..1 + dcid_len].to_vec());

        Some((
            Self {
                spin,
                key_phase,
                pn_length,
                dcid,
            },
            1 + dcid_len,
        ))
    }

    /// エンコード
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // First byte
        let mut first_byte = 0x40; // Fixed Bit
        if self.spin {
            first_byte |= 0x20;
        }
        if self.key_phase {
            first_byte |= 0x04;
        }
        first_byte |= (self.pn_length - 1) & 0x03;
        buf.push(first_byte);

        // DCID
        buf.extend_from_slice(self.dcid.as_ref());

        buf
    }
}

/// パケット番号をデコード
pub fn decode_packet_number(data: &[u8], length: u8) -> Option<(u64, usize)> {
    let len = length as usize;
    if data.len() < len {
        return None;
    }

    let pn = match len {
        1 => data[0] as u64,
        2 => u16::from_be_bytes([data[0], data[1]]) as u64,
        3 => ((data[0] as u64) << 16) | ((data[1] as u64) << 8) | (data[2] as u64),
        4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
        _ => return None,
    };

    Some((pn, len))
}

/// パケット番号をエンコード
pub fn encode_packet_number(pn: u64, length: u8) -> Vec<u8> {
    match length {
        1 => vec![pn as u8],
        2 => (pn as u16).to_be_bytes().to_vec(),
        3 => vec![((pn >> 16) & 0xFF) as u8, ((pn >> 8) & 0xFF) as u8, (pn & 0xFF) as u8],
        4 => (pn as u32).to_be_bytes().to_vec(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_long_header_encode_decode() {
        let header = LongHeader {
            packet_type: PacketType::Initial,
            version: super::super::QUIC_VERSION_1,
            dcid: ConnectionId(vec![1, 2, 3, 4]),
            scid: ConnectionId(vec![5, 6, 7, 8]),
        };

        let encoded = header.encode(0);
        let (decoded, _) = LongHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.packet_type, PacketType::Initial);
        assert_eq!(decoded.version, super::super::QUIC_VERSION_1);
        assert_eq!(decoded.dcid.0, vec![1, 2, 3, 4]);
        assert_eq!(decoded.scid.0, vec![5, 6, 7, 8]);
    }

    #[test]
    fn test_short_header_encode_decode() {
        let header = ShortHeader {
            spin: true,
            key_phase: false,
            pn_length: 2,
            dcid: ConnectionId(vec![1, 2, 3, 4]),
        };

        let encoded = header.encode();
        let (decoded, _) = ShortHeader::decode(&encoded, 4).unwrap();

        assert_eq!(decoded.spin, true);
        assert_eq!(decoded.key_phase, false);
        assert_eq!(decoded.pn_length, 2);
        assert_eq!(decoded.dcid.0, vec![1, 2, 3, 4]);
    }
}
