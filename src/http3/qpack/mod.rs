//! # QPACK ヘッダー圧縮 (RFC 9204)
//!
//! HTTP/3 用のヘッダー圧縮アルゴリズムを実装します。
//! QPACK は HPACK をベースに、QUIC のストリーム独立性に対応しています。

pub mod encoder;
pub mod decoder;
pub mod table;

pub use encoder::QpackEncoder;
pub use decoder::QpackDecoder;
pub use table::{StaticTable, DynamicTable, HeaderField};

/// QPACK エラー
#[derive(Debug, Clone)]
pub enum QpackError {
    /// 無効なインデックス
    InvalidIndex(usize),
    /// 整数オーバーフロー
    IntegerOverflow,
    /// Huffman デコードエラー
    HuffmanDecodeError,
    /// 無効な文字列
    InvalidString,
    /// バッファ不足
    BufferTooShort,
    /// デコーダストリームエラー
    DecoderStreamError,
    /// エンコーダストリームエラー
    EncoderStreamError,
}

impl std::fmt::Display for QpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIndex(i) => write!(f, "Invalid QPACK index: {}", i),
            Self::IntegerOverflow => write!(f, "QPACK integer overflow"),
            Self::HuffmanDecodeError => write!(f, "Huffman decode error"),
            Self::InvalidString => write!(f, "Invalid QPACK string"),
            Self::BufferTooShort => write!(f, "Buffer too short for QPACK"),
            Self::DecoderStreamError => write!(f, "QPACK decoder stream error"),
            Self::EncoderStreamError => write!(f, "QPACK encoder stream error"),
        }
    }
}

impl std::error::Error for QpackError {}

/// QPACK 処理結果
pub type QpackResult<T> = Result<T, QpackError>;

/// QPACK プレフィックス整数デコード (RFC 9204 Section 4.1.1)
pub fn decode_integer(buf: &[u8], prefix_bits: u8) -> QpackResult<(usize, usize)> {
    if buf.is_empty() {
        return Err(QpackError::BufferTooShort);
    }

    let mask = if prefix_bits >= 8 { 0xFFu8 } else { (1u8 << prefix_bits) - 1 };
    let first_byte = buf[0] & mask;

    if first_byte < mask {
        return Ok((first_byte as usize, 1));
    }

    let mut value = mask as usize;
    let mut m: u32 = 0;
    let mut i = 1;

    loop {
        if i >= buf.len() {
            return Err(QpackError::BufferTooShort);
        }

        let byte = buf[i];
        let add = ((byte & 0x7F) as usize)
            .checked_shl(m)
            .ok_or(QpackError::IntegerOverflow)?;
        value = value.checked_add(add).ok_or(QpackError::IntegerOverflow)?;
        i += 1;

        if byte & 0x80 == 0 {
            break;
        }

        m += 7;
        if m > 28 {
            return Err(QpackError::IntegerOverflow);
        }
    }

    Ok((value, i))
}

/// QPACK プレフィックス整数エンコード (RFC 9204 Section 4.1.1)
pub fn encode_integer(buf: &mut Vec<u8>, value: usize, prefix_bits: u8, prefix: u8) {
    let mask = if prefix_bits >= 8 { 0xFFu8 } else { (1u8 << prefix_bits) - 1 };

    if value < mask as usize {
        buf.push(prefix | (value as u8));
        return;
    }

    buf.push(prefix | mask);
    let mut remaining = value - mask as usize;

    while remaining >= 128 {
        buf.push(0x80 | (remaining as u8 & 0x7F));
        remaining >>= 7;
    }

    buf.push(remaining as u8);
}
