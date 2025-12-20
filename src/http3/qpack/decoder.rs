//! # QPACK デコーダ (RFC 9204)

use super::{QpackError, QpackResult, decode_integer};
use super::table::{StaticTable, DynamicTable, HeaderField};

/// QPACK デコーダ
#[allow(dead_code)]
pub struct QpackDecoder {
    /// 動的テーブル
    dynamic_table: DynamicTable,
    /// 最大ブロックストリーム数
    max_blocked_streams: usize,
}

impl QpackDecoder {
    /// 新しいデコーダを作成
    pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(max_table_capacity),
            max_blocked_streams,
        }
    }

    /// ヘッダーブロックをデコード
    pub fn decode(&mut self, buf: &[u8]) -> QpackResult<Vec<HeaderField>> {
        if buf.len() < 2 {
            return Err(QpackError::BufferTooShort);
        }

        let mut pos = 0;

        // Required Insert Count
        let (_ric, ric_len) = decode_integer(buf, 8)?;
        pos += ric_len;

        // Delta Base
        let (_delta_base, db_len) = decode_integer(&buf[pos..], 7)?;
        pos += db_len;

        let mut headers = Vec::new();

        while pos < buf.len() {
            let first_byte = buf[pos];

            if first_byte & 0x80 != 0 {
                // Indexed Header Field
                let is_static = first_byte & 0x40 != 0;
                let (index, len) = decode_integer(&buf[pos..], 6)?;
                pos += len;

                let field = if is_static {
                    let (name, value) = StaticTable::get(index)
                        .ok_or(QpackError::InvalidIndex(index))?;
                    HeaderField::new(name, value)
                } else {
                    self.dynamic_table.get(index)
                        .ok_or(QpackError::InvalidIndex(index))?
                        .clone()
                };

                headers.push(field);
            } else if first_byte & 0x40 != 0 {
                // Literal with Name Reference
                let is_static = first_byte & 0x10 != 0;
                let (name_index, name_len) = decode_integer(&buf[pos..], 4)?;
                pos += name_len;

                let name = if is_static {
                    StaticTable::get(name_index)
                        .ok_or(QpackError::InvalidIndex(name_index))?
                        .0.to_vec()
                } else {
                    self.dynamic_table.get(name_index)
                        .ok_or(QpackError::InvalidIndex(name_index))?
                        .name.clone()
                };

                let (value, value_len) = self.decode_string(&buf[pos..])?;
                pos += value_len;

                headers.push(HeaderField::new(name, value));
            } else if first_byte & 0x20 != 0 {
                // Literal without Name Reference
                pos += 1; // Skip the prefix byte

                let (name, name_len) = self.decode_string(&buf[pos..])?;
                pos += name_len;

                let (value, value_len) = self.decode_string(&buf[pos..])?;
                pos += value_len;

                headers.push(HeaderField::new(name, value));
            } else {
                // 未知のエンコーディング
                return Err(QpackError::InvalidIndex(0));
            }
        }

        Ok(headers)
    }

    /// 文字列をデコード
    fn decode_string(&self, buf: &[u8]) -> QpackResult<(Vec<u8>, usize)> {
        if buf.is_empty() {
            return Err(QpackError::BufferTooShort);
        }

        let huffman = buf[0] & 0x80 != 0;
        let (length, len_len) = decode_integer(buf, 7)?;

        if buf.len() < len_len + length {
            return Err(QpackError::BufferTooShort);
        }

        let string_data = &buf[len_len..len_len + length];

        if huffman {
            // Huffman デコード (簡略化のためエラー)
            Err(QpackError::HuffmanDecodeError)
        } else {
            Ok((string_data.to_vec(), len_len + length))
        }
    }

    /// 動的テーブルの最大サイズを設定
    pub fn set_max_table_capacity(&mut self, capacity: usize) {
        self.dynamic_table.set_max_size(capacity);
    }
}

impl Default for QpackDecoder {
    fn default() -> Self {
        Self::new(0, 0) // 動的テーブル無効
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::encoder::QpackEncoder;

    #[test]
    fn test_encode_decode_static() {
        let encoder = QpackEncoder::new(0, 0);
        let mut decoder = QpackDecoder::new(0, 0);

        let headers = [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ];

        let encoded = encoder.encode_static(&headers).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].name, b":method");
        assert_eq!(decoded[0].value, b"GET");
        assert_eq!(decoded[1].name, b":path");
        assert_eq!(decoded[1].value, b"/");
    }
}
