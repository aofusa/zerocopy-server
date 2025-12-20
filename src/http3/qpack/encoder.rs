//! # QPACK エンコーダ (RFC 9204)

use super::{QpackResult, encode_integer};
use super::table::{StaticTable, DynamicTable};

/// QPACK エンコーダ
#[allow(dead_code)]
pub struct QpackEncoder {
    /// 動的テーブル
    dynamic_table: DynamicTable,
    /// 最大ブロックストリーム数
    max_blocked_streams: usize,
}

impl QpackEncoder {
    /// 新しいエンコーダを作成
    pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(max_table_capacity),
            max_blocked_streams,
        }
    }

    /// ヘッダーリストをエンコード (静的テーブルのみ使用、ブロックなし)
    pub fn encode_static(&self, headers: &[(&[u8], &[u8])]) -> QpackResult<Vec<u8>> {
        let mut buf = Vec::with_capacity(headers.len() * 32);

        // Required Insert Count = 0 (静的テーブルのみ)
        buf.push(0);
        // Delta Base = 0
        buf.push(0);

        for &(name, value) in headers {
            // 静的テーブルで完全一致を検索
            if let Some(index) = StaticTable::find_exact(name, value) {
                // Indexed Header Field (Static)
                // 1TNNNNNN
                encode_integer(&mut buf, index, 6, 0xc0);
            } else if let Some(name_index) = StaticTable::find_name(name) {
                // Literal with Name Reference (Static)
                // 01NTNNNN + value
                encode_integer(&mut buf, name_index, 4, 0x50);
                self.encode_string(&mut buf, value)?;
            } else {
                // Literal without Name Reference
                // 001NNNNN + name + value
                buf.push(0x20);
                self.encode_string(&mut buf, name)?;
                self.encode_string(&mut buf, value)?;
            }
        }

        Ok(buf)
    }

    /// 文字列をエンコード
    fn encode_string(&self, buf: &mut Vec<u8>, s: &[u8]) -> QpackResult<()> {
        // 簡略化: Huffman エンコードなし
        encode_integer(buf, s.len(), 7, 0x00);
        buf.extend_from_slice(s);
        Ok(())
    }

    /// 動的テーブルの最大サイズを設定
    pub fn set_max_table_capacity(&mut self, capacity: usize) {
        self.dynamic_table.set_max_size(capacity);
    }
}

impl Default for QpackEncoder {
    fn default() -> Self {
        Self::new(0, 0) // 動的テーブル無効
    }
}
