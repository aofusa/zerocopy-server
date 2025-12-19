//! # QPACK テーブル (RFC 9204)
//!
//! QPACK の静的テーブルと動的テーブルを実装します。

use std::collections::VecDeque;

/// HTTP ヘッダーフィールド
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    /// ヘッダー名
    pub name: Vec<u8>,
    /// ヘッダー値
    pub value: Vec<u8>,
}

impl HeaderField {
    /// 新しいヘッダーフィールドを作成
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// エントリサイズ
    #[inline]
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

/// QPACK 静的テーブル (RFC 9204 Appendix A)
pub struct StaticTable;

impl StaticTable {
    /// 静的テーブルのエントリ数
    pub const SIZE: usize = 99;

    /// 静的テーブルエントリ (0-indexed)
    const ENTRIES: [(&'static [u8], &'static [u8]); 99] = [
        (b":authority", b""),
        (b":path", b"/"),
        (b"age", b"0"),
        (b"content-disposition", b""),
        (b"content-length", b"0"),
        (b"cookie", b""),
        (b"date", b""),
        (b"etag", b""),
        (b"if-modified-since", b""),
        (b"if-none-match", b""),
        (b"last-modified", b""),
        (b"link", b""),
        (b"location", b""),
        (b"referer", b""),
        (b"set-cookie", b""),
        (b":method", b"CONNECT"),
        (b":method", b"DELETE"),
        (b":method", b"GET"),
        (b":method", b"HEAD"),
        (b":method", b"OPTIONS"),
        (b":method", b"POST"),
        (b":method", b"PUT"),
        (b":scheme", b"http"),
        (b":scheme", b"https"),
        (b":status", b"103"),
        (b":status", b"200"),
        (b":status", b"304"),
        (b":status", b"404"),
        (b":status", b"503"),
        (b"accept", b"*/*"),
        (b"accept", b"application/dns-message"),
        (b"accept-encoding", b"gzip, deflate, br"),
        (b"accept-ranges", b"bytes"),
        (b"access-control-allow-headers", b"cache-control"),
        (b"access-control-allow-headers", b"content-type"),
        (b"access-control-allow-origin", b"*"),
        (b"cache-control", b"max-age=0"),
        (b"cache-control", b"max-age=2592000"),
        (b"cache-control", b"max-age=604800"),
        (b"cache-control", b"no-cache"),
        (b"cache-control", b"no-store"),
        (b"cache-control", b"public, max-age=31536000"),
        (b"content-encoding", b"br"),
        (b"content-encoding", b"gzip"),
        (b"content-type", b"application/dns-message"),
        (b"content-type", b"application/javascript"),
        (b"content-type", b"application/json"),
        (b"content-type", b"application/x-www-form-urlencoded"),
        (b"content-type", b"image/gif"),
        (b"content-type", b"image/jpeg"),
        (b"content-type", b"image/png"),
        (b"content-type", b"text/css"),
        (b"content-type", b"text/html; charset=utf-8"),
        (b"content-type", b"text/plain"),
        (b"content-type", b"text/plain;charset=utf-8"),
        (b"range", b"bytes=0-"),
        (b"strict-transport-security", b"max-age=31536000"),
        (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
        (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
        (b"vary", b"accept-encoding"),
        (b"vary", b"origin"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-xss-protection", b"1; mode=block"),
        (b":status", b"100"),
        (b":status", b"204"),
        (b":status", b"206"),
        (b":status", b"302"),
        (b":status", b"400"),
        (b":status", b"403"),
        (b":status", b"421"),
        (b":status", b"425"),
        (b":status", b"500"),
        (b"accept-language", b""),
        (b"access-control-allow-credentials", b"FALSE"),
        (b"access-control-allow-credentials", b"TRUE"),
        (b"access-control-allow-headers", b"*"),
        (b"access-control-allow-methods", b"get"),
        (b"access-control-allow-methods", b"get, post, options"),
        (b"access-control-allow-methods", b"options"),
        (b"access-control-expose-headers", b"content-length"),
        (b"access-control-request-headers", b"content-type"),
        (b"access-control-request-method", b"get"),
        (b"access-control-request-method", b"post"),
        (b"alt-svc", b"clear"),
        (b"authorization", b""),
        (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
        (b"early-data", b"1"),
        (b"expect-ct", b""),
        (b"forwarded", b""),
        (b"if-range", b""),
        (b"origin", b""),
        (b"purpose", b"prefetch"),
        (b"server", b""),
        (b"timing-allow-origin", b"*"),
        (b"upgrade-insecure-requests", b"1"),
        (b"user-agent", b""),
        (b"x-forwarded-for", b""),
        (b"x-frame-options", b"deny"),
        (b"x-frame-options", b"sameorigin"),
    ];

    /// インデックスでエントリを取得 (0-indexed)
    #[inline]
    pub fn get(index: usize) -> Option<(&'static [u8], &'static [u8])> {
        if index >= Self::SIZE {
            return None;
        }
        let (name, value) = Self::ENTRIES[index];
        Some((name, value))
    }

    /// 名前と値が完全一致するインデックスを検索
    pub fn find_exact(name: &[u8], value: &[u8]) -> Option<usize> {
        for (i, (n, v)) in Self::ENTRIES.iter().enumerate() {
            if *n == name && *v == value {
                return Some(i);
            }
        }
        None
    }

    /// 名前が一致するインデックスを検索
    pub fn find_name(name: &[u8]) -> Option<usize> {
        for (i, (n, _)) in Self::ENTRIES.iter().enumerate() {
            if *n == name {
                return Some(i);
            }
        }
        None
    }
}

/// QPACK 動的テーブル
pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    size: usize,
    max_size: usize,
    /// 挿入カウント (絶対インデックス計算用)
    insert_count: u64,
}

impl DynamicTable {
    /// 新しい動的テーブルを作成
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
            insert_count: 0,
        }
    }

    /// エントリ数
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 現在のサイズ
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// 挿入カウント
    #[inline]
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// 最大サイズを設定
    pub fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.evict();
    }

    /// エントリを追加
    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry = HeaderField { name, value };
        let entry_size = entry.size();

        if entry_size > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }

        while self.size + entry_size > self.max_size && !self.entries.is_empty() {
            if let Some(old) = self.entries.pop_back() {
                self.size = self.size.saturating_sub(old.size());
            }
        }

        self.entries.push_front(entry);
        self.size += entry_size;
        self.insert_count += 1;
    }

    /// 相対インデックスでエントリを取得
    #[inline]
    pub fn get(&self, relative_index: usize) -> Option<&HeaderField> {
        self.entries.get(relative_index)
    }

    /// 絶対インデックスでエントリを取得
    pub fn get_absolute(&self, absolute_index: u64) -> Option<&HeaderField> {
        if absolute_index >= self.insert_count {
            return None;
        }
        let relative = (self.insert_count - 1 - absolute_index) as usize;
        self.entries.get(relative)
    }

    /// 削除
    fn evict(&mut self) {
        while self.size > self.max_size && !self.entries.is_empty() {
            if let Some(old) = self.entries.pop_back() {
                self.size = self.size.saturating_sub(old.size());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_table() {
        // :authority (index 0)
        let (name, value) = StaticTable::get(0).unwrap();
        assert_eq!(name, b":authority");
        assert_eq!(value, b"");

        // :method GET (index 17)
        let (name, value) = StaticTable::get(17).unwrap();
        assert_eq!(name, b":method");
        assert_eq!(value, b"GET");

        // :status 200 (index 25)
        let (name, value) = StaticTable::get(25).unwrap();
        assert_eq!(name, b":status");
        assert_eq!(value, b"200");
    }

    #[test]
    fn test_dynamic_table() {
        let mut table = DynamicTable::new(4096);

        table.insert(b"custom-header".to_vec(), b"custom-value".to_vec());
        assert_eq!(table.len(), 1);
        assert_eq!(table.insert_count(), 1);

        let entry = table.get(0).unwrap();
        assert_eq!(entry.name, b"custom-header");
        assert_eq!(entry.value, b"custom-value");
    }
}
