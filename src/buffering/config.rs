//! バッファリング設定

use serde::Deserialize;
use std::path::PathBuf;

/// バッファリングモード
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum BufferingMode {
    /// ストリーミング転送（従来の動作）
    /// 
    /// バックエンドからの読み込みと同時にクライアントへ書き込み。
    /// メモリ効率は良いが、低速クライアントでバックエンド占有の問題あり。
    #[default]
    Streaming,
    
    /// フルバッファリング
    /// 
    /// バックエンドからのレスポンス全体をバッファに格納してから
    /// クライアントへ送信開始。バックエンド接続を早期に解放可能。
    Full,
    
    /// 適応型バッファリング
    /// 
    /// 小さいレスポンスはフルバッファリング、
    /// 大きいレスポンスはストリーミングに自動切り替え。
    Adaptive,
}

impl<'de> Deserialize<'de> for BufferingMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "streaming" => Ok(BufferingMode::Streaming),
            "full" => Ok(BufferingMode::Full),
            "adaptive" => Ok(BufferingMode::Adaptive),
            other => Err(serde::de::Error::custom(format!(
                "unknown buffering mode: '{}', expected 'streaming', 'full', or 'adaptive'",
                other
            ))),
        }
    }
}

/// デフォルト値関数
fn default_max_memory_buffer() -> usize { 10 * 1024 * 1024 } // 10MB
fn default_adaptive_threshold() -> usize { 1024 * 1024 } // 1MB
fn default_max_disk_buffer() -> usize { 100 * 1024 * 1024 } // 100MB
fn default_client_write_timeout() -> u64 { 60 }
fn default_true() -> bool { true }

/// バッファリング設定
#[derive(Deserialize, Clone, Debug)]
pub struct BufferingConfig {
    /// バッファリングモード
    /// 
    /// - `"streaming"`: ストリーミング転送（デフォルト）
    /// - `"full"`: フルバッファリング
    /// - `"adaptive"`: 適応型
    #[serde(default)]
    pub mode: BufferingMode,
    
    /// フルバッファリング時のメモリ最大サイズ（バイト）
    /// 
    /// この値を超えるレスポンスはディスクバッファへスピルオーバー、
    /// または適応型モードではストリーミングにフォールバック。
    /// 
    /// デフォルト: 10MB
    #[serde(default = "default_max_memory_buffer")]
    pub max_memory_buffer: usize,
    
    /// 適応型モードの閾値（バイト）
    /// 
    /// Content-Lengthがこの値以下の場合はフルバッファリング、
    /// 超える場合はストリーミング転送。
    /// 
    /// デフォルト: 1MB
    #[serde(default = "default_adaptive_threshold")]
    pub adaptive_threshold: usize,
    
    /// ディスクバッファパス
    /// 
    /// メモリバッファを超えた場合の一時ファイル保存先。
    /// 未設定の場合はディスクバッファを使用しない。
    #[serde(default)]
    pub disk_buffer_path: Option<PathBuf>,
    
    /// ディスクバッファ最大サイズ（バイト）
    /// 
    /// デフォルト: 100MB
    #[serde(default = "default_max_disk_buffer")]
    pub max_disk_buffer: usize,
    
    /// クライアント書き込みタイムアウト（秒）
    /// 
    /// バッファからクライアントへの書き込みがこの時間を超えると
    /// 接続を切断。低速クライアントの検出に使用。
    /// 
    /// デフォルト: 60秒
    #[serde(default = "default_client_write_timeout")]
    pub client_write_timeout_secs: u64,
    
    /// レスポンスヘッダーのバッファリングを有効化
    /// 
    /// trueの場合、ヘッダーもバッファに含める。
    /// 
    /// デフォルト: true
    #[serde(default = "default_true")]
    pub buffer_headers: bool,
}

impl Default for BufferingConfig {
    fn default() -> Self {
        Self {
            mode: BufferingMode::default(),
            max_memory_buffer: default_max_memory_buffer(),
            adaptive_threshold: default_adaptive_threshold(),
            disk_buffer_path: None,
            max_disk_buffer: default_max_disk_buffer(),
            client_write_timeout_secs: default_client_write_timeout(),
            buffer_headers: true,
        }
    }
}

impl BufferingConfig {
    /// バッファリングが有効かどうか
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.mode != BufferingMode::Streaming
    }
    
    /// 指定されたContent-Lengthに対してフルバッファリングを使用すべきか判定
    #[inline]
    pub fn should_buffer(&self, content_length: Option<usize>) -> bool {
        match self.mode {
            BufferingMode::Streaming => false,
            BufferingMode::Full => true,
            BufferingMode::Adaptive => {
                match content_length {
                    Some(len) => len <= self.adaptive_threshold,
                    // Content-Lengthが不明な場合はストリーミング
                    None => false,
                }
            }
        }
    }
    
    /// ディスクバッファが使用可能かどうか
    #[inline]
    pub fn disk_buffer_available(&self) -> bool {
        self.disk_buffer_path.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffering_mode_default() {
        let config = BufferingConfig::default();
        assert_eq!(config.mode, BufferingMode::Streaming);
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_should_buffer_streaming() {
        let config = BufferingConfig {
            mode: BufferingMode::Streaming,
            ..Default::default()
        };
        assert!(!config.should_buffer(Some(100)));
        assert!(!config.should_buffer(Some(10_000_000)));
        assert!(!config.should_buffer(None));
    }

    #[test]
    fn test_should_buffer_full() {
        let config = BufferingConfig {
            mode: BufferingMode::Full,
            ..Default::default()
        };
        assert!(config.should_buffer(Some(100)));
        assert!(config.should_buffer(Some(10_000_000)));
        assert!(config.should_buffer(None));
    }

    #[test]
    fn test_should_buffer_adaptive() {
        let config = BufferingConfig {
            mode: BufferingMode::Adaptive,
            adaptive_threshold: 1024 * 1024, // 1MB
            ..Default::default()
        };
        // 閾値以下はバッファリング
        assert!(config.should_buffer(Some(1024)));
        assert!(config.should_buffer(Some(1024 * 1024)));
        // 閾値超過はストリーミング
        assert!(!config.should_buffer(Some(1024 * 1024 + 1)));
        // Content-Length不明はストリーミング
        assert!(!config.should_buffer(None));
    }
}

