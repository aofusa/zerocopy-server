//! ディスクバッファ操作
//!
//! バッファリング時に大きいレスポンスをディスクにスピルオーバーする機能を提供します。

/// ディスクバッファ操作（monoio::fs使用）
#[cfg(target_os = "linux")]
pub mod disk_buffer {
    use monoio::fs::File;
    use std::io;
    use std::path::Path;
    use xxhash_rust::xxh3::xxh3_64;
    
    /// ディスクバッファへの非同期書き込み
    pub async fn write_to_disk(base_path: &Path, key: &[u8], data: Vec<u8>) -> io::Result<std::path::PathBuf> {
        let hash = xxh3_64(key);
        
        // ハッシュベースのパス生成（ディレクトリ分散）
        let dir1 = format!("{:02x}", (hash >> 56) as u8);
        let dir2 = format!("{:02x}", (hash >> 48) as u8);
        let filename = format!("{:016x}.buf", hash);
        
        let dir_path = base_path.join(&dir1).join(&dir2);
        let file_path = dir_path.join(&filename);
        
        // ディレクトリ作成（同期だが頻度は低い）
        std::fs::create_dir_all(&dir_path)?;
        
        // io_uring による非同期書き込み
        let file = File::create(&file_path).await?;
        let (res, _) = file.write_all_at(data, 0).await;
        res?;
        
        // fsync（データ整合性のため）
        file.sync_all().await?;
        
        Ok(file_path)
    }
    
    /// ディスクバッファからの非同期読み込み
    pub async fn read_from_disk(path: &Path) -> io::Result<Vec<u8>> {
        let file = File::open(path).await?;
        
        // ファイルサイズ取得
        let metadata = std::fs::metadata(path)?;
        let size = metadata.len() as usize;
        
        let mut buf = Vec::with_capacity(size);
        #[allow(clippy::uninit_vec)]
        unsafe { buf.set_len(size); }
        
        // io_uring による非同期読み込み
        let (res, buf) = file.read_exact_at(buf, 0).await;
        res?;
        
        Ok(buf)
    }
    
    /// ディスクバッファを削除
    pub fn remove_disk_buffer(path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}
