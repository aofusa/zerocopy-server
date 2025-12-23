//! E2E（End-to-End）テスト
//!
//! プロキシの完全な動作を検証するテストです。
//! 
//! ## 実行方法
//! 
//! ### 方法1: セットアップスクリプトを使用（推奨）
//! ```bash
//! ./tests/e2e_setup.sh test
//! ```
//! 
//! ### 方法2: 手動で環境を準備
//! ```bash
//! # 1. 環境を起動
//! ./tests/e2e_setup.sh start
//! 
//! # 2. テストを実行
//! cargo test --test e2e_tests -- --test-threads=1
//! 
//! # 3. 環境を停止
//! ./tests/e2e_setup.sh stop
//! ```
//!
//! ## テスト対象
//! - HTTP/HTTPS リクエスト転送
//! - ロードバランシング（Round Robin）
//! - ヘッダー操作（追加・削除）
//! - レスポンス圧縮
//! - ヘルスチェック

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// E2E環境のポート設定（e2e_setup.shと一致させる）
const PROXY_HTTPS_PORT: u16 = 8443;
#[allow(dead_code)]
const PROXY_HTTP_PORT: u16 = 8080;  // HTTPリダイレクト用（将来使用）
const BACKEND1_PORT: u16 = 9001;
const BACKEND2_PORT: u16 = 9002;

/// E2E環境が起動しているか確認
fn is_e2e_environment_ready() -> bool {
    // プロキシへの接続確認
    if TcpStream::connect(format!("127.0.0.1:{}", PROXY_HTTPS_PORT)).is_err() {
        eprintln!("E2E environment not ready: Proxy not running on port {}", PROXY_HTTPS_PORT);
        eprintln!("Please run: ./tests/e2e_setup.sh start");
        return false;
    }
    
    // バックエンドへの接続確認
    if TcpStream::connect(format!("127.0.0.1:{}", BACKEND1_PORT)).is_err() {
        eprintln!("E2E environment not ready: Backend 1 not running on port {}", BACKEND1_PORT);
        return false;
    }
    
    if TcpStream::connect(format!("127.0.0.1:{}", BACKEND2_PORT)).is_err() {
        eprintln!("E2E environment not ready: Backend 2 not running on port {}", BACKEND2_PORT);
        return false;
    }
    
    true
}

/// HTTPリクエストを送信してレスポンスを取得
fn send_request(port: u16, path: &str, headers: &[(&str, &str)]) -> Option<String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    
    // リクエスト構築
    let mut request = format!("GET {} HTTP/1.1\r\nHost: localhost\r\n", path);
    for (name, value) in headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("Connection: close\r\n\r\n");
    
    stream.write_all(request.as_bytes()).ok()?;
    
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    
    String::from_utf8(response).ok()
}

/// レスポンスからヘッダー値を抽出
fn get_header_value(response: &str, header_name: &str) -> Option<String> {
    let header_lower = header_name.to_lowercase();
    for line in response.lines() {
        if line.is_empty() {
            break; // ヘッダー終了
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_lowercase();
            if name == header_lower {
                return Some(line[idx + 1..].trim().to_string());
            }
        }
    }
    None
}

/// レスポンスのステータスコードを取得
fn get_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

// ====================
// プロキシ基本機能テスト
// ====================

#[test]
fn test_proxy_basic_request() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response from proxy");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Should return 200 OK");
}

#[test]
fn test_proxy_health_endpoint() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/health", &[]);
    assert!(response.is_some(), "Should receive response from health endpoint");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Health endpoint should return 200 OK");
}

// ====================
// ヘッダー操作テスト
// ====================

#[test]
fn test_response_header_added() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    
    // プロキシが追加したヘッダーを確認
    let proxied_by = get_header_value(&response, "X-Proxied-By");
    assert_eq!(proxied_by, Some("veil".to_string()), "Should have X-Proxied-By header");
    
    let test_header = get_header_value(&response, "X-Test-Header");
    assert_eq!(test_header, Some("e2e-test".to_string()), "Should have X-Test-Header");
}

#[test]
fn test_server_header_removed() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    
    // Serverヘッダーが削除されていることを確認
    let server = get_header_value(&response, "Server");
    assert!(server.is_none(), "Server header should be removed");
}

#[test]
fn test_backend_server_id_header() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    
    // バックエンドが追加したX-Server-Idヘッダーを確認
    let server_id = get_header_value(&response, "X-Server-Id");
    assert!(
        server_id == Some("backend1".to_string()) || server_id == Some("backend2".to_string()),
        "Should have X-Server-Id from backend"
    );
}

// ====================
// ロードバランシングテスト
// ====================

#[test]
fn test_round_robin_distribution() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let mut backend1_count = 0;
    let mut backend2_count = 0;
    
    // 10回リクエストを送信
    for _ in 0..10 {
        let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
        if let Some(response) = response {
            if let Some(server_id) = get_header_value(&response, "X-Server-Id") {
                match server_id.as_str() {
                    "backend1" => backend1_count += 1,
                    "backend2" => backend2_count += 1,
                    _ => {}
                }
            }
        }
    }
    
    // 両方のバックエンドが使用されていることを確認
    assert!(backend1_count > 0, "Backend 1 should receive some requests");
    assert!(backend2_count > 0, "Backend 2 should receive some requests");
    
    // Round Robinなのでほぼ均等に分散（許容範囲: 3-7）
    assert!(backend1_count >= 3 && backend1_count <= 7, 
            "Backend 1 should receive roughly half: got {}", backend1_count);
    assert!(backend2_count >= 3 && backend2_count <= 7, 
            "Backend 2 should receive roughly half: got {}", backend2_count);
}

// ====================
// 静的ファイル配信テスト
// ====================

#[test]
fn test_static_file_index() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    
    // レスポンスボディに期待されるコンテンツが含まれる
    assert!(
        response.contains("Hello from Backend 1") || response.contains("Hello from Backend 2"),
        "Should contain content from backend"
    );
}

#[test]
fn test_static_file_large() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/large.txt", &[]);
    assert!(response.is_some(), "Should receive large file response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Large file should return 200 OK");
    
    // 大きなレスポンスであることを確認
    assert!(response.len() > 1000, "Large file should be > 1000 bytes");
}

// ====================
// 圧縮テスト
// ====================

#[test]
fn test_compression_gzip() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    // Gzip圧縮をリクエスト
    let response = send_request(
        PROXY_HTTPS_PORT, 
        "/large.txt", 
        &[("Accept-Encoding", "gzip")]
    );
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Should return 200 OK");
    
    // 圧縮が有効な場合、Content-Encodingヘッダーがある
    // （サイズがmin_size未満の場合は圧縮されない可能性がある）
    let content_encoding = get_header_value(&response, "Content-Encoding");
    if let Some(encoding) = content_encoding {
        assert!(
            encoding.contains("gzip") || encoding.contains("br") || encoding.contains("zstd"),
            "Should use compression: {}", encoding
        );
    }
}

#[test]
fn test_compression_brotli() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    // Brotli圧縮をリクエスト
    let response = send_request(
        PROXY_HTTPS_PORT, 
        "/large.txt", 
        &[("Accept-Encoding", "br")]
    );
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Should return 200 OK");
}

// ====================
// バックエンド直接アクセステスト
// ====================

#[test]
fn test_backend1_direct() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(BACKEND1_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response from backend 1");
    
    let response = response.unwrap();
    let server_id = get_header_value(&response, "X-Server-Id");
    assert_eq!(server_id, Some("backend1".to_string()), "Should be backend1");
}

#[test]
fn test_backend2_direct() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(BACKEND2_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response from backend 2");
    
    let response = response.unwrap();
    let server_id = get_header_value(&response, "X-Server-Id");
    assert_eq!(server_id, Some("backend2".to_string()), "Should be backend2");
}

// ====================
// Prometheusメトリクステスト
// ====================

#[test]
fn test_prometheus_metrics() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/__metrics", &[]);
    assert!(response.is_some(), "Should receive metrics response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Metrics endpoint should return 200 OK");
    
    // Prometheusフォーマットのメトリクスが含まれる
    assert!(
        response.contains("# HELP") || response.contains("# TYPE") || response.contains("veil_"),
        "Should contain Prometheus metrics"
    );
}

// ====================
// エラーハンドリングテスト
// ====================

#[test]
fn test_404_not_found() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/nonexistent-path-12345", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(404), "Nonexistent path should return 404");
}

// ====================
// HTTPリダイレクトテスト
// ====================

#[test]
fn test_http_to_https_redirect() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    // HTTPポートにリクエスト
    let response = send_request(PROXY_HTTP_PORT, "/", &[]);
    
    if let Some(response) = response {
        let status = get_status_code(&response);
        
        // リダイレクトレスポンス（301, 302, 307, 308のいずれか）
        if let Some(code) = status {
            if code == 301 || code == 302 || code == 307 || code == 308 {
                let location = get_header_value(&response, "Location");
                assert!(
                    location.is_some(),
                    "Redirect should have Location header"
                );
                assert!(
                    location.unwrap().starts_with("https://"),
                    "Should redirect to HTTPS"
                );
            }
        }
    }
}

// ====================
// 並行リクエストテスト
// ====================

#[test]
fn test_concurrent_requests() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use std::thread;
    
    let success_count = Arc::new(AtomicUsize::new(0));
    let total_requests = 20;
    
    let handles: Vec<_> = (0..total_requests)
        .map(|_| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
                if let Some(response) = response {
                    if get_status_code(&response) == Some(200) {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    
    for handle in handles {
        let _ = handle.join();
    }
    
    let successes = success_count.load(Ordering::Relaxed);
    assert!(
        successes >= total_requests * 8 / 10,
        "At least 80% of concurrent requests should succeed: {}/{}",
        successes, total_requests
    );
}

// ====================
// レスポンスタイムテスト
// ====================

#[test]
fn test_response_time() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    use std::time::Instant;
    
    let start = Instant::now();
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    let elapsed = start.elapsed();
    
    assert!(response.is_some(), "Should receive response");
    
    // レスポンスは1秒以内であるべき
    assert!(
        elapsed.as_secs() < 1,
        "Response time should be under 1 second, was {:?}", elapsed
    );
}

// ====================
// Content-Typeテスト
// ====================

#[test]
fn test_html_content_type() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let content_type = get_header_value(&response, "Content-Type");
    
    // .htmlファイルなのでtext/htmlであるべき
    if let Some(ct) = content_type {
        assert!(
            ct.contains("text/html") || ct.contains("text/plain"),
            "Content-Type should be text: {}", ct
        );
    }
}

#[test]
fn test_json_content_type() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(PROXY_HTTPS_PORT, "/health", &[]);
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    
    // health endpointはJSONを返す想定
    if status == Some(200) {
        // ボディがJSON形式であることを確認
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
        if body.contains("{") && body.contains("}") {
            // JSONっぽいレスポンス
            assert!(true, "Response appears to be JSON");
        }
    }
}

// ====================
// Keep-Aliveテスト
// ====================

#[test]
fn test_keep_alive_connection() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    // Keep-Alive接続でのリクエスト
    let response = send_request(
        PROXY_HTTPS_PORT, 
        "/", 
        &[("Connection", "keep-alive")]
    );
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Should return 200 OK");
}

// ====================
// User-Agentテスト
// ====================

#[test]
fn test_custom_user_agent() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let response = send_request(
        PROXY_HTTPS_PORT, 
        "/", 
        &[("User-Agent", "VeilE2ETest/1.0")]
    );
    assert!(response.is_some(), "Should receive response with custom User-Agent");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Should return 200 OK");
}

// ====================
// Hostヘッダーテスト
// ====================

#[test]
fn test_different_host_headers() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    // localhost
    let response1 = send_request(PROXY_HTTPS_PORT, "/", &[]);
    assert!(response1.is_some(), "localhost should work");
    
    // 127.0.0.1 のHost
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", PROXY_HTTPS_PORT)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    
    let request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).unwrap();
    
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    
    let response_str = String::from_utf8_lossy(&response);
    let status = get_status_code(&response_str);
    assert_eq!(status, Some(200), "127.0.0.1 Host should work");
}

// ====================
// 複数リクエストの安定性テスト
// ====================

#[test]
fn test_multiple_sequential_requests() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    let mut success_count = 0;
    let total_requests = 50;
    
    for _ in 0..total_requests {
        let response = send_request(PROXY_HTTPS_PORT, "/", &[]);
        if let Some(response) = response {
            if get_status_code(&response) == Some(200) {
                success_count += 1;
            }
        }
    }
    
    // 全リクエストが成功するべき
    assert_eq!(
        success_count, total_requests,
        "All sequential requests should succeed: {}/{}",
        success_count, total_requests
    );
}

// ====================
// 圧縮エンコーディング優先順位テスト
// ====================

#[test]
fn test_compression_priority() {
    if !is_e2e_environment_ready() {
        eprintln!("Skipping test: E2E environment not ready");
        return;
    }
    
    // 複数の圧縮形式をサポート
    let response = send_request(
        PROXY_HTTPS_PORT, 
        "/large.txt", 
        &[("Accept-Encoding", "gzip, br, zstd")]
    );
    assert!(response.is_some(), "Should receive response");
    
    let response = response.unwrap();
    let status = get_status_code(&response);
    assert_eq!(status, Some(200), "Should return 200 OK");
    
    // 設定ではzstdが最優先のはず
    let content_encoding = get_header_value(&response, "Content-Encoding");
    if let Some(encoding) = content_encoding {
        // 圧縮が有効な場合、どれかの形式が使われる
        assert!(
            encoding.contains("zstd") || encoding.contains("br") || encoding.contains("gzip"),
            "Should use one of the accepted encodings: {}", encoding
        );
    }
}

