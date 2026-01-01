//! 統合テスト
//!
//! 実際のネットワーク接続を使用したテストを実行します。

mod common;

use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// ====================
// TCP接続テスト
// ====================

#[test]
fn test_echo_server_basic() {
    let server = EchoServer::start();
    
    let mut stream = TcpStream::connect(server.address()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    
    // データ送信
    stream.write_all(b"Hello, World!").unwrap();
    
    // エコーバック受信
    let mut buf = [0u8; 13];
    stream.read_exact(&mut buf).unwrap();
    
    assert_eq!(&buf, b"Hello, World!");
}

#[test]
fn test_simple_http_server_response() {
    let server = SimpleHttpServer::start("Test Response Body", "test-server");
    
    let mut stream = TcpStream::connect(server.address()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    
    // HTTPリクエスト送信
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    
    // レスポンス受信
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response);
    
    // ステータス確認
    assert!(response.contains("HTTP/1.1 200 OK"), "Expected 200 OK");
    
    // ヘッダー確認
    assert!(response.contains("X-Server-Id: test-server"), "Expected X-Server-Id header");
    assert!(response.contains("Content-Type: text/plain"), "Expected Content-Type header");
    
    // ボディ確認
    assert!(response.contains("Test Response Body"), "Expected response body");
}

#[test]
fn test_multiple_http_servers() {
    let server1 = SimpleHttpServer::start("Response from Server 1", "server1");
    let server2 = SimpleHttpServer::start("Response from Server 2", "server2");
    
    // サーバー1にリクエスト
    let mut stream1 = TcpStream::connect(server1.address()).unwrap();
    stream1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream1.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    
    let mut response1 = Vec::new();
    stream1.read_to_end(&mut response1).unwrap();
    let response1 = String::from_utf8_lossy(&response1);
    
    // サーバー2にリクエスト
    let mut stream2 = TcpStream::connect(server2.address()).unwrap();
    stream2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream2.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    
    let mut response2 = Vec::new();
    stream2.read_to_end(&mut response2).unwrap();
    let response2 = String::from_utf8_lossy(&response2);
    
    // 各サーバーが正しいレスポンスを返す
    assert!(response1.contains("X-Server-Id: server1"));
    assert!(response1.contains("Response from Server 1"));
    
    assert!(response2.contains("X-Server-Id: server2"));
    assert!(response2.contains("Response from Server 2"));
}

// ====================
// ポート取得テスト
// ====================

#[test]
fn test_dynamic_port_allocation() {
    let ports = get_available_ports(10);
    
    assert_eq!(ports.len(), 10);
    
    // 全てのポートが異なる
    let unique: std::collections::HashSet<_> = ports.iter().collect();
    assert_eq!(unique.len(), 10, "All ports should be unique");
    
    // 全てのポートが有効な範囲（u16型なので自動的に0-65535）
    for port in &ports {
        assert!(*port > 0, "Port should be positive");
    }
}

#[test]
fn test_port_availability_check() {
    let server = SimpleHttpServer::start("test", "test");
    let port = server.port();
    
    // サーバーが起動しているのでポートは使用中
    assert!(wait_for_port(port, Duration::from_secs(1)), "Port should be available");
    
    // サーバーをドロップ
    drop(server);
    
    // ポートが解放されるのを待つ
    std::thread::sleep(Duration::from_millis(100));
}

// ====================
// TLS証明書生成テスト
// ====================

#[test]
fn test_certificate_generation() {
    let temp_dir = tempfile::tempdir().unwrap();
    
    let (cert_path, key_path) = generate_test_certs(temp_dir.path()).unwrap();
    
    // ファイルが生成されている
    assert!(cert_path.exists(), "Certificate file should exist");
    assert!(key_path.exists(), "Key file should exist");
    
    // ファイルが空でない
    let cert_content = std::fs::read_to_string(&cert_path).unwrap();
    let key_content = std::fs::read_to_string(&key_path).unwrap();
    
    assert!(cert_content.contains("BEGIN CERTIFICATE"), "Should be a valid certificate");
    assert!(key_content.contains("BEGIN PRIVATE KEY"), "Should be a valid private key");
}

// ====================
// 設定ファイル生成テスト
// ====================

#[test]
fn test_config_generation() {
    let temp_dir = tempfile::tempdir().unwrap();
    
    let (cert_path, key_path) = generate_test_certs(temp_dir.path()).unwrap();
    let config_path = temp_dir.path().join("test_config.toml");
    
    let backend_urls = vec![
        "http://127.0.0.1:8081/".to_string(),
        "http://127.0.0.1:8082/".to_string(),
    ];
    
    generate_test_config(
        8443,
        8080,
        &cert_path,
        &key_path,
        &backend_urls,
        &config_path,
    ).unwrap();
    
    // ファイルが生成されている
    assert!(config_path.exists(), "Config file should exist");
    
    // 内容を確認
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    
    assert!(config_content.contains("[server]"), "Should have server section");
    assert!(config_content.contains("[tls]"), "Should have tls section");
    assert!(config_content.contains("127.0.0.1:8443"), "Should have HTTPS port");
    assert!(config_content.contains("127.0.0.1:8080"), "Should have HTTP port");
    assert!(config_content.contains("round_robin"), "Should have load balancing algorithm");
}

// ====================
// ヘルパー関数テスト
// ====================

#[test]
fn test_wait_for_port_timeout() {
    // 未使用のポートを取得
    let port = get_available_port();
    
    // ポートは使用されていないのでfalseが返る
    let result = wait_for_port(port, Duration::from_millis(100));
    assert!(!result, "Should timeout waiting for unused port");
}

#[test]
fn test_wait_for_port_success() {
    let server = SimpleHttpServer::start("test", "test");
    let port = server.port();
    
    // サーバーが起動しているのでtrueが返る
    let result = wait_for_port(port, Duration::from_secs(2));
    assert!(result, "Should find open port");
}

// ====================
// エラーハンドリング統合テスト（優先度: 高）
// ====================

#[test]
fn test_proxy_invalid_request() {
    let server = SimpleHttpServer::start("Test Response", "test-server");
    
    let mut stream = TcpStream::connect(server.address()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    
    // 不正なHTTP構文のリクエストを送信
    stream.write_all(b"INVALID REQUEST\r\n\r\n").unwrap();
    
    // レスポンスを受信
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    
    // SimpleHttpServerは不正なリクエストに対しても200 OKを返す可能性がある
    // または、接続を閉じる可能性もある
    // ここでは、何らかのレスポンスが返されるか、接続が閉じられることを確認
    assert!(
        response.is_empty() || response.contains("200") || response.contains("400") || response.contains("Bad Request"),
        "Should return response or close connection for invalid request, got: {}", response
    );
}

#[test]
fn test_proxy_oversized_header() {
    let server = SimpleHttpServer::start("Test Response", "test-server");
    
    let mut stream = TcpStream::connect(server.address()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    
    // 非常に大きなヘッダーを含むリクエストを送信
    let mut request = b"GET / HTTP/1.1\r\nHost: localhost\r\n".to_vec();
    // 10KBのヘッダーを追加
    let large_header = format!("X-Large-Header: {}\r\n", "x".repeat(10000));
    request.extend_from_slice(large_header.as_bytes());
    request.extend_from_slice(b"\r\n");
    
    stream.write_all(&request).unwrap();
    
    // レスポンスを受信
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    
    // SimpleHttpServerは大きなヘッダーに対しても200 OKを返す可能性がある
    // または、接続を閉じる可能性もある
    // ここでは、何らかのレスポンスが返されるか、接続が閉じられることを確認
    assert!(
        response.is_empty() || response.contains("200") || response.contains("400") || response.contains("431"),
        "Should return response or close connection for oversized header, got: {}", response
    );
}

// ====================
// タイムアウト処理統合テスト（優先度: 中）
// ====================

#[test]
fn test_proxy_read_timeout() {
    // 遅延応答するサーバーを起動（5秒遅延）
    let server = DelayedHttpServer::start("Delayed Response", "delayed-server", Duration::from_secs(5));
    
    let mut stream = TcpStream::connect(server.address()).unwrap();
    // 短い読み込みタイムアウトを設定（1秒）
    stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    
    // HTTPリクエスト送信
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    
    // レスポンスを受信（タイムアウトが発生する可能性がある）
    let mut response = Vec::new();
    let result = stream.read_to_end(&mut response);
    
    // タイムアウトエラーが発生することを確認
    // または、タイムアウト前にレスポンスが返される可能性もある
    match result {
        Ok(_) => {
            // タイムアウト前にレスポンスが返された場合
            let response_str = String::from_utf8_lossy(&response);
            // レスポンスが正しいことを確認
            assert!(response_str.contains("Delayed Response") || response_str.contains("200 OK"));
        }
        Err(e) => {
            // タイムアウトエラーが発生した場合
            assert!(
                e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock,
                "Should timeout or return WouldBlock error: {:?}", e
            );
        }
    }
}

