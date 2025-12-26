# Header Filter

Proxy-WASM用のシンプルなヘッダ操作フィルタ

## 概要

リクエスト/レスポンスヘッダを追加・変更・削除するための基本的なフィルタ。
WASM フィルタの実装例としても参照できます。

## ビルド

```bash
cargo build --target wasm32-wasip1 --release
```

出力: `target/wasm32-wasip1/release/header_filter.wasm` (約144 KB)

## 設定例

```json
{
  "request_headers": {
    "add": {
      "X-Forwarded-By": "veil-proxy",
      "X-Request-ID": "{{uuid}}"
    },
    "remove": ["X-Debug"]
  },
  "response_headers": {
    "add": {
      "X-Powered-By": "veil-proxy",
      "X-Response-Time": "{{elapsed_ms}}"
    },
    "remove": ["Server"]
  }
}
```

## 設定オプション

### request_headers

リクエストヘッダの操作設定

| フィールド | 型 | 説明 |
|-----------|------|------|
| `add` | object | 追加/上書きするヘッダ |
| `remove` | array | 削除するヘッダ名 |

### response_headers

レスポンスヘッダの操作設定

| フィールド | 型 | 説明 |
|-----------|------|------|
| `add` | object | 追加/上書きするヘッダ |
| `remove` | array | 削除するヘッダ名 |

## 使用例

### セキュリティヘッダの追加

```json
{
  "response_headers": {
    "add": {
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block"
    }
  }
}
```

### プロキシ情報の追加

```json
{
  "request_headers": {
    "add": {
      "X-Forwarded-For": "{{client_ip}}",
      "X-Real-IP": "{{client_ip}}"
    }
  }
}
```

### 機密ヘッダの削除

```json
{
  "response_headers": {
    "remove": ["Server", "X-Powered-By", "X-AspNet-Version"]
  }
}
```

## 実装ファイル

| ファイル | 説明 |
|---------|------|
| `src/lib.rs` | Proxy-WASM統合・ヘッダ操作ロジック |
