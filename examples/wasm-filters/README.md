# WASM Filters

veil-proxy用のProxy-WASMフィルタサンプル集

## フィルタ一覧

| フィルタ | 説明 | サイズ |
|---------|------|--------|
| [header-filter](./header-filter/) | ヘッダ追加・削除 | 144 KB |
| [waf-filter](./waf-filter/) | Web Application Firewall | 1.2 MB |
| [lua-filter](./lua-filter/) | Luaスクリプト実行 | 503 KB |

## ビルド方法

### 前提条件

```bash
# WASM ターゲットをインストール
rustup target add wasm32-wasip1
```

### 全フィルタをビルド

```bash
cd examples/wasm-filters

# Header Filter
cd header-filter && cargo build --target wasm32-wasip1 --release && cd ..

# WAF Filter
cd waf-filter && cargo build --target wasm32-wasip1 --release && cd ..

# Lua Filter
cd lua-filter && cargo build --target wasm32-wasip1 --release && cd ..
```

### ビルド済みWASMファイルの場所

```
target/wasm32-wasip1/release/
├── header_filter.wasm
├── waf_filter.wasm
└── lua_filter.wasm
```

## veil-proxyでの使用方法

### 設定例 (config.toml)

```toml
# WASMフィルタを有効化
[[routes]]
path = "/api/*"
upstream = "backend"

[[routes.wasm_filters]]
path = "/path/to/waf_filter.wasm"
config = '''
{
  "mode": "block",
  "rules": ["sqli", "xss"]
}
'''

[[routes.wasm_filters]]
path = "/path/to/lua_filter.wasm"
config = '''
{
  "script": "function on_request() veil.log('info', veil.get_path()) return 'continue' end"
}
'''
```

## フィルタ詳細

### Header Filter

シンプルなヘッダ操作フィルタ。Proxy-WASMの基本実装例。

```json
{
  "request_headers": { "add": {"X-Custom": "value"} },
  "response_headers": { "remove": ["Server"] }
}
```

### WAF Filter

OWASP ModSecurity CRSベースの攻撃検出。

対応攻撃:
- SQLインジェクション
- クロスサイトスクリプティング (XSS)
- パストラバーサル
- コマンドインジェクション

### Lua Filter

純粋Rust製Luaインタープリタ (外部ライブラリ不使用)。

機能:
- クロージャ
- パターンマッチング (`string.match`, `string.gsub`)
- 標準ライブラリ (`string.*`, `math.*`, `table.*`)
- ビット演算子

## ライセンス

各フィルタはveil-proxyと同じライセンスの下で提供されます。
