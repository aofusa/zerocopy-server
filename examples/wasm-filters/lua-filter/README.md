# Lua Filter

Proxy-WASM用の純粋Rust製Luaインタープリタフィルタ

## 概要

外部Luaライブラリを一切使用せず、ゼロから実装したLua 5.4互換インタープリタ。
クロージャ、パターンマッチング、ビット演算子など主要機能をサポート。

## ビルド

```bash
cargo build --target wasm32-wasip1 --release
```

出力: `target/wasm32-wasip1/release/lua_filter.wasm` (503 KB)

## 設定例

```json
{
  "script": "function on_request() veil.set_request_header('X-Lua', 'true') return 'continue' end",
  "debug": true
}
```

## Lua API (veil.*)

| 関数 | 説明 |
|------|------|
| `veil.log(level, msg)` | ログ出力 (debug/info/warn/error) |
| `veil.get_request_header(name)` | リクエストヘッダ取得 |
| `veil.set_request_header(name, val)` | リクエストヘッダ設定 |
| `veil.get_response_header(name)` | レスポンスヘッダ取得 |
| `veil.set_response_header(name, val)` | レスポンスヘッダ設定 |
| `veil.get_path()` | リクエストパス取得 |
| `veil.get_method()` | HTTPメソッド取得 |
| `veil.send_local_response(status, body)` | レスポンス送信 |
| `veil.get_headers()` | 全ヘッダをテーブルで取得 |

## サポート機能

### コア言語
- 変数・関数・クロージャ
- 可変長引数 (`...`)
- if/while/repeat/for
- テーブル

### パターンマッチング
```lua
string.match("Hello 123", "(%a+) (%d+)")  -- "Hello", "123"
string.gsub("foo bar", "(%w+)", "[%1]")   -- "[foo] [bar]"
```

サポートパターン: `. %a %d %s %w %p * + - ? ^ $ () [set] %bxy %1-9`

### 標準ライブラリ
- `string.*`: len, sub, upper, lower, find, match, gsub, format, rep, reverse
- `math.*`: abs, ceil, floor, sin, cos, sqrt, random, pi, huge
- `table.*`: concat, pack, unpack

### ビット演算子 (Lua 5.3+)
```lua
local x = 0xFF & 0x0F  -- 15
local y = 1 << 4       -- 16
```

## サンプルスクリプト

```lua
function on_request()
    local path = veil.get_path()
    local method = veil.get_method()
    veil.log('info', method .. ' ' .. path)
    
    -- カスタムヘッダ追加
    veil.set_request_header('X-Lua-Filter', 'true')
    
    -- 管理画面へのアクセス制御
    if string.find(path, '/admin') then
        local auth = veil.get_request_header('Authorization')
        if auth == nil then
            veil.send_local_response(403, 'Forbidden')
            return 'stop'
        end
    end
    
    return 'continue'
end

function on_response()
    veil.set_response_header('X-Processed-By', 'Lua-Filter')
    return 'continue'
end
```

## 実装詳細

| コンポーネント | ファイル | 行数 |
|---------------|---------|------|
| 字句解析 | `src/lua/lexer.rs` | ~400 |
| 構文解析 | `src/lua/parser.rs` | ~750 |
| AST | `src/lua/ast.rs` | ~200 |
| 値型 | `src/lua/value.rs` | ~260 |
| パターン | `src/lua/pattern.rs` | ~550 |
| インタープリタ | `src/lua/interpreter.rs` | ~1,280 |
| **合計** | | **~3,440** |
