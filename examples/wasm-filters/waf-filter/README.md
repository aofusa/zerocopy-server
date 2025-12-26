# WAF Filter

Proxy-WASM用のWeb Application Firewall (WAF) フィルタ

## 概要

OWASP ModSecurity Core Rule Set (CRS) にインスパイアされた正規表現ベースのWAFフィルタ。
SQLインジェクション、XSS、パストラバーサル、コマンドインジェクションを検出・ブロック。

## ビルド

```bash
cargo build --target wasm32-wasip1 --release
```

出力: `target/wasm32-wasip1/release/waf_filter.wasm` (約1.2 MB)

## 設定例

```json
{
  "mode": "block",
  "rules": ["sqli", "xss", "path_traversal", "cmd_injection"],
  "whitelist": ["/health", "/metrics"],
  "enable_url_decode": true,
  "log_matches": true
}
```

## 設定オプション

| オプション | 型 | デフォルト | 説明 |
|-----------|------|---------|------|
| `mode` | string | "block" | "block": ブロック, "detect": 検出のみ |
| `rules` | array | 全ルール | 有効にするルール一覧 |
| `whitelist` | array | [] | 検査をスキップするパス |
| `enable_url_decode` | bool | true | URLデコードを有効化 |
| `log_matches` | bool | true | マッチ時にログ出力 |

## 検出ルール

### SQLインジェクション (`sqli`)
```
SELECT * FROM users WHERE id = '1' OR '1'='1'
UNION SELECT password FROM admins
```

検出パターン:
- UNION/SELECT句
- OR/AND条件操作
- コメント記法 (`--`, `/**/`)
- 16進数値 (`0x`)

### クロスサイトスクリプティング (`xss`)
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:alert(1)
```

検出パターン:
- `<script>` タグ
- イベントハンドラ (`onload`, `onerror`, `onclick` 等)
- `javascript:` URL

### パストラバーサル (`path_traversal`)
```
../../etc/passwd
..%2f..%2fetc/passwd
```

検出パターン:
- `../` シーケンス
- URLエンコードされたトラバーサル
- `/etc/passwd`, `/windows/` 等の機密パス

### コマンドインジェクション (`cmd_injection`)
```
; cat /etc/passwd
| whoami
`rm -rf /`
```

検出パターン:
- シェルメタ文字 (`;`, `|`, `&`, `$()`, `` ` ``)
- 危険なコマンド (`cat`, `wget`, `curl`, `rm`, `chmod`)

## 動作フロー

1. **リクエスト受信**
2. **ホワイトリストチェック** → スキップ対象なら通過
3. **URLデコード** (有効な場合)
4. **ルール検査**
   - URI
   - クエリパラメータ
   - ヘッダ
   - ボディ (POST)
5. **結果判定**
   - block モード: 403レスポンス
   - detect モード: ログ出力のみ

## 実装ファイル

| ファイル | 説明 |
|---------|------|
| `src/lib.rs` | Proxy-WASM統合 |
| `src/rules.rs` | ルールエンジン・検出パターン |

## 注意事項

- 本番環境ではホワイトリストを適切に設定してください
- 誤検知を避けるため、`detect` モードでテストしてから `block` モードに切り替えることを推奨します
