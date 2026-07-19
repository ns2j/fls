# Keycloak FeliCa ログイン連携ガイド

`fls_ws`（FeliCa WebSocket サーバー）を使用することで、Keycloakのログイン画面でFeliCa Lite-Sカードをかざすだけで、ユーザー名とパスワードを自動入力し即座にログインする仕組みを構築できます。

## 概要
PCに接続されたFeliCaリーダーからカード内の情報（SPAD10: ユーザー名、SPAD11: パスワード）を読み取り、WebSocket経由でブラウザ上のKeycloakログイン画面に送信して自動ログインを行います。

## 事前準備

1. **カードの準備**
   `fls` コマンドを使用して、FeliCa Lite-Sカードのユーザー領域にログイン情報を書き込んでおきます。
   - `SPAD10`: ユーザー名
   - `SPAD11`: パスワード

2. **WebSocketサーバーの起動**
   Keycloakを開くPC（FeliCaリーダーが繋がっているPC）で、`fls_ws` をパスワード読み取りオプション（`-p`）付きで起動しておきます。
   ```bash
   ./fls_ws -p
   ```
   ※ ポート `48080` を使用します。

---

## Keycloak カスタムテーマの設定

Keycloakのログイン画面本体（`.ftl` ファイル）を直接編集すると、バージョン違い等によるテンプレートエンジンのエラー（HTTP 500）が起きやすくなります。
そのため、**外部のJavaScriptファイル（`felica-login.js`）として読み込ませる安全なアプローチ**を採用します。

### 1. テーマディレクトリの準備
Keycloakの `themes` ディレクトリ内に、FeliCa連携用のカスタムテーマディレクトリを作成します。
（例: `felica-theme` という名前のテーマにする場合）

```text
/opt/keycloak/themes/
└── felica-theme/
    └── login/
        ├── theme.properties
        └── resources/
            └── js/
                └── felica-login.js
```

### 2. ファイルの配置

本リポジトリに含まれる `felica-login.js` を、作成したテーマ内の `resources/js/` フォルダ内に配置します。

### 3. `theme.properties` の配置
本リポジトリに含まれる `theme.properties` を、作成したテーマ内の `login` フォルダ直下に配置します。これにより、Keycloakの標準デザインを引き継ぎつつ、追加のスクリプトを読み込ませることができます。

*(※ Keycloakのバージョンが古い場合はファイル内の `parent=keycloak` を `parent=base` に変更する必要があることがあります)*

### 4. テーマの適用
1. Keycloakの管理コンソール (Admin Console) にログインします。
2. 画面左上のドロップダウンから、テーマを適用したい対象の Realm を選択します。
3. 左メニューの `Realm settings` -> `Themes` タブを開きます。
4. `Login theme` のドロップダウンから、作成したテーマ（例: `felica-theme`）を選択して保存します。

---

## 使い方

1. バックグラウンドで `./fls_ws -p` が動いていることを確認します。
2. ブラウザで Keycloak のログイン画面を開きます。
3. ブラウザのコンソールに `FeliCa Reader (fls_ws) と接続しました。カードをかざしてください。` と出力されていることを確認します。
4. FeliCaリーダーにカードをかざすと、ユーザー名とパスワードが一瞬で自動入力され、即座にログインが完了します！

## トラブルシューティング

* **パスワードが自動入力されない場合**
  `fls_ws` が `-p` オプションなしで起動しているか、ブラウザ側が古いJavaScriptファイルをキャッシュしている可能性があります。`fls_ws` を再起動するか、ブラウザでスーパーリロード（`Ctrl`+`Shift`+`R`）をお試しください。
* **Internal Server Error (500) になる場合**
  カスタムテーマ内のディレクトリ名（`resources` など）のスペルミスや、`theme.properties` の配置場所が間違っている可能性があります。ディレクトリ階層が正しいかもう一度確認してください。
