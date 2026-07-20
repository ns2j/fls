# fls_ws の systemd サービス化ガイド (Linux)

このガイドでは、Linux 環境で `fls_ws` (WebSocket サーバー) を systemd サービスとして登録し、システム起動時に自動的にバックグラウンド実行されるように設定する手順を説明します。

---

## 導入手順

### 1. バイナリの配置
`make all` または `make fls_ws` でビルドした `fls_ws` バイナリを、システムのパスが通った場所（例: `/usr/local/bin`）にコピーします。

```bash
sudo cp fls_ws /usr/local/bin/
```

### 2. systemd サービスファイルの配置
本リポジトリに含まれる `fls_ws.service` を `/etc/systemd/system/fls_ws.service` にコピーします。

```bash
sudo cp fls_ws.service /etc/systemd/system/fls_ws.service
```

### 3. サービスファイルの設定調整（必要に応じて）
必要に応じて `/etc/systemd/system/fls_ws.service` を編集します。

```ini
[Unit]
Description=FeliCa WebSocket Server
After=network.target pcscd.service
Wants=pcscd.service

[Service]
Type=simple
# パスワードも取得する場合は -p オプションを指定してください
ExecStart=/usr/local/bin/fls_ws -p
WorkingDirectory=/usr/local/bin

# 一般ユーザー権限で実行したい場合は以下を有効化・調整してください
# User=your_username

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 4. サービスの有効化と起動

systemd の設定を再読み込みし、サービスを有効化・起動します。

```bash
# 設定の再読み込み
sudo systemctl daemon-reload

# 自動起動の有効化
sudo systemctl enable fls_ws

# サービスの即時起動
sudo systemctl start fls_ws
```

### 5. 状態の確認

サービスが正常に動作しているか確認します。

```bash
sudo systemctl status fls_ws
```

---

## 停止および無効化

サービスを停止・自動起動解除する場合は、以下のコマンドを実行します。

```bash
# サービスの停止
sudo systemctl stop fls_ws

# 自動起動の無効化
sudo systemctl disable fls_ws
```
