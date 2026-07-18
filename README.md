# FeliCa Lite-S Security & PAM Integration Tool

FeliCa Lite-S のセキュアな機能（MAC_Aによる相互認証、NDEF対応）を活用し、システムへの安全なログイン(PAM)やWebSocket経由での認証情報取得などを実現するツール群です。

> **解説記事**: 本ツールの開発背景や詳細な仕組みについては、以下のQiita記事をご参照ください。
> [FeliCa Lite-SのRC-S300での読み書き(Windows/Linux両対応) - Qiita](https://qiita.com/igariy/items/b819ca1d2f1b6acf6d55)

## 特徴
*   **SONY PaSoRi RC-S300 対応:** RC-S300 などの PC/SC 対応 NFC リーダーで動作します。
*   **FeliCa Lite-Sの相互認証 (MAC_A) 対応:** 不正なカードへの書き込み防止や改ざん検知、読み出し保護に利用できます。
*   **ハードウェアレベルのアクセス制限とNDEFの完全共存:** 一般のスマホからは公開されたNDEF領域（ブロック1〜12のURL等）だけが見え、ユーザーデータ領域（SPAD10〜13）は存在自体が隠蔽されます。専用のツールから相互認証（MAC認証）を行った時のみ読み書きが可能です。
*   **Windows Credential Provider (`FelicaCredentialProvider`):** Windows 10/11 のログオン画面でカードをタッチするだけで、安全にWindowsにサインインできます。
*   **PAMモジュール (`pam_fls.so`):** Linuxシステムのログイン(sudo等)にFeliCaを用いた認証を組み込めます。
*   **WebSocketサーバー (`fls_ws`):** ブラウザ側のフロントエンドアプリと連携し、カード情報をリアルタイムで送信できます。

---

## 必要なハードウェア・環境
*   **NFCカードリーダー**: SONY PaSoRi RC-S300 (PC/SC対応のリーダー/ライター)
*   **ICカード**: FeliCa Lite-S
*   C++コンパイラ (`g++` や `Visual Studio` 等)
*   Windows環境の場合は `nmake` (Makefile.vc) にてビルドします。

### Linux 環境の必須パッケージ

**Ubuntu / Debian 系の場合:**
```bash
sudo apt update
sudo apt install build-essential pcscd libpcsclite-dev libmbedtls-dev libpam0g-dev
```

**Fedora / RHEL 系の場合:**
```bash
sudo dnf install gcc-c++ pcsc-lite pcsc-lite-devel mbedtls-devel pam-devel
```
*(※ WindowsではOS標準のBCryptを使用するため MbedTLS は不要です)*

---

## インストールとビルド手順

### 1. 鍵ファイルの設定
セキュリティの観点から、カードおよびプログラムの認証に使用する鍵はリポジトリに含まれていません。
まずサンプルファイルをコピーして独自の鍵ファイルを作成してください。

```bash
cp felica_keys.h.sample felica_keys.h
```

コピーした `felica_keys.h` をエディタで開き、`CK1` と `CK2` (各8バイト) を任意の安全な値に変更してください。

> **警告:** ここで設定した鍵は絶対に外部に公開しないでください！

### 2. コンパイル

**Linux 環境:**
```bash
make all
```
これにより、以下のバイナリが生成されます。
*   `fls`: カードへのデータ読み書き・設定用CLIツール
*   `fls_ws`: WebSocketサーバー
*   `pam_fls.so`: Linuxログイン用PAMモジュール

**Windows 環境 (nmake):**
「x64 Native Tools Command Prompt for VS」などを開き、以下を実行します。
```cmd
nmake /f Makefile.vc
```
これにより `fls.exe` および `fls_ws.exe` が生成されます。

---

## 主なツールの使い方

### `fls` (カード設定・読み書きツール)
カードに対するセキュリティ設定や、秘密領域データの読み書きを行います。
実行にはPC/SC対応のカードリーダーが必要です。

```bash
# ヘルプの表示
./fls -h

# 【推奨フロー：ハイブリッドタグの作成】

# 1. 鍵の書き込みと必須化 (初期設定)
# これを実行した瞬間から SPAD13 へのアクセスは MAC 認証が必須になります。
./fls -W

# 2. NDEF(URL)を書き込む（要MAC相互認証 -m）
# ※ ブロック1〜12に書き込まれ、一般のスマホでも読めるようになります。
./fls -N https://example.com -m

# 3. 認証情報をカードに書き込む（SPAD10〜13に書き込み。要MAC相互認証 -m）
# ※ SPAD領域は保護されているため、-m が必須です。
./fls -U "taro_yamada" -m  # SPAD10: ユーザ名
./fls -P "my_password" -m  # SPAD11: パスワード
./fls -D "MYDOMAIN" -m     # SPAD12-13: ドメイン名

# 4. カードステータスと鍵の確認
# ※ SPAD10〜13だけが読み取りエラーになり、隠蔽されていることが確認できます。
./fls -s
# ※ MAC_A計算を用いて、カードに書き込んだ鍵が正しいか検証できます。
./fls -c

# 5. 認証情報を読み取る（要MAC相互認証 -m）
# ※ 正しい鍵を使った相互認証でロックを解除し、内容を読み取ります。
./fls -u -m  # ユーザ名の読み取り
./fls -p -m  # パスワードの読み取り
./fls -d -m  # ドメイン名の読み取り

# 6. 1次発行（最終ロック）
# 全ての設定が完了したら、カード設定を永続的にロックし、正式なNDEFタグとして完成させます。
./fls -1
```

### `fls_ws` (WebSocketサーバー)
ブラウザ等からローカル(ws://localhost:8080/ws)で接続し、かざされたカードから安全に読み取った秘密データ（SPAD10のユーザ名など）をリアルタイムに受け取ることができます。WebアプリでのFeliCa連携に利用します。

```bash
./fls_ws
```

### `pam_fls.so` (PAMモジュール)
Linuxシステムの `/etc/pam.d/sudo` 等に追記することで、パスワード入力の代わりにFeliCaをかざし、SPAD10のユーザ名情報を用いて認証を実現できます。
*(設定方法はシステムのPAM仕様に従ってください)*

### `FelicaCredentialProvider` (Windows ログオンプロバイダ)
Windows のログオン画面でFeliCaをかざしてパスワードレス認証を行うための拡張機能です。
詳細は `FelicaCredentialProvider/README.md` を参照してください。

---

## 開発・構成ファイル
*   `lazypcscfelicalite.h`: PC/SC API を叩く主要ヘッダ（MbedTLSによる暗号処理等を含む）。詳細は `REFERENCE.md` および `CHANGES.md` を参照。
*   `fls.cpp`: メインのCLIツールソース。
*   `fls_ws.cpp`: WebSocketサーバーソース (mongoose.c 利用)。
*   `pam_fls.cpp`: PAMモジュールソース。

---

## 謝辞 (Credits)
本プロジェクトの基盤となっているFeliCa通信ライブラリ `lazypcscfelicalite.h` のオリジナル版は、[gpsnmeajp 氏の Qiita 記事](https://qiita.com/gpsnmeajp/items/a378e1829fba1c3a3ed7) にて公開されたものをベースにしています。有用なライブラリの公開に感謝いたします。
