# FeliCa Lite-S Credential Provider

FeliCa Lite-S を用いて Windows にパスワードレス（ICカードタッチ）でログオンするためのカスタム Credential Provider のサンプル実装です。
`lazypcscfelicalite.h` をバックエンドの通信ライブラリとして使用しています。

## 概要

この Credential Provider は、Windows のログオン画面で FeliCa Lite-S カードのタッチを待機します。
カードが検出されると、カードとの間で **MAC_A を用いた相互認証** を行い、指定されたユーザーデータ領域 (SPAD10 〜 SPAD13) から「ユーザー名」「パスワード」「ドメイン名」を読み取ります。
読み取った情報は `KERB_INTERACTIVE_LOGON` 構造体に変換され、Windowsの標準認証（Local Security Authority）へ渡されることでログオンが実行されます。

### メモリマップ (SPAD の利用用途)
付属の `fls` コマンドツールで以下のようにデータを書き込んでおく必要があります。

* **SPAD10 (最大15文字):** ユーザー名 (`.\fls -U <ユーザー名> -m`)
* **SPAD11 (最大15文字):** パスワード (`.\fls -P <パスワード> -m`)
* **SPAD12 - SPAD13 (最大31文字):** ドメイン名 (`.\fls -D <ドメイン名> -m`)

## 動作要件

* Windows 10 / 11
* Visual Studio (C++ デスクトップ開発ワークロード) および Windows SDK
* FeliCa対応 ICカードリーダー (PaSoRi 等)
* FeliCa Lite-S カード

## ビルド方法

「x64 Native Tools Command Prompt for VS」などを開き、以下のコマンドを実行してください。

```cmd
cd FelicaCredentialProvider
nmake /f Makefile.vc
```

ビルドが成功すると、同フォルダ内に `FelicaCredentialProvider.dll` が生成されます。

## インストールと登録

1. ビルドされた `FelicaCredentialProvider.dll` を安全な場所（例: `C:\Windows\System32` や、任意のアプリケーションフォルダ）にコピーします。
2. 同梱されている `Register.reg.sample` をコピーして `Register.reg` を作成し、テキストエディタで開きます。
3. 一番下の行にある DLL のパスを、手順1で配置した**実際のフルパス**に書き換えます。
   *(注意: パスの区切り文字 `\` は、レジストリファイル内では `\\` のようにエスケープする必要があります。デフォルトでは `C:\\Windows\\System32\\FelicaCredentialProvider.dll` になっています)*
4. `Register.reg` をダブルクリックしてレジストリにマージします。
5. ログアウト（または画面ロック `Win + L`）すると、サインイン画面に新しい FeliCa 用のアイコン（タイル）が追加されます。

### アンインストール方法

1. `Unregister.reg` をダブルクリックしてレジストリから登録を解除します。
2. PCを再起動します（またはログオンし直します）。
3. 配置した `FelicaCredentialProvider.dll` を削除します。

## 鍵の設定 (セキュリティ上の注意)

本プロジェクト内のコード (`Credential.cpp` の `PollingThread`) では、FeliCaカードと相互認証を行うためのマスターキー (`CK1`, `CK2`) として、親ディレクトリにある `felica_keys.h` で定義された `FELICA_CK1_INIT` および `FELICA_CK2_INIT` を参照します。

実稼働環境で使用する場合は、必ず安全な鍵情報が `felica_keys.h` に設定されていることを確認してください。カード側も同じキーで1次発行 (`.\fls -1`) されている必要があります。

## ⚠️ 警告・免責事項

* **ロックアウトの危険性**: カスタム Credential Provider に不具合やクラッシュが発生すると、Windowsに一切ログインできなくなる（ロックアウトされる）リスクがあります。
* 開発・テストを行う際は、**必ず別の管理者アカウントやパスワードログインの手段を残しておく**か、**Hyper-V などの仮想マシン上でテスト**するようにしてください。
* 本ソフトウェアの使用により生じたいかなる損害についても、作者は責任を負いません。
