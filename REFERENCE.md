# `lazypcscfelicalite.h` 完全リファレンス

このライブラリは、C++から PC/SC API を通じて FeliCa Lite および FeliCa Lite-S の操作を行うためのヘッダオンリーライブラリです。

## クラス: `LazyPCSCFelicaLite::PCSCFelicaLite`

### 1. コンストラクタ / デストラクタ
*   `PCSCFelicaLite(bool debug = false, std::string name = "PCSCFelicaLite")`
    *   PC/SC サービスへ接続し、初期化します。`debug=true`で詳細ログを出力します。
*   `~PCSCFelicaLite()`
    *   切断・リソース解放を行います。

### 2. カードの接続・切断
*   `bool autoConnectToFelica(uint32_t waitMs = 0)`
    *   カードがかざされるまで待機し、接続します（0は無限待機）。
*   `void disconnectCard()`
    *   カードとの接続を切断します。

### 3. カード情報の取得と判定
*   `uint8_t getCardTypeCode()` / `uint8_t readCardTypeCode()`
    *   FeliCa のカードタイプ（IDm等から判定したシステムコード等）を取得します。
*   `bool isFelica()`
    *   カードが FeliCa かどうかを判定します。
*   `bool isFelicaLite()`
    *   カードが FeliCa Lite (または Lite-S) かどうかを判定します。
*   `bool isFelicaLiteS()`
    *   カードが FeliCa Lite-S かどうかを判定します。
*   `void readCardTypeString(char *cardTypeString = NULL)`
    *   カードの種類を文字列として取得します。
*   `uint16_t getSystemcode()` / `uint16_t readSystemcode(uint16_t scancode = SYSTEMCODE_ANY)`
    *   カードのシステムコードを取得します。
*   `uint16_t polling(uint8_t UID[] = NULL, uint8_t PMm[] = NULL, uint16_t scancode = SYSTEMCODE_ANY)`
    *   FeliCa の Polling コマンドを発行し、IDm (UID) と PMm を取得します。
*   `void sendControl()`
    *   (内部用) 直接 PC/SC のエスケープコマンドを送信します。

### 4. カードの状態チェック・発行処理
*   `bool isFirstIssued()` / `bool isSecondIssued()`
    *   カードが 1次発行済 / 2次発行済 であるかを確認します。
*   `void FirstIssue()`
    *   カードを1次発行済状態にします。内部的には MC ブロックに対して `MC_ALL` (0x00: 設定ロック), `SYS_OP` (0x01: NDEF有効化) などを書き込みます。また、`SPAD10〜13` の読み取りMAC必須化 (`MC_SP_REG_R_RESTR`) も同時に設定され、秘密領域としての利用を確定させます。

### 5. 基本的なデータの読み書き
*   `void readBinary(uint16_t BlockAdr, uint8_t BLOCK[16])`
    *   指定ブロック（16バイト）を読み込みます。
*   `void updateBinary(uint16_t BlockAdr, uint8_t BLOCK[16])`
    *   指定ブロック（16バイト）を書き込みます。

### 6. MAC付きの読み書き (FeliCa Lite/Lite-S 共通・専用)
*   `void readBinaryWithMAC(uint16_t BlockAdr, uint8_t BLOCK[16], uint8_t MAC[16])`
    *   (Lite) MAC ブロックと同時にデータを読み込みます。
*   `void readBinaryWithMAC_A(uint16_t BlockAdr, uint8_t BLOCK[16], uint8_t MAC[16])`
    *   (Lite-S) 改ざん検知用の MAC_A ブロックと同時にデータを読み込みます。
*   `void updateBinaryWithMAC_A(uint16_t BlockAdr, uint8_t BLOCK[16], uint8_t CK1[8], uint8_t CK2[8])`
    *   (Lite-S) ローカルで計算した MAC_A とともにデータを書き込みます（MAC必須書き込み用）。

### 7. 高度なセキュリティ・認証機能 (Lite-S)

*   `void writeCardKey(uint8_t CK1[8], uint8_t CK2[8])`
    *   カードに認証鍵（CK1, CK2）を書き込み、CKV（バージョン）を有効化します。
*   `void writeRandomChallenge(uint8_t RC1[8], uint8_t RC2[8])`
    *   カードにランダムチャレンジを書き込みます（MAC計算の前準備）。
*   `bool cardIdCheckMAC(uint8_t CK1[8], uint8_t CK2[8])`
    *   (Lite) MACを用いてカードの正当性を確認します。
*   `bool cardIdCheckMAC_A(uint8_t CK1[8], uint8_t CK2[8])`
    *   (Lite-S) MAC_Aを用いてカードの正当性を確認します。
*   `void enableSTATE()` / `void setSTATE_EXT_AUTH(bool auth, uint8_t CK1[8], uint8_t CK2[8])`
    *   `enableSTATE()`: ユーザデータ領域全体への書き込みをMAC必須化し、さらに `SPAD10〜13` については読み取りもMAC必須化します。
    *   `setSTATE_EXT_AUTH()`: 外部認証（相互認証）状態の設定およびセッションキーの生成を行います。



### 8. NDEF (NFC Data Exchange Format) 操作
*   `bool isNdefEnabled()`
    *   NDEFが有効化されているかを確認します。
*   `void enableNDEF(bool en = true)`
    *   カードを NDEF 形式として初期化（フォーマット）します。
*   `void writeNdefURI(uint8_t mode, const char str[])`
    *   NDEF フォーマットで URI を書き込みます（Androidでの読み込み互換性を高める Pure URI フォーマット）。`SPAD10〜13` を秘密領域として残すため、`Nmaxb` は 12 ブロックで宣言されます。
*   `void writeNdefURIWithMAC(uint8_t mode, const char str[], uint8_t CK1[8], uint8_t CK2[8])`
    *   上記 NDEF フォーマットを MAC 付加書き込み（セキュア書き込み）します。
*   `void readNdefURI(std::string &out_uri)` / `void readNdefContent(std::string &content)`
    *   NDEF 領域のデータを読み取ります。`readNdefContent` はペイロードサイズ等の境界チェック (`Ln <= 192` やバッファオーバーラン防止) を備えており、不正なタグでもクラッシュせずに安全に処理できます。

### 9. 内部用 暗号・MAC計算アルゴリズム関数群 (MbedTLSラップ)
これらの関数は通常直接呼び出す必要はありません。
*   `void desEncryptFixedLength(...)` / `void desDecryptFixedLength(...)`
    *   8バイト固定長の DES 暗号化 / 復号化処理。
*   `void zeroIV(uint8_t IV[8])`
    *   初期化ベクトル (IV) をゼロ埋めします。
*   `void arryXor(...)`
    *   8バイト配列同士の XOR を計算します。
*   `void swapByteOrder(uint8_t inout[8])`
    *   8バイトのエンディアンを反転させます（MbedTLS仕様への適合等）。
*   `void Key2des3(...)` / `void DualKey2des3(...)`
    *   2鍵 3DES（Triple DES）演算を行います。
*   `void makeSessionKey(...)`
    *   RC（ランダムチャレンジ）と CK（カード鍵）からセッションキー（SK1, SK2）を生成します。
*   `void makeMAC(...)`
    *   (Lite用) MACを生成します。
*   `void makeReadMAC_A(...)` / `void makeWriteMAC_A(...)`
    *   (Lite-S用) MAC_Aを生成します。書き込み用にはWCNT（書き込み回数カウンタ）が利用されます。
*   `bool compareMAC(...)` / `bool compareMAC_A(...)`
    *   計算したMAC(MAC_A)とカードから取得したMAC(MAC_A)を比較検証します。
*   `void makeRandomChallenge(uint8_t RC1[8], uint8_t RC2[8])` / `uint8_t CryptRand()`
    *   乱数生成器を用いてランダムチャレンジ用データを生成します。

### 10. デバッグユーティリティ
*   `void showMAC(const uint8_t input[8])`
    *   8バイトのデータを16進数で標準出力に表示します（デバッグ用途）。


