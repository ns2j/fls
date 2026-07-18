/*
LazyPCSCfelicaLite v0.41

zlib License
Copyright (c) 2018 GPS_NMEA_JP

This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
*/

/*
v0.41
autoConnectToFelicaで，Felicaではないカードを検出した際に例外を吐く不具合を修正

v0.4

PCSCCryptographicExceptionを追加．
Felica Lite-Sの内部アドレスを定数化
readBinaryの応答チェックを厳格化(サイズチェック)
readBinaryWithMACを追加．MAC付き読み取りができるように
updateBinaryWithMAC_Aを追加．MAC付き書き込みができるように
書き込み時にメモリ寿命警告をエラーとして扱わないように変更
書き込み時に書き込み内容をデバッグ表示するように変更

MAC検証系命令を追加
desEncryptFixedLength
desDecryptFixedLength
swapByteOrder
showMAC
arryXor
zeroIV
Key2des3
DualKey2des3
makeSessionKey
makeMAC
makeReadMAC_A
makeWriteMAC_A
compareMAC
compareMAC_A
writeRandomChallenge
writeCardKey
cardIdCheckMAC
cardIdCheckMAC_A
makeRandomChallenge
enableSTATE
setSTATE_EXT_AUTH
updateBinaryWithMAC_A_Auto
CryptRand
を追加

v0.31 
システムコード取得の関係のマジックナンバーを定数化
取得には50msあれば十分なことがわかったので50msでタイムアウトに．
isCardSet()とreadSystemcode()が干渉する(カードの取り外しをisCardSetで検出できない)ことが判明．→対処にはポーリング間隔分の待ち時間を入れる必要がある...
readTypecodeの内部表記を修正．
例外クラス内のC++規則違反を修正．
デバッグ表示の関数名ミス撲滅のため仕様を変更．
カード種別などのキャッシュの初期値を修正
connect時にシステムコードとカード種別をキャッシュする際にミスってFelica以外を受け付けなくなっていたのを修正
インスタンス名をつけられるように． setInstanceNameを追加．
例外クラスPCSCCardRemovedExceptionを追加．カード取り外し系は以後こちらに
リトライを削除
autoConnectToFelicaを追加．接続関係の処理を自動で行い，干渉問題に対処．

v0.3
getSystemcodeをreadSystemcodeに
getCardTypeをreadCardTypeに
connect時にシステムコードとカード種別をキャッシュするように
connect時のシステムコード取得を粘るように(微妙な距離だと失敗するため)

v0.2
pollingを追加
getCurrentStateを追加
多重接続防止処理を追加
isCardのバグ(自分が使用していても他者が使用中に見える)を修正

v0.1
初版

※デフォルトの設定だと，タッチから反応まで少々時間がかかります．
　コントロールパネルの「NFCポート／パソリ」にて，
 　・「ポーリング間隔」を「高速にする」
  　・「検出対象カード」を「NFC-F」のみにする
   　と，改札機並みの反応になります．
	　(ただし，検出対象カードを絞るとe-taxやマイナンバーポータルで使えなくなります．)

	 「FeliCa」および「PaSoRi」および「パソリ」はソニー株式会社の登録商標です。
	 「MIFARE」はNXPセミコンダクターズの登録商標です。
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <exception>
#include <stdexcept>
#include <vector>
#include <string>

#include <winscard.h>
#pragma comment (lib, "winscard.lib")
#include <Bcrypt.h>
#pragma comment (lib, "Bcrypt.lib")

namespace LazyPCSCFelicaLite
{
	using std::vector;
	using std::string;

	// PC/SCのエラー応答．通常は発生しない．コマンド誤りか状態が異常
	//プログラムミスか機器故障を疑うこと
	class PCSCErrorException : public std::runtime_error
	{
	public:
		PCSCErrorException(const char *Message, uint8_t SW1, uint8_t SW2)
			: Errinfo(), runtime_error(Message)
		{
			Errinfo.SW1 = SW1;
			Errinfo.SW2 = SW2;
		}

		uint8_t sw1()
		{
			return Errinfo.SW1;
		}
		uint8_t sw2()
		{
			return Errinfo.SW2;
		}
	private:
		struct PCSCError_struct
		{
			uint8_t SW1;
			uint8_t SW2;
		};
		PCSCError_struct Errinfo;
	};

	// PC/SCの関数エラー．まずめったに発生しない．(直接接続中にカード関係操作をした場合を除く)
	//プログラムミスか機器故障を疑うこと
	class PCSCCommandException : public std::runtime_error
	{
	public:
		PCSCCommandException(const char *Message, LONG res)
			: Errinfo(res), runtime_error(Message)
		{}

		LONG returncode()
		{
			return Errinfo;
		}
	private:
		LONG Errinfo;
	};

	//本来あるべきではない状態で実行しようとした．
	//プログラムミス
	class PCSCIllegalStateException : public  std::runtime_error
	{
	public:
		PCSCIllegalStateException(const char *Message)
			: runtime_error(Message)
		{}
	};

	//カードがない，カードが途中で取り外された
	//カードがセットされていない状態でconnectCard()を呼び出した場合はかならず出る．
	class PCSCCardRemovedException : public std::runtime_error
	{
	public:
		PCSCCardRemovedException(const char *Message)
			: runtime_error(Message)
		{}
	};

	//暗号化処理エラー
	class PCSCCryptographicException : public std::runtime_error
	{
	public:
		PCSCCryptographicException(const char *Message)
			: runtime_error(Message)
		{}
	};

	//カードリーダーがない，カードが異常な応答を返した，PC/SC SERVICEに接続できないなど，
	//継続不能な，システム的あるいは物理的なランタイム問題
	class PCSCFatalException : public std::runtime_error
	{
	public:
		enum
		{
			FAILD_TO_ESTABLISH,
			NO_READERS_AVAILABLE,
			FAILED_TO_DETECT_READER,
			FAILED_TO_GET_CARD_STATUS,
			READER_DISCONNECTED,
			UNKNOWN_STATUS,
			UNKNOWN_ERROR,
			FAILED_TO_DIRECT_CONNECTION,
			CARD_HAS_LOCKED_BY_ANOTHER_PROGRAM,
			READER_NOT_FOUND,
			INVALID_READER_NAME,
		};

		PCSCFatalException(const char *Message, int errorcode, LONG ret)
			: Errinfo(), runtime_error(Message)
		{
			Errinfo.errorcode = errorcode;
			Errinfo.ret = ret;
		}

		int errorcode()
		{
			return Errinfo.errorcode;
		}
		LONG returncode()
		{
			return Errinfo.ret;
		}
	private:
		struct PCSCFatalError_struct
		{
			int errorcode;
			LONG ret;
		};

		PCSCFatalError_struct Errinfo;
	};

	//Felicaカード側エラー．
	//書き込み禁止領域に書き込もうとしたり，認証しないで要認証領域に書き込もうとした場合など．
	//基本的にプログラムミス．SonyのFelica仕様書をよく読むこと．
	//エラーメッセージに詳細情報が書かれている
	class FelicaErrorException : public std::runtime_error
	{
	public:
		FelicaErrorException(const char *Message, uint8_t High, uint8_t Low)
			: Errinfo(), runtime_error(Message)
		{
			Errinfo.High = High;
			Errinfo.Low = Low;
		}

		uint8_t high()
		{
			return Errinfo.High;
		}
		uint8_t low()
		{
			return Errinfo.Low;
		}
	private:
		struct PCSCError_struct
		{
			uint8_t High;
			uint8_t Low;
		};
		PCSCError_struct Errinfo;
	};

	//Felicaカード状態異常
	//1次発行されているカードに対して発行関係の処理をしようとしたなど
	class FelicaFatalException : public std::runtime_error
	{
	public:
		enum
		{
			ALREADY_FIRST_ISSUED,
			CARD_IS_NOT_FELICA_LITE,
			INVALID_RESPONSE,
			WCNT_CLIP
		};

		FelicaFatalException(const char *Message, int errorcode)
			: Errinfo(errorcode), runtime_error(Message)
		{}

		int errorcode()
		{
			return Errinfo;
		}
	private:
		int Errinfo;
	};

	//---------------------------------------


	class PCSCFelicaLite
	{
	private:
		SCARDCONTEXT hContext = NULL;
		LPSTR       lpszReaderName = NULL;
		DWORD        readerNameListSize = 0;
		SCARDHANDLE  hCard = NULL;
		SCARD_READERSTATEA readerState;

		string InstanceName = "PCSCFelicaLite";
		uint16_t cardSystemcode = SYSTEMCODE_ANY;
		uint8_t cardTypecode = CARD_TYPE_UNKNOWN;

		vector<string> ReaderNameList;
		string activeReaderName = "";

		bool debugFlag = false;
		void debugInfo2(const char *funcname, const char *fmt, ...)
		{
			if ( debugFlag == false )
			{
				return;
			}
			printf("[%s.%s]", InstanceName.c_str(),funcname);
			va_list va;
			va_start(va, fmt);
			vprintf(fmt, va);
			va_end(va);
		}

	public:
		enum
		{
			ESC_CMD_GET_INFO = 0xC0, //バージョンなど各種情報の取得
			ESC_CMD_SET_OPTION = 0xC1, //情報の設定
			ESC_CMD_TARGET_COMM = 0xC4, //ターゲット通信
			ESC_CMD_SNEP = 0xC6, //SNEP通信
			ESC_CMD_APDU_WRAP = 0xFF, //PC / SC 2.02のAPDU用ラッパ

									  //ESC_CMD_GET_INFO
			DRIVER_VERSION = 0x01, //ドライババージョン(AA.BB.CC.DD)
			FW_VERSION = 0x02,
			VENDOR_ID = 0x04,
			VENDOR_NAME = 0x05,
			PRODUCT_ID = 0x06,
			PRODUCT_NAME = 0x07,
			PRODUCT_SERIAL_NUMBER = 0x08,
			CAPTURED_CARD_ID = 0x10, //0=UNCAPTURED, FF=Unknown
			NFC_DEP_ATR_REG_GENERAL_BYYES = 0x12,

			//----------APDU------------
			APDU_CLA_GENERIC = 0xFF,

			APDU_INS_GET_DATA = 0xCA,
			APDU_INS_READ_BINARY = 0xB0,
			APDU_INS_UPDATE_BINARY = 0xD6,
			APDU_INS_DATA_EXCHANGE = 0xFE,
			APDU_INS_SELECT_FILE = 0xA4,

			APDU_P2_NONE = 0x00,

			//----APDU_INS_GET_DATA----
			APDU_P1_GET_UID = 0x00,
			APDU_P1_GET_PMm = 0x01,
			APDU_P1_GET_CARD_ID = 0xF0,
			APDU_P1_GET_CARD_NAME = 0xF1,
			APDU_P1_GET_CARD_SPEED = 0xF2,
			APDU_P1_GET_CARD_TYPE = 0xF3,
			APDU_P1_GET_CARD_TYPE_NAME = 0xF4,
			APDU_P1_NFC_DEP_TARGET_STATE = 0xF9,

			APDU_LE_MAX_LENGTH = 0x00,

			UID_SIZE_ISO14443B = 4,
			UID_SIZE_PICOPASS = 8,
			UID_SIZE_NFCTYPE1 = 7,
			UID_SIZE_FELICA = 8,

			CARD_SPEED_106KBPS = 0x01,
			CARD_SPEED_212KBPS = 0x02,
			CARD_SPEED_424KBPS = 0x03,
			CARD_SPEED_848KBPS = 0x04,

			CARD_TYPE_UNKNOWN = 0x00,
			CARD_TYPE_ISO14443A = 0x01,
			CARD_TYPE_ISO14443B = 0x02,
			CARD_TYPE_PICOPASSB = 0x03,
			CARD_TYPE_FELICA = 0x04,
			CARD_TYPE_NFC_TYPE_1 = 0x05,
			CARD_TYPE_MIFARE_EC = 0x06,
			CARD_TYPE_ISO14443A_4A = 0x07,
			CARD_TYPE_ISO14443B_4B = 0x08,
			CARD_TYPE_TYPE_A_NFC_DEP = 0x09,
			CARD_TYPE_FELICA_NFC_DEP = 0x0A,

			//APDU_INS_READ_BINARY
			USE_BLOCKLIST = 0x80,
			NO_RFU = 0,

			//----------APDU_INS_DATA_EXCHANGE-----
			APDU_P1_THRU = 0x00,
			APDU_P1_DIRECT = 0x01,
			APDU_P1_NFC_DEP = 0x02,
			APDU_P1_DESELECT = 0xFD,
			APDU_P1_RELEASE = 0xFE,

			APDU_P2_TIMEOUT_AUTO = 0x00,
			APDU_P2_TIMEOUT_50MS = 0x05,
			APDU_P2_TIMEOUT_INFINITY = 0xFF,

			EXCHANGE_POLLING_PACKET_SIZE = 5,
			EXCHANGE_POLLING = 0x00,
			POLLING_REQUEST_SYSTEM_CODE = 0x01,
			POLLING_TIMESLOT_16 = 0x0F,

			//---------NDEF-----------
			NDEF_HTTP_WWW = 0x01,
			NDEF_HTTPS_WWW = 0x02,
			NDEF_HTTP = 0x03,
			NDEF_HTTPS = 0x04,

			//--------Felica-----
			SYSTEMCODE_ANY = 0xFFFF,
			SYSTEMCODE_FELICALITE = 0x88B4,
			SYSTEMCODE_NFC_TYPE3 = 0x12FC,

			ADDRESS_SPAD0 = 0x00,
			ADDRESS_SPAD1 = 0x01,
			ADDRESS_SPAD2 = 0x02,
			ADDRESS_SPAD3 = 0x03,
			ADDRESS_SPAD4 = 0x04,
			ADDRESS_SPAD5 = 0x05,
			ADDRESS_SPAD6 = 0x06,
			ADDRESS_SPAD7 = 0x07,
			ADDRESS_SPAD8 = 0x08,
			ADDRESS_SPAD9 = 0x09,
			ADDRESS_SPAD10 = 0x0A,
			ADDRESS_SPAD11 = 0x0B,
			ADDRESS_SPAD12 = 0x0C,
			ADDRESS_SPAD13 = 0x0D,
			ADDRESS_RC = 0x80,
			ADDRESS_MAC = 0x81,
			ADDRESS_ID = 0x82,
			ADDRESS_D_ID = 0x83,
			ADDRESS_SER_C = 0x84,
			ADDRESS_SYS_C = 0x85,
			ADDRESS_CKV = 0x86,
			ADDRESS_CK = 0x87,
			ADDRESS_MC = 0x88,
			ADDRESS_WCNT = 0x90,
			ADDRESS_MAC_A = 0x91,
			ADDRESS_STATE = 0x92,
			ADDRESS_CRC = 0xA0,
		};

		PCSCFelicaLite()
		{
			debugFlag = false;
			debugInfo2(__func__, " PCSCFelicaLite()\n");
		}

		PCSCFelicaLite(bool debug)
		{
			debugFlag = debug;
			debugInfo2(__func__, " PCSCFelicaLite(bool debug)\n");
		}

		PCSCFelicaLite(bool debug, string name)
		{
			debugFlag = debug;
			InstanceName = name;
			debugInfo2(__func__, " PCSCFelicaLite(bool debug,string name)\n");
		}

		~PCSCFelicaLite()
		{
			//自動クローズ
			debugInfo2(__func__, " デコンストラクタ\n");
			disconnectCard();
			closeService();
		}

		SCARDHANDLE getCardHandle()
		{
			return hCard;
		}
		SCARDCONTEXT getCardContext()
		{
			return hContext;
		}

		vector<string> getReaderNameList()
		{
			return ReaderNameList;
		}
		string getActiveReaderName()
		{
			return activeReaderName;
		}
		void setActiveReaderName(string s)
		{
			activeReaderName = s;
			debugInfo2(__func__, " %sを使用します\n", activeReaderName.c_str());
		}

		void setDebug(bool mode)
		{
			debugFlag = mode;
		}

		void setInstanceName(string name){
			InstanceName = name;
		}

		void checkReadyContext()
		{
			if ( hContext == NULL )
			{
				//				throw PCSCFatalException("スマートカードリソースマネージャにまだ接続していない", PCSCFatalException::NOT_CONNECTED_TO_SERVICE, 0);
				throw PCSCIllegalStateException("スマートカードリソースマネージャにまだ接続していない");
			}
		}

		void checkReadyCard()
		{
			if ( hContext == NULL )
			{
				//				throw PCSCFatalException("スマートカードリソースマネージャにまだ接続していない", PCSCFatalException::NOT_CONNECTED_TO_SERVICE, 0);
				throw PCSCIllegalStateException("スマートカードリソースマネージャにまだ接続していない");
			}
			if ( hCard == NULL )
			{
				//				throw PCSCFatalException("カードにまだ接続していない", PCSCFatalException::NOT_CONNECTED_TO_CARD, 0);
				throw PCSCIllegalStateException("カードにまだ接続していない");
			}
		}


		//------PC/SC処理------

		//接続・切断・カードの検出までを自動で行う．
		//カードへ接続できればtrue，カードが存在しなければfalse，カードリーダー環境などに問題があれば例外
		bool autoConnectToFelica(uint32_t timeout=0)
		{
			debugInfo2(__func__, "カードへの自動接続開始\n");
			//コンテキストがなければ自動でサービスを開く
			if( hContext == NULL )
			{
				openService();
			}
			//探索前にカードリーダーを利用可能にしておく
			disconnectCard();

			if(timeout != 0)
			{
				waitForSetCard(timeout);
			}

			//カードを探索
			if( !isCardSet() )
			{
				debugInfo2(__func__, "カードが見つからない\n");
				return false;
			}

			disconnectCard();
			//カードリーダーへ接続

			try{
				connectDirect();
			}catch( PCSCFatalException e)
			{
				if( PCSCFatalException::CARD_HAS_LOCKED_BY_ANOTHER_PROGRAM )
				{
					Sleep(100); //解放待ち時間
					connectDirect();
				}else{
					throw e;
				}
			}

			//ポーリングに成功すればカードが存在，なければ失敗
			try{
				polling();
			}catch( PCSCCardRemovedException e){
				disconnectCard();
				debugInfo2(__func__, "カードが見つからない\n");
				return false;
			}catch ( FelicaFatalException e )
			{
				debugInfo2(__func__, "Felicaではないカードを検出した\n");
				return false;
			}
			disconnectCard();

			//カードが確実に存在するのでカードに接続．
			try
			{
				connectCard();
			} catch ( PCSCCardRemovedException e )
			{
				//接続処理中に外された
				disconnectCard();
				debugInfo2(__func__, "カードが見つからない\n");
				return false;
			}
			debugInfo2(__func__, "カードへの接続に成功\n");
			return true;
		}


		//スマートカードリソースマネージャへの接続と，カードリーダーの取得
		void openService()
		{
			LONG res;

			closeService();//多重呼び出し対策

						   //---サービスに接続---
			res = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
			if ( res != SCARD_S_SUCCESS )
			{
				hContext = NULL;
				debugInfo2(__func__, " スマートカードリソースマネージャへの接続失敗:%X\n", res);
				throw PCSCFatalException("スマートカードリソースマネージャへの接続に失敗", PCSCFatalException::FAILD_TO_ESTABLISH, res);
			}
			debugInfo2(__func__, " スマートカードリソースマネージャへの接続に成功\n");

			//---カードリーダーリストの取得---
			DWORD dwAutoAllocate = SCARD_AUTOALLOCATE;
			res = SCardListReadersA(hContext, NULL, (LPSTR)&lpszReaderName, &dwAutoAllocate);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_E_NO_READERS_AVAILABLE )
				{
					debugInfo2(__func__, " カードリーダが接続されていません。\n");
					throw PCSCFatalException("カードリーダが接続されていません。", PCSCFatalException::NO_READERS_AVAILABLE, res);
				} else
				{
					debugInfo2(__func__, " エラーによりカードリーダの検出に失敗:%X\n", res);
					throw PCSCFatalException("エラーによりカードリーダの検出に失敗", PCSCFatalException::FAILED_TO_DETECT_READER, res);
				}
			}
			readerNameListSize = dwAutoAllocate;

			//---カードリーダー名を抽出しvectorに変換---
			vector<char> buf;
			ReaderNameList.clear();
			for ( unsigned int i = 0; i < (readerNameListSize - 1); i++ )
			{
				buf.push_back(lpszReaderName[i]);
				if ( lpszReaderName[i] == '\0' )
				{
					//文字列に変換して投入
					ReaderNameList.push_back(string(buf.begin(), buf.end()));
					buf.clear();
				}
			}

			//カードリーダー名はもはや不要
			SCardFreeMemory(hContext, lpszReaderName);
			lpszReaderName = NULL;

			//表示
			if ( debugFlag )
			{
				debugInfo2(__func__, " カードリーダー名リスト\n");
				int i = 0;
				for ( string name : ReaderNameList )
				{
					debugInfo2(__func__, "[%d] %s\n", i, name.c_str());
					i++;
				}
			}


			//カードリーダー名の検索
			activeReaderName = "";
			for ( string name : ReaderNameList )
			{
				if ( name.find("FeliCa") != string::npos )
				{
					activeReaderName = name;
				}
			}

			if ( activeReaderName == "" )
			{
				debugInfo2(__func__, " 利用できるカードリーダ名が見つかりませんでした\n");
				throw PCSCFatalException("利用できるカードリーダ名が見つかりませんでした", PCSCFatalException::READER_NOT_FOUND, res);
			}
			debugInfo2(__func__, " %sを使用します\n", activeReaderName.c_str());
		}

		//スマートカードリソースマネージャからの切断
		void closeService()
		{
			//カードに接続していたら切断する
			disconnectCard();

			//解放
			if ( hContext != NULL )
			{
				SCardReleaseContext(hContext);
				debugInfo2(__func__, " スマートカードリソースマネージャを解放\n");
			}

			hContext = NULL;

		}

		//現在の状態を取得する(特に指定しなければ現在の状態を取得して即戻る)
		bool isCardSet(uint32_t state = SCARD_STATE_UNAWARE, uint32_t timeout = 0)
		{
			checkReadyContext(); //コンテキストが利用可能可チェック(ダメなら例外)

			readerState.szReader = (LPCSTR)activeReaderName.c_str();//lpszReaderName;
			readerState.dwCurrentState = (DWORD)state;


			if ( timeout == INFINITE )
				debugInfo2(__func__, " 状態の取得を開始(timeout=無限に待機)\n");
			else if ( timeout == 0 )
				;
			else
				debugInfo2(__func__, " 状態の取得を開始(timeout=%dms)\n", timeout);

			LONG res = SCardGetStatusChangeA(hContext, (DWORD)timeout, &readerState, 1);
			if ( res == SCARD_E_TIMEOUT )
			{
				debugInfo2(__func__, " 読み取りタイムアウト\n");
				return false;
			}

			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_E_UNKNOWN_READER )
				{
					debugInfo2(__func__, " カードリーダー名が不正:%X\n", res);
					throw PCSCFatalException("カードリーダー名が不正", PCSCFatalException::INVALID_READER_NAME, res);
				}
				debugInfo2(__func__, " カード状態の取得に失敗:%X\n", res);
				throw PCSCFatalException("カード状態の取得に失敗", PCSCFatalException::FAILED_TO_GET_CARD_STATUS, res);
			}

			//状態を更新．
			readerState.dwCurrentState = readerState.dwEventState;

			if ( readerState.dwEventState & SCARD_STATE_UNAVAILABLE )
			{
				debugInfo2(__func__, " カードリーダーが接続されていないか利用不能\n");
				throw PCSCFatalException("カードリーダーが接続されていないか利用不能", PCSCFatalException::READER_DISCONNECTED, readerState.dwEventState);
			}

			if ( readerState.dwEventState & SCARD_STATE_EMPTY )
			{
				debugInfo2(__func__, " カードがセットされていない\n");
				return false;
			}

			if ( readerState.dwEventState & SCARD_STATE_INUSE && (hCard == NULL) ) //自分が使ってるときはそりゃ使用中
			{
				debugInfo2(__func__, " カードは他のアプリケーションに使用されています\n");
				return false;
			}

			if ( !(readerState.dwEventState & SCARD_STATE_PRESENT) )
			{
				debugInfo2(__func__, " 不明な状態\n");
				throw PCSCFatalException("不明な状態", PCSCFatalException::UNKNOWN_STATUS, readerState.dwEventState);
			}
/*
			//直接pollingする場合，カードがセットされていないのにセットされているようにみえることがある対策
			if ( (hCard != NULL) && (isFelica()) ) //接続中でかつFelicaなら
			{
				debugInfo2(__func__, " システムコードスキャンを試行\n");
				try
				{
					cardSystemcode = readSystemcode();
				} catch ( PCSCFatalException e )
				{
					//失敗したならばカードがない
					debugInfo2(__func__, " カードが取り外された\n");
					Sleep(2000);//高速
					return false;
				}
			}
*/
			debugInfo2(__func__, " カードがセットされています %X\n", readerState.dwEventState);
			return true;
		}

		uint32_t getCurrentState()
		{
			return readerState.dwCurrentState;
		}

		//カードがセットされるまで指定時間待つ．INFINYTEをセットすると無限に待つ
		bool waitForSetCard(uint32_t timeout=INFINITE)
		{
			checkReadyContext(); //コンテキストが利用可能可チェック(ダメなら例外)

								 //すでにカードがセットされているかをチェック．同時に現在の状態を更新
			if ( isCardSet() )
			{
				return true;
			}

			debugInfo2(__func__, " カードがセットされるまで待ちます\n");
			//状態変化するまで永遠に待機
			return isCardSet(readerState.dwCurrentState, timeout);
		}

		//かざされているカードに接続する
		void connectCard(bool exclusive = true)
		{
			checkReadyContext(); //コンテキストが利用可能可チェック(ダメなら例外)
			disconnectCard(); //多重接続防止の為切断しておく

			DWORD dwActiveProtocol;
			//カードを共有しない

			DWORD dwShareMode = SCARD_SHARE_SHARED;
			if ( exclusive )
			{
				dwShareMode = SCARD_SHARE_EXCLUSIVE;
			}

			//lpszReaderName;
			LONG res = SCardConnectA(hContext, activeReaderName.c_str(), dwShareMode, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " カードがセットされていません\n");
					throw PCSCCardRemovedException("カードがセットされていません");
				} else if ( res == SCARD_E_SHARING_VIOLATION )
				{
					debugInfo2(__func__, " 他のアプリケーションがカードを排他的に使用中です\n");
					throw PCSCFatalException("他のアプリケーションがカードを排他的に使用中です", PCSCFatalException::CARD_HAS_LOCKED_BY_ANOTHER_PROGRAM, res);
				} else
				{
					debugInfo2(__func__, " 不明なエラー\n");
					throw PCSCFatalException("不明なエラー", PCSCFatalException::UNKNOWN_ERROR, res);
				}
			}

			//システムコードの取得は副作用が多いので最初に取得してしまう．
			cardTypecode = CARD_TYPE_UNKNOWN;////初期化
			cardSystemcode = SYSTEMCODE_ANY; //初期化

			cardTypecode = readCardTypeCode();
			if( cardTypecode == CARD_TYPE_FELICA ) //Felicaじゃないもの取得できん
			{
				cardSystemcode = readSystemcode();
			}
			debugInfo2(__func__, " カードに接続しました(カード種別:%02X, システムコード:%04X)\n", cardTypecode, cardSystemcode);
		}

		//カードの存在にかかわらずカードリーダーに直接接続する
		void connectDirect()
		{
			checkReadyContext(); //コンテキストが利用可能可チェック(ダメなら例外)
			disconnectCard(); //多重接続防止の為切断しておく

			DWORD dwActiveProtocol;
			LONG res = SCardConnectA(hContext, activeReaderName.c_str(), SCARD_SHARE_DIRECT, 0, &hCard, &dwActiveProtocol);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_E_SHARING_VIOLATION )
				{
					debugInfo2(__func__, " 他のアプリケーションがカードを排他的に使用中です\n");
					throw PCSCFatalException("他のアプリケーションがカードを排他的に使用中です", PCSCFatalException::CARD_HAS_LOCKED_BY_ANOTHER_PROGRAM, res);
				}
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " 直接接続に失敗\n");
					throw PCSCFatalException("直接接続に失敗", PCSCFatalException::FAILED_TO_DIRECT_CONNECTION, res);
				} else
				{
					debugInfo2(__func__, " 不明なエラー\n");
					throw PCSCFatalException("不明なエラー", PCSCFatalException::UNKNOWN_ERROR, res);
				}
			}
			debugInfo2(__func__, " 直接接続しました\n");
		}

		//カードから切断する
		void disconnectCard()
		{
			if ( hCard != NULL )
			{
				debugInfo2(__func__, " 接続を切断しました\n");
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
			}
			hCard = NULL;
		}

		//カードから情報を読み取る
		void readBinary(uint16_t adr, uint8_t dat[16])
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE DataSize = 3; //後続のデータ数(Le含めず)
			BYTE BlockNum = 1;

			BYTE BlockList[3] = {0};
			BlockList[0] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[1] = (adr)& 0xFF;
			BlockList[2] = (adr >> 8) & 0xFF;

			BYTE Le = 16 * BlockNum;

			BYTE pbSendBuffer[256] = {APDU_CLA_GENERIC,APDU_INS_READ_BINARY,USE_BLOCKLIST | NO_RFU,BlockNum};

			BYTE pbRecvBuffer[256] = {0};
			DWORD pcbRecvLength = 256;

			//データ生成
			int i = 0;
			for ( i = 0; i<DataSize; i++ )
			{
				pbSendBuffer[5 + i] = BlockList[i];
			}
			pbSendBuffer[4] = i; //データリストサイズを書き込む
			pbSendBuffer[5 + i] = Le; //最後に受信するブロックサイズを書き込む
			int bufsize = i + 6;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, bufsize, NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res == SCARD_W_REMOVED_CARD )
			{
				debugInfo2(__func__, " カードが取り外されました．\n");
				throw PCSCCardRemovedException("カードが取り外されました．");
			}

			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];
			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				debugInfo2(__func__, " アドレス:%04X カードはエラー応答しました．SW1=%02X,SW2=%02X\n", adr, SW1, SW2);
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( SW1 == 0x91 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " Felicaカード側処理エラーです．コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
					debugInfo2(__func__, " %s\n", FellicaErrorInfo(pbRecvBuffer[1]));
					throw FelicaErrorException(FellicaErrorInfo(pbRecvBuffer[1]), pbRecvBuffer[0], pbRecvBuffer[1]);
				}

				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}
			if ( pcbRecvLength != (16 + 2) )
			{
				debugInfo2(__func__, " 応答サイズ異常 %d\n", pcbRecvLength);
				throw FelicaFatalException("応答サイズ異常", FelicaFatalException::INVALID_RESPONSE);
			}

			//データコピー
			for ( DWORD i = 0; i < pcbRecvLength - 2; i++ )
			{
				if ( i < 16 )
					dat[i] = pbRecvBuffer[i];
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " アドレス:%04X 読み込み完了\n", adr);
				debugInfo2(__func__, " 内容:");
				for ( DWORD i = 0; i < pcbRecvLength - 2; i++ )
				{
					printf("%02X,", pbRecvBuffer[i]);
				}
				printf("\n");
			}
		}

		//カードからMAC付きで情報を読み取る
		void readBinaryWithMAC(uint16_t adr, uint8_t dat[16], uint8_t mac[16])
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE DataSize = 6; //後続のデータ数(Le含めず)
			BYTE BlockNum = 2;

			BYTE BlockList[6] = {0};
			BlockList[0] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[1] = (adr)& 0xFF;
			BlockList[2] = (adr >> 8) & 0xFF;
			BlockList[3] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[4] = ADDRESS_MAC;//MAC
			BlockList[5] = 0x00;

			BYTE Le = 16 * BlockNum;

			BYTE pbSendBuffer[256] = {APDU_CLA_GENERIC,APDU_INS_READ_BINARY,USE_BLOCKLIST | NO_RFU,BlockNum};

			BYTE pbRecvBuffer[256] = {0};
			DWORD pcbRecvLength = 256;

			//データ生成
			int i = 0;
			for ( i = 0; i<DataSize; i++ )
			{
				pbSendBuffer[5 + i] = BlockList[i];
			}
			pbSendBuffer[4] = i; //データリストサイズを書き込む
			pbSendBuffer[5 + i] = Le; //最後に受信するブロックサイズを書き込む
			int bufsize = i + 6;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, bufsize, NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res == SCARD_W_REMOVED_CARD )
			{
				debugInfo2(__func__, " カードが取り外されました．\n");
				throw PCSCCardRemovedException("カードが取り外されました．");
			}

			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];
			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				debugInfo2(__func__, " アドレス:%04X カードはエラー応答しました．SW1=%02X,SW2=%02X\n", adr, SW1, SW2);
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( SW1 == 0x91 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " Felicaカード側処理エラーです．コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
					debugInfo2(__func__, " %s\n", FellicaErrorInfo(pbRecvBuffer[1]));
					throw FelicaErrorException(FellicaErrorInfo(pbRecvBuffer[1]), pbRecvBuffer[0], pbRecvBuffer[1]);
				}

				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if( pcbRecvLength != (32 + 2))
			{
				debugInfo2(__func__, " 応答サイズ異常 %d\n", pcbRecvLength);
				throw FelicaFatalException("応答サイズ異常", FelicaFatalException::INVALID_RESPONSE);
			}

			//データコピー
			for ( DWORD i = 0; i < pcbRecvLength - 2; i++ )
			{
				if ( i < 16 )
				{
					dat[i] = pbRecvBuffer[i];
					mac[i] = pbRecvBuffer[i+16];
				}
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " アドレス:%04X 読み込み完了\n", adr);
				debugInfo2(__func__, " 内容:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", dat[i]);
				}
				printf("\n");
				debugInfo2(__func__, " MAC:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", mac[i]);
				}
				printf("\n");
			}
		}

		//カードからMAC_A付きで情報を読み取る
		void readBinaryWithMAC_A(uint16_t adr, uint8_t dat[16], uint8_t mac[16])
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE DataSize = 6; //後続のデータ数(Le含めず)
			BYTE BlockNum = 2;

			BYTE BlockList[6] = {0};
			BlockList[0] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[1] = (adr)& 0xFF;
			BlockList[2] = (adr >> 8) & 0xFF;
			BlockList[3] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[4] = ADDRESS_MAC_A;//MAC_A
			BlockList[5] = 0x00;

			BYTE Le = 16 * BlockNum;

			BYTE pbSendBuffer[256] = {APDU_CLA_GENERIC,APDU_INS_READ_BINARY,USE_BLOCKLIST | NO_RFU,BlockNum};

			BYTE pbRecvBuffer[256] = {0};
			DWORD pcbRecvLength = 256;

			//データ生成
			int i = 0;
			for ( i = 0; i<DataSize; i++ )
			{
				pbSendBuffer[5 + i] = BlockList[i];
			}
			pbSendBuffer[4] = i; //データリストサイズを書き込む
			pbSendBuffer[5 + i] = Le; //最後に受信するブロックサイズを書き込む
			int bufsize = i + 6;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, bufsize, NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res == SCARD_W_REMOVED_CARD )
			{
				debugInfo2(__func__, " カードが取り外されました．\n");
				throw PCSCCardRemovedException("カードが取り外されました．");
			}

			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];
			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				debugInfo2(__func__, " アドレス:%04X カードはエラー応答しました．SW1=%02X,SW2=%02X\n", adr, SW1, SW2);
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( SW1 == 0x91 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " Felicaカード側処理エラーです．コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
					debugInfo2(__func__, " %s\n", FellicaErrorInfo(pbRecvBuffer[1]));
					throw FelicaErrorException(FellicaErrorInfo(pbRecvBuffer[1]), pbRecvBuffer[0], pbRecvBuffer[1]);
				}

				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if ( pcbRecvLength != (32 + 2) )
			{
				debugInfo2(__func__, " 応答サイズ異常 %d\n", pcbRecvLength);
				throw FelicaFatalException("応答サイズ異常", FelicaFatalException::INVALID_RESPONSE);
			}

			//データコピー
			for ( DWORD i = 0; i < pcbRecvLength - 2; i++ )
			{
				if ( i < 16 )
				{
					dat[i] = pbRecvBuffer[i];
					mac[i] = pbRecvBuffer[i + 16];
				}
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " アドレス:%04X 読み込み完了\n", adr);
				debugInfo2(__func__, " 内容:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", dat[i]);
				}
				printf("\n");
				debugInfo2(__func__, " MAC:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", mac[i]);
				}
				printf("\n");
			}
		}

		//カードへの書き込み
		void updateBinary(uint16_t adr, uint8_t dat[16])
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE DataSize = 3; //後続のデータ数(Le含めず)
			BYTE BlockNum = 1;

			BYTE BlockList[3] = {0};
			BlockList[0] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[1] = (adr)& 0xFF;
			BlockList[2] = (adr >> 8) & 0xFF;

			BYTE Le = 0;

			BYTE pbSendBuffer[256] = {APDU_CLA_GENERIC,APDU_INS_UPDATE_BINARY,USE_BLOCKLIST | NO_RFU,BlockNum};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//データ生成
			int i, j;
			for ( i = 0; i<DataSize; i++ )
			{
				pbSendBuffer[5 + i] = BlockList[i];
			}
			for ( j = 0; j<16; j++ )
			{
				pbSendBuffer[5 + i + j] = dat[j];
			}
			pbSendBuffer[4] = i + j; //データサイズを書き込む
			pbSendBuffer[5 + i + j] = Le; //最後に受信するブロックサイズを書き込む
			DWORD bufsize = i + j + 6;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res == SCARD_W_REMOVED_CARD )
			{
				debugInfo2(__func__, " カードが取り外されました．\n");
				throw PCSCCardRemovedException("カードが取り外されました．");
			}

			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException(" カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				debugInfo2(__func__, " アドレス:%04X カードはエラー応答しました．SW1=%02X,SW2=%02X\n", adr, SW1, SW2);
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}

				if ( SW1 == 0x91 && SW2 == 0x00 )
				{
					if( pbRecvBuffer[0]==0xFF && pbRecvBuffer[1]==0x71)
					{
						debugInfo2(__func__, " Felicaカード側処理警告です(メモリ寿命近し)コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
					}else{
						debugInfo2(__func__, " Felicaカード側処理エラーです．コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
						debugInfo2(__func__, " %s\n", FellicaErrorInfo(pbRecvBuffer[1]));
						throw FelicaErrorException(FellicaErrorInfo(pbRecvBuffer[1]), pbRecvBuffer[0], pbRecvBuffer[1]);
					}
				}

				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);

			}
			if ( debugFlag )
			{
				debugInfo2(__func__, "  アドレス:%04X 書き込み成功\n", adr);
				debugInfo2(__func__, " 内容:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", dat[i]);
				}
				printf("\n");
			}
		}
		//カードへの書き込み
		void updateBinaryWithMAC_A(uint16_t adr, uint8_t dat[16], uint8_t mac[16])
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE DataSize = 6; //後続のデータ数(Le含めず)
			BYTE BlockNum = 2;

			BYTE BlockList[6] = {0};
			BlockList[0] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[1] = (adr)& 0xFF;
			BlockList[2] = (adr >> 8) & 0xFF;
			BlockList[3] = 0; //0x00 : [長さ(1=1byte,0=2byte:1bit] [アクセスモード:3bit] [SERVICEコードリスト順番:4bit]
			BlockList[4] = ADDRESS_MAC_A;//MAC_A
			BlockList[5] = 0x00;

			BYTE Le = 0;

			BYTE pbSendBuffer[256] = {APDU_CLA_GENERIC,APDU_INS_UPDATE_BINARY,USE_BLOCKLIST | NO_RFU,BlockNum};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//データ生成
			int i, j, k;
			for ( i = 0; i<DataSize; i++ )
			{
				pbSendBuffer[5 + i] = BlockList[i];
			}
			for ( j = 0; j<16; j++ )
			{
				pbSendBuffer[5 + i + j] = dat[j];
			}
			for ( k = 0; k<16; k++ )
			{
				pbSendBuffer[5 + i + j + k] = mac[k];
			}
			pbSendBuffer[4] = i + j + k; //データサイズを書き込む
			pbSendBuffer[5 + i + j + k] = Le; //最後に受信するブロックサイズを書き込む
			DWORD bufsize = i + j + k + 6;


			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res == SCARD_W_REMOVED_CARD )
			{
				debugInfo2(__func__, " カードが取り外されました．\n");
				throw PCSCCardRemovedException("カードが取り外されました．");
			}

			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException(" カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				debugInfo2(__func__, " アドレス:%04X カードはエラー応答しました．SW1=%02X,SW2=%02X\n", adr, SW1, SW2);
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}

				if ( SW1 == 0x91 && SW2 == 0x00 )
				{
					if ( pbRecvBuffer[0] == 0xFF && pbRecvBuffer[1] == 0x71 )
					{
						debugInfo2(__func__, " Felicaカード側処理警告です(メモリ寿命近し)コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
					} else
					{
						debugInfo2(__func__, " Felicaカード側処理エラーです．コード:%02X,%02X\n", pbRecvBuffer[0], pbRecvBuffer[1]);
						debugInfo2(__func__, " %s\n", FellicaErrorInfo(pbRecvBuffer[1]));
						throw FelicaErrorException(FellicaErrorInfo(pbRecvBuffer[1]), pbRecvBuffer[0], pbRecvBuffer[1]);
					}
				}

				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);

			}
			if ( debugFlag )
			{
				debugInfo2(__func__, "  アドレス:%04X 書き込み成功\n", adr);
				debugInfo2(__func__, " 内容:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", dat[i]);
				}
				printf("\n");
				debugInfo2(__func__, " MAC:");
				for ( DWORD i = 0; i < 16; i++ )
				{
					printf("%02X,", mac[i]);
				}
				printf("\n");
			}

		}

		//------Felica Lite関係処理------

		//PaSoRiのシリアルナンバーを取得(カードか，あるいは直接接続する必要あり)
		void getPaSoRiSerialNumber(char *serialNumberString = NULL)
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE lpInBuffer[] = {ESC_CMD_GET_INFO,PRODUCT_SERIAL_NUMBER};
			BYTE lpOutBuffer[256];
			DWORD lpBytesReturned = 0;

			LONG res = SCardControl(hCard, SCARD_CTL_CODE(3500), lpInBuffer, sizeof(lpInBuffer), lpOutBuffer, sizeof(lpOutBuffer), &lpBytesReturned);
			if ( res != SCARD_S_SUCCESS )
			{
				debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//Debug用
			if ( serialNumberString != NULL )
			{
				for ( int i = 0; i < 256; i++ )
					serialNumberString[i] = lpOutBuffer[i];
			}

			debugInfo2(__func__, " カードリーダーシリアルナンバー:%s\n", lpOutBuffer);
		}

		//カードのIDmを取得
		uint32_t readUID(uint8_t UID[] = NULL)
		{
			checkReadyCard(); //カードが利用可能可チェック

							  //CLA,INS,P1,P2,Le
			BYTE pbSendBuffer[5] = {APDU_CLA_GENERIC, APDU_INS_GET_DATA, APDU_P1_GET_UID,APDU_P2_NONE,APDU_LE_MAX_LENGTH};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}

				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " UID:");
				for ( DWORD i = 0; i < pcbRecvLength - 2; i++ ) //最後の2バイトはレスポンス
				{
					printf("%02X", pbRecvBuffer[i]);
				}
				printf("\n");
			}

			if ( UID != NULL )
			{
				for ( DWORD i = 0; i < pcbRecvLength - 2; i++ ) //最後の2バイトはレスポンス
				{
					UID[i] = pbRecvBuffer[i];
				}
			}
			return (uint32_t)(pcbRecvLength - 2);
		}
		//カードのPMmを取得
		uint32_t readPMm(uint8_t PMm[] = NULL)
		{
			checkReadyCard(); //カードが利用可能可チェック

							  //CLA,INS,P1,P2,Le
			BYTE pbSendBuffer[5] = {APDU_CLA_GENERIC, APDU_INS_GET_DATA, APDU_P1_GET_PMm,APDU_P2_NONE,APDU_LE_MAX_LENGTH};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}

				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " PMm:");
				for ( DWORD i = 0; i < pcbRecvLength - 2; i++ ) //最後の2バイトはレスポンス
				{
					printf("%02X", pbRecvBuffer[i]);
				}
				printf("\n");
			}

			if ( PMm != NULL )
			{
				for ( DWORD i = 0; i < pcbRecvLength - 2; i++ ) //最後の2バイトはレスポンス
				{
					PMm[i] = pbRecvBuffer[i];
				}
			}
			return (uint32_t)(pcbRecvLength - 2);
		}
		//カードの種類を取得
		uint8_t getCardTypeCode()
		{
			return cardTypecode;
		}

		//カードの種類を取得
		uint8_t readCardTypeCode()
		{
			checkReadyCard(); //カードが利用可能可チェック

							  //CLA,INS,P1,P2,Le
			BYTE pbSendBuffer[5] = {APDU_CLA_GENERIC, APDU_INS_GET_DATA, APDU_P1_GET_CARD_TYPE,APDU_P2_NONE,APDU_LE_MAX_LENGTH};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}

				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}

				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}


			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}

				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " カード種別:%02X\n", pbRecvBuffer[0]);
				switch ( pbRecvBuffer[0] )
				{
					case CARD_TYPE_FELICA: debugInfo2(__func__, " このカードはFelicaです．\n"); break;
					case CARD_TYPE_ISO14443A: debugInfo2(__func__, " このカードはISO14443Aです．\n"); break;
					case CARD_TYPE_ISO14443B: debugInfo2(__func__, " このカードはISO14443Bです．\n"); break;
					case CARD_TYPE_PICOPASSB: debugInfo2(__func__, " このカードはPICOPASSBです．\n"); break;
					case CARD_TYPE_NFC_TYPE_1: debugInfo2(__func__, " このカードはNFC_TYPE_1です．\n"); break;
					case CARD_TYPE_MIFARE_EC: debugInfo2(__func__, " このカードはMIFARE_ECです．\n"); break;
					case CARD_TYPE_ISO14443A_4A: debugInfo2(__func__, " このカードはISO14443A_4Aです．\n"); break;
					case CARD_TYPE_ISO14443B_4B: debugInfo2(__func__, " このカードはISO14443B_4Bです．\n"); break;
					case CARD_TYPE_TYPE_A_NFC_DEP: debugInfo2(__func__, " このカードはTYPE_A_NFC_DEPです．\n"); break;
					case CARD_TYPE_FELICA_NFC_DEP: debugInfo2(__func__, " このカードはFELICA_NFC_DEPです．\n"); break;
					default: debugInfo2(__func__, " このカードの種類は不明です．\n"); break;
				}
			}

			return pbRecvBuffer[0];
		}


		bool isFelica()
		{
			return (getCardTypeCode() == CARD_TYPE_FELICA);
		}
		bool isFelicaLite()
		{
			if ( !isFelica() )
			{
				debugInfo2(__func__, " このカードはFelicaではない\n");
				return false;
			}

			if ( (getSystemcode() != SYSTEMCODE_NFC_TYPE3) && (getSystemcode() != SYSTEMCODE_FELICALITE) )
			{
				debugInfo2(__func__, " このカードはFelica Liteではない\n");
				return false;
			}
			debugInfo2(__func__, " このカードはFelica Lite系です\n");
			return true;
		}

		/*
		bool isFelicaLite()
		{
		if(getCardTypeCode() != CARD_TYPE_FELICA)
		{
		debugInfo2(__func__," このカードはFelicaではない(カード種別が違う)\n");
		return false;
		}

		uint8_t PMm[64]={0};
		uint32_t  size = readPMm(PMm);
		if(size != 8)
		{
		debugInfo2(__func__," このカードはFelicaではない(PMmが8byteではない)\n");
		return false;
		}

		if(PMm[1] < 0xF0)
		{
		debugInfo2(__func__," このカードはFelica Liteではない(StandardおよびモバイルFelicaなど)\n");
		return false;
		}

		switch( PMm[1] )
		{
		case 0xF0: debugInfo2(__func__," このカードはFelica Liteです．(RC-S965)\n");break;
		case 0xF1: debugInfo2(__func__," このカードはFelica Lite-Sです．(RC-S966)\n"); break;
		case 0xF2: debugInfo2(__func__," このカードはFelica Linkです．(RC-S967/Lite-S/Lite-S HT)\n"); break;
		case 0xE0: debugInfo2(__func__," このカードはFelica Plugです．(RC-S926)\n"); break;
		case 0xE1: debugInfo2(__func__," このカードはFelica Linkです．(RC-S967/Plug)\n"); break;
		case 0xFF: debugInfo2(__func__," このカードはNFC仕様のFelicaです．\n"); break;
		default :  debugInfo2(__func__," このカードはFelica Liteっぽいです．(不明)\n"); break;
		}
		return true;
		}

		bool isFelicaLiteS()
		{
		if ( getCardTypeCode() != CARD_TYPE_FELICA )
		{
		debugInfo2(__func__," このカードはFelicaではない(カード種別が違う)\n");
		return false;
		}

		uint8_t PMm[64] = {0};
		uint32_t  size = readPMm(PMm);
		if ( size != 8 )
		{
		debugInfo2(__func__," このカードはFelicaではない(PMmが8byteではない)\n");
		return false;
		}

		if ( PMm[1] < 0xF0 )
		{
		debugInfo2(__func__," このカードはFelica Liteではない(StandardおよびモバイルFelicaなど)\n");
		return false;
		}

		if(PMm[1] == 0xF1 )
		{
		debugInfo2(__func__," このカードはFelica Lite-Sです．(RC-S966)\n");
		return true;
		}else{
		debugInfo2(__func__," このカードはFelica LiteですがLite-Sではありません．\n");
		return false;
		}
		}
		*/
		void readCardTypeString(char *cardTypeString = NULL)
		{
			checkReadyCard(); //カードが利用可能可チェック

							  //CLA,INS,P1,P2,Le
			BYTE pbSendBuffer[5] = {APDU_CLA_GENERIC, APDU_INS_GET_DATA, APDU_P1_GET_CARD_TYPE_NAME,APDU_P2_NONE,APDU_LE_MAX_LENGTH};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			for ( DWORD i = 0; i<pcbRecvLength - 2; i++ ) //最後の2バイトはレスポンス
			{
				cardTypeString[i] = pbRecvBuffer[i];
			}

			if ( debugFlag )
			{
				debugInfo2(__func__, " カード種別名称:");
				for ( DWORD i = 0; i < pcbRecvLength - 2; i++ ) //最後の2バイトはレスポンス
				{
					printf("%c", pbRecvBuffer[i]);
				}
				printf("\n");
			}
		}

		//システムコードを取得する
		uint16_t getSystemcode()
		{
			return cardSystemcode;
		}

		//直接Pollingすることでシステムコードを取得する(IDmなども取得できているが)
		uint16_t readSystemcode(uint16_t scancode = SYSTEMCODE_ANY)
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE scancode_high = (scancode >> 8) & 0xFF;
			BYTE scancode_low = (scancode)& 0xFF;

			//CLA,INS,P1,P2,Le
			BYTE pbSendBuffer[10] = {APDU_CLA_GENERIC, APDU_INS_DATA_EXCHANGE, APDU_P1_THRU,APDU_P2_TIMEOUT_50MS,EXCHANGE_POLLING_PACKET_SIZE,EXCHANGE_POLLING,scancode_high,scancode_low,POLLING_REQUEST_SYSTEM_CODE,POLLING_TIMESLOT_16};

			BYTE pbRecvBuffer[256];
			DWORD pcbRecvLength = 256;

			//コマンド送信
			LONG res = SCardTransmit(hCard, SCARD_PCI_T1, pbSendBuffer, sizeof(pbSendBuffer), NULL, pbRecvBuffer, &pcbRecvLength);
			if ( res != SCARD_S_SUCCESS )
			{
				if ( res == SCARD_W_REMOVED_CARD )
				{
					debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
					throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
				}
				if ( res == 0x458 )
				{
					debugInfo2(__func__, " カードハンドルが無効になりました．\n");
					throw PCSCCardRemovedException("カードハンドルが無効になりました．");
				}
				if ( res == ERROR_BAD_COMMAND )
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です (直接接続していませんか？)%X\n", res);
				} else
				{
					debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				}
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = pbRecvBuffer[pcbRecvLength - 2];
			BYTE SW2 = pbRecvBuffer[pcbRecvLength - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					if ( scancode == SYSTEMCODE_ANY )
					{
						debugInfo2(__func__, " PC/SCコマンド発行中にカードが取り外されました．\n");
						throw PCSCCardRemovedException("PC/SCコマンド発行中にカードが取り外されました．");
					}

					debugInfo2(__func__, " 該当するシステムコードのカードは見つかりませんでした．(タイムアウト)\n");
					throw PCSCCardRemovedException("該当するシステムコードのカードは見つかりませんでした．(タイムアウト)");
				}
				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if ( pcbRecvLength - 2 != 19 || pbRecvBuffer[0] != 0x01 )
			{
				debugInfo2(__func__, " 期待される応答ではない．長さ%d (本来:19) 応答:%02X\n", pcbRecvLength - 2, pbRecvBuffer[0]);
				throw FelicaFatalException("期待される応答ではない", FelicaFatalException::INVALID_RESPONSE);
			}

			uint16_t systemcode = ((pbRecvBuffer[pcbRecvLength - 4] << 8) & 0xFF00) | (pbRecvBuffer[pcbRecvLength - 3] & 0xFF);
			debugInfo2(__func__, " システムコード:%04X\n", systemcode);

			return systemcode;
		}

		//直接PollingしてIDmとPMmとシステムコードを取得する(直接接続用)
		uint16_t polling(uint8_t UID[] = NULL, uint8_t PMm[] = NULL, uint16_t scancode = SYSTEMCODE_ANY)
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE scancode_high = (scancode >> 8) & 0xFF;
			BYTE scancode_low = (scancode)& 0xFF;

			BYTE timeout = 5;//x10ms


			BYTE lpInBuffer[10] = {ESC_CMD_APDU_WRAP, APDU_INS_DATA_EXCHANGE, APDU_P1_THRU,APDU_P2_TIMEOUT_50MS,EXCHANGE_POLLING_PACKET_SIZE,EXCHANGE_POLLING,scancode_high,scancode_low,POLLING_REQUEST_SYSTEM_CODE,POLLING_TIMESLOT_16};
			BYTE lpOutBuffer[256];
			DWORD lpBytesReturned = 0;

			LONG res = SCardControl(hCard, SCARD_CTL_CODE(3500), lpInBuffer, sizeof(lpInBuffer), lpOutBuffer, sizeof(lpOutBuffer), &lpBytesReturned);
			if ( res != SCARD_S_SUCCESS )
			{
				debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = lpOutBuffer[lpBytesReturned - 2];
			BYTE SW2 = lpOutBuffer[lpBytesReturned - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				if ( SW1 == 0x63 && SW2 == 0x00 )
				{
					debugInfo2(__func__, " 該当するシステムコードのカードは見つかりませんでした．(タイムアウト)\n");
					throw PCSCCardRemovedException("該当するシステムコードのカードは見つかりませんでした．(タイムアウト)");
				}
				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			if ( lpBytesReturned - 2 != 19 || lpOutBuffer[0] != 0x01 )
			{
				debugInfo2(__func__, " 期待される応答ではない．長さ%d (本来:19) 応答:%02X\n", lpBytesReturned - 2, lpOutBuffer[0]);
				throw FelicaFatalException("期待される応答ではない", FelicaFatalException::INVALID_RESPONSE);
			}

			if ( UID != NULL )
			{
				for ( DWORD i = 0; i < 8; i++ )
				{
					UID[i] = lpOutBuffer[i + 1];
				}
			}

			if ( PMm != NULL )
			{
				for ( DWORD i = 0; i <8; i++ )
				{
					PMm[i] = lpOutBuffer[i + 9];
				}
			}

			uint16_t systemcode = ((lpOutBuffer[lpBytesReturned - 4] << 8) & 0xFF00) | (lpOutBuffer[lpBytesReturned - 3] & 0xFF);

			if ( debugFlag )
			{
				debugInfo2(__func__, " IDm:");
				for ( DWORD i = 0; i < 8; i++ )
				{
					printf("%02X", lpOutBuffer[i + 1]);
				}
				printf("\n");
				debugInfo2(__func__, " PMm:");
				for ( DWORD i = 0; i < 8; i++ )
				{
					printf("%02X", lpOutBuffer[i + 9]);
				}
				printf("\n");
				debugInfo2(__func__, " システムコード:%04X\n", systemcode);
			}

			return systemcode;
		}

		//直接コマンドを投げる(ライブラリ開発用隠し関数)
		void sendControl()
		{
			checkReadyCard(); //カードが利用可能可チェック

			BYTE lpInBuffer[] = {0xFF,0x00,0x00,0x00,0x03,0xD4,0x12,0x34};
			BYTE lpOutBuffer[256];
			DWORD lpBytesReturned = 0;

			LONG res = SCardControl(hCard, SCARD_CTL_CODE(3500), lpInBuffer, sizeof(lpInBuffer), lpOutBuffer, sizeof(lpOutBuffer), &lpBytesReturned);
			if ( res != SCARD_S_SUCCESS )
			{
				debugInfo2(__func__, " コマンドに誤りがあるか不適切な状態です %X\n", res);
				throw PCSCCommandException("コマンドに誤りがあるか不適切な状態", res);
			}

			//レスポンス解析
			BYTE SW1 = lpOutBuffer[lpBytesReturned - 2];
			BYTE SW2 = lpOutBuffer[lpBytesReturned - 1];

			if ( SW1 != 0x90 || SW2 != 0x00 )
			{
				debugInfo2(__func__, " カードはエラー応答しました．SW1=%02X,SW2=%02X\n", SW1, SW2);
				throw PCSCErrorException("PC/SC カードエラー応答", SW1, SW2);
			}

			for ( DWORD i = 0; i < lpBytesReturned - 2; i++ ) //最後の2バイトはレスポンス
			{
				printf("%02X ", lpOutBuffer[i]);
			}
			printf("\n");

			return;
		}



		//NDEFが有効か
		bool isNdefEnabled()
		{
			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("このカードはFelica Liteではない", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}

			uint8_t mc[16] = {0};
			readBinary(ADDRESS_MC, mc);
			if ( mc[3] == 0x01 )
			{
				debugInfo2(__func__, " このカードはNDEFが有効です\n");
				return true;
			} else
			{
				debugInfo2(__func__, " このカードはNDEFが無効です\n");
				return false;
			}
		}

		//1次発行済か
		bool isFirstIssued()
		{
			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("このカードはFelica Liteではない", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}

			uint8_t mc[16] = {0};
			readBinary(ADDRESS_MC, mc);
			if ( mc[2] != 0xFF )
			{
				debugInfo2(__func__, " このカードは1次発行済みです\n");
				return true;
			} else
			{
				debugInfo2(__func__, " このカードはまだ1次発行されていません\n");
				return false;
			}
		}

		//2次発行済か
		bool isSecondIssued()
		{
			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("このカードはFelica Liteではない", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}

			uint8_t mc[16] = {0};
			readBinary(ADDRESS_MC, mc);
			if ( (mc[1] & 0x80) == 0 )
			{
				debugInfo2(__func__, " このカードは2次発行済みです\n");
				return true;
			} else
			{
				debugInfo2(__func__, " このカードはまだ2次発行されていません\n");
				return false;
			}
		}

		//------オマケ機能----

		//簡易的な1次発行を行う(二度と戻せないので注意！)
		void FirstIssue()
		{
			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("Felica Liteではないカードを書き換えることはできません", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}

			if ( isFirstIssued() )
			{
				throw FelicaFatalException("1次発行済のため書き換え不能", FelicaFatalException::ALREADY_FIRST_ISSUED);
			}
			debugInfo2(__func__, " 1次発行を行います\n");

			//MC_ALL = RO
			//SYS_OP = NDEF対応
			//MC_CKCKV_W_MAC_A = 1 (書き込みにMAC必要/あとからカード鍵書き換え許可 )
			//MC_STATE_W_MAC_A = 1 (相互認証有効)

			uint8_t mc[16] = {0xFF,0xFF,0x00,0x01,0x07,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00};
			updateBinary(ADDRESS_MC, mc);

			debugInfo2(__func__, " 1次発行を行いました\n");
		}

		//NDEFを有効・無効にする．1次発行前のみ可能．1次発行はしないため0次発行+NDEFとなる
		void enableNDEF(bool en = true)
		{
			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("Felica Liteではないカードを書き換えることはできません", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}
			if ( isFirstIssued() )
			{
				throw FelicaFatalException("1次発行済のため書き換え不能", FelicaFatalException::ALREADY_FIRST_ISSUED);
			}

			uint8_t mc[16] = {0};
			readBinary(ADDRESS_MC, mc);
			if ( en )
			{
				debugInfo2(__func__, " NDEF有効化\n");
				mc[3] = 0x01;
			} else
			{
				debugInfo2(__func__, " NDEF無効化\n");
				mc[3] = 0x00;
			}
			updateBinary(ADDRESS_MC, mc);
		}

		//簡易的なNDEF(URI)を書き込む
		void writeNdefURI(uint8_t mode, const char str[])
		{
			//mode
			//0x01- http://www.
			//0x02->https://www.
			//0x03->http://
			//0x04->https://

			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("Felica Liteではないカードを書き換えることはできません", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}

			if ( str == NULL )
			{
				throw std::invalid_argument("NullPointerException");
			}

			uint8_t ndef_head[16] = {0x10,0x04,0x01,0x00,0x0D,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00};
			uint8_t ndef_urlhead[16] = {0xD1,0x02,0xC2,0x53,0x70,0x91,0x01,0x03,0x54,0x02,0x6A,0x61,0x11,0x01,0x00,0x55};
			uint8_t ndef_foot[6] = {0x51,0x03,0x01,0x61,0x63,0x74};
			uint8_t url_buf[256] = {mode};

			int len = 0;
			for ( len = 0; len<184; len++ )
			{
				url_buf[len + 1] = str[len] & 0xFF;
				if ( str[len] == '\0' )
					break;
			}
			if ( len >= 184 )
			{
				throw std::length_error("URIが長すぎる");
			}

			for ( int i = 0; i<6; i++ )
			{
				url_buf[len + i + 1] = ndef_foot[i];
			}

			ndef_urlhead[14] = len + 1;
			ndef_urlhead[2] = ndef_urlhead[14] + 18;

			//Checksum計算
			ndef_head[13] = ndef_urlhead[14] + 23;

			int sum = 0;
			for ( int i = 0; i<16; i++ )
			{
				sum += ndef_head[i];
			}
			ndef_head[15] = sum;

			updateBinary(ADDRESS_SPAD0, ndef_head);
			updateBinary(ADDRESS_SPAD1, ndef_urlhead);

			for ( int i = 0; i<12; i++ )
			{
				unsigned char buf[16] = {0};
				for ( int k = 0; k<16; k++ )
				{
					buf[k] = url_buf[(i * 16) + k];
				}

				updateBinary(ADDRESS_SPAD2 + i, buf);
			}

			debugInfo2(__func__, " NDEF書き込み完了 %s\n",str);
		}

		const char* FellicaErrorInfo(uint8_t code)
		{
			switch ( code )
			{
				case 0x01: return ("パースアンダーフロー");
				case 0x02: return ("キャッシュバックオーバーフロー");
				case 0x70: return ("致命的メモリエラー");
				case 0x71: return ("メモリ寿命警告(処理を継続できます)");
				case 0xA1: return ("サービス数が0x01でない");
				case 0xA2: return ("ブロック数が0x01～0x04の範囲外");
				case 0xA3: return ("ブロックリストのサービスコードリスト順番が0でない");
				case 0xA4: return ("サービスタイプ不正");
				case 0xA5: return ("アクセス不許可");
				case 0xA6: return ("サービスコードがRWまたはROではないか，不一致");
				case 0xA7: return ("ブロックリストのアクセスモードが0でない");
				case 0xA8: return ("ブロック番号が既定ではないか，RO領域をRWで読み出そうとしている，あるいはD2が0でない");
				case 0xA9: return ("書き込み失敗");
				case 0xB0: return ("MACとMAC_Aブロックを同時にアクセスしている");
				case 0xB1: return ("認証が必要なブロックで認証していない");
				case 0xB2: return ("MAC_A不一致(RC書き込みなし，WCNT不一致、書き込みデータ不一致、書き込み回数エラーなど)あるいはMAC付き書き込み不要なブロックに書き込もうとしている");
				default: return ("不明なエラー");
			}
		}

		//-----------------------------------------

		//8バイト固定長でDES暗号化を行う
		void desEncryptFixedLength(const uint8_t input[8], const uint8_t key[8], const uint8_t IV[8], uint8_t output[8])
		{
			const int dataLength = 8;
			DWORD KeyObjectSize;
			BCRYPT_ALG_HANDLE hAlgorithm;
			DWORD res = 0;

			if ( BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_DES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) )
			{
				throw PCSCCryptographicException("BCryptOpenAlgorithmProviderがエラーを返しました");
			}
			if ( BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)(&KeyObjectSize), sizeof(DWORD), &res, 0) )
			{
				throw PCSCCryptographicException("BCryptGetPropertyがエラーを返しました");
			}
			PUCHAR pKeyObject = (PUCHAR)(malloc(KeyObjectSize));
			if ( pKeyObject == NULL )
			{
				throw PCSCCryptographicException("KeyObjectのメモリ確保に失敗");
			}

			BCRYPT_KEY_HANDLE hKey;
			try
			{
				if ( BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pKeyObject, KeyObjectSize, (PUCHAR)key, dataLength, 0) )
				{
					throw PCSCCryptographicException("BCryptGenerateSymmetricKeyがエラーを返しました");
				}

				if ( BCryptEncrypt(hKey, (PUCHAR)input, dataLength, nullptr, (PUCHAR)IV, dataLength, (PUCHAR)output, dataLength, &res, 0) )
				{
					throw PCSCCryptographicException("BCryptEncryptがエラーを返しました");
				}
			} catch ( ... )
			{
				BCryptDestroyKey(hKey);
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				free(pKeyObject);
				throw; //上に投げる
			}

			BCryptDestroyKey(hKey);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			free(pKeyObject);
		}

		//8バイト固定長でDES復号化を行う
		void desDecryptFixedLength(const uint8_t input[8], const uint8_t key[8], const uint8_t IV[8], uint8_t output[8])
		{
			const int dataLength = 8;
			DWORD KeyObjectSize;
			BCRYPT_ALG_HANDLE hAlgorithm;
			DWORD res = 0;

			if ( BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_DES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) )
			{
				throw PCSCCryptographicException("BCryptOpenAlgorithmProviderがエラーを返しました");
			}
			if ( BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)(&KeyObjectSize), sizeof(DWORD), &res, 0) )
			{
				throw PCSCCryptographicException("BCryptGetPropertyがエラーを返しました");
			}
			PUCHAR pKeyObject = (PUCHAR)(malloc(KeyObjectSize));
			if ( pKeyObject == NULL )
			{
				throw PCSCCryptographicException("KeyObjectのメモリ確保に失敗");
			}

			BCRYPT_KEY_HANDLE hKey;
			try
			{
				if ( BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pKeyObject, KeyObjectSize, (PUCHAR)key, dataLength, 0) )
				{
					throw PCSCCryptographicException("BCryptGenerateSymmetricKeyがエラーを返しました");
				}

				if ( BCryptDecrypt(hKey, (PUCHAR)input, dataLength, nullptr, (PUCHAR)IV, dataLength, (PUCHAR)output, dataLength, &res, 0) )
				{
					throw PCSCCryptographicException("BCryptDecryptがエラーを返しました");
				}
			} catch ( ... )
			{
				BCryptDestroyKey(hKey);
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				free(pKeyObject);
				throw; //上に投げる
			}

			BCryptDestroyKey(hKey);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			free(pKeyObject);
		}

		//バイトオーダーを入れ替える(ポインタの先を直に入れ替えるので注意！)
		void swapByteOrder(uint8_t inout[8])
		{
			uint8_t swap[8];
			for ( int i = 0; i<8; i++ )
			{
				swap[7 - i] = inout[i];
			}
			for ( int i = 0; i<8; i++ )
			{
				inout[i] = swap[i];
			}
		}

		//デバッグ用:8Byteの16進数の表示
		void showMAC(const uint8_t input[8])
		{
			for ( int i = 0; i<8; i++ )
			{
				printf("%02X ", input[i]);
			}
			printf("\n");
		}

		//8バイトのXOR
		void arryXor(const uint8_t input1[8], const uint8_t input2[8], uint8_t output[8])
		{
			for ( int i = 0; i<8; i++ )
			{
				output[i] = input1[i] ^ input2[i];
			}
		}

		//初期化ベクトルを初期化
		void zeroIV(uint8_t IV[8])
		{
			for ( int i = 0; i<8; i++ )
			{
				IV[i] = 0;
			}
		}

		//2key-3DESを行う．
		void Key2des3(const uint8_t input[8], const uint8_t XorInput[8], const uint8_t key1[8], const uint8_t key2[8], uint8_t output[8])
		{
			uint8_t IV[8], tmp[8], tmp2[8];
			arryXor(input, XorInput, tmp2);

			zeroIV(IV);
			desEncryptFixedLength(tmp2, key1, IV, tmp);
			zeroIV(IV);
			desDecryptFixedLength(tmp, key2, IV, tmp2);
			zeroIV(IV);
			desEncryptFixedLength(tmp2, key1, IV, output);
		}

		//2key-3DESを行う．但しFelica Lite用にバイトオーダー入れ替え処理と，2連処理を内包している
		void DualKey2des3(const uint8_t input1[8], const uint8_t input2[8], const uint8_t XorInput[8], const uint8_t key1[8], const uint8_t key2[8], uint8_t output1[8], uint8_t output2[8])
		{
			uint8_t Tinput1[8], Tinput2[8], TXorInput[8], Tkey1[8], Tkey2[8];

			//元データを破壊しないため
			for ( int i = 0; i<8; i++ )
			{
				Tinput1[i] = input1[i];
				Tinput2[i] = input2[i];
				TXorInput[i] = XorInput[i];
				Tkey1[i] = key1[i];
				Tkey2[i] = key2[i];
			}

			swapByteOrder(Tinput1);
			swapByteOrder(Tinput2);
			swapByteOrder(TXorInput);
			swapByteOrder(Tkey1);
			swapByteOrder(Tkey2);

			Key2des3(Tinput1, TXorInput, Tkey1, Tkey2, output1);
			Key2des3(Tinput2, output1, Tkey1, Tkey2, output2);

			swapByteOrder(output1);
			swapByteOrder(output2);
		}

		//Felica Liteセッションキーを生成する
		void makeSessionKey(uint8_t RC1[8], uint8_t RC2[8], uint8_t CK1[8], uint8_t CK2[8], uint8_t SK1[8], uint8_t SK2[8])
		{
			uint8_t ZERO[8] = {0};

			DualKey2des3(RC1, RC2, ZERO, CK1, CK2, SK1, SK2);
			debugInfo2(__func__, " セッションキーを生成しました\n");
			if ( debugFlag )
			{
				debugInfo2(__func__, " SK1 ");
				showMAC(SK1);
				debugInfo2(__func__, " SK2 ");
				showMAC(SK2);
			}
		}

		//Felica LiteのMACを生成する．(Felica Lite-SのMAC_Aではない！Felica Liteユーザーズマニュアルを読むこと！)
		void makeMAC(uint8_t BLOCK[16], uint8_t RC1[8], uint8_t SK1[8], uint8_t SK2[8], uint8_t MAC[8])
		{
			uint8_t BLOCK_HIGH[8], BLOCK_LOW[8];
			uint8_t UNUSED[8]; //中間変数．捨てる

			for ( int i = 0; i<8; i++ )
			{
				BLOCK_HIGH[i] = BLOCK[8 + i];
				BLOCK_LOW[i] = BLOCK[0 + i];
			}
			DualKey2des3(BLOCK_LOW, BLOCK_HIGH, RC1, SK1, SK2, UNUSED, MAC);
			debugInfo2(__func__, " MACを生成しました\n");
			if(debugFlag)
			{
				debugInfo2(__func__, " MAC ");
				showMAC(MAC);
			}
		}

		//Felica Lite-Sの読み出し時MAC_Aを生成する．(Felica LiteのMACではない！Felica Lite-Sユーザーズマニュアルを読むこと！)
		void makeReadMAC_A(uint16_t BlockAdr,uint8_t BLOCK[16], uint8_t RC1[8], uint8_t SK1[8], uint8_t SK2[8], uint8_t MAC[8])
		{
			uint8_t BLOCK_HIGH[8], BLOCK_LOW[8];
			uint8_t tmp1[8], tmp2[8]; //中間変数
			uint8_t Tinput1[8], Tinput2[8], TXorInput[8], Tkey1[8], Tkey2[8], TBlockInfo[8];
			uint8_t ZERO[8]={0};
			for ( int i = 0; i<8; i++ )
			{
				BLOCK_HIGH[i] = BLOCK[8 + i];
				BLOCK_LOW[i] = BLOCK[0 + i];
			}
			uint8_t BlockInfo[8] = {(uint8_t)(BlockAdr&0xFF),(uint8_t)((BlockAdr>>8) & 0xFF),(uint8_t)(ADDRESS_MAC_A & 0xFF),(uint8_t)((ADDRESS_MAC_A >> 8) & 0xFF),0xFF,0xFF,0xFF,0xFF};

			//元データを破壊しないため
			for ( int i = 0; i<8; i++ )
			{
				TBlockInfo[i] = BlockInfo[i];
				Tinput1[i] = BLOCK_LOW[i];
				Tinput2[i] = BLOCK_HIGH[i];
				TXorInput[i] = RC1[i];
				Tkey1[i] = SK1[i];
				Tkey2[i] = SK2[i];
			}

			swapByteOrder(TBlockInfo);
			swapByteOrder(Tinput1);
			swapByteOrder(Tinput2);
			swapByteOrder(TXorInput);
			swapByteOrder(Tkey1);
			swapByteOrder(Tkey2);

			Key2des3(TBlockInfo, TXorInput, Tkey1, Tkey2, tmp1);
			Key2des3(Tinput1, tmp1, Tkey1, Tkey2, tmp2);
			Key2des3(Tinput2, tmp2, Tkey1, Tkey2, MAC);

			swapByteOrder(MAC);

			debugInfo2(__func__, " MAC_Aを生成しました\n");
			if ( debugFlag )
			{
				debugInfo2(__func__, " MAC_A ");
				showMAC(MAC);
			}
		}

		//Felica Lite-Sの書き込み時MAC_Aを生成する．(Felica LiteのMACではない！Felica Lite-Sユーザーズマニュアルを読むこと！)
		void makeWriteMAC_A(uint16_t BlockAdr, uint8_t WCNT[8], uint8_t BLOCK[16], uint8_t RC1[8], uint8_t SK1[8], uint8_t SK2[8], uint8_t MAC[8])
		{
			uint8_t BLOCK_HIGH[8], BLOCK_LOW[8];
			uint8_t tmp1[8], tmp2[8]; //中間変数
			uint8_t Tinput1[8], Tinput2[8], TXorInput[8], Tkey1[8], Tkey2[8], TBlockInfo[8];
			uint8_t ZERO[8] = {0};

			if(( WCNT[0] == 0xFF && WCNT[1] == 0xFF && WCNT[2] == 0xFF) || (WCNT[0] == 0x00 && WCNT[1] == 0xFE && WCNT[2] == 0xFF) )
			{
				throw FelicaFatalException("書き込み回数が限界のためMAC_A書き込みできません", FelicaFatalException::WCNT_CLIP);
			}

			for ( int i = 0; i<8; i++ )
			{
				BLOCK_HIGH[i] = BLOCK[8 + i];
				BLOCK_LOW[i] = BLOCK[0 + i];
			}
			uint8_t BlockInfo[8] = {WCNT[0],WCNT[1],WCNT[2],WCNT[3],(uint8_t)(BlockAdr & 0xFF),(uint8_t)((BlockAdr >> 8) & 0xFF),(uint8_t)(ADDRESS_MAC_A & 0xFF),(uint8_t)((ADDRESS_MAC_A >> 8) & 0xFF)};
			//元データを破壊しないため
			for ( int i = 0; i<8; i++ )
			{
				TBlockInfo[i] = BlockInfo[i];
				Tinput1[i] = BLOCK_LOW[i];
				Tinput2[i] = BLOCK_HIGH[i];
				TXorInput[i] = RC1[i];
				Tkey1[i] = SK1[i];
				Tkey2[i] = SK2[i];
			}

			swapByteOrder(TBlockInfo);
			swapByteOrder(Tinput1);
			swapByteOrder(Tinput2);
			swapByteOrder(TXorInput);
			swapByteOrder(Tkey1);
			swapByteOrder(Tkey2);

			//Keyが入れ替わっていることに注意
			Key2des3(TBlockInfo, TXorInput, Tkey2, Tkey1, tmp1);
			Key2des3(Tinput1, tmp1, Tkey2, Tkey1, tmp2);
			Key2des3(Tinput2, tmp2, Tkey2, Tkey1, MAC);

			swapByteOrder(MAC);

			debugInfo2(__func__, " MAC_Aを生成しました\n");
			if ( debugFlag )
			{
				debugInfo2(__func__, " MAC_A ");
				showMAC(MAC);
			}
		}
		
		//MACを生成して比較する
		bool compareMAC(uint8_t BLOCK[16], uint8_t MAC[16], uint8_t RC1[8], uint8_t RC2[8], uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t SK1[8], SK2[8], CALC_MAC[16]={0};
			makeSessionKey(RC1,RC2,CK1,CK2,SK1,SK2);
			makeMAC(BLOCK,RC1,SK1,SK2,CALC_MAC);

			for ( int i = 0; i<8; i++ )
			{
				if(MAC[i] != CALC_MAC[i])
				{
					debugInfo2(__func__, " MAC不一致\n");
					return false;
				}
			}
			debugInfo2(__func__, " MAC一致\n");
			return true;
		}

		//MAC_Aを生成して比較する
		bool compareMAC_A(uint16_t BlockAdr, uint8_t BLOCK[16], uint8_t MAC[16], uint8_t RC1[8], uint8_t RC2[8], uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t SK1[8], SK2[8], CALC_MAC[16] = {0};
			makeSessionKey(RC1, RC2, CK1, CK2, SK1, SK2);
			makeReadMAC_A(BlockAdr,BLOCK, RC1, SK1, SK2, CALC_MAC);

			for ( int i = 0; i<8; i++ )
			{
				if ( MAC[i] != CALC_MAC[i] )
				{
					debugInfo2(__func__, " MAC不一致\n");
					return false;
				}
			}
			debugInfo2(__func__, " MAC一致\n");
			return true;
		}

		//RandomChallengeをカードに書き込む
		void writeRandomChallenge(uint8_t RC1[8], uint8_t RC2[8])
		{
			uint8_t RC[16];
			for(int i=0;i<8;i++ )
			{
				RC[i] = RC1[i];
				RC[i+8] = RC2[i];
			}

			updateBinary(ADDRESS_RC,RC);
			debugInfo2(__func__, " RCを書き込みました\n");
		}
		//CardKeyをカードに書き込む(CKを書き込み後は，RCを書き込んでセッション鍵を再生成させること)
		void writeCardKey(uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t CK[16];
			for ( int i = 0; i<8; i++ )
			{
				CK[i] = CK1[i];
				CK[i + 8] = CK2[i];
			}

			updateBinary(ADDRESS_CK, CK);
			debugInfo2(__func__, " CKを書き込みました\n");
		}

		//カード鍵を使い，MACを読み込んでIDmの検証を行うのを自動で行う．カード鍵と自分の持っている鍵が正しいかの検証になる．
		bool cardIdCheckMAC(uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t dat[16],mac[16];
			uint8_t RC1[8], RC2[8];

			makeRandomChallenge(RC1,RC2);
			writeRandomChallenge(RC1, RC2);
			readBinaryWithMAC(ADDRESS_ID, dat, mac);
			if (! compareMAC(dat, mac, RC1, RC2, CK1, CK2) )
			{
				debugInfo2(__func__, " カード鍵照合に失敗\n");
				return false;
			}
			debugInfo2(__func__, " カード鍵照合に成功\n");
			return true;
		}

		//カード鍵を使い，MAC_Aを読み込んでIDmの検証を行うのを自動で行う．Felica Lite-S専用
		bool cardIdCheckMAC_A(uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t dat[16], mac[16];
			uint8_t RC1[8], RC2[8];

			makeRandomChallenge(RC1, RC2);
			writeRandomChallenge(RC1, RC2);
			readBinaryWithMAC_A(ADDRESS_ID, dat, mac);
			if ( !compareMAC_A(ADDRESS_ID,dat, mac, RC1, RC2, CK1, CK2) )
			{
				debugInfo2(__func__, " カード鍵照合に失敗\n");
				return false;
			}
			debugInfo2(__func__, " カード鍵照合に成功\n");
			return true;
		}

		//RandomChallengeを乱数から生成する
		void makeRandomChallenge(uint8_t RC1[8], uint8_t RC2[8])
		{
			for ( int i = 0; i<8; i++ )
			{
				RC1[i] = CryptRand();
				RC2[i] = CryptRand();
			}

			debugInfo2(__func__, " RCを生成しました\n");
			if ( debugFlag )
			{
				debugInfo2(__func__, " RC1 ");
				showMAC(RC1);
				debugInfo2(__func__, " RC2 ");
				showMAC(RC2);
			}
		}

		//STATEを有効にする．もとに戻せない．
		void enableSTATE()
		{
			if ( !isFelicaLite() )
			{
				throw FelicaFatalException("Felica Liteではないカードを書き換えることはできません", FelicaFatalException::CARD_IS_NOT_FELICA_LITE);
			}

			uint8_t mc[16];
			readBinary(ADDRESS_MC, mc);
			mc[12] = 0x01;
			updateBinary(ADDRESS_MC, mc);
			debugInfo2(__func__, " STATEのMAC付き書き込みを有効にしました\n");
		}

		//STATEのEXT_AUTHを立てたり折ったりする(STATEを有効にしないと使えません)
		void setSTATE_EXT_AUTH(bool auth, uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t state[16] = {0};
			readBinary(ADDRESS_STATE, state);

			if(auth)
			{
				debugInfo2(__func__, " 外部認証を開始します\n");
				state[0] = 0x01;
			}else{
				debugInfo2(__func__, " 外部認証を終了します\n");
				state[0] = 0x00;
			}
			updateBinaryWithMAC_A_Auto(ADDRESS_STATE, state, CK1, CK2);
			debugInfo2(__func__, " 外部認証処理に成功しました\n");			
		}

		//MAC付き書き込みを，セッションキーの生成から自動で行う
		void updateBinaryWithMAC_A_Auto(uint16_t adr, uint8_t dat[16],uint8_t CK1[8], uint8_t CK2[8])
		{
			uint8_t mac[16],wcnt[16];
			uint8_t RC1[8], RC2[8], SK1[8], SK2[8];

			debugInfo2(__func__, " 自動MAC_A付き書き込み開始\n");

			makeRandomChallenge(RC1, RC2);
			debugInfo2(__func__, " RC生成完了\n");

			writeRandomChallenge(RC1, RC2);
			debugInfo2(__func__, " RC書き込み完了\n");

			makeSessionKey(RC1, RC2, CK1, CK2, SK1, SK2);
			debugInfo2(__func__, " セッションキー生成完了\n");

			readBinary(ADDRESS_WCNT, wcnt);
			debugInfo2(__func__, " WCNT読み取り完了\n");
			debugInfo2(__func__, " WCNT: ");
			showMAC(wcnt);

			makeWriteMAC_A(adr, wcnt, dat, RC1, SK1, SK2, mac);
			debugInfo2(__func__, " 書き込みMAC_A生成完了\n");

			mac[8] = wcnt[0];
			mac[9] = wcnt[1];
			mac[10] = wcnt[2];
			mac[11] = wcnt[3];
			updateBinaryWithMAC_A(adr, dat, mac);
			debugInfo2(__func__, " MAC_A付き書き込み完了\n");
		}

		//暗号論的擬似乱数を生成する
		uint8_t CryptRand()
		{
			HCRYPTPROV hProv;
			BYTE buf[1];

			if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0) )
			{
				throw PCSCCryptographicException("CryptAcquireContextがエラーを返しました");
			}

			if(!CryptGenRandom(hProv,1,buf))
			{
				throw PCSCCryptographicException("CryptGenRandomがエラーを返しました");
			}

			CryptReleaseContext(hProv, NULL);

			return buf[0];
		}

	};
}