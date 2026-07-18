#include "lazypcscfelicalite.h"
#include "felica_keys.h"
#include <cstring>

using LazyPCSCFelicaLite::PCSCFelicaLite;
using LazyPCSCFelicaLite::PCSCErrorException;
using LazyPCSCFelicaLite::PCSCIllegalStateException;
using LazyPCSCFelicaLite::PCSCCommandException;
using LazyPCSCFelicaLite::PCSCFatalException;
using LazyPCSCFelicaLite::FelicaErrorException;
using LazyPCSCFelicaLite::FelicaFatalException;
using LazyPCSCFelicaLite::PCSCCardRemovedException;

int main(int argc, char* argv[])
{
	bool do_first_issue = false;
	bool do_write_key = false;
	bool do_check_mac = false;
	bool do_mutual_auth = false;
	bool do_read_ndef = false;
	bool do_write_ndef = false;
	bool do_write_ndef_text = false;
	bool do_show_status = false;
	bool do_debug = false;
	bool do_fix_ndef = false;
	bool do_dump_blocks = false;
	bool do_read_username = false;
	bool do_read_password = false;
	bool do_read_domain = false;
	std::string write_username = "";
	std::string write_password = "";
	std::string write_domain = "";
	std::string write_ndef_uri = "";
	std::string write_ndef_text = "";
	bool show_help = false;
	if (argc == 1) {
		show_help = true;
	}

	for (int i = 1; i < argc; i++) {
		if (std::string(argv[i]) == "-h") show_help = true;
		else if (std::string(argv[i]) == "-1") {
			do_first_issue = true;
			do_write_key = true; // 安全のため1次発行は必ず鍵の書き込みとセットで行う
		}
		else if (std::string(argv[i]) == "-W") do_write_key = true;
		else if (std::string(argv[i]) == "-c") do_check_mac = true;
		else if (std::string(argv[i]) == "-m") do_mutual_auth = true;
		else if (std::string(argv[i]) == "-n") do_read_ndef = true;
		else if (std::string(argv[i]) == "-N" && i + 1 < argc) {
			do_write_ndef = true;
			write_ndef_uri = argv[i+1];
			i++;
		}
		else if (std::string(argv[i]) == "-T" && i + 1 < argc) {
			do_write_ndef_text = true;
			write_ndef_text = argv[i+1];
			i++;
		}
		else if (std::string(argv[i]) == "-s") do_show_status = true;
		else if (std::string(argv[i]) == "-u") do_read_username = true;
		else if (std::string(argv[i]) == "-p") do_read_password = true;
		else if (std::string(argv[i]) == "-d") do_read_domain = true;
		else if (std::string(argv[i]) == "-v") do_debug = true;
		else if (std::string(argv[i]) == "-F") do_fix_ndef = true;
		else if (std::string(argv[i]) == "-B") do_dump_blocks = true; // -D was used for domain
		else if (std::string(argv[i]) == "-U" && i + 1 < argc) {
			write_username = argv[i+1];
			i++;
		}
		else if (std::string(argv[i]) == "-P" && i + 1 < argc) {
			write_password = argv[i+1];
			i++;
		}
		else if (std::string(argv[i]) == "-D" && i + 1 < argc) {
			write_domain = argv[i+1];
			i++;
		}
	}

	if (show_help) {
		printf("使用方法:\n");
		printf("  -h : ヘルプ表示 (デフォルト)\n");
		printf("  -s : カードステータス表示\n");
		printf("  -1 : 1次発行の実行 (※安全のため内部で自動的に -W も実行されます)\n");
		printf("  -W : カード鍵とMCブロック設定(MAC必須化)の書き込みのみ\n");
		printf("  -c : カード鍵の照合確認\n");
		printf("  -m : 相互認証(外部認証)の実行\n");
		printf("  -n : NDEFの読み込み\n");
		printf("  -N <URI> : NDEF(URL)の書き込み (単体だと通常書き込み、-m と併用でMAC付き書き込み)\n");
		printf("  -T <text> : NDEF(テキスト)の書き込み (-m と併用でMAC付き書き込み)\n");
		printf("  -U <name> : ユーザ名の書き込み(SPAD10) (-m と併用でMAC付き書き込み)\n");
		printf("  -P <pass> : パスワードの書き込み(SPAD11) (-m と併用でMAC付き書き込み)\n");
		printf("  -D <domain> : ドメイン名の書き込み(SPAD12-13) (-m と併用でMAC付き書き込み)\n");
		printf("  -u : ユーザ名(SPAD10)の読み込み\n");
		printf("  -p : パスワード(SPAD11)の読み込み\n");
		printf("  -d : ドメイン名(SPAD12-13)の読み込み\n");
		printf("  -v : デバッグモード (PC/SCの通信内容を詳細表示)\n");
		return 0;
	}

	PCSCFelicaLite f = PCSCFelicaLite(do_debug, "f");

	try
	{
		printf("かざしてください...\n");
		//カードに接続
		f.autoConnectToFelica(INFINITE);

		if (do_show_status) {
			printf("\n--- カードの内部ステータス (--show) ---\n");
			uint8_t buf[16] = {0};
			
			// CKV (Card Key Version)
			try {
				f.readBinary(PCSCFelicaLite::ADDRESS_CKV, buf);
				printf("CKV (Card Key Version) [0x86]: %02X %02X\n", buf[0], buf[1]);
				if (buf[0] == 0 && buf[1] == 0) {
					printf("  -> CKVが0x0000のため、カード鍵(CK)は無効(未発行状態)です。\n");
				} else {
					printf("  -> CKVが非ゼロのため、カード鍵(CK)によるMAC認証が有効です。\n");
				}
			} catch(std::exception& e) { printf("CKV 読み取り失敗: %s\n", e.what()); }

			// MC (Memory Configuration)
			try {
				f.readBinary(PCSCFelicaLite::ADDRESS_MC, buf);
				printf("MC_ALL (System Block Access) [0x88, Byte2]: %02X\n", buf[2]);
				if (buf[2] != 0xFF) {
					printf("  -> 1次発行: 済み (カード設定はロックされています)\n");
				} else {
					printf("  -> 1次発行: まだされていません (未発行状態)\n");
				}

				printf("MC_STATE_W_MAC_A (State Block Access) [0x88, Byte12]: %02X\n", buf[12]);
				if (buf[12] == 0x01) {
					printf("  -> STATEブロックの書き込みにMAC認証が必須化されています(安全)。\n");
				} else {
					printf("  -> STATEブロックは誰でもMACなしで書き込み可能です(ザル状態)。\n");
				}

				printf("MCブロック生データ: ");
				for(int i=0; i<16; i++) printf("%02X ", buf[i]);
				printf("\n");
			} catch(std::exception& e) { printf("MC 読み取り失敗: %s\n", e.what()); }

			// STATE (Authentication State)
			try {
				f.readBinary(PCSCFelicaLite::ADDRESS_STATE, buf);
				printf("STATE (Current Auth State)   [0x92]: %02X\n", buf[0]);
			} catch(std::exception& e) { printf("STATE 読み取り失敗: %s\n", e.what()); }

			// SPAD0~13
			printf("\n--- ユーザデータ (SPAD0〜13) ---\n");
			for (int i = 0; i <= 13; i++) {
				try {
					f.readBinary(f.ADDRESS_SPAD0 + i, buf);
					printf("SPAD%02d [0x%02X]: ", i, f.ADDRESS_SPAD0 + i);
					for(int j=0; j<16; j++) {
						printf("%02X ", buf[j]);
					}
					printf(" | ");
					for(int j=0; j<16; j++) {
						if (buf[j] >= 32 && buf[j] <= 126) {
							printf("%c", buf[j]);
						} else {
							printf(".");
						}
					}
					printf("\n");
				} catch(std::exception& e) { 
					printf("SPAD%02d 読み取り失敗: %s\n", i, e.what()); 
				}
			}
			printf("--------------------------------------\n\n");
			
			// エラー状態（SPAD13読み取り失敗など）をリセットするため再接続
			f.disconnectCard();
			f.autoConnectToFelica(INFINITE);
		}

		// IDmとPMmの取得と表示
		uint8_t idm[8] = {0};
		uint32_t idm_len = f.readUID(idm);
		printf("IDm: ");
		for (uint32_t i = 0; i < idm_len; i++) {
			printf("%02X", idm[i]);
		}
		printf("\n");

		uint8_t pmm[8] = {0};
		uint32_t pmm_len = f.readPMm(pmm);
		printf("PMm: ");
		for (uint32_t i = 0; i < pmm_len; i++) {
			printf("%02X", pmm[i]);
		}
		printf("\n");



		uint8_t ck1[8] = FELICA_CK1_INIT;
		uint8_t ck2[8] = FELICA_CK2_INIT;

		printf("現在プログラムに組み込まれている鍵(先頭2バイト): CK1=%02X%02X, CK2=%02X%02X\n", ck1[0], ck1[1], ck2[0], ck2[1]);

		if (do_mutual_auth) {
			printf("相互認証(外部認証)を行います...\n");
			try {
				f.setSTATE_EXT_AUTH(true, ck1, ck2);
				printf("相互認証に成功しました！\n");
			} catch (std::exception &e) {
				printf("相互認証に失敗しました: %s\n", e.what());
			}
		}

		if (do_write_key) {
			printf("カード鍵の書き込みを行います...\n");
			try {
				if (do_mutual_auth) {
					f.writeCardKeyWithMAC_A(ck1, ck2, ck1, ck2);
				} else {
					f.writeCardKey(ck1, ck2);
				}
				printf("カード鍵の書き込みに成功しました！\n");
			} catch (std::exception &e) {
				printf("カード鍵の書き込みに失敗しました: %s\n", e.what());
			}
			printf("MCブロックを書き換え、相互認証(MAC付き書き込み)を必須化します...\n");
			try {
				f.enableSTATE();
				printf("MCブロックの書き換えに成功しました！\n");
			} catch (std::exception &e) {
				printf("MCブロックの書き換えに失敗しました: %s\n", e.what());
			}
		}

		if (do_check_mac) {
			printf("カード鍵の照合を行います...\n");
			bool ok = f.cardIdCheckMAC_A(ck1, ck2);
			if (ok) {
				printf("カード鍵の照合に成功しました！\n");
			} else {
				printf("カード鍵の照合に失敗しました...\n");
			}
		}



		if (!write_username.empty()) {
			printf("ユーザ名を書き込みます...\n");
			uint8_t spad[16] = {0};
			// 最大15文字 + NULL終端
			strncpy((char*)spad, write_username.c_str(), 15);

			try {
				if (do_mutual_auth) {
					// Use the Session Key established by setSTATE_EXT_AUTH!
					f.updateBinaryWithMAC_A_Session(f.ADDRESS_SPAD10, spad);
				} else {
					f.updateBinary(f.ADDRESS_SPAD10, spad);
				}
				printf("ユーザ名を書き込みました(SPAD10): %s\n", write_username.c_str());
			} catch (std::exception &e) {
				printf("ユーザ名の書き込みに失敗しました: %s\n", e.what());
			}
		}

		if (!write_password.empty()) {
			printf("パスワードを書き込みます...\n");
			uint8_t spad[16] = {0};
			strncpy((char*)spad, write_password.c_str(), 15);

			try {
				if (do_mutual_auth) {
					f.updateBinaryWithMAC_A_Session(f.ADDRESS_SPAD11, spad);
				} else {
					f.updateBinary(f.ADDRESS_SPAD11, spad);
				}
				printf("パスワードを書き込みました(SPAD11)\n");
			} catch (std::exception &e) {
				printf("パスワードの書き込みに失敗しました: %s\n", e.what());
			}
		}

		if (!write_domain.empty()) {
			printf("ドメイン名を書き込みます...\n");
			uint8_t spad12[16] = {0};
			uint8_t spad13[16] = {0};
			std::string d = write_domain;
			
			size_t len12 = d.length() > 16 ? 16 : d.length();
			memcpy(spad12, d.c_str(), len12);
			
			if (d.length() > 16) {
				size_t len13 = (d.length() - 16) > 15 ? 15 : (d.length() - 16);
				memcpy(spad13, d.c_str() + 16, len13);
			}

			try {
				if (do_mutual_auth) {
					f.updateBinaryWithMAC_A_Session(f.ADDRESS_SPAD12, spad12);
					f.updateBinaryWithMAC_A_Session(f.ADDRESS_SPAD13, spad13);
				} else {
					f.updateBinary(f.ADDRESS_SPAD12, spad12);
					f.updateBinary(f.ADDRESS_SPAD13, spad13);
				}
				printf("ドメイン名を書き込みました(SPAD12, SPAD13): %s\n", write_domain.c_str());
			} catch (std::exception &e) {
				printf("ドメイン名の書き込みに失敗しました: %s\n", e.what());
			}
		}

		if (do_read_username) {
			printf("ユーザ名(SPAD10)を読み込みます...\n");
			try {
				uint8_t spad[16] = {0};
				if (do_mutual_auth) {
					uint8_t dummy_mac[16];
					f.readBinaryWithMAC_A(f.ADDRESS_SPAD10, spad, dummy_mac);
				} else {
					f.readBinary(f.ADDRESS_SPAD10, spad);
				}
				
				spad[15] = '\0';
				printf("読み込まれたユーザ名: %s\n", (char*)spad);
			} catch(std::exception &e) {
				printf("ユーザ名の読み込みに失敗しました: %s\n", e.what());
			}
		}

		if (do_read_password) {
			printf("パスワード(SPAD11)を読み込みます...\n");
			try {
				uint8_t spad[16] = {0};
				if (do_mutual_auth) {
					uint8_t dummy_mac[16];
					f.readBinaryWithMAC_A(f.ADDRESS_SPAD11, spad, dummy_mac);
				} else {
					f.readBinary(f.ADDRESS_SPAD11, spad);
				}
				
				spad[15] = '\0';
				printf("読み込まれたパスワード: %s\n", (char*)spad);
			} catch(std::exception &e) {
				printf("パスワードの読み込みに失敗しました: %s\n", e.what());
			}
		}

		if (do_read_domain) {
			printf("ドメイン名(SPAD12-13)を読み込みます...\n");
			try {
				uint8_t spad12[16] = {0};
				uint8_t spad13[16] = {0};
				if (do_mutual_auth) {
					uint8_t dummy_mac[16];
					f.readBinaryWithMAC_A(f.ADDRESS_SPAD12, spad12, dummy_mac);
					f.readBinaryWithMAC_A(f.ADDRESS_SPAD13, spad13, dummy_mac);
				} else {
					f.readBinary(f.ADDRESS_SPAD12, spad12);
					f.readBinary(f.ADDRESS_SPAD13, spad13);
				}
				
				char domain[32] = {0};
				memcpy(domain, spad12, 16);
				memcpy(domain + 16, spad13, 15); // max 31 chars
				domain[31] = '\0';
				printf("読み込まれたドメイン名: %s\n", domain);
			} catch(std::exception &e) {
				printf("ドメイン名の読み込みに失敗しました: %s\n", e.what());
			}
		}

		if (do_read_ndef) {
			printf("NDEFの読み込みを試みます...\n");
			try {
				std::string ndef_content;
				f.readNdefContent(ndef_content);
				printf("NDEFコンテンツ: %s\n", ndef_content.c_str());
			} catch (std::exception& e) {
				printf("NDEF読み取り失敗: %s\n", e.what());
			}
		}

		if (do_fix_ndef) {
			printf("Android NDEF対応修正(SYS_OP)を行います...\n");
			try {
				f.fixAndroidNdef(ck1, ck2);
				printf("修正完了。\n");
			} catch (std::exception& e) {
				printf("修正失敗: %s\n", e.what());
			}
		}

		if (do_dump_blocks) {
			printf("カードブロックのダンプを取得します...\n");
			uint8_t buf[16];
			try {
				f.readBinary(0x0088, buf); // MC (ADDRESS_MC)
				printf("MC    : ");
				for(int i=0; i<16; i++) printf("%02X ", buf[i]);
				printf("\n");

				f.readBinary(0x0000, buf); // SPAD0
				printf("SPAD0 : ");
				for(int i=0; i<16; i++) printf("%02X ", buf[i]);
				printf("\n");

				f.readBinary(0x0001, buf); // SPAD1
				printf("SPAD1 : ");
				for(int i=0; i<16; i++) printf("%02X ", buf[i]);
				printf("\n");

				f.readBinary(0x0002, buf); // SPAD2
				printf("SPAD2 : ");
				for(int i=0; i<16; i++) printf("%02X ", buf[i]);
				printf("\n");
			} catch (std::exception& e) {
				printf("ダンプ失敗: %s\n", e.what());
			}
		}

		if (do_write_ndef_text) {
			printf("NDEFテキストを書き込みます...\n");
			try {
				if (do_mutual_auth) {
					// Session Key established by setSTATE_EXT_AUTH
					f.writeNdefTextWithMAC_A_Session(write_ndef_text.c_str());
				} else {
					f.writeNdefText(write_ndef_text.c_str());
				}
				printf("NDEFテキスト書き込み成功！\n");
			} catch (std::exception &e) {
				printf("NDEFテキスト書き込み失敗: %s\n", e.what());
			}
		}

		if (do_first_issue) {
			printf("一次発行を行います...\n");
			f.FirstIssue();
		}

		if (do_write_ndef) {
			try {
				f.enableNDEF(true);
			} catch (FelicaFatalException &e) {
				// 1次発行済みの場合は例外が出るが、すでに有効化されているので無視してよい
			}
			
			uint8_t mode = PCSCFelicaLite::NDEF_HTTPS;
			std::string uri_body = write_ndef_uri;
			if (uri_body.find("https://www.") == 0) {
				mode = PCSCFelicaLite::NDEF_HTTPS_WWW;
				uri_body = uri_body.substr(12);
			} else if (uri_body.find("http://www.") == 0) {
				mode = PCSCFelicaLite::NDEF_HTTP_WWW;
				uri_body = uri_body.substr(11);
			} else if (uri_body.find("https://") == 0) {
				mode = PCSCFelicaLite::NDEF_HTTPS;
				uri_body = uri_body.substr(8);
			} else if (uri_body.find("http://") == 0) {
				mode = PCSCFelicaLite::NDEF_HTTP;
				uri_body = uri_body.substr(7);
			} else if (uri_body.find("mailto:") == 0) {
				mode = 0x06;
				uri_body = uri_body.substr(7);
			} else if (uri_body.find("tel:") == 0) {
				mode = 0x05;
				uri_body = uri_body.substr(4);
			}

			if (do_mutual_auth) {
				printf("MAC付きでNDEFを書き込みます...\n");
				f.writeNdefURIWithMAC(mode, uri_body.c_str(), ck1, ck2);
			} else {
				printf("通常書き込みでNDEFを書き込みます...\n");
				f.writeNdefURI(mode, uri_body.c_str());
			}
			printf("NDEFの書き込みが完了しました。\n");
		}

		//カードから切断
		f.disconnectCard();
		//サービスを閉じる
		f.closeService();
	} catch ( PCSCCardRemovedException e )
	{
		printf("PCSCCardRemoved例外: %s\n");
	} catch ( PCSCErrorException e )
	{
		printf("PCSCErrorException例外: %s SW1=%02X,SW2=%02X\n", e.what(), e.sw1(), e.sw2());
	} catch ( PCSCIllegalStateException e )
	{
		printf("PCSCIllegalStateException例外: %s\n", e.what());
	} catch ( PCSCCommandException e )
	{
		printf("PCSCCommandException例外: %s %X\n", e.what(), e.returncode());
	} catch ( PCSCFatalException e )
	{
		printf("PCSCFatalException例外: %s %X %X\n", e.what(), e.errorcode(), e.returncode());
	} catch ( FelicaErrorException e )
	{
		printf("FelicaErrorException例外: %s High=%02X,Low=%02X\n", e.what(), e.high(), e.low());
	} catch ( FelicaFatalException e )
	{
		printf("FelicaFatalException例外: %s %X\n", e.what(), e.errorcode());
	}
}
