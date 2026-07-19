#include <stdio.h>
#include <string.h>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include "mongoose.h"
#include "lazypcscfelicalite.h"
#include "felica_keys.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace LazyPCSCFelicaLite;

std::mutex ws_mutex;
std::string latest_user = "";
std::string latest_ndef = "";
std::string latest_pass = "";
bool new_user_read = false;
bool enable_password = false;

// Mongoose event handler
static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_match(hm->uri, mg_str("/ws"), NULL)) {
            // WebSocketへのアップグレード
            mg_ws_upgrade(c, hm, NULL);
        } else {
            // 通常のHTTPリクエストは public ディレクトリから静的ファイルを返す
            struct mg_http_serve_opts opts = {0};
            opts.root_dir = "public";
            mg_http_serve_dir(c, hm, &opts);
        }
    } else if (ev == MG_EV_WS_OPEN) {
        printf("[WebSocket] クライアントが接続しました\n");
    } else if (ev == MG_EV_CLOSE) {
        if (c->is_websocket) {
            printf("[WebSocket] クライアントが切断しました\n");
        }
    }
}

// FeliCaを監視し続けるバックグラウンドスレッド
void felica_thread_func() {
    bool debug = false;
    uint8_t ck1[8] = FELICA_CK1_INIT;
    uint8_t ck2[8] = FELICA_CK2_INIT;

    printf("FeliCaリーダーの監視を開始しました。\n");

    uint8_t last_idm[8] = {0};

    while (true) {
        try {
            PCSCFelicaLite f(debug, "fls_ws");
            
            // 1秒タイムアウトでカードを待機
            if (f.autoConnectToFelica(1000)) {
                try {
                    uint8_t current_idm[8] = {0};
                    f.readUID(current_idm);
                    
                    if (memcmp(current_idm, last_idm, 8) == 0) {
                        // 前回と同じカードが置かれたままなのでスキップ
                        f.disconnectCard();
                        f.closeService();
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        continue;
                    }
                    
                    // 新しいカード（または置き直されたカード）なのでIDmを更新
                    memcpy(last_idm, current_idm, 8);

                    // 相互認証 (EXT_AUTH) を実行
                    f.setSTATE_EXT_AUTH(true, ck1, ck2);
                    
                    // ユーザー名が格納されているブロック(ADDRESS_SPAD10)を読み込む
                    uint8_t spad[16] = {0};
                    uint8_t dummy_mac[16];
                    f.readBinaryWithMAC_A(f.ADDRESS_SPAD10, spad, dummy_mac);
                    
                    char username[17] = {0};
                    memcpy(username, spad, 16);
                    for (int i = 0; i < 16; i++) {
                        if (username[i] == ' ' || username[i] == '\r' || username[i] == '\n' || username[i] == 0) {
                            username[i] = '\0';
                            break;
                        }
                    }
                    
                    if (strlen(username) > 0) {
                        // オプションでパスワード(SPAD11)の読み込み
                        char password[17] = {0};
                        if (enable_password) {
                            uint8_t spad_pass[16] = {0};
                            uint8_t dummy_mac_p[16];
                            f.readBinaryWithMAC_A(f.ADDRESS_SPAD11, spad_pass, dummy_mac_p);
                            memcpy(password, spad_pass, 16);
                            for (int i = 0; i < 16; i++) {
                                if (password[i] == ' ' || password[i] == '\r' || password[i] == '\n' || password[i] == 0) {
                                    password[i] = '\0';
                                    break;
                                }
                            }
                        }

                        // NDEFの読み取り
                        std::string ndef_uri = "";
                        try {
                            f.readNdefContent(ndef_uri);
                        } catch (...) {}

                        std::lock_guard<std::mutex> lock(ws_mutex);
                        latest_user = username;
                        latest_ndef = ndef_uri;
                        latest_pass = password;
                        new_user_read = true;
                        if (enable_password) {
                            printf("[FeliCa] カード検知: ユーザー '%s', パスワード読出済, NDEF: '%s'\n", username, ndef_uri.c_str());
                        } else {
                            printf("[FeliCa] カード検知: ユーザー '%s', NDEF: '%s'\n", username, ndef_uri.c_str());
                        }
                    }
                } catch (std::exception &e) {
                    printf("[FeliCa] 読み取りエラー: %s\n", e.what());
                }
                
                f.disconnectCard();
                f.closeService();
                
                // 連続読み取りを防ぐために3秒待機
                std::this_thread::sleep_for(std::chrono::seconds(3));
            } else {
                // カードが取り除かれた場合は last_idm をリセット
                memset(last_idm, 0, 8);
            }
        } catch (std::exception &e) {
            memset(last_idm, 0, 8);
            // リーダーが見つからない等の場合は少し待ってリトライ
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (...) {
            memset(last_idm, 0, 8);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            enable_password = true;
        }
    }
    printf("DEBUG: enable_password = %d (argc=%d)\n", enable_password, argc);

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    
    const char *url = "ws://0.0.0.0:48080";
    if (mg_http_listen(&mgr, url, ev_handler, NULL) == NULL) {
        printf("WebSocketサーバーの起動に失敗しました: %s\n", url);
        return 1;
    }
    
    printf("WebSocketサーバーを起動しました: %s\n", url);
    printf("ブラウザで http://localhost:48080 にアクセスしてテストできます。\n");
    
    // FeliCa監視スレッドを起動
    std::thread f_thread(felica_thread_func);
    f_thread.detach();

    // Mongooseのイベントループ
    while (true) {
        mg_mgr_poll(&mgr, 100); // 100msごとにイベント処理
        
        // FeliCa側から新しいユーザー情報が届いているかチェック
        std::string user_to_send, ndef_to_send, pass_to_send;
        {
            std::lock_guard<std::mutex> lock(ws_mutex);
            if (new_user_read) {
                user_to_send = latest_user;
                ndef_to_send = latest_ndef;
                pass_to_send = latest_pass;
                new_user_read = false;
            }
        }
        
        if (!user_to_send.empty()) {
            std::string json_msg = "{\"username\": \"" + user_to_send + "\", \"ndef\": \"" + ndef_to_send + "\", \"password\": \"" + pass_to_send + "\"}";
            for (struct mg_connection *c = mgr.conns; c != NULL; c = c->next) {
                if (c->is_websocket) {
                    mg_ws_send(c, json_msg.c_str(), json_msg.length(), WEBSOCKET_OP_TEXT);
                }
            }
        }
    }
    
    mg_mgr_free(&mgr);
    return 0;
}
