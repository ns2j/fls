#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "lazypcscfelicalite.h"
#include "felica_keys.h"

using namespace LazyPCSCFelicaLite;

extern "C" {
    PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        bool debug = false;
        for (int i = 0; i < argc; i++) {
            if (strcmp(argv[i], "debug") == 0) debug = true;
        }

        openlog("pam_fls", LOG_PID | LOG_NDELAY, LOG_AUTH);
        syslog(LOG_INFO, "pam_sm_authenticate started (debug=%d)", debug);

        try {
            PCSCFelicaLite f(debug, "pam_fls");
            // 最大5秒間カードを待機する
            syslog(LOG_INFO, "Waiting for FeliCa card...");
            if (!f.autoConnectToFelica(5000)) {
                syslog(LOG_WARNING, "No FeliCa card detected within timeout.");
                closelog();
                return PAM_AUTHINFO_UNAVAIL;
            }

            uint8_t ck1[8] = FELICA_CK1_INIT;
            uint8_t ck2[8] = FELICA_CK2_INIT;

            // 相互認証 (EXT_AUTH) を実行
            f.setSTATE_EXT_AUTH(true, ck1, ck2);

            // 相互認証に成功した場合、ユーザ名を格納しているブロック(ADDRESS_SPAD10)を読み込む
            uint8_t spad[16] = {0};
            uint8_t dummy_mac[16];
            f.readBinaryWithMAC_A(f.ADDRESS_SPAD10, spad, dummy_mac);

            char username[17] = {0};
            memcpy(username, spad, 16);

            // 終端処理 (スペースやヌル文字、改行文字以降をカット)
            for (int i = 0; i < 16; i++) {
                if (username[i] == ' ' || username[i] == '\r' || username[i] == '\n' || username[i] == 0) {
                    username[i] = '\0';
                    break;
                }
            }

            if (strlen(username) == 0) {
                syslog(LOG_WARNING, "Username read from FeliCa is empty.");
                closelog();
                return PAM_IGNORE;
            }

            // GDM等から要求されているユーザー名を取得する
            const char *requested_user = NULL;
            pam_get_item(pamh, PAM_USER, (const void **)&requested_user);

            if (requested_user != NULL && strlen(requested_user) > 0) {
                // 要求されたユーザーが存在する場合、カードのユーザー名と比較する
                if (strcmp(requested_user, username) != 0) {
                    syslog(LOG_WARNING, "Username mismatch. Requested: '%s', Card: '%s'", requested_user, username);
                    closelog();
                    return PAM_IGNORE; // エラーにせず無視してパスワード認証へ進める
                }
            } else {
                // 要求されたユーザーが存在しない場合（通常はあり得ないが安全のため）、PAMにセットする
                int pam_err = pam_set_item(pamh, PAM_USER, username);
                if (pam_err != PAM_SUCCESS) {
                    syslog(LOG_ERR, "Failed to set PAM_USER.");
                    closelog();
                    return PAM_IGNORE;
                }
            }

            syslog(LOG_INFO, "Successfully authenticated via FeliCa. Extracted user: '%s'", username);
            closelog();
            return PAM_SUCCESS;

        } catch (std::exception &e) {
            syslog(LOG_ERR, "FeliCa Exception: %s", e.what());
            if (debug) {
                fprintf(stderr, "PAM Felica Error: %s\n", e.what());
            }
            closelog();
            return PAM_AUTH_ERR;
        } catch (...) {
            syslog(LOG_ERR, "Unknown exception during FeliCa authentication.");
            closelog();
            return PAM_AUTH_ERR;
        }
    }
}
