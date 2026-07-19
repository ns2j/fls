document.addEventListener("DOMContentLoaded", function() {
    // ローカルで動いている fls_ws に接続
    const ws = new WebSocket('ws://localhost:48080/ws');
    
    ws.onopen = function() {
        console.log("FeliCa Reader (fls_ws) と接続しました。カードをかざしてください。");
    };

    ws.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            
            // FeliCaからユーザ名が読み取れた場合
            if (data.username && data.username.length > 0) {
                console.log("FeliCaからユーザーを検知:", data.username);
                
                const usernameInput = document.getElementById('username');
                if (usernameInput) {
                    usernameInput.value = data.username;
                }
                
                // パスワード(SPAD11)も読み取れた場合はセット
                if (data.password && data.password.length > 0) {
                    const passwordInput = document.getElementById('password');
                    if (passwordInput) {
                        passwordInput.value = data.password;
                    }
                }
                
                const loginForm = document.getElementById('kc-form-login');
                if (loginForm) {
                    // ユーザー名セット後、自動ログイン
                    loginForm.submit();
                }
            }
        } catch (e) {
            console.error("JSONのパースに失敗しました", e);
        }
    };
    
    ws.onerror = function(error) {
        console.log("fls_ws と接続できません。FeliCa連携は無効になります。");
    };
});
