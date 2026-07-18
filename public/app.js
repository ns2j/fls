document.addEventListener('DOMContentLoaded', () => {
    const waitingState = document.getElementById('waiting-state');
    const successState = document.getElementById('success-state');
    const wsStatus = document.getElementById('ws-status');
    const dot = document.querySelector('.dot');
    
    const userNameEl = document.getElementById('user-name');
    const userAvatarEl = document.getElementById('user-avatar');
    const cardNdefEl = document.getElementById('card-ndef');
    const authTimeEl = document.getElementById('auth-time');
    const resetBtn = document.getElementById('reset-btn');

    let ws = null;
    let reconnectTimer = null;
    let autoResetTimer = null;

    function resetToWaiting() {
        successState.classList.remove('active');
        waitingState.classList.add('active');
    }

    function connectWebSocket() {
        // Automatically determine WS URL based on current host
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        wsStatus.textContent = 'Connecting...';
        dot.className = 'dot';
        
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('WebSocket Connected');
            wsStatus.textContent = 'Ready - Waiting for FeliCa';
            dot.className = 'dot connected pulse';
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                console.log('Received:', data);
                
                if (data.username) {
                    showSuccess(data);
                }
            } catch (err) {
                console.error('JSON parse error:', err);
            }
        };

        ws.onclose = () => {
            console.log('WebSocket Disconnected');
            wsStatus.textContent = 'Disconnected - Reconnecting...';
            dot.className = 'dot';
            
            // Reconnect after 3 seconds
            clearTimeout(reconnectTimer);
            reconnectTimer = setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = (err) => {
            console.error('WebSocket Error:', err);
        };
    }

    function showSuccess(data) {
        // Update DOM elements
        userNameEl.textContent = data.username;
        userAvatarEl.textContent = data.username.charAt(0).toUpperCase();
        cardNdefEl.textContent = data.ndef || "Not Found";
        authTimeEl.textContent = new Date().toLocaleString();

        // Transition states
        waitingState.classList.remove('active');
        successState.classList.add('active');

        // 5秒後に自動で待機画面へ戻す
        clearTimeout(autoResetTimer);
        autoResetTimer = setTimeout(resetToWaiting, 5000);
    }

    resetBtn.addEventListener('click', () => {
        clearTimeout(autoResetTimer);
        resetToWaiting();
    });

    // Initialize connection
    connectWebSocket();
});
