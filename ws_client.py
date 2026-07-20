import asyncio
import json
import websockets

async def listen_to_fls():
    url = "ws://localhost:48080/ws"
    print(f"WebSocketサーバー ({url}) に接続しています...")
    
    try:
        # WebSocketサーバーに接続
        async with websockets.connect(url) as websocket:
            print("接続に成功しました！FeliCaカードをタッチしてください。\n")
            
            # サーバーからのメッセージを無限ループで待ち受ける
            while True:
                # メッセージの受信を待機
                message = await websocket.recv()
                
                # 受信したJSON文字列を辞書（ディクショナリ）に変換
                data = json.loads(message)
                
                if "username" in data:
                    print(f"[検知] ユーザーがタッチしました: {data['username']}")
                else:
                    print(f"[受信] 未知のデータ: {data}")
                    
    except websockets.exceptions.ConnectionClosedError:
        print("サーバーとの接続が切断されました。")
    except ConnectionRefusedError:
        print("エラー: サーバーに接続できません。先に ./fls_ws を起動してください。")
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}")

if __name__ == "__main__":
    # イベントループを実行
    asyncio.run(listen_to_fls())
