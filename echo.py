from sanic import Sanic
from sanic.response import json
from sanic.exceptions import SanicException
from sanic.server.protocols.websocket_protocol import WebSocketProtocol
import logging
from datetime import datetime

# 初始化应用
app = Sanic("EchoServer")

# 配置日志
logging.basicConfig(level=logging.DEBUG)

# HTTP Echo 接口
@app.route("/echo", methods=["POST"])
async def echo(request):
    try:
        headers = request.headers
        body = request.body.decode("utf-8")
        print(f"\n[{datetime.now()}] Received HTTP Request:")
        print(f"Headers: {headers}")
        print(f"Body: {body}")

        data = request.json
        if data is None:
            raise ValueError("Invalid JSON body")

        print(f"Parsed JSON: {data}")
        return json(data)

    except Exception as e:
        print(f"Error occurred: {e}")
        return json({"error": "Bad Request", "message": str(e)}, status=400)

# WebSocket Echo 接口
@app.websocket("/ws/echo")
async def ws_echo(request, ws):
    print(request)
    print(f"[{datetime.now()}] WebSocket connection established")
    try:
        while True:
            data = await ws.recv()
            print(f"[{datetime.now()}] Received: {data}")
            await ws.send(data)  # 回显
    except Exception as e:
        print(f"[{datetime.now()}] WebSocket closed or error: {e}")

# 自定义 HTTP 异常处理
@app.exception(SanicException)
async def handle_sanic_exception(request, exception):
    if isinstance(exception, SanicException) and exception.status_code == 400:
        print(f"[{datetime.now()}] Bad Request: {exception.args}")
        headers = request.headers
        body = request.body.decode("utf-8")
        print(f"Headers: {headers}")
        print(f"Body: {body}")
    return json({"error": "Bad Request"}, status=400)

if __name__ == "__main__":
    # 启动支持 WebSocket 的 Sanic 服务
    app.run(host="0.0.0.0", port=8000)
