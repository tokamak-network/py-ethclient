"""HTTP JSON-RPC server using stdlib."""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable

from .methods import create_methods


class RPCHandler(BaseHTTPRequestHandler):
    chain = None
    
    def __init__(self, *args, **kwargs):
        self.methods = create_methods(self.chain)
        super().__init__(*args, **kwargs)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._send_error(-32700, "Parse error")
            return

        if not isinstance(request, dict):
            self._send_error(-32600, "Invalid Request")
            return

        request_id = request.get("id")
        method_name = request.get("method")
        params = request.get("params", [])

        if not method_name:
            self._send_error(-32600, "Invalid Request", request_id)
            return

        if method_name not in self.methods:
            self._send_error(-32601, f"Method not found: {method_name}", request_id)
            return

        try:
            result = self.methods[method_name](params)
            self._send_result(result, request_id)
        except Exception as e:
            self._send_error(-32603, str(e), request_id)

    def _send_result(self, result: Any, request_id: Any):
        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id,
        }
        self._send_response(response)

    def _send_error(self, code: int, message: str, request_id: Any = None):
        response = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id,
        }
        self._send_response(response)

    def _send_response(self, response: dict):
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def create_server(chain, host: str = "127.0.0.1", port: int = 8545) -> HTTPServer:
    RPCHandler.chain = chain
    return HTTPServer((host, port), RPCHandler)


def _block_producer(chain):
    while True:
        time.sleep(1)
        if chain.should_build_block():
            chain.build_block()


def serve(chain, host: str = "127.0.0.1", port: int = 8545):
    server = create_server(chain, host, port)
    
    block_thread = threading.Thread(target=_block_producer, args=(chain,), daemon=True)
    block_thread.start()
    
    print(f"JSON-RPC server listening on {host}:{port}")
    print(f"Block production interval: {chain.block_time}s")
    server.serve_forever()