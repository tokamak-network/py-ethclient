"""HTTP JSON-RPC server using stdlib.

Implements JSON-RPC 2.0 specification:
https://www.jsonrpc.org/specification

Key behavior:
- Batch requests supported (array of requests)
- Notifications supported (absent 'id' field = no response per JSON-RPC spec)
- Error codes follow spec (-32700 to -32603 for standard errors)
"""

import json
import signal
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
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_error(-32700, "Parse error")
            return

        # Handle batch requests (array)
        if isinstance(data, list):
            self._handle_batch(data)
            return
        
        # Handle single request (object)
        if isinstance(data, dict):
            response = self._handle_single(data)
            # Notifications (id field is absent) don't send response
            if response is not None:
                self._send_response(response)
            else:
                # Return 204 No Content for notifications
                self.send_response(204)
                self.end_headers()
            return
        
        # Invalid request type
        self._send_error(-32600, "Invalid Request: expected object or array")

    def _handle_single(self, request: dict) -> dict | None:
        """Handle a single JSON-RPC request. Returns response or None for notifications.
        
        Per JSON-RPC 2.0 spec:
        - Notification = request without "id" field (not id: null)
        - Server MUST NOT reply to notifications, including invalid ones
        """
        has_id = "id" in request  # id field present (even if null)
        request_id = request.get("id")  # id value (can be null)

        # Validate jsonrpc field
        if request.get("jsonrpc") != "2.0":
            # Per spec: MUST NOT reply to invalid notifications
            if not has_id:
                return None
            return self._build_error(-32600, "Invalid Request: jsonrpc must be 2.0", request_id)

        method_name = request.get("method")
        if not method_name or not isinstance(method_name, str):
            # Per spec: MUST NOT reply to invalid notifications
            if not has_id:
                return None
            return self._build_error(-32600, "Invalid Request: method required", request_id)

        params = request.get("params", [])
        if params is not None and not isinstance(params, (list, dict)):
            # Per spec: MUST NOT reply to invalid notifications
            if not has_id:
                return None
            return self._build_error(-32600, "Invalid Request: params must be array or object", request_id)

        if method_name not in self.methods:
            # Per spec: MUST NOT reply to invalid notifications
            if not has_id:
                return None
            return self._build_error(-32601, f"Method not found: {method_name}", request_id)

        try:
            result = self.methods[method_name](params)
            # Notification: no "id" field present
            if not has_id:
                return None
            return self._build_result(result, request_id)
        except Exception as e:
            # Per spec: MUST NOT reply to notifications (even with errors)
            if not has_id:
                return None
            return self._build_error(-32603, str(e), request_id)

    def _handle_batch(self, requests: list):
        """Handle batch of JSON-RPC requests.
        
        Per JSON-RPC 2.0 spec:
        - Empty batch returns Invalid Request error (-32600)
        - Returns array of responses (excluding notifications)
        - Batch with only notifications returns nothing
        """
        # Spec: "If the batch call is empty, return Invalid Request"
        if len(requests) == 0:
            self._send_error(-32600, "Invalid Request: empty batch")
            return
        
        responses = []
        
        for req in requests:
            if not isinstance(req, dict):
                # Invalid item in batch - always needs response
                responses.append(self._build_error(-32600, "Invalid Request: batch item must be object"))
                continue
            
            response = self._handle_single(req)
            if response is not None:  # Skip notifications
                responses.append(response)
        
        # Spec: "If there are no Response objects to return, return nothing"
        if responses:
            self._send_response(responses)
        else:
            # All notifications - no response body
            self.send_response(204)
            self.end_headers()

    def _build_result(self, result: Any, request_id: Any) -> dict:
        """Build a successful response object."""
        return {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id,
        }

    def _build_error(self, code: int, message: str, request_id: Any = None) -> dict:
        """Build an error response object."""
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id,
        }

    def _send_result(self, result: Any, request_id: Any):
        """Send a successful response (deprecated, use _build_result)."""
        self._send_response(self._build_result(result, request_id))

    def _send_error(self, code: int, message: str, request_id: Any = None):
        """Send an error response (for backwards compatibility)."""
        self._send_response(self._build_error(code, message, request_id))

    def _send_response(self, response: dict):
        """Send JSON-RPC response."""
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


def _block_producer(chain, max_errors: int = 10):
    """Background block producer with error recovery.
    
    Stops after max_errors consecutive failures to allow recovery.
    """
    errors = 0
    while errors < max_errors:
        try:
            time.sleep(1)
            if chain.should_build_block():
                chain.build_block()
                errors = 0  # Reset on success
        except Exception as e:
            errors += 1
            print(f"[ERROR] Block producer {errors}/{max_errors}: {e}")
            if errors < max_errors:
                time.sleep(5)  # Backoff
    print("[FATAL] Block producer stopped after max errors")


def serve(chain, host: str = "127.0.0.1", port: int = 8545):
    """Start JSON-RPC server with graceful shutdown."""
    server = create_server(chain, host, port)
    threading.Thread(target=_block_producer, args=(chain,), daemon=True).start()
    
    print(f"JSON-RPC server listening on {host}:{port}")
    print(f"Block production interval: {chain.block_time}s")
    
    def on_signal(signum, frame):
        print("\nShutting down...")
        server.shutdown()
    
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    
    try:
        server.serve_forever()
    finally:
        if hasattr(chain.store, 'close'):
            chain.store.close()
        print("Shutdown complete")