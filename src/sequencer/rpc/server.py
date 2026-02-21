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
import sys
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


def _block_producer(chain):
    """Background thread that produces blocks at regular intervals.
    
    Includes error handling to prevent silent crashes. After 10 consecutive
    errors, the thread stops to allow for recovery mechanisms.
    """
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    while True:
        try:
            time.sleep(1)
            if chain.should_build_block():
                chain.build_block()
                consecutive_errors = 0  # Reset on success
        except Exception as e:
            consecutive_errors += 1
            print(f"[CRITICAL] Block producer error ({consecutive_errors}/{max_consecutive_errors}): {e}")
            if consecutive_errors >= max_consecutive_errors:
                print(f"[FATAL] Too many consecutive errors, stopping block production")
                break  # Stop thread, let main process handle recovery
            time.sleep(5)  # Backoff on error


def serve(chain, host: str = "127.0.0.1", port: int = 8545):
    """Start the JSON-RPC server with graceful shutdown support.
    
    Handles SIGINT and SIGTERM to properly close database connections
    and shutdown the server.
    """
    server = create_server(chain, host, port)
    
    block_thread = threading.Thread(target=_block_producer, args=(chain,), daemon=True)
    block_thread.start()
    
    print(f"JSON-RPC server listening on {host}:{port}")
    print(f"Block production interval: {chain.block_time}s")
    
    # Setup graceful shutdown
    def shutdown_handler(signum, frame):
        print("\nShutting down gracefully...")
        server.shutdown()
        # Close database connection if available
        if hasattr(chain, 'store') and hasattr(chain.store, 'close'):
            chain.store.close()
            print("Database connection closed")
        print("Shutdown complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    try:
        server.serve_forever()
    finally:
        # Ensure cleanup even if serve_forever raises
        if hasattr(chain, 'store') and hasattr(chain.store, 'close'):
            chain.store.close()