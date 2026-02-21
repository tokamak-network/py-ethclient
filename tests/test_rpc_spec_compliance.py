#!/usr/bin/env python3
"""
JSON-RPC 2.0 Compliance Test Script

Tests the JSON-RPC server against the official specification:
https://www.jsonrpc.org/specification

Run this script to verify compliance (standard library only):
    python3 tests/test_rpc_spec_compliance.py
"""

import json
import http.client
import threading
import time
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sequencer.sequencer.chain import Chain
from sequencer.rpc.server import create_server


def create_test_chain():
    """Create a test chain for RPC testing."""
    genesis = {
        bytes.fromhex("deadbeef" * 5): {
            "balance": 10**18 * 100,  # 100 ETH
            "nonce": 0,
            "code": b"",
            "storage": {}
        }
    }
    return Chain.from_genesis(genesis, chain_id=1337, block_time=3600)


class RPCTestClient:
    """JSON-RPC test client using stdlib."""
    
    def __init__(self, host="127.0.0.1", port=18545):
        self.host = host
        self.port = port
    
    def send_raw(self, data: str, headers=None) -> tuple:
        """Send raw HTTP request. Returns (status_code, body)."""
        conn = http.client.HTTPConnection(self.host, self.port)
        try:
            headers = headers or {"Content-Type": "application/json"}
            conn.request("POST", "/", body=data, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            body = resp.read().decode('utf-8')
            return status, body
        finally:
            conn.close()
    
    def call(self, method: str, params=None, id_=1) -> dict | None:
        """Make JSON-RPC call."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": id_
        }
        status, body = self.send_raw(json.dumps(payload))
        if status == 204:
            return None
        if not body:
            return None
        return json.loads(body)
    
    def notify(self, method: str, params=None) -> tuple:
        """Send notification (no id)."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or []
        }
        return self.send_raw(json.dumps(payload))


class TestRunner:
    """Run JSON-RPC compliance tests."""
    
    def __init__(self):
        self.server = None
        self.client = None
        self.passed = 0
        self.failed = 0
    
    def setup(self):
        """Start test server."""
        print("Starting test server...")
        chain = create_test_chain()
        self.server = create_server(chain, "127.0.0.1", 18545)
        
        def run_server():
            self.server.serve_forever()
        
        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()
        time.sleep(0.5)  # Give server time to start
        
        self.client = RPCTestClient("127.0.0.1", 18545)
    
    def teardown(self):
        """Stop test server."""
        if self.server:
            self.server.shutdown()
    
    def test(self, name: str, expected: bool, actual: bool, details: str = ""):
        """Record test result."""
        if expected == actual:
            self.passed += 1
            print(f"  ✅ PASS: {name}")
        else:
            self.failed += 1
            print(f"  ❌ FAIL: {name}")
            if details:
                print(f"     Details: {details}")
    
    def run_all(self):
        """Run all compliance tests."""
        print("\n" + "="*70)
        print("JSON-RPC 2.0 Compliance Tests")
        print("https://www.jsonrpc.org/specification")
        print("="*70 + "\n")
        
        self.setup()
        
        try:
            # Test Group 1: Request/Response Format
            print("📋 Test Group 1: Request/Response Format")
            print("-" * 40)
            
            resp = self.client.call("eth_chainId")
            self.test(
                "Response contains jsonrpc field",
                True,
                resp is not None and "jsonrpc" in resp,
                f"Fields: {list(resp.keys()) if resp else 'None'}"
            )
            self.test(
                "jsonrpc version is 2.0",
                True,
                resp is not None and resp.get("jsonrpc") == "2.0",
                f"Version: {resp.get('jsonrpc') if resp else 'None'}"
            )
            self.test(
                "Response contains result field",
                True,
                resp is not None and "result" in resp,
                f"Fields: {list(resp.keys()) if resp else 'None'}"
            )
            self.test(
                "Result contains valid hex string",
                True,
                resp is not None and str(resp.get("result", "")).startswith("0x"),
                f"Result: {resp.get('result') if resp else 'None'}"
            )
            
            # Test Group 2: Error Handling
            print("\n📋 Test Group 2: Error Handling")
            print("-" * 40)
            
            resp = self.client.call("nonexistent_method")
            self.test(
                "Unknown method returns error object",
                True,
                resp is not None and "error" in resp,
                f"Response: {resp}"
            )
            self.test(
                "Method not found error code is -32601",
                True,
                resp is not None and resp.get("error", {}).get("code") == -32601,
                f"Code: {resp.get('error', {}).get('code') if resp else 'None'}"
            )
            
            # Parse error test
            status, body = self.client.send_raw("invalid json {{{")
            try:
                result = json.loads(body)
                parse_error = result.get("error", {}).get("code") == -32700
            except:
                parse_error = False
            
            self.test(
                "Invalid JSON returns parse error (-32700)",
                True,
                parse_error,
                f"Body: {body[:100]}"
            )
            
            # Test Group 3: Request ID
            print("\n📋 Test Group 3: Request ID Preservation")
            print("-" * 40)
            
            resp = self.client.call("eth_chainId", id_=42)
            self.test(
                "Numeric ID is preserved in response (id=42)",
                True,
                resp is not None and resp.get("id") == 42,
                f"ID: {resp.get('id') if resp else 'None'}"
            )
            
            resp = self.client.call("eth_chainId", id_="my-id")
            self.test(
                "String ID is preserved",
                True,
                resp is not None and resp.get("id") == "my-id",
                f"ID: {resp.get('id') if resp else 'None'}"
            )
            
            resp = self.client.call("eth_chainId", id_=0)
            self.test(
                "ID 0 is preserved (not treated as falsy)",
                True,
                resp is not None and resp.get("id") == 0,
                f"ID: {resp.get('id') if resp else 'None'}"
            )
            
            # Test Group 4: Notifications
            print("\n📋 Test Group 4: Notifications")
            print("-" * 40)
            print("  Spec: Notification = request WITHOUT 'id' field (NOT id: null)")
            print("  Spec: Server MUST NOT reply to notifications, including invalid ones")
            
            # Valid notification - no id field
            status, body = self.client.send_raw(json.dumps({
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": []
            }))
            self.test(
                "Valid notification (no 'id' field) returns no response",
                True,
                status == 204 or (status == 200 and not body),
                f"Status: {status}, Body: {repr(body) if body else '(empty)'[:100]}"
            )
            
            # Invalid notification - missing jsonrpc, no id
            status, body = self.client.send_raw(json.dumps({
                "method": "eth_chainId",
                "params": []
            }))
            self.test(
                "Invalid notification (missing jsonrpc) returns no response",
                True,
                status == 204 or (status == 200 and not body),
                f"Status: {status}, Body: {repr(body) if body else '(empty)'[:100]}"
            )
            
            # Invalid notification - invalid method, no id
            status, body = self.client.send_raw(json.dumps({
                "jsonrpc": "2.0",
                "method": "nonexistent_method",
                "params": []
            }))
            self.test(
                "Invalid notification (bad method) returns no response",
                True,
                status == 204 or (status == 200 and not body),
                f"Status: {status}, Body: {repr(body) if body else '(empty)'[:100]}"
            )
            
            # Request with id: null IS NOT a notification per spec
            status, body = self.client.send_raw(json.dumps({
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": [],
                "id": None
            }))
            self.test(
                "Request with id: null returns response (not a notification)",
                True,
                status == 200 and "id" in json.loads(body),
                f"Status: {status}, Body: {repr(body)[:100]}"
            )
            
            # Test Group 5: Batch Requests
            print("\n📋 Test Group 5: Batch Requests")
            print("-" * 40)
            print("  Spec: Batch requests [...] should return array of responses [...]")
            print("  Spec: Empty batch [] should return Invalid Request error")
            
            # Normal batch
            status, body = self.client.send_raw(json.dumps([
                {"jsonrpc": "2.0", "method": "eth_chainId", "id": 1},
                {"jsonrpc": "2.0", "method": "eth_blockNumber", "id": 2}
            ]))
            try:
                result = json.loads(body)
                is_array = isinstance(result, list)
                batch_works = is_array and len(result) == 2
            except:
                is_array = False
                batch_works = False
            
            self.test(
                "Batch request returns array of responses",
                True,
                batch_works,
                f"Status: {status}, Is array: {is_array}, Body: {body[:100]}"
            )
            
            # Empty batch - should return error
            status, body = self.client.send_raw(json.dumps([]))
            try:
                result = json.loads(body)
                is_error = "error" in result and result.get("error", {}).get("code") == -32600
            except:
                is_error = False
            
            self.test(
                "Empty batch [] returns Invalid Request error (-32600)",
                True,
                is_error,
                f"Status: {status}, Body: {body[:100]}"
            )
            
            # Batch with mix of requests and notifications
            status, body = self.client.send_raw(json.dumps([
                {"jsonrpc": "2.0", "method": "eth_chainId", "id": 1},
                {"jsonrpc": "2.0", "method": "eth_blockNumber"}  # notification
            ]))
            try:
                result = json.loads(body)
                # Should only have 1 response (notification is ignored)
                correct = isinstance(result, list) and len(result) == 1
            except:
                correct = False
            
            self.test(
                "Batch with notification returns only non-notification responses",
                True,
                correct,
                f"Status: {status}, Body: {body[:100]}"
            )
            
            # Test Group 6: Content-Type
            print("\n📋 Test Group 6: Content-Type Header")
            print("-" * 40)
            print("  Note: Spec recommends application/json but doesn't mandate rejection")
            
            status, body = self.client.send_raw(
                json.dumps({"jsonrpc": "2.0", "method": "eth_chainId", "id": 1}),
                headers={"Content-Type": "text/plain"}
            )
            self.test(
                "Wrong Content-Type returns 200 (optional behavior)",
                False,  # Not expected to reject
                status != 200,  # Does it reject?
                f"Status: {status}"
            )
            
            # Test Group 7: Error Structure
            print("\n📋 Test Group 7: Error Response Structure")
            print("-" * 40)
            
            resp = self.client.call("nonexistent_method")
            self.test(
                "Error response contains 'error' object",
                True,
                isinstance(resp.get("error"), dict) if resp else False,
                f"Error type: {type(resp.get('error')).__name__ if resp else 'None'}"
            )
            if resp and isinstance(resp.get("error"), dict):
                self.test(
                    "Error object has 'code' field (integer)",
                    True,
                    isinstance(resp["error"].get("code"), int),
                    f"Code type: {type(resp['error'].get('code')).__name__}"
                )
                self.test(
                    "Error object has 'message' field (string)",
                    True,
                    isinstance(resp["error"].get("message"), str),
                    f"Message: {resp['error'].get('message', '')[:50]}"
                )
            
            # Test Group 8: Missing jsonrpc field
            print("\n📋 Test Group 8: Request Validation")
            print("-" * 40)
            
            status, body = self.client.send_raw(json.dumps({
                "method": "eth_chainId",  # Missing jsonrpc field
                "params": [],
                "id": 1
            }))
            try:
                result = json.loads(body)
                version_validated = "error" in result
            except:
                version_validated = False
            
            self.test(
                "Missing 'jsonrpc' field rejected (spec requires)",
                True,  # Should reject
                version_validated,  # Does it reject?
                f"Body: {body[:100]}"
            )
            
        finally:
            self.teardown()
        
        # Summary
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        total = self.passed + self.failed
        pct = (self.passed / total * 100) if total > 0 else 0
        print(f"Total Tests:  {total}")
        print(f"Passed:       {self.passed} ✅")
        print(f"Failed:       {self.failed} ❌")
        print(f"Success Rate: {pct:.1f}%")
        print("="*70)
        
        # Compliance Grade
        print("\n📊 JSON-RPC 2.0 COMPLIANCE GRADE:")
        if self.failed == 0:
            print("   A - Fully Compliant")
            print("\n✅ This implementation follows JSON-RPC 2.0 specification")
        elif pct >= 90:
            print("   B - Mostly Compliant (Minor Issues)")
        elif pct >= 80:
            print("   C - Partially Compliant (Some Issues)")
        elif pct >= 70:
            print("   D - Limited Compliance (Major Issues)")
        else:
            print("   F - Non-Compliant (Critical Deficiencies)")
        
        print("\n🔍 Key Findings:")
        if self.failed > 0:
            print("   • Review failed tests above for specific issues")
        else:
            print("   • All critical JSON-RPC 2.0 requirements met")
            print("   • Ready for Ethereum client integration")
        
        return self.failed == 0


if __name__ == "__main__":
    runner = TestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)
