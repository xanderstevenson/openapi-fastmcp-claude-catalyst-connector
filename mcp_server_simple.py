#!/usr/bin/env python3

import json
import sys
import os
import time
import traceback
import signal
import asyncio
import fcntl
import select
import dotenv
from dotenv import load_dotenv
import requests
import urllib3

class MCPServer:
    def __init__(self):
        self.VERSION = "0.1.1"
        self.should_exit = False
        self.graceful_shutdown_deadline = None  # when set, delay exit until this time
        self.initialized = False
        self.last_activity = time.time()
        self.lock_file = None
        self.lock_path = "/tmp/catalyst_center_mcp.lock"
        self.is_primary = True  # becomes False if another instance already holds the lock
        # Standby behavior policy
        # Force 'immediate' to ensure losing transport does not receive discovery and
        # to avoid 5s cancellations and attach instability in Claude Desktop.
        self.standby_policy = "immediate"
        
        # Record original signal handlers and install our handlers
        self.original_sigint = signal.getsignal(signal.SIGINT)
        self.original_sigterm = signal.getsignal(signal.SIGTERM)
        self.setup_signal_handlers()
        self.log("Signal handlers installed")

        # Enforce single instance using file lock
        self.acquire_single_instance_lock()
        
        # No special stdout tracking; rely on immediate exit on BrokenPipe
        
        # Define available tools
        self.tools = [
            {
                "name": "get_network_devices",
                "description": "Get a list of network devices from Catalyst Center",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "health_check",
                "description": "Check if the server is running",
                "inputSchema": {"type": "object", "properties": {}}
            }
        ]

        self._load_config()

    def log(self, message):
        """Log messages to stderr with timestamp (never stdout)."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sys.stderr.write(f"[{ts}] [MCP] {message}\n")
        sys.stderr.flush()

    def setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown"""
        def handle_signal(signum, frame):
            self.log(f"Signal {signum} received, scheduling graceful shutdown...")
            # Give the client a brief window to detach without surfacing warnings
            self.graceful_shutdown_deadline = time.time() + 2.0
            self.should_exit = True
            
        # Save original signal handlers
        self.original_handlers = {
            signal.SIGINT: signal.getsignal(signal.SIGINT),
            signal.SIGTERM: signal.getsignal(signal.SIGTERM)
        }
        
        # Set new signal handlers that trigger graceful shutdown
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    def acquire_single_instance_lock(self):
        """Acquire an exclusive lock. If already locked, switch to standby mode and do NOT block.

        Standby mode (is_primary=False): respond immediately with JSON-RPC errors and exit,
        preventing client-side request timeouts from a blocked process.
        """
        try:
            self.lock_file = open(self.lock_path, "w")
            try:
                # Attempt non-blocking; if locked, do NOT block (enter standby)
                fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.is_primary = False
                self.log("Another instance is running; entering standby (non-primary) mode")
                # Close the file since we didn't acquire the lock
                try:
                    self.lock_file.close()
                finally:
                    self.lock_file = None
                return
            # We acquired the primary lock
            self.lock_file.write(str(os.getpid()))
            self.lock_file.flush()
            self.log(f"Acquired single-instance lock at {self.lock_path}")
        except Exception as e:
            self.log(f"Warning: failed to acquire lock: {e}. Continuing without lock.")

    def release_single_instance_lock(self):
        try:
            if self.lock_file is not None:
                fcntl.flock(self.lock_file, fcntl.LOCK_UN)
                self.lock_file.close()
                self.lock_file = None
                self.log("Released single-instance lock")
        except Exception as e:
            self.log(f"Warning: failed to release lock: {e}")

    def send_response(self, response):
        """Send a JSON-RPC response"""
        if not response:
            return
        
        response_str = json.dumps(response)
        self.log(f"Sending: {response_str}")
        try:
            print(response_str, flush=True)
        except BrokenPipeError:
            # Client closed stdout; exit gracefully to avoid noisy stack traces
            self.log("Stdout closed (BrokenPipe); exiting main loop gracefully")
            self.should_exit = True
            return
        self.last_activity = time.time()

    def handle_initialize(self, message):
        """Handle initialize request"""
        self.log("Handling initialize request")
        self.initialized = True
        protocol_version = None
        try:
            params = message.get("params") or {}
            protocol_version = params.get("protocolVersion")
        except Exception:
            protocol_version = None
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": protocol_version or "2025-06-18",
                "capabilities": {
                    "resources": {},
                    "prompts": {},
                    "tools": {}
                },
                "serverInfo": {
                    "name": "Catalyst Center MCP",
                    "version": self.VERSION
                }
            }
        }

    def handle_health_check(self, message):
        """Handle health check request"""
        self.log("Handling health check")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "status": "ok",
                "version": self.VERSION
            }
        }

    def handle_get_network_devices(self, message):
        """Handle get_network_devices request"""
        self.log("Handling get_network_devices")
        # Try real Catalyst Center if credentials are present; otherwise fallback to mock
        if self.cc_base_url and (getattr(self, 'cc_token', None) or (self.cc_username and self.cc_password)):
            try:
                path = self._resolve_network_devices_path()
                using_direct_token = bool(getattr(self, 'cc_token', None))
                self.log(f"Device fetch setup: base_url={self.cc_base_url}, path={path}, using_direct_token={using_direct_token}")
                token = self.cc_token if using_direct_token else self._cc_get_token()
                payload = self._cc_get(path, token)
                # DNAC typically returns { "response": [ ... ] }
                items = payload.get("response") if isinstance(payload, dict) else None
                if items is None:
                    # Some specs use a top-level list
                    items = payload if isinstance(payload, list) else []
                devices = []
                for d in items:
                    if not isinstance(d, dict):
                        continue
                    dev_id = d.get("id") or d.get("serialNumber") or d.get("macAddress") or d.get("instanceUuid") or "unknown"
                    name = d.get("hostname") or d.get("managementIpAddress") or d.get("name") or dev_id
                    status = d.get("reachabilityStatus") or d.get("collectionStatus") or d.get("deviceSupportLevel") or "unknown"
                    devices.append({"id": dev_id, "name": name, "status": status})
                self.log(f"Fetched {len(devices)} devices from Catalyst Center")
                return {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {"devices": devices}
                }
            except Exception as e:
                self.log(f"Catalyst Center fetch failed, falling back to mock: {e}")
                try:
                    self.log(traceback.format_exc())
                except Exception:
                    pass
                # fall through to mock
        # Mock fallback
        self.log("Using mock devices (no valid Catalyst Center response/config)")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "devices": [
                    {"id": "device1", "name": "Switch 1", "status": "up"},
                    {"id": "device2", "name": "Router 1", "status": "up"}
                ]
            }
        }

    def handle_tools_list(self, message):
        """Handle MCP tools/list request"""
        self.log("Handling tools/list")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "tools": self.tools
            }
        }

    def handle_resources_list(self, message):
        """Handle MCP resources/list request (return empty list)"""
        self.log("Handling resources/list")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "resources": [
                    {
                        "uri": "mcp://catalyst-center/README",
                        "name": "Catalyst Center MCP README",
                        "description": "About this MCP server",
                        "mimeType": "text/plain"
                    }
                ]
            }
        }

    def handle_prompts_list(self, message):
        """Handle MCP prompts/list request (return empty list)"""
        self.log("Handling prompts/list")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "prompts": [
                    {
                        "name": "health_check",
                        "description": "Check server health using the health_check tool",
                        "arguments": []
                    }
                ]
            }
        }

    def handle_resources_read(self, message):
        """Handle MCP resources/read request (return contents)"""
        self.log("Handling resources/read")
        params = message.get("params") or {}
        uri = params.get("uri") or params.get("uris", [None])[0]
        if uri == "mcp://catalyst-center/README":
            content = {
                "type": "text",
                "text": "Catalyst Center MCP server is running. Tools: health_check, get_network_devices.",
                "mimeType": "text/plain"
            }
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "contents": [content]
                }
            }
        # Unknown resource: return empty contents
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"contents": []}
        }

    def handle_prompts_get(self, message):
        """Handle MCP prompts/get request (return a simple prompt)"""
        self.log("Handling prompts/get")
        params = message.get("params") or {}
        name = params.get("name")
        if name == "health_check":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "messages": [
                        {"role": "system", "content": [{"type": "text", "text": "Run the health_check tool to verify server status."}]}
                    ]
                }
            }
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32601, "message": f"Prompt not found: {name}"}
        }

    def handle_tools_call(self, message):
        """Handle MCP tools/call request by dispatching to our tools"""
        self.log("Handling tools/call")
        params = message.get("params") or {}
        name = params.get("name") or params.get("toolName")
        arguments = params.get("arguments") or {}
        # Map to existing handlers
        if name == "health_check":
            res = self.handle_health_check({"id": message.get("id")})
            # Wrap tool result shape
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res.get("result"))}],
                    "isError": False
                }
            }
        elif name == "get_network_devices":
            res = self.handle_get_network_devices({"id": message.get("id"), "params": arguments})
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res.get("result"))}],
                    "isError": False
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": f"Unknown tool: {name}"}
            }

    async def run(self):
        """Main server loop"""
        self.log("Starting MCP server main loop")
        self.log("Server is now running with graceful SIGTERM/SIGINT handling")
        
        # Main server loop
        while not self.should_exit:
            try:
                # Check for input with a short timeout to minimize latency (< client timeout)
                rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
                
                if rlist:
                    line = sys.stdin.readline()
                    if not line:
                        # EOF from stdin: client closed the transport; exit cleanly
                        self.log("EOF on stdin; exiting main loop")
                        break
                        
                    response = self.process_message(line)
                    if response and not self.should_exit:
                        self.send_response(response)
                        # Standby instances stay alive and keep responding quickly with errors
                        # so the client transport remains open and no timeouts occur.
                
                # No unsolicited keep-alive notifications; MCP client manages transport
                
            except asyncio.CancelledError:
                self.log("Server loop cancelled")
                break
            except Exception as e:
                self.log(f"Error in server loop: {e}")
                self.log(traceback.format_exc())
                break
        
        # If graceful shutdown requested, wait briefly to allow client to detach quietly
        if self.graceful_shutdown_deadline:
            remaining = self.graceful_shutdown_deadline - time.time()
            while remaining > 0:
                try:
                    # Drain stdin without responding
                    rlist, _, _ = select.select([sys.stdin], [], [], min(0.05, remaining))
                    if rlist:
                        _ = sys.stdin.readline()
                    remaining = self.graceful_shutdown_deadline - time.time()
                except Exception:
                    break

        self.log("MCP server main loop ended")

    def process_message(self, line):
        """Process a single JSON-RPC message"""
        try:
            if not line or not line.strip():
                return None
                
            message = json.loads(line)
            method = message.get("method", "")
            msg_id = message.get("id", None)
            # Avoid dumping full payload for noisy cancellation notifications
            if method == "notifications/cancelled":
                pass
            else:
                self.log(f"Received: {json.dumps(message, indent=2)}")

            # If this is a standby instance, emulate minimal valid responses for discovery calls
            # so Claude's dual-probe startup succeeds without timeouts, but avoid executing tools.
            if not self.is_primary:
                # Standby behavior depends on policy
                if method == "initialize":
                    # Minimal change: always ignore initialize in standby to avoid client-facing errors
                    self.log("Standby received initialize; waiting for client EOF (no response)")
                    return None
                # For discovery requests, return minimal successful responses immediately, then exit
                if msg_id is not None and method in ("tools/list", "prompts/list", "resources/list"):
                    if method == "tools/list":
                        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": self.tools}}
                    elif method == "prompts/list":
                        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": [{"name": "health_check", "description": "Check server health using the health_check tool", "arguments": []}]}}
                    else:  # resources/list
                        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": [{"uri": "mcp://catalyst-center/README", "name": "Catalyst Center MCP README", "description": "About this MCP server", "mimeType": "text/plain"}]}}
                    self.log(f"Standby responded minimally to {method}; exiting standby")
                    self.should_exit = True
                    return resp
                if msg_id is not None:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": f"Method not handled in standby: {method}"}
                    }
                    # After sending this response, exit to avoid dual-transport races
                    # Cosmetic: make intentional standby exit obvious in logs
                    self.log(f"Exiting standby (expected) after handling method on standby: {method}")
                    self.should_exit = True
                    return resp
                # For notifications on standby, ignore without exiting so we can
                # handle and immediately error the first discovery call, then exit.
                return None
            
            if method == "initialize":
                return self.handle_initialize(message)
            elif method == "health_check":
                return self.handle_health_check(message)
            elif method == "get_network_devices":
                return self.handle_get_network_devices(message)
            elif method == "resources/list":
                return self.handle_resources_list(message)
            elif method == "resources/read":
                return self.handle_resources_read(message)
            elif method == "prompts/list":
                return self.handle_prompts_list(message)
            elif method == "prompts/get":
                return self.handle_prompts_get(message)
            elif method == "tools/call":
                return self.handle_tools_call(message)
            elif method == "tools/list":
                return self.handle_tools_list(message)
            elif method == "shutdown":
                # Optional: allow explicit shutdown request
                self.should_exit = True
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"ok": True}
                }
            else:
                # Only send error for requests (with id)
                if msg_id is not None:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}"
                        }
                    }
                return None
                
        except json.JSONDecodeError as e:
            self.log(f"JSON decode error: {e}")
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error"
                }
            }
        except Exception as e:
            self.log(f"Error processing message: {e}")
            self.log(traceback.format_exc())
            return {
                "jsonrpc": "2.0",
                "id": message.get("id") if 'message' in locals() else None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }

    def _load_config(self):
        """Load configuration from environment/.env without affecting MCP behavior."""
        try:
            # Load .env from the script directory to avoid CWD issues under Claude Desktop
            env_path = os.path.join(os.path.dirname(__file__), ".env")
            load_dotenv(dotenv_path=env_path)
        except Exception:
            pass
        # Defaults chosen to be safe (TLS verify on). Base URL defaults to sandbox if not provided.
        self.cc_base_url = os.getenv("CATALYST_BASE_URL", "https://sandboxdnac.cisco.com").rstrip("/")
        self.cc_username = os.getenv("CATALYST_USERNAME")
        self.cc_password = os.getenv("CATALYST_PASSWORD")
        # Optional direct token support
        self.cc_token = os.getenv("CATALYST_TOKEN")
        self.cc_verify_tls = str(os.getenv("CATALYST_VERIFY_TLS", "true")).lower() != "false"
        try:
            self.cc_timeout = float(os.getenv("CATALYST_TIMEOUT", "15"))
        except Exception:
            self.cc_timeout = 15.0
        # Suppress TLS warnings only if verification is explicitly disabled
        try:
            if not self.cc_verify_tls:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        # Safe config log (no secrets)
        try:
            self.log(
                f"Catalyst config: base_url={self.cc_base_url}, username_set={'yes' if self.cc_username else 'no'}, token_set={'yes' if self.cc_token else 'no'}, verify_tls={self.cc_verify_tls}, timeout={self.cc_timeout}s"
            )
        except Exception:
            pass

    def _resolve_network_devices_path(self):
        """Resolve the network devices endpoint path (default DNAC path)."""
        return "/dna/intent/api/v1/network-device"

    def _cc_get_token(self):
        """Obtain an X-Auth-Token from Catalyst Center using basic auth."""
        if not (self.cc_username and self.cc_password):
            raise RuntimeError("Catalyst Center credentials not set")
        url = f"{self.cc_base_url}/dna/system/api/v1/auth/token"
        self.log(f"Auth: POST {url} (verify_tls={self.cc_verify_tls}, timeout={self.cc_timeout}s)")
        resp = requests.post(
            url,
            auth=(self.cc_username, self.cc_password),
            headers={"Content-Type": "application/json"},
            verify=self.cc_verify_tls,
            timeout=self.cc_timeout,
        )
        self.log(f"Auth response: status={resp.status_code}")
        if resp.status_code >= 400:
            raise RuntimeError(f"Auth failed ({resp.status_code})")
        ct = resp.headers.get("content-type", "")
        data = resp.json() if "application/json" in ct else {}
        token = data.get("Token") or data.get("token")
        if not token:
            raise RuntimeError("No token in auth response")
        return token

    def _cc_get(self, path, token):
        """GET helper for Catalyst Center with X-Auth-Token."""
        url = f"{self.cc_base_url}{path}"
        self.log(f"GET {url} (verify_tls={self.cc_verify_tls}, timeout={self.cc_timeout}s)")
        headers = {"Content-Type": "application/json", "X-Auth-Token": token}
        resp = requests.get(url, headers=headers, verify=self.cc_verify_tls, timeout=self.cc_timeout)
        self.log(f"GET response: status={resp.status_code}")
        if resp.status_code >= 400:
            raise RuntimeError(f"Request failed ({resp.status_code})")
        return resp.json()

def main():
    server = MCPServer()
    
    # Create a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Run the server
        server.log(f"Starting MCP server v{server.VERSION} (graceful SIGTERM/SIGINT)")
        loop.run_until_complete(server.run())
    except Exception as e:
        server.log(f"Fatal error: {e}")
        server.log(traceback.format_exc())
    finally:
        # Release single-instance lock
        server.release_single_instance_lock()
        loop.close()
        server.log("MCP server stopped")

if __name__ == "__main__":
    import select
    main()
