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

class MCPServer:
    def __init__(self):
        self.VERSION = "0.1.1"
        self.should_exit = False
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

    def log(self, message):
        """Log messages to stderr with timestamp (never stdout)."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sys.stderr.write(f"[{ts}] [MCP] {message}\n")
        sys.stderr.flush()

    def setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown"""
        def handle_signal(signum, frame):
            self.log(f"Signal {signum} received, scheduling shutdown...")
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
                    if response:
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
                    if self.standby_policy == "hold":
                        # Do not respond; keep process alive so client closes transport
                        self.log("Standby(policy=hold) received initialize; waiting for client EOF (no response)")
                        return None
                    # Default policy: respond with error and exit immediately
                    resp = {
                        "jsonrpc": "2.0",
                        "id": (msg_id if msg_id is not None else 0),
                        "error": {"code": -32001, "message": "Initialize rejected: standby instance"}
                    }
                    self.log("Exiting standby (expected) after init reject [policy=immediate]")
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
            
            # Notifications (no id) should not be responded to
            if msg_id is None and method:
                if method == "notifications/cancelled":
                    # Suppress noisy cancellation logs; these are expected when the client
                    # cleans up the losing transport during dual-launch probing.
                    pass
                else:
                    self.log(f"Notification received: {method}")
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
