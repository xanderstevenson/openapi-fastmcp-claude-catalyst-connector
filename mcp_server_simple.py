#!/usr/bin/env python3
"""
Catalyst Center MCP Server

A lightweight MCP server that exposes Catalyst Center API functionality to Claude Desktop.
"""

import os
import sys
import json
import time
import ssl
import signal
import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional
from fastmcp import FastMCP
from dotenv import load_dotenv

# Configure logging to stderr for better visibility in Claude Desktop
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("catalyst_mcp")
logger.setLevel(logging.INFO)

# Load environment variables from .env file in the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
    logger.info(f"Loaded environment variables from {env_path}")
else:
    logger.warning(f"No .env file found at {env_path}")

# Log environment variable status (without sensitive values)
required_vars = ['CATALYST_BASE_URL', 'CATALYST_USERNAME', 'CATALYST_PASSWORD']
for var in required_vars:
    if os.getenv(var):
        logger.info(f"Found environment variable: {var}")
    else:
        logger.warning(f"Missing required environment variable: {var}")

# Signal handler for graceful shutdown
def handle_signal(signum, frame):
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

class CatalystCenterClient:
    """Client for interacting with the Cisco Catalyst Center API."""
    
    def __init__(self):
        self.base_url = os.getenv('CATALYST_BASE_URL', '').rstrip('/')
        self.username = os.getenv('CATALYST_USERNAME')
        self.password = os.getenv('CATALYST_PASSWORD')
        self.verify_tls = os.getenv('CATALYST_VERIFY_TLS', 'false').lower() == 'true'  # Default to False for sandbox
        self.timeout = int(os.getenv('CATALYST_TIMEOUT', '60'))  # Increased default timeout to 60 seconds
        self.token = None
        self.session = None
        
        # Log SSL verification status
        if not self.verify_tls:
            logger.warning("SSL verification is DISABLED. This should only be used for development/sandbox environments.")
        else:
            logger.info("SSL verification is ENABLED")
            
        if not all([self.base_url, self.username, self.password]):
            error_msg = "Missing required Catalyst Center configuration in .env"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        logger.info(f"Initialized CatalystCenterClient with base URL: {self.base_url}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        try:
            logger.info("Creating aiohttp session...")
            # Create a custom connector with SSL verification disabled if needed
            ssl_context = ssl.create_default_context()
            if not self.verify_tls:
                logger.warning("SSL verification is DISABLED. This is not recommended for production.")
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create a TCPConnector with our custom SSL context
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit_per_host=5,
                enable_cleanup_closed=True,
                force_close=True
            )
            
            # Create a timeout object
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=10,  # 10 seconds to connect
                sock_connect=10,  # 10 seconds to connect to socket
                sock_read=30  # 30 seconds to read response
            )
            
            # Create the session with retry options
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                connector_owner=True
            )
            
            # Authenticate
            logger.info("Authenticating with Catalyst Center...")
            await self.authenticate()
            logger.info("Successfully authenticated with Catalyst Center")
            return self
            
        except Exception as e:
            error_msg = f"Failed to initialize Catalyst Center client: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if hasattr(self, 'session') and not self.session.closed:
                await self.session.close()
            raise RuntimeError(error_msg) from e
    
    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
    
    async def authenticate(self):
        """Authenticate with Catalyst Center and get an access token."""
        if not all([self.base_url, self.username, self.password]):
            error_msg = "Missing required Catalyst Center configuration in .env"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        auth_url = f"{self.base_url}/dna/system/api/v1/auth/token"
        auth = aiohttp.BasicAuth(self.username, self.password)
        
        logger.info(f"Authenticating with {auth_url}")
        
        try:
            # Increase timeout to 60 seconds with 30s connection timeout
            timeout = aiohttp.ClientTimeout(total=60, connect=30)
            
            async with self.session.post(
                auth_url,
                auth=auth,
                timeout=timeout
            ) as response:
                response.raise_for_status()
                data = await response.json()
                self.token = data.get('Token') or data.get('token')
                
                if not self.token:
                    error_msg = "No token received in authentication response"
                    logger.error(f"{error_msg}. Response: {data}")
                    raise ValueError(error_msg)
                    
                logger.info("Successfully authenticated with Catalyst Center")
                return self.token
                
        except aiohttp.ClientError as e:
            error_msg = f"Network error during authentication: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise RuntimeError("Failed to connect to Catalyst Center. Please check your network connection and try again.") from e
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response from Catalyst Center: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise RuntimeError("Received an invalid response from Catalyst Center. The service may be temporarily unavailable.") from e
            
        except Exception as e:
            error_msg = f"Unexpected error during authentication: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise RuntimeError("An unexpected error occurred during authentication. Please check the logs for more details.") from e
    
    async def get_network_devices(self) -> Dict[str, Any]:
        """
        Get a list of network devices from Catalyst Center.
        
        Returns:
            Dict containing:
            - success: Boolean indicating if the operation was successful
            - response: List of network devices (if successful)
            - error: Error message (if failed)
            - hint: Helpful hint for troubleshooting (if failed)
        """
        start_time = time.time()
        logger.info("Starting to fetch network devices...")
        
        def format_error_response(error_msg, details=None, hint=None):
            """Helper to format consistent error responses."""
            error_msg = str(error_msg)
            logger.error(f"Error in get_network_devices: {error_msg}")
            if details:
                logger.debug(f"Error details: {details}")
            if hint:
                logger.info(f"Hint: {hint}")
                
            response = {
                "success": False,
                "error": error_msg,
            }
            if details:
                response["details"] = str(details)
            if hint:
                response["hint"] = str(hint)
            return response
        
        try:
            # Log environment status with all relevant info (except password)
            logger.info("=== Starting get_network_devices ===")
            logger.info(f"Base URL: {self.base_url}")
            logger.info(f"Username: {self.username}")
            logger.info(f"Verify TLS: {self.verify_tls}")
            logger.info(f"Timeout: {self.timeout} seconds")
            
            # Check for missing configuration
            if not all([self.base_url, self.username, self.password]):
                missing = []
                if not self.base_url:
                    missing.append("CATALYST_BASE_URL")
                if not self.username:
                    missing.append("CATALYST_USERNAME")
                if not self.password:
                    missing.append("CATALYST_PASSWORD")
                error_msg = f"Missing required configuration in .env: {', '.join(missing)}"
                logger.error(error_msg)
                return format_error_response(
                    "Configuration error",
                    details=error_msg,
                    hint="Please check your .env file and ensure all required variables are set"
                )
            
            # Log connection attempt with all details (except password)
            logger.info(f"Connecting to Catalyst Center at {self.base_url}...")
            logger.info(f"Username: {self.username}")
            logger.info(f"Verify TLS: {self.verify_tls}")
            
            # Get or refresh token with detailed error handling
            if not self.token:
                logger.info("No authentication token found, authenticating...")
                try:
                    await self.authenticate()
                    logger.info("Successfully authenticated")
                except aiohttp.ClientError as e:
                    error_msg = f"Network error during authentication: {str(e)}"
                    logger.error(error_msg, exc_info=True)
                    return format_error_response(
                        "Authentication failed - Network error",
                        details=str(e),
                        hint="Check your network connection and Catalyst Center URL"
                    )
                except Exception as e:
                    error_msg = f"Authentication failed: {str(e)}"
                    logger.error(error_msg, exc_info=True)
                    return format_error_response(
                        "Authentication failed",
                        details=str(e),
                        hint="Check your credentials and verify the Catalyst Center is accessible"
                    )
            
            # Build the API endpoint URL
            url = f"{self.base_url}/dna/intent/api/v1/network-device"
            headers = {
                "X-Auth-Token": self.token,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Log request details
            logger.info(f"Preparing API request to: {url}")
            logger.info(f"Using headers: { {k: v for k, v in headers.items() if k != 'X-Auth-Token'} }")
            logger.info(f"SSL Verification: {'Enabled' if self.verify_tls else 'Disabled'}")
            
            try:
                # Log before making the request
                logger.info(f"Sending GET request to: {url}")
                
                # Make the request - SSL is handled by the session's connector
                request_timeout = aiohttp.ClientTimeout(total=45)  # 45 seconds for the request
                
                async with self.session.get(
                    url=url,
                    headers=headers,
                    timeout=request_timeout
                ) as response:
                    # Read and log response details
                    response_text = await response.text()
                    logger.info(f"Response status: {response.status} {response.reason}")
                    
                    # Log response headers for debugging
                    logger.debug(f"Response headers: {dict(response.headers)}")
                    
                    # Check for rate limiting
                    if response.status == 429:
                        retry_after = response.headers.get('Retry-After', '60')
                        error_msg = f"Rate limited. Please try again after {retry_after} seconds."
                        logger.warning(error_msg)
                        return format_error_response(
                            error_msg,
                            hint=f"The API rate limit has been exceeded. Please wait {retry_after} seconds before trying again."
                        )
                    
                    # Check for authentication errors
                    if response.status == 401:
                        error_msg = "Authentication failed. The token may have expired."
                        logger.error(error_msg)
                        return format_error_response(
                            error_msg,
                            hint="Try re-authenticating to get a new token."
                        )
                    
                    # Check for other HTTP errors
                    if response.status >= 400:
                        error_msg = f"HTTP error {response.status}: {response.reason}"
                        logger.error(f"{error_msg}. Response: {response_text}")
                        return format_error_response(
                            error_msg,
                            details=response_text,
                            hint="Check the API documentation for the expected request/response format."
                        )
                    
                    # Try to parse the response as JSON
                    try:
                        data = await response.json()
                        
                        # Check if the response has the expected structure
                        if not isinstance(data, dict) or 'response' not in data:
                            error_msg = "Unexpected response format from Catalyst Center"
                            logger.error(f"{error_msg}. Response: {data}")
                            return format_error_response(
                                error_msg,
                                details=data,
                                hint="The API response format doesn't match expectations. Check the API version and endpoint."
                            )
                        
                        # Log success
                        devices = data.get('response', [])
                        duration = time.time() - start_time
                        logger.info(f"Successfully retrieved {len(devices)} devices in {duration:.2f} seconds")
                        
                        # Log a sample device (first one) for debugging
                        if devices:
                            sample_device = devices[0]
                            logger.debug(f"Sample device: {sample_device.get('hostname')} ({sample_device.get('managementIpAddress')})")
                        
                        return {
                            "success": True,
                            "response": devices,
                            "count": len(devices),
                            "version": "1.0"  # Add version for API compatibility
                        }
                        
                    except json.JSONDecodeError as e:
                        error_msg = f"Failed to parse JSON response: {str(e)}"
                        logger.error(f"{error_msg}. Response text: {response_text}")
                        return format_error_response(
                            "The server returned an invalid response",
                            details=error_msg,
                            hint="Check if the API endpoint is correct and the server is responding as expected."
                        )
                    
            except asyncio.TimeoutError:
                error_msg = "Request to Catalyst Center timed out"
                logger.error(error_msg)
                return format_error_response(
                    error_msg,
                    hint="The request took too long to complete. The server might be under heavy load. Please try again later."
                )
                
            except aiohttp.ClientError as e:
                error_msg = f"Network error while fetching devices: {str(e)}"
                logger.error(error_msg, exc_info=True)
                return format_error_response(
                    "Failed to connect to Catalyst Center",
                    details=str(e),
                    hint="Check your network connection and verify the Catalyst Center URL is correct."
                )
                
        except Exception as e:
            error_msg = f"Unexpected error in get_network_devices: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            # Try to extract more details about the exception
            error_type = type(e).__name__
            error_details = str(e) or "No additional details available"
            
            # Provide more context based on the error type
            if "ConnectionRefusedError" in error_type:
                hint = (
                    f"Connection was refused by {self.base_url}. "
                    "Check if the Catalyst Center service is running and accessible from this network."
                )
            elif "TimeoutError" in error_type or "asyncio.TimeoutError" in error_type:
                hint = (
                    "The request timed out. This could be due to network latency or the service being overloaded. "
                    f"Current timeout is set to {self.timeout} seconds. Consider increasing it if needed."
                )
            elif "SSL" in error_type:
                hint = (
                    "An SSL/TLS error occurred. If this is a development environment, "
                    "you can try setting CATALYST_VERIFY_TLS=false in your .env file."
                )
            else:
                hint = (
                    "An unexpected error occurred. Please check the server logs for more details. "
                    f"Error type: {error_type}"
                )
            
            return format_error_response(
                error_msg,
                details=error_details,
                hint=hint
            )
            
        finally:
            elapsed = time.time() - start_time
            logger.info(f"get_network_devices completed in {elapsed:.2f} seconds")

async def build_mcp():
    mcp = FastMCP("Catalyst Center (FastMCP)")
    
    @mcp.tool(
        name="Get_the_list_of_network_devices",
        description="Get the list of network devices from Catalyst Center",
        output_schema={
            "type": "object",
            "properties": {
                "response": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "hostname": {"type": "string"},
                            "managementIpAddress": {"type": "string"},
                            "type": {"type": "string"},
                            "macAddress": {"type": "string"},
                            "softwareVersion": {"type": "string"},
                            "upTime": {"type": "string"},
                            "role": {"type": "string"},
                            "reachabilityStatus": {"type": "string"}
                        }
                    }
                },
                "version": {"type": "string"}
            },
            "required": ["response", "version"]
        }
    )
    async def get_network_devices():
        """Get network devices with proper response format"""
        async with CatalystCenterClient() as client:
            return await client.get_network_devices()
    
    return mcp

async def main():
    """Run the MCP server."""
    logger.info("Starting Catalyst Center MCP server...")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Working directory: {os.getcwd()}")
    
    try:
        # Build and run the MCP server
        mcp = await build_mcp()
        logger.info("MCP server is running and ready to accept connections")
        await mcp.run_async()
    except Exception as e:
        logger.error(f"Error in MCP server: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
