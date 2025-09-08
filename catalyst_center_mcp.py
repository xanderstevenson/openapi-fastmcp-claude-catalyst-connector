#!/usr/bin/env python3
"""
Cisco Catalyst Center MCP Server

A lightweight MCP server that exposes read-only Catalyst Center API functionality.
"""
import asyncio
import os
import logging
import aiohttp
from fastmcp import FastMCP
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("catalyst_mcp")

# Load environment variables from .env file in the current directory
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
    logger.info(f"Loaded environment variables from {env_path}")
else:
    logger.warning(f"No .env file found at {env_path}, using system environment variables")

class CatalystCenterClient:
    """Client for interacting with the Cisco Catalyst Center API."""
    
    def __init__(self):
        # Get environment variables
        self.base_url = os.getenv('CATALYST_BASE_URL', '').rstrip('/')
        self.username = os.getenv('CATALYST_USERNAME')
        self.password = os.getenv('CATALYST_PASSWORD')
        self.verify_tls = os.getenv('CATALYST_VERIFY_TLS', 'false').lower() == 'true'
        self.timeout = int(os.getenv('CATALYST_TIMEOUT', '60'))
        self.token = None
        self.session = None
        
        # Log environment variable status (without sensitive data)
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"Username: {'*' * (len(self.username) if self.username else 0)}")
        logger.info(f"Verify TLS: {self.verify_tls}")
        
        # Validate required environment variables
        missing_vars = []
        if not self.base_url:
            missing_vars.append("CATALYST_BASE_URL")
        if not self.username:
            missing_vars.append("CATALYST_USERNAME")
        if not self.password:
            missing_vars.append("CATALYST_PASSWORD")
            
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
    
    async def authenticate(self):
        """Authenticate with Catalyst Center and get an access token."""
        auth_url = f"{self.base_url}/dna/system/api/v1/auth/token"
        auth = aiohttp.BasicAuth(self.username, self.password)
        
        try:
            timeout = aiohttp.ClientTimeout(total=60, connect=30)
            async with self.session.post(
                auth_url,
                auth=auth,
                timeout=timeout,
                ssl=False if not self.verify_tls else None
            ) as response:
                response.raise_for_status()
                data = await response.json()
                self.token = data.get('Token') or data.get('token')
                
                if not self.token:
                    raise ValueError("No token received in authentication response")
                
                logger.info("Successfully authenticated with Catalyst Center")
                return self.token
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise
    
    async def make_request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make an authenticated request to the Catalyst Center API."""
        if not self.token:
            await self.authenticate()
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            'X-Auth-Token': self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        if 'headers' in kwargs:
            headers.update(kwargs.pop('headers'))
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                ssl=False if not self.verify_tls else None,
                **kwargs
            ) as response:
                response.raise_for_status()
                if response.status == 204:  # No content
                    return {}
                return await response.json()
        except Exception as e:
            logger.error(f"API request to {endpoint} failed: {str(e)}")
            raise

async def build_mcp():
    """Build and return the MCP server with all tools."""
    mcp = FastMCP("Cisco Catalyst Center")
    
    @mcp.tool(
        name="Get_Network_Devices",
        description="Get a list of all network devices managed by Catalyst Center",
        output_schema={"type": "object"}
    )
    async def get_network_devices():
        """Get a list of all network devices managed by Catalyst Center."""
        try:
            async with CatalystCenterClient() as client:
                response = await client.make_request("GET", "/dna/intent/api/v1/network-device")
                logger.info(f"Successfully retrieved {len(response.get('response', []))} network devices")
                return response
        except Exception as e:
            logger.error(f"Error in Get_Network_Devices: {str(e)}")
            raise ValueError(f"Failed to get network devices: {str(e)}")
    
    @mcp.tool(
        name="Get_Network_Health",
        description="Get the overall network health status",
        output_schema={"type": "object"}
    )
    async def get_network_health():
        """Get the overall network health status."""
        try:
            async with CatalystCenterClient() as client:
                response = await client.make_request("GET", "/dna/intent/api/v1/network-health")
                health_score = response.get('response', [{}])[0].get('healthScore', 'N/A')
                logger.info(f"Network health score: {health_score}")
                return response
        except Exception as e:
            logger.error(f"Error in Get_Network_Health: {str(e)}")
            raise ValueError(f"Failed to get network health: {str(e)}")
    
    # @mcp.tool(
    #     name="Get_Client_Health",
    #     description="Get client health statistics",
    #     output_schema={"type": "object"}
    # )
    # async def get_client_health():
    #     """Get client health statistics."""
    #     try:
    #         async with CatalystCenterClient() as client:
    #             response = await client.make_request("GET", "/dna/intent/api/v1/client-health")
    #             logger.info("Successfully retrieved client health statistics")
    #             return response
    #     except Exception as e:
    #         logger.error(f"Error in Get_Client_Health: {str(e)}")
    #         raise ValueError(f"Failed to get client health: {str(e)}")
    
    # @mcp.tool(
    #     name="Get_Site_Topology",
    #     description="Get the site topology information",
    #     output_schema={"type": "object"}
    # )
    # async def get_site_topology():
    #     """Get the site topology information."""
    #     try:
    #         async with CatalystCenterClient() as client:
    #             response = await client.make_request("GET", "/dna/intent/api/v1/topology/site-topology")
    #             sites = response.get('response', {}).get('sites', [])
    #             logger.info(f"Found {len(sites)} sites in topology")
    #             return response
    #     except Exception as e:
    #         logger.error(f"Error in Get_Site_Topology: {str(e)}")
    #         raise ValueError(f"Failed to get site topology: {str(e)}")
    
    @mcp.tool(
        name="Get_Device_Interfaces",
        description="Get interfaces for a specific device",
        output_schema={"type": "object"}
    )
    async def get_device_interfaces(device_id: str):
        """Get interfaces for a specific device.
        
        Args:
            device_id: The ID of the device
        """
        try:
            if not device_id:
                raise ValueError("Device ID is required")
                
            async with CatalystCenterClient() as client:
                response = await client.make_request(
                    "GET", 
                    f"/dna/intent/api/v1/interface/network-device/{device_id}"
                )
                interfaces = response.get('response', [])
                logger.info(f"Found {len(interfaces)} interfaces for device {device_id}")
                return response
        except Exception as e:
            logger.error(f"Error in Get_Device_Interfaces: {str(e)}")
            raise ValueError(f"Failed to get device interfaces: {str(e)}")
    
    @mcp.tool(
        name="Get_Device_Details",
        description="Get detailed information about a specific device",
        output_schema={"type": "object"}
    )
    async def get_device_details(device_id: str):
        """Get detailed information about a specific device.
        
        Args:
            device_id: The ID of the device
        """
        try:
            if not device_id:
                raise ValueError("Device ID is required")
                
            async with CatalystCenterClient() as client:
                response = await client.make_request(
                    "GET", 
                    f"/dna/intent/api/v1/network-device/{device_id}"
                )
                logger.info(f"Retrieved details for device {device_id}")
                return response
        except Exception as e:
            logger.error(f"Error in Get_Device_Details: {str(e)}")
            raise ValueError(f"Failed to get device details: {str(e)}")
    
    return mcp

async def main():
    """Run the MCP server."""
    try:
        mcp = await build_mcp()
        logger.info("MCP server is running and ready to accept connections")
        await mcp.run_async()
    except Exception as e:
        logger.error(f"Error in MCP server: {e}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
