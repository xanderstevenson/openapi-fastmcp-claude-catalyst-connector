#!/usr/bin/env python3
"""
Cisco Catalyst Center MCP Server for Claude Desktop

A Model Control Plane (MCP) server that enables Claude Desktop to interact with
Cisco Catalyst Center (formerly DNA Center) through its REST API.

🔧 Available Tools:
1. @Get_Network_Devices - List all network devices with status and details
2. @Get_Network_Health - View overall network health metrics and scores
3. @Get_Device_Interfaces - Get interface details for a specific device
4. @Get_Device_Details - Get comprehensive information about a specific device

Usage Examples:
- "Show me all network devices with high CPU usage"
- "What's the current health score of our network?"
- "List all interfaces on device with ID xyz"
- "Show me details for device ABC-123"

Security Note:
- All API calls are authenticated using environment variables
- No sensitive data is logged or exposed in responses
- TLS verification can be enabled via configuration

Pro Tips:
- Use @Get_Network_Devices first to find device IDs
- Check network health before diving into device details
- For interface issues, use @Get_Device_Interfaces with the device ID
- All tools are read-only - no configuration changes can be made
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
        description="""Retrieve a comprehensive list of all network devices managed by Catalyst Center.
        
        This tool provides detailed information about each network device including:
        - Device hostname and IP address
        - Device type and model
        - Software version
        - Reachability status
        - Uptime and last updated timestamp
        
        Example usage in Claude Desktop:
        @Get_Network_Devices
        
        Note: For large networks, consider filtering the results by device type
        or location if you need specific information.
        """,
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
        description="""Retrieve the overall health status of the network.
        
        This tool provides a comprehensive view of the network's health, including:
        - Overall health score (0-100)
        - Health scores by category (wired, wireless, etc.)
        - Number of healthy, warning, and critical devices
        - Trend information and historical comparison
        
        Example usage in Claude Desktop:
        @Get_Network_Health
        
        Note: The health score is calculated based on various factors including
        device status, interface errors, and performance metrics. A score below 70
        indicates potential issues that may require attention.
        """,
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
    
    @mcp.tool(
        name="Get_Device_Interfaces",
        description="""Retrieve detailed interface information for a specific network device.
        
        This tool provides comprehensive interface details including:
        - Interface names and descriptions
        - Operational and administrative status
        - Speed and duplex settings
        - IP addresses and subnet masks
        - VLAN assignments
        - Traffic statistics (input/output rates, errors, discards)
        
        Parameters:
            device_id (str): The unique identifier of the target network device.
                           Can be obtained using @Get_Network_Devices.
                           
        Example usage in Claude Desktop:
        @Get_Device_Interfaces device_id="7c1b9833-1be7-43f4-b327-4663c816c4cc"
        
        Note: This tool is particularly useful for troubleshooting connectivity
        issues or verifying interface configurations. For high-density devices,
        the response may be large.
        """,
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
        description="""Retrieve comprehensive details about a specific network device.
        
        This tool provides extensive device information including:
        - Hardware and software inventory
        - Management IP and hostname
        - Platform and OS details
        - Uptime and last updated timestamp
        - Serial number and MAC address
        - Role and capabilities
        - Management state and reachability
        
        Parameters:
            device_id (str): The unique identifier of the target network device.
                           Can be obtained using @Get_Network_Devices.
                           
        Example usage in Claude Desktop:
        @Get_Device_Details device_id="7c1b9833-1be7-43f4-b327-4663c816c4cc"
        
        Note: Use this tool when you need complete device information.
        For interface details, use @Get_Device_Interfaces instead.
        """,
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