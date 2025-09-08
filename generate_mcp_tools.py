#!/usr/bin/env python3
"""
Generate MCP tools from Cisco DNA Center OpenAPI specification.
"""
import json
import os
import asyncio
import aiohttp
import logging
from typing import Dict, Any, List, Optional, Tuple
from fastmcp import FastMCP
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("catalyst_mcp")

# Load environment variables
load_dotenv()

class CatalystCenterClient:
    """Client for interacting with the Cisco Catalyst Center API."""
    
    def __init__(self):
        self.base_url = os.getenv('CATALYST_BASE_URL', '').rstrip('/')
        self.username = os.getenv('CATALYST_USERNAME')
        self.password = os.getenv('CATALYST_PASSWORD')
        self.verify_tls = os.getenv('CATALYST_VERIFY_TLS', 'false').lower() == 'true'
        self.timeout = int(os.getenv('CATALYST_TIMEOUT', '60'))
        self.token = None
        self.session = None
        
        if not all([self.base_url, self.username, self.password]):
            raise ValueError("Missing required Catalyst Center configuration in .env")
    
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
    
    async def make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
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
            logger.error(f"API request failed: {str(e)}")
            raise

def generate_tool_function(endpoint: str, method: str, summary: str) -> str:
    """Generate the Python function code for a tool."""
    func_name = endpoint.strip('/').replace('/', '_').replace('-', '_').lower()
    docstring = f'    """{summary}"""'
    
    code = f"""    @mcp.tool(
        name="{name}",
        description="{description}",
        output_schema={{"type": "object"}}
    )
    async def {func_name}():
{indent}with CatalystCenterClient() as client:
{indent}    return await client.make_request("{method}", "{endpoint}")
"""
    return code

def generate_mcp_server(tools: List[Dict[str, Any]]) -> str:
    """Generate the complete MCP server code."""
    imports = """#!/usr/bin/env python3
"""
    
    server_code = """import asyncio
import os
import logging
from fastmcp import FastMCP
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("catalyst_mcp")

# Load environment variables
load_dotenv()

class CatalystCenterClient:
    """Client for interacting with the Cisco Catalyst Center API."""
    
    def __init__(self):
        self.base_url = os.getenv('CATALYST_BASE_URL', '').rstrip('/')
        self.username = os.getenv('CATALYST_USERNAME')
        self.password = os.getenv('CATALYST_PASSWORD')
        self.verify_tls = os.getenv('CATALYST_VERIFY_TLS', 'false').lower() == 'true'
        self.timeout = int(os.getenv('CATALYST_TIMEOUT', '60'))
        self.token = None
        self.session = None
        
        if not all([self.base_url, self.username, self.password]):
            raise ValueError("Missing required Catalyst Center configuration in .env")
    
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
    
    # Add tools here
    @mcp.tool(
        name="Get_Network_Devices",
        description="Get a list of network devices from Catalyst Center",
        output_schema={"type": "object"}
    )
    async def get_network_devices():
        """Get a list of network devices from Catalyst Center."""
        async with CatalystCenterClient() as client:
            return await client.make_request("GET", "/dna/intent/api/v1/network-device")
    
    @mcp.tool(
        name="Get_Network_Health",
        description="Get the overall network health",
        output_schema={"type": "object"}
    )
    async def get_network_health():
        """Get the overall network health."""
        async with CatalystCenterClient() as client:
            return await client.make_request("GET", "/dna/intent/api/v1/network-health")
    
    @mcp.tool(
        name="Get_Client_Health",
        description="Get client health statistics",
        output_schema={"type": "object"}
    )
    async def get_client_health():
        """Get client health statistics."""
        async with CatalystCenterClient() as client:
            return await client.make_request("GET", "/dna/intent/api/v1/client-health")
    
    @mcp.tool(
        name="Get_Site_Topology",
        description="Get the site topology",
        output_schema={"type": "object"}
    )
    async def get_site_topology():
        """Get the site topology."""
        async with CatalystCenterClient() as client:
            return await client.make_request("GET", "/dna/intent/api/v1/topology/site-topology")
    
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
"""
    
    return server_code

def main():
    # Generate the MCP server code
    with open('generated_mcp_server.py', 'w') as f:
        f.write(generate_mcp_server([]))
    
    print("Generated MCP server code in 'generated_mcp_server.py'")
    print("\nTo use the MCP server:")
    print("1. Make sure your .env file has the correct Catalyst Center credentials")
    print("2. Run: python generated_mcp_server.py")
    print("3. In Claude Desktop, import the MCP configuration")

if __name__ == "__main__":
    main()
