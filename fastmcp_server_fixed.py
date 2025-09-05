import os
import json
import base64
import asyncio
import aiohttp
from fastmcp import FastMCP
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

class CatalystCenterClient:
    def __init__(self):
        self.base_url = os.getenv('CATALYST_BASE_URL')
        self.username = os.getenv('CATALYST_USERNAME')
        self.password = os.getenv('CATALYST_PASSWORD')
        self.token = None
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def authenticate(self):
        if not all([self.username, self.password, self.base_url]):
            raise ValueError("Missing required environment variables")
        
        auth_str = f"{self.username}:{self.password}"
        auth_bytes = auth_str.encode('ascii')
        auth_token = base64.b64encode(auth_bytes).decode('ascii')
        
        try:
            async with self.session.post(
                f"{self.base_url}/api/system/v1/auth/token",
                headers={
                    "Authorization": f"Basic {auth_token}",
                    "Content-Type": "application/json"
                },
                ssl=False
            ) as response:
                response.raise_for_status()
                data = await response.json()
                self.token = data.get('Token')
                if not self.token:
                    raise ValueError("No token received in authentication response")
                return self.token
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            raise

    async def get_network_devices(self):
        if not self.token:
            await self.authenticate()
        
        url = f"{self.base_url}/dna/intent/api/v1/network-device"
        headers = {
            "X-Auth-Token": self.token,
            "Content-Type": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers, ssl=False) as response:
                response.raise_for_status()
                data = await response.json()
                
                # Transform to expected format
                devices = data.get("response", [])
                return {
                    "response": [
                        {
                            "id": str(device.get("id", "")),
                            "hostname": str(device.get("hostname", "")),
                            "managementIpAddress": str(device.get("managementIpAddress", "")),
                            "type": str(device.get("type", "")),
                            "macAddress": str(device.get("macAddress", "")),
                            "softwareVersion": str(device.get("softwareVersion", "")),
                            "upTime": str(device.get("upTime", "")),
                            "role": str(device.get("role", "")),
                            "reachabilityStatus": str(device.get("reachabilityStatus", ""))
                        }
                        for device in devices
                    ],
                    "version": str(data.get("version", "1.0.0"))
                }
        except Exception as e:
            print(f"Error getting network devices: {str(e)}")
            raise

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
    mcp = await build_mcp()
    await mcp.run_async()

if __name__ == "__main__":
    asyncio.run(main())
