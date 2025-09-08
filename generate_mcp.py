import os
import json
import base64
import asyncio
import aiohttp
import inspect
import functools
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from fastmcp import FastMCP
from dotenv import load_dotenv
from typing import Dict, Any, List

# Load environment variables
load_dotenv(override=True)

# --- API Key Security ---
API_KEY = os.getenv("MCP_SERVER_API_KEY", "default_api_key")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key(api_key: str = Depends(api_key_header)):
    if not api_key or api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return api_key

# --- Catalyst Center Client ---
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
            raise ValueError("Missing required Catalyst Center environment variables")
        
        auth_str = f"{self.username}:{self.password}"
        auth_bytes = auth_str.encode('ascii')
        auth_token = base64.b64encode(auth_bytes).decode('ascii')
        
        auth_url = f"{self.base_url}/dna/system/api/v1/auth/token"
        headers = {"Authorization": f"Basic {auth_token}"}
        
        try:
            async with self.session.post(auth_url, headers=headers, ssl=False) as response:
                response.raise_for_status()
                data = await response.json()
                self.token = data.get('Token')
                if not self.token:
                    raise ValueError("No token in authentication response")
        except Exception as e:
            print(f"Authentication error: {e}")
            raise

    async def make_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        if not self.token:
            await self.authenticate()
        
        url = f"{self.base_url}{path}"
        headers = {"X-Auth-Token": self.token, "Content-Type": "application/json"}
        
        try:
            async with self.session.request(method, url, headers=headers, ssl=False, **kwargs) as response:
                response.raise_for_status()
                if response.status == 204:  # No Content
                    return {}
                return await response.json()
        except aiohttp.ClientError as e:
            print(f"API request failed: {e}")
            raise

# --- Tool Generation ---
def generate_tools_from_spec(mcp: FastMCP, spec: Dict[str, Any]) -> int:
    client_factory = CatalystCenterClient
    tool_count = 0
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.lower() in ["get", "post"]:
                op_id = details.get("operationId", f"{method}_{path.replace('/', '_')}")
                desc = details.get("summary", "No description")

                async def handler(path=path, method=method):
                    async with client_factory() as client:
                        return await client.make_request(method.upper(), path)

                mcp.tool(name=op_id, description=desc)(handler)
                tool_count += 1
    return tool_count

# --- FastAPI App ---
mcp_server: FastMCP = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global mcp_server
    print("Starting up MCP server...")
    mcp_server = FastMCP("Catalyst Center MCP")
    try:
        with open("catalyst_center_openapi.json", "r") as f:
            spec = json.load(f)
        tool_count = generate_tools_from_spec(mcp_server, spec)
        print(f"MCP server started with {tool_count} tools.")
    except FileNotFoundError:
        print("ERROR: catalyst_center_openapi.json not found. No tools will be generated.")
    yield
    print("Shutting down MCP server...")

app = FastAPI(lifespan=lifespan)

@app.post("/mcp")
async def mcp_handler(request: Dict[str, Any], api_key: str = Depends(get_api_key)):
    if mcp_server is None:
        raise HTTPException(status_code=503, detail="MCP Server is not available")
    response = await mcp_server.handle(request)
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
