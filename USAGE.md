# Catalyst Center MCP Server Setup

## Quick Start

1. **Start the MCP Server**
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Start the server
   python generate_mcp.py
   ```

2. **Configure Claude Desktop**
   - Open Claude Desktop
   - Go to Settings > MCP Servers
   - Add a new MCP server with these settings:
     - Name: `Catalyst Center MCP`
     - URL: `http://localhost:8000` (or your machine's IP if accessing over network)
     - API Key: (leave empty unless you've set one in `.env`)

## Network Access

To access the MCP server from other devices:

1. Update `claude_mcp_config.json`:
   ```json
   {
     ...
     "base_url": "http://YOUR_LOCAL_IP:8000",
     ...
   }
   ```
   Replace `YOUR_LOCAL_IP` with your machine's local IP address.

2. Ensure your firewall allows incoming connections on port 8000.

## Available Endpoints

- `GET /health` - Check if the server is running
- `GET /api/v1/network-device` - List all network devices

## Troubleshooting

- **Connection Refused**: Ensure the server is running and the port is accessible
- **Invalid Token**: Verify your Catalyst Center credentials in `.env`
- **CORS Issues**: Make sure to access the server from an allowed origin
