# Cisco Catalyst Center MCP Server with FastMCP

A Model Context Protocol (MCP) server for Cisco Catalyst Center (formerly DNA Center) using FastMCP. Enables Claude AI to interact with your network through a structured API.

## 🚀 Features

- Auto-generated from Catalyst Center OpenAPI spec
- Full API coverage through FastMCP
- Secure authentication
- Claude Desktop integration

## 📋 Prerequisites

- Python 3.8+
- Cisco Catalyst Center access
- Valid API credentials

## 🛠️ Setup

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd openapi-to-fastmcp
   ```

2. **Set up environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure**

   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

## 🚀 Quick Start

1. **Test connection**
   ```bash
   python test_connection.py
   ```

2. **Generate MCP server**
   ```bash
   python generate_mcp_simple.py
   ```

3. **Start server**
   ```bash
   uvicorn catalyst_center_mcp_server:app --reload
   ```

4. **Connect Claude Desktop**
   - Import `claude_mcp_config.json`
   - Toggle the server on

## 🔒 Authentication System

This project implements a secure Model Context Protocol (MCP) server for Cisco Catalyst Center (formerly DNA Center) with multiple layers of authentication and fine-grained access control.

### Features

- 🔒 **Three-Layer Security**:
  - API key authentication for MCP server access
  - User authentication with username/password
  - Role-based access control for individual tools
- 🛠️ Tool access control with configurable permissions
- 🔄 Session management for authenticated users
- 🚀 Easy integration with Claude Desktop

### Configuration

Edit the `.env` file to configure the following sections:

#### MCP Server Configuration
```
PORT=8000
HOST=0.0.0.0
DEBUG=True
```

#### Authentication
```
# Generate a strong random key: openssl rand -hex 32
MCP_SERVER_API_KEY=your_server_api_key_here

# Format: username:bcrypt_hashed_password
# Generate hashed password: python3 -c "import bcrypt; print(bcrypt.hashpw('your_password'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))"
MCP_USERS=admin:$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW  # password: password
```

#### Tool Access Control
```
# Format: {"tool_name": ["role1", "role2"]}
TOOL_ACCESS={
  "network_devices": ["admin", "network_engineer"],
  "health_monitoring": ["admin", "network_engineer", "support"],
  "configuration": ["admin"]
}
```

#### Catalyst Center API
```
CATALYST_CENTER_URL=https://sandboxdnac.cisco.com
CATALYST_CENTER_USERNAME=devnetuser
CATALYST_CENTER_PASSWORD=Cisco123!
```

## 🏗️ Project Structure

```text
.
├── generate_mcp_simple.py  # MCP server generator
├── test_connection.py      # Connection tester
├── requirements.txt        # Dependencies
└── .env.example           # Configuration template
```

## 🔍 Example Queries

- "List all network devices"
- "Show network health status"
- "Find device with IP 10.0.0.1"

## 🛠 Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection failed | Verify `.env` credentials |
| Server not responding | Check if port 8000 is free |
| API errors | Review server logs |

## 📄 License

MIT - See [LICENSE](LICENSE)

## Acknowledgments

- Inspired by the [Meraki MCP Server](https://github.com/kiskander/meraki-mcp-server)

1. Start the server
2. In Claude Desktop, connect to the MCP server
3. Ask Claude about network devices or health status
