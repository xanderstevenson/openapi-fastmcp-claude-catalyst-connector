# Cisco Catalyst Center MCP for Claude Desktop

A Model Control Plane (MCP) server that enables Claude Desktop to interact with Cisco Catalyst Center (formerly DNA Center) through its API.

## 🚀 Features

- Get network device information from Catalyst Center
- Secure authentication
- Easy Claude Desktop integration
- Lightweight and fast

## 📋 Prerequisites

- Python 3.8 or higher
- Claude Desktop installed
- Access to a Cisco Catalyst Center instance

## 🛠️ Setup

1. **Clone this repository**

   ```bash
   git clone <repository-url>
   cd openapi-fastmcp-claude-catalyst-connector
   ```

2. **Create and activate a virtual environment (recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**

   Create a `.env` file in the project root with your Catalyst Center credentials:

   ```env
   CATALYST_BASE_URL=https://your-catalyst-center-url
   CATALYST_USERNAME=your-username
   CATALYST_PASSWORD=your-password
   CATALYST_VERIFY_TLS=false  # Set to true in production with valid certificates
   CATALYST_TIMEOUT=10
   ```

## Installing in Claude Desktop

1. Open Claude Desktop
2. Go to Settings > Model Control Planes
3. Click "Add MCP Server"
4. Select the `fastmcp_mcp_config_fixed.json` file from this repository
5. Restart Claude Desktop

## 🛠️ Available Tools

- **Get Network Devices**: Retrieves a list of all network devices managed by Catalyst Center

## 💻 Usage

Once installed, you can use the MCP in Claude Desktop by mentioning the tool name in your conversation, for example:

```
@Get Network Devices
```

## 🔍 Troubleshooting

### Common Issues

- **Connection Issues**:
  - Verify your `.env` file contains the correct credentials and URL
  - Ensure your Catalyst Center instance is accessible from your machine
  - Check if your firewall allows outgoing connections to the Catalyst Center

- **MCP Server Not Loading**:
  - Ensure the MCP server is running
  - Verify the configuration file path in Claude Desktop is correct
  - Check that all required environment variables are set in your `.env` file

- **Authentication Failures**:
  - Double-check your Catalyst Center credentials
  - Verify your account has the necessary permissions
  - Check if your account is locked out due to too many failed attempts

### Checking Logs

For detailed error information, check the Claude Desktop logs:
- On macOS: `~/Library/Logs/Claude/`
- On Windows: `%APPDATA%\Claude\logs\`
- On Linux: `~/.config/Claude/logs/`

## 🔒 Security Note

- Never commit your `.env` file to version control
- Use environment variables or a secure secret management system for production use
- Consider using API tokens or service accounts instead of username/password when possible

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
