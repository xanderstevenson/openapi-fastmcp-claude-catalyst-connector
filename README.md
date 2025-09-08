# Cisco Catalyst Center MCP for Claude Desktop

A Model Control Plane (MCP) server that enables Claude Desktop to interact with Cisco Catalyst Center (formerly DNA Center) through its API.

## 🚀 Features

- Generate FastMCP server code from OpenAPI specifications
- Automatic endpoint generation with proper type hints
- Retrieve network device information from Catalyst Center
- Monitor network health and client statistics
- Access site topology and device details
- Secure authentication with environment variables
- Easy integration with Claude Desktop

## 📋 Prerequisites

- Python 3.8 or higher
- Claude Desktop installed
- Access to a Cisco Catalyst Center instance
- Basic knowledge of Cisco networking concepts

## 🛠️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/openapi-fastmcp-claude-catalyst-connector.git
cd openapi-fastmcp-claude-catalyst-connector
```

### 2. Set Up Virtual Environment

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```



Look at OpenAPI docs
In this case versio 2.3.7.9 from DevNet
https://developer.cisco.com/docs/dna-center/2-3-7-9/cisco-catalyst-center-2-3-7-9-api-overview/


Download the OpenAPI docs from the Catalyst Center we will be working with
In this case, Catalyst Center Always-On v2.3.3.6
Side menu -> Platform -> Developer Toolkit > Swagger docs



### 4. Generate FastMCP Server from OpenAPI

If you have an OpenAPI specification file (JSON or YAML), you can generate a FastMCP server with all endpoints automatically:

```bash
# Generate FastMCP server from OpenAPI spec
python generate_from_openapi.py cisco-dna-center-apis.json -o catalyst_center_mcp.py

# Make the generated file executable (Linux/macOS)
chmod +x catalyst_center_mcp.py
```

This will create a FastMCP server with all the endpoints defined in your OpenAPI specification.

### 5. Configure Environment Variables

Create a `.env` file in the project root with your Catalyst Center credentials:

```env
# Required
CATALYST_BASE_URL=https://your-catalyst-center-address
CATALYST_USERNAME=your-username
CATALYST_PASSWORD=your-password

# Optional (defaults shown)
CATALYST_VERIFY_TLS=false  # Set to true in production with valid certificates
CATALYST_TIMEOUT=30        # API request timeout in seconds
```

### 6. Configure Claude Desktop

1. Open Claude Desktop
2. Go to Settings > Model Control Planes
3. Click "Add MCP Server"
4. Select the `claude_mcp_config.json` file from this repository
5. Restart Claude Desktop to apply changes

## 🚀 Available Tools

Once configured, you can use these tools in Claude Desktop:

- `@Get_Network_Devices` - List all network devices
- `@Get_Network_Health` - Check overall network health
- `@Get_Client_Health` - View client health statistics
- `@Get_Site_Topology` - View site topology
- `@Get_Device_Details device_id=DEVICE_ID` - Get details for a specific device
- `@Get_Device_Interfaces device_id=DEVICE_ID` - Get interfaces for a specific device

## 🔍 Example Usage

```bash
@Get_Network_Devices
```

```bash
@Get_Device_Details device_id=7c1b9833-1be7-43f4-b327-4663c816c4cc
```

## 🔧 Troubleshooting

### Common Issues

#### Authentication Errors

- Verify your credentials in the `.env` file
- Ensure your account has the necessary permissions in Catalyst Center

#### Connection Issues

- Verify network connectivity to the Catalyst Center
- Check if a firewall is blocking the connection

#### Environment Variables Not Loading

- Ensure the `.env` file is in the project root
- Check for typos in variable names
- Restart Claude Desktop after making changes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Cisco DevNet](https://developer.cisco.com/) for the Catalyst Center API documentation
- [FastMCP](https://gofastmcp.com/) for the MCP server framework

## 🔄 Updating from OpenAPI

When the Catalyst Center API changes, you can easily update your MCP server:

1. Download the latest OpenAPI spec from your Catalyst Center instance
2. Regenerate the MCP server code:

   ```bash
   python generate_from_openapi.py path/to/updated-spec.json -o catalyst_center_mcp.py --force
   ```

3. Restart your MCP server

## 🛠️ Available Tools

- **Get Network Devices**: Retrieves a list of all network devices managed by Catalyst Center

## 💻 Usage

Once installed, you can use the MCP in Claude Desktop by mentioning the tool name in your conversation, for example:

```bash
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
