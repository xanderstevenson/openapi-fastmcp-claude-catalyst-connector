#!/usr/bin/env python3
"""
Test script for Catalyst Center MCP tools.
"""
import asyncio
import os
import sys
import logging
from dotenv import load_dotenv

# Add the current directory to the path so we can import catalyst_center_mcp
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from catalyst_center_mcp import CatalystCenterClient

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('catalyst_test.log')
    ]
)
logger = logging.getLogger("catalyst_test")

async def test_connection():
    """Test connection to Catalyst Center."""
    try:
        async with CatalystCenterClient() as client:
            # Test authentication
            token = await client.authenticate()
            if token:
                print("✅ Successfully authenticated with Catalyst Center")
                print(f"Token: {token[:10]}...")
                return True
    except Exception as e:
        logger.error(f"Connection test failed: {str(e)}", exc_info=True)
        print(f"❌ Connection test failed: {str(e)}")
        return False

async def test_network_health():
    """Test Get_Network_Health tool."""
    try:
        async with CatalystCenterClient() as client:
            result = await client.make_request("GET", "/dna/intent/api/v1/network-health")
            print("\n📊 Network Health:")
            print(result)
            return True
    except Exception as e:
        logger.error(f"Network health test failed: {str(e)}", exc_info=True)
        print(f"❌ Network health test failed: {str(e)}")
        return False

async def test_network_devices():
    """Test Get_Network_Devices tool."""
    try:
        async with CatalystCenterClient() as client:
            result = await client.make_request("GET", "/dna/intent/api/v1/network-device")
            print("\n🖥️  Network Devices:")
            if 'response' in result:
                print(f"Found {len(result['response'])} devices")
                for device in result['response'][:5]:  # Show first 5 devices
                    print(f"- {device.get('hostname')} ({device.get('managementIpAddress')}): {device.get('platformId')}")
                if len(result['response']) > 5:
                    print(f"... and {len(result['response']) - 5} more devices")
            return True
    except Exception as e:
        logger.error(f"Network devices test failed: {str(e)}", exc_info=True)
        print(f"❌ Network devices test failed: {str(e)}")
        return False

async def run_tests():
    """Run all tests."""
    print("🔍 Starting Catalyst Center MCP tests...")
    
    # Load .env file
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
        print(f"✅ Loaded .env file from {env_path}")
    else:
        print("⚠️  No .env file found. Using system environment variables.")
    
    # Run tests
    success = await test_connection()
    if success:
        await test_network_health()
        await test_network_devices()
    
    print("\n✅ Tests completed. Check catalyst_test.log for detailed logs.")

if __name__ == "__main__":
    asyncio.run(run_tests())
