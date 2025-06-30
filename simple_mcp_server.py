#!/usr/bin/env python3
"""
MCP Active Directory Management Server

A Model Context Protocol server for managing Active Directory users and domains
through PowerShell backend with secure credential management.

Author: [Your Name]
Version: 3.0.0
License: MIT
"""

import asyncio
import json
import subprocess
import sys
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

# Set UTF-8 encoding for Windows compatibility
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

# Configuration
POWERSHELL_SCRIPT_PATH = r"C:\MCPServer\ad_operations.ps1"
CREDENTIAL_TARGET = "MCPActiveDirectory"
LOG_DIRECTORY = r"C:\MCPServer\logs"

# Ensure log directory exists
Path(LOG_DIRECTORY).mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIRECTORY, 'mcp_server.log')),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

class MCPADServer:
    """MCP Active Directory Management Server"""
    
    def __init__(self):
        self.server_info = {
            "name": "Enhanced AD Management Server",
            "version": "3.0.0"
        }
        logger.info(f"Initializing {self.server_info['name']} v{self.server_info['version']}")
    
    async def get_credentials_from_credential_manager(self) -> tuple[Optional[str], Optional[str]]:
        """
        Retrieve credentials from Windows Credential Manager.
        Returns tuple: (username, password) or (None, None) if failed
        """
        try:
            logger.debug("Retrieving credentials from Windows Credential Manager...")
            
            powershell_cmd = f"""
            try {{
                Import-Module CredentialManager -ErrorAction Stop
                $cred = Get-StoredCredential -Target '{CREDENTIAL_TARGET}' -ErrorAction Stop
                if ($cred) {{
                    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))
                    Write-Output "SUCCESS|$($cred.UserName)|$plainPassword"
                }} else {{
                    Write-Output "NOTFOUND"
                }}
            }} catch {{
                Write-Output "MODULE_ERROR|$($_.Exception.Message)"
            }}
            """
            
            result = await asyncio.create_subprocess_exec(
                "powershell.exe", "-Command", powershell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            output = stdout.decode().strip()
            
            if output.startswith("SUCCESS|"):
                _, username, password = output.split("|", 2)
                logger.info("✓ Credentials retrieved from Windows Credential Manager")
                return username, password
            else:
                logger.error(f"❌ Failed to retrieve credentials: {output}")
                return None, None
                
        except Exception as e:
            logger.error(f"❌ Error accessing Credential Manager: {e}")
            return None, None

    async def run_powershell_script(self, operation: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute PowerShell script with given operation and data using Credential Manager."""
        try:
            start_time = datetime.now()
            logger.info(f"Executing operation: {operation}")
            
            # Get credentials from Windows Credential Manager
            username, password = await self.get_credentials_from_credential_manager()
            
            if not username or not password:
                error_msg = "Failed to retrieve credentials from Windows Credential Manager. Please run setup script first."
                logger.error(error_msg)
                return {
                    "success": False,
                    "message": error_msg
                }
            
            cmd = [
                "powershell.exe",
                "-ExecutionPolicy", "Bypass",
                "-File", POWERSHELL_SCRIPT_PATH,
                "-Operation", operation,
                "-Username", username,
                "-Password", password
            ]
            
            if data:
                json_data = json.dumps(data)
                cmd.extend(["-JsonData", json_data])
                logger.debug(f"Operation data: {json_data}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(POWERSHELL_SCRIPT_PATH)
            )
            
            stdout, stderr = await process.communicate()
            execution_time = (datetime.now() - start_time).total_seconds()
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"PowerShell execution failed in {execution_time:.2f}s: {error_msg}")
                return {
                    "success": False,
                    "message": f"PowerShell execution failed: {error_msg}"
                }
            
            stdout_text = stdout.decode('utf-8', errors='ignore').strip()
            
            if not stdout_text:
                error_msg = "No output received from PowerShell script"
                logger.warning(error_msg)
                return {
                    "success": False,
                    "message": error_msg
                }
            
            try:
                result = json.loads(stdout_text)
                logger.info(f"Operation {operation} completed successfully in {execution_time:.2f}s")
                return result
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse PowerShell output as JSON: {e}\nOutput: {stdout_text}"
                logger.error(error_msg)
                return {
                    "success": False,
                    "message": error_msg
                }
            
        except Exception as e:
            logger.error(f"Error executing PowerShell script: {str(e)}")
            return {
                "success": False,
                "message": f"Error executing PowerShell script: {str(e)}"
            }

    async def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle incoming MCP requests with proper JSON-RPC 2.0 format."""
        try:
            method = request.get("method")
            request_id = request.get("id")
            params = request.get("params", {})
            
            logger.debug(f"Processing method: {method}, ID: {request_id}")
            
            # Handle initialization - REQUIRED for Claude Desktop
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id if request_id is not None else 0,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": self.server_info
                    }
                }
            elif method == "initialized":
                # Notification that initialization is complete
                return None  # No response for notifications
            elif method == "tools/list":
                tools = self._get_available_tools()
                return {
                    "jsonrpc": "2.0",
                    "id": request_id if request_id is not None else 0,
                    "result": {
                        "tools": tools
                    }
                }
            elif method == "tools/call":
                return await self._handle_tool_call(request_id, params)
            else:
                return {
                    "jsonrpc": "2.0", 
                    "id": request_id if request_id is not None else 0,
                    "error": {
                        "code": -32601,
                        "message": f"Unknown method: {method}"
                    }
                }
        except Exception as e:
            request_id = request.get("id", 0) if isinstance(request, dict) else 0
            logger.error(f"Error handling request: {str(e)}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }

    def _get_available_tools(self) -> list[Dict[str, Any]]:
        """Get list of available AD management tools."""
        return [
            # BASIC USER MANAGEMENT TOOLS
            {
                "name": "create_ad_user",
                "description": "Create a new Active Directory user account",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "SamAccountName": {"type": "string", "description": "Username (must be unique)"},
                        "Name": {"type": "string", "description": "Full name"},
                        "GivenName": {"type": "string", "description": "First name"},
                        "Surname": {"type": "string", "description": "Last name"},
                        "DisplayName": {"type": "string", "description": "Display name (optional)"},
                        "Department": {"type": "string", "description": "Department (optional)"},
                        "Title": {"type": "string", "description": "Job title (optional)"},
                        "EmailAddress": {"type": "string", "description": "Email address (optional)"}
                    },
                    "required": ["SamAccountName", "Name", "GivenName", "Surname"]
                }
            },
            {
                "name": "modify_ad_user",
                "description": "Modify an existing Active Directory user account",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "SamAccountName": {"type": "string", "description": "Username to modify"},
                        "GivenName": {"type": "string", "description": "First name (optional)"},
                        "Surname": {"type": "string", "description": "Last name (optional)"},
                        "DisplayName": {"type": "string", "description": "Display name (optional)"},
                        "Department": {"type": "string", "description": "Department (optional)"},
                        "Title": {"type": "string", "description": "Job title (optional)"},
                        "EmailAddress": {"type": "string", "description": "Email address (optional)"},
                        "Enabled": {"type": "boolean", "description": "Enable/disable account (optional)"}
                    },
                    "required": ["SamAccountName"]
                }
            },
            {
                "name": "add_user_to_group",
                "description": "Add user to Active Directory group",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "SamAccountName": {"type": "string", "description": "Username"},
                        "GroupName": {"type": "string", "description": "Group name"}
                    },
                    "required": ["SamAccountName", "GroupName"]
                }
            },
            {
                "name": "remove_user_from_group",
                "description": "Remove user from Active Directory group",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "SamAccountName": {"type": "string", "description": "Username"},
                        "GroupName": {"type": "string", "description": "Group name"}
                    },
                    "required": ["SamAccountName", "GroupName"]
                }
            },
            {
                "name": "get_ad_user_info",
                "description": "Get Active Directory user information",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "SamAccountName": {"type": "string", "description": "Username"}
                    },
                    "required": ["SamAccountName"]
                }
            },
            {
                "name": "test_ad_connection",
                "description": "Test Active Directory connection",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            
            # ENHANCED DOMAIN/FOREST MANAGEMENT TOOLS
            {
                "name": "get_domain_info",
                "description": "Get comprehensive Active Directory domain information (equivalent to Get-ADDomain)",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_forest_info",
                "description": "Get comprehensive Active Directory forest information (equivalent to Get-ADForest)",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_trust_info",
                "description": "Get Active Directory trust relationships information (equivalent to Get-ADTrust)",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_default_domain_policy",
                "description": "Get information about the Default Domain Policy GPO",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_replication_status",
                "description": "Get Active Directory replication status and identify any replication errors",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_all_user_attributes",
                "description": "Get all attributes for all user objects within the ManagedUsers OU",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_all_computer_attributes",
                "description": "Get all attributes for all computer objects within the ManagedUsers OU",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "get_sites_and_services",
                "description": "Get Active Directory Sites and Services information including sites, site links, and subnets",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        ]

    async def _handle_tool_call(self, request_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool call requests."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        operation_map = {
            # Basic operations
            "create_ad_user": "CreateUser",
            "modify_ad_user": "ModifyUser",
            "add_user_to_group": "AddToGroup", 
            "remove_user_from_group": "RemoveFromGroup",
            "get_ad_user_info": "GetUserInfo", 
            "test_ad_connection": "TestConnection",
            
            # Enhanced operations
            "get_domain_info": "GetDomainInfo",
            "get_forest_info": "GetForestInfo",
            "get_trust_info": "GetTrustInfo",
            "get_default_domain_policy": "GetDefaultDomainPolicy",
            "get_replication_status": "GetReplicationStatus",
            "get_all_user_attributes": "GetAllUserAttributes",
            "get_all_computer_attributes": "GetAllComputerAttributes",
            "get_sites_and_services": "GetSitesAndServices"
        }
        
        if tool_name in operation_map:
            operation = operation_map[tool_name]
            
            # Operations that don't need arguments
            no_args_operations = [
                "test_ad_connection", "get_domain_info", "get_forest_info", 
                "get_trust_info", "get_default_domain_policy", "get_replication_status",
                "get_all_user_attributes", "get_all_computer_attributes", "get_sites_and_services"
            ]
            
            if tool_name in no_args_operations:
                result = await self.run_powershell_script(operation)
            else:
                result = await self.run_powershell_script(operation, arguments)
            
            if result["success"]:
                content_text = result["message"]
                if result.get("data"):
                    # Format the data nicely for different tool types
                    if tool_name in ["get_domain_info", "get_forest_info"]:
                        content_text += "\n\n🏢 **Domain/Forest Information:**"
                    elif tool_name == "get_trust_info":
                        content_text += "\n\n🔗 **Trust Relationships:**"
                    elif tool_name == "get_replication_status":
                        content_text += "\n\n🔄 **Replication Status:**"
                    elif tool_name == "get_default_domain_policy":
                        content_text += "\n\n📋 **Default Domain Policy:**"
                    elif tool_name in ["get_all_user_attributes", "get_all_computer_attributes"]:
                        content_text += "\n\n👥 **Object Attributes:**"
                    elif tool_name == "get_sites_and_services":
                        content_text += "\n\n🌐 **Sites and Services:**"
                    
                    content_text += f"\n```json\n{json.dumps(result['data'], indent=2)}\n```"
                
                return {
                    "jsonrpc": "2.0",
                    "id": request_id if request_id is not None else 0,
                    "result": {
                        "content": [{"type": "text", "text": content_text}]
                    }
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id if request_id is not None else 0,
                    "result": {
                        "content": [{"type": "text", "text": f"❌ Error: {result['message']}"}]
                    }
                }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id if request_id is not None else 0,
                "error": {
                    "code": -32601,
                    "message": f"Unknown tool: {tool_name}"
                }
            }

    async def run_server(self):
        """Run the MCP server using stdin/stdout with proper JSON-RPC."""
        # Send startup messages to stderr so they don't interfere with JSON-RPC
        logger.info("🚀 Enhanced AD Management MCP Server starting...")
        
        # Test credential retrieval
        logger.info("🔐 Testing Windows Credential Manager access...")
        username, password = await self.get_credentials_from_credential_manager()
        
        if username and password:
            logger.info("✓ Credentials loaded successfully from Windows Credential Manager")
            logger.info(f"  👤 Username: {username}")
            logger.info(f"  🔒 Password: [PROTECTED - {len(password)} characters]")
            
            # Test AD connection
            test_result = await self.run_powershell_script("TestConnection")
            if test_result["success"]:
                logger.info("✅ AD Connection: SUCCESS")
            else:
                logger.error(f"❌ AD Connection: FAILED - {test_result['message']}")
        else:
            logger.error("❌ Failed to load credentials from Windows Credential Manager")
            logger.error("   Please run the credential setup script first:")
            logger.error("   powershell.exe -ExecutionPolicy Bypass -File setup_credentials.ps1")
        
        logger.info("🎯 Enhanced MCP Server ready with 14 AD management tools!")
        logger.info("   📋 Basic Tools: User management, groups, connections")
        logger.info("   🏢 Advanced Tools: Domain/Forest info, trusts, replication")
        logger.info("   🔍 Deep Inspection: All attributes, sites & services, policies")
        
        # Handle JSON-RPC requests
        try:
            while True:
                request_id = 0  # Initialize default request ID
                try:
                    line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                    if not line:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse JSON and extract ID early for error handling
                    try:
                        request = json.loads(line)
                        request_id = request.get("id", 0)  # Get actual request ID
                    except json.JSONDecodeError as e:
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": 0,
                            "error": {
                                "code": -32700,
                                "message": f"Parse error: {str(e)}"
                            }
                        }
                        print(json.dumps(error_response), flush=True)
                        continue
                    
                    # Handle the request
                    logger.debug(f"🔧 Handling request: {request.get('method', 'unknown')} with ID: {request_id}")
                    response = await self.handle_request(request)
                    
                    if response is not None:  # Don't respond to notifications
                        logger.debug(f"📤 Sending response for ID: {response.get('id', 'unknown')}")
                        print(json.dumps(response), flush=True)
                    else:
                        logger.debug("📢 No response needed (notification)")
                    
                except Exception as e:
                    logger.error(f"Error processing request: {str(e)}")
                    error_response = {
                        "jsonrpc": "2.0", 
                        "id": request_id,
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(e)}"
                        }
                    }
                    print(json.dumps(error_response), flush=True)
                    
        except KeyboardInterrupt:
            logger.info("🛑 Server stopped")

async def main():
    """Main entry point."""
    server = MCPADServer()
    await server.run_server()

if __name__ == "__main__":
    asyncio.run(main())