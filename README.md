# mcp-active-directory-server
MCP server for Active Directory management with Python server and PowerShell backend

# 🏗️ Architecture Overview

Claude Desktop ↔ MCP Protocol ↔ Python Server ↔ PowerShell ↔ Active Directory

The system uses a 3-tier architecture:

 - Presentation Layer : Claude Desktop (AI interface)
 - Application Layer : Python MCP Server (protocol handler & orchestrator)
 - Data Layer : PowerShell Script → Active Directory (actual AD operations)

# 📁 Component Breakdown

**1. `simple_mcp_server.py` - The MCP Protocol Bridge 🌉**

  **Role**: Acts as the main orchestrator and protocol translator

**What it does:**

- **Protocol Handler** : Implements the Model Context Protocol (MCP) JSON-RPC 2.0 specification

- **Tool Registry**: Defines 14 available tools for Claude to use:

   - 6 Basic tools (user management, groups, connections)
   - 8 Advanced tools (domain info, forest info, trusts, replication, etc.)


-**Credential Manager**: Securely retrieves AD service account credentials from Windows Credential Manager

-**PowerShell Orchestrator**: Executes the PowerShell script with appropriate parameters

-**Response Formatter**: Converts PowerShell JSON output into MCP-compliant responses

**Key Functions**:

```python
async def handle_request(request)     # Handles MCP protocol requests

async def run_powershell_script()    # Executes PowerShell operations

async def get_credentials_from_credential_manager()  # Security layer
```

**2. `ad_operations.ps1` **- The Active Directory Workhorse ⚙️**

**Role:** Contains all actual Active Directory operations and business logic

**What it does:**

 - **AD Operations:** 14 distinct functions for different AD tasks
 - **Input Validation:** Handles JSON parameter parsing and validation
 - **Credential Management:** Uses provided domain credentials for AD authentication
 - **Error Handling:** Comprehensive try-catch blocks with structured error responses
 - **Structured Output:** Returns JSON-formatted results for consistent processing

**Function Categories:**

**Basic Operations (6):**
```powershell
powershellCreate-User              # New-ADUser operations
Modify-User              # Set-ADUser operations  
Add-UserToGroup          # Add-ADGroupMember
Remove-UserFromGroup     # Remove-ADGroupMember
Get-UserInfo            # Get-ADUser with all properties
Test-ADConnection       # Domain connectivity test
```

**Enhanced Operations (8):**
```powershell
powershellGet-DomainInfo          # Get-ADDomain equivalent
Get-ForestInfo          # Get-ADForest equivalent
Get-TrustInfo           # Get-ADTrust relationships
Get-DomainPasswordPolicy # Get-ADDefaultDomainPasswordPolicy
Get-ReplicationStatus   # AD replication health
Get-AllUserAttributes   # Deep user inspection
Get-AllComputerAttributes # Deep computer inspection
Get-SitesAndServices    # Sites, links, subnets
```

**3. Security & Configuration Layer 🔐**

**Credential Management:**

- Uses Windows Credential Manager for secure credential storage
- Target: "MCPActiveDirectory"
- Service account with minimal required permissions
- No hardcoded passwords in scripts

**Configuration Variables:**
```powershell
powershell$TargetOU = "OU=ManagedUsers,DC=demo,DC=local"  # Managed OU
$DomainName = "demo.local"                       # Domain name
$DefaultPassword = "TempPassword123!"            # Initial password
```


# 🔄 Data Flow Architecture

**1. Request Flow (Claude → AD)**

```
Claude Desktop
    ↓ (User request: "Create user John Smith")
Python MCP Server
    ↓ (Validates request, formats parameters)
    ↓ (Retrieves credentials from Credential Manager)
    ↓ (Calls PowerShell with JSON data)

PowerShell Script
    ↓ (Parses JSON, authenticates to AD)
    ↓ (Executes New-ADUser cmdlet)
Active Directory
```

**2. Response Flow (AD → Claude)**
```
Active Directory
  ↓ (Returns AD object/status)
PowerShell Script  
  ↓ (Formats as JSON with success/error status)
Python MCP Server
  ↓ (Receives JSON, validates, formats for MCP)
  ↓ (Creates MCP-compliant response)
Claude Desktop
  ↓ (Displays formatted result to user)
```

# 🎯 Component Responsibilities

**Python Server Responsibilities:**

- ✅ MCP protocol compliance
- ✅ Tool registration and discovery
- ✅ Security (credential retrieval)
- ✅ Error handling and logging
- ✅ Async operation handling
- ✅ JSON-RPC 2.0 implementation


**PowerShell Script Responsibilities:**

- ✅ All Active Directory operations
- ✅ Parameter validation and sanitization
- ✅ Domain authentication
- ✅ Business logic implementation
- ✅ Structured error reporting
- ✅ Comprehensive data retrieval

**Security Model:**

- 🔐 Credentials: Stored in Windows Credential Manager (encrypted)
- 🔐 Authentication: Service account with minimal permissions
- 🔐 Scope: Limited to specific OU (ManagedUsers)