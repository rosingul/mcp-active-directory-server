# MCP Active Directory Management Server

A comprehensive Model Context Protocol (MCP) server for managing Active Directory through Claude AI with an enhanced PowerShell backend.

## 🚀 Features

### Basic User Management
- **User Creation & Modification**: Create, modify, and manage AD user accounts
- **Group Operations**: Add/remove users from AD groups
- **User Information**: Get comprehensive user details and group memberships

### Advanced Domain Management
- **Domain Information**: Get comprehensive domain details (equivalent to Get-ADDomain)
- **Forest Information**: Get forest-wide information (equivalent to Get-ADForest)
- **Trust Relationships**: View and analyze domain trusts (equivalent to Get-ADTrust)
- **Replication Status**: Monitor AD replication health and identify issues
- **Sites and Services**: Get detailed information about AD sites, site links, and subnets
- **Group Policy**: Access Default Domain Policy information
- **Deep Inspection**: Get all attributes for users and computers in managed OUs

### Security & Integration
- **Secure Authentication**: Uses Windows Credential Manager for secure credential storage
- **Comprehensive Logging**: Full audit trail with structured logging
- **Claude Integration**: Seamless integration with Claude Desktop

## 📊 Available Tools (14 Total)

### Basic Tools (6)
1. `create_ad_user` - Create new AD user accounts
2. `modify_ad_user` - Modify existing user properties
3. `get_ad_user_info` - Get comprehensive user information
4. `add_user_to_group` - Add users to AD groups
5. `remove_user_from_group` - Remove users from AD groups
6. `test_ad_connection` - Test AD connectivity

### Advanced Tools (8)
7. `get_domain_info` - Get comprehensive domain information
8. `get_forest_info` - Get forest-wide information
9. `get_trust_info` - Get trust relationship details
10. `get_default_domain_policy` - Get Default Domain Policy info
11. `get_replication_status` - Check AD replication health
12. `get_all_user_attributes` - Get all user attributes in managed OU
13. `get_all_computer_attributes` - Get all computer attributes in managed OU
14. `get_sites_and_services` - Get Sites and Services information

## 📋 Prerequisites

### System Requirements
- Windows Server 2016+ or Windows 10/11 Pro
- PowerShell 5.1+
- Python 3.8+
- Active Directory Domain Services access
- Local Administrator rights (for installation)

### Active Directory Requirements
- Domain Controller access
- Service account with user management permissions
- Target OU for managed users
- Optional: RSAT-GroupPolicy for policy features

## 🔧 Installation

### Step 1: Download Files
```bash
git clone https://github.com/YOUR_USERNAME/mcp-active-directory-server.git
cd mcp-active-directory-server
```

### Step 2: Create Service Account (On Domain Controller)
```powershell
# Create service account
New-ADUser -Name "MCPServiceAccount" `
           -SamAccountName "MCPServiceAccount" `
           -UserPrincipalName "MCPServiceAccount@yourdomain.com" `
           -AccountPassword (ConvertTo-SecureString "YourSecurePassword123!" -AsPlainText -Force) `
           -Enabled $true `
           -PasswordNeverExpires $true

# Create target OU
New-ADOrganizationalUnit -Name "ManagedUsers" -Path "DC=yourdomain,DC=com"

# Grant permissions
$ServiceAccountDN = (Get-ADUser -Identity "MCPServiceAccount").DistinguishedName
$TargetOU = "OU=ManagedUsers,DC=yourdomain,DC=com"

dsacls $TargetOU /G "${ServiceAccountDN}:CCDC;user"  # Create/Delete users
dsacls $TargetOU /G "${ServiceAccountDN}:WP;;user"   # Write user properties
dsacls $TargetOU /G "${ServiceAccountDN}:RP;;user"   # Read user properties
dsacls $TargetOU /G "${ServiceAccountDN}:WP;member;group"  # Group membership
```

### Step 3: Setup Server Environment
```powershell
# Create directory
New-Item -ItemType Directory -Path "C:\MCPServer" -Force

# Copy files
Copy-Item "simple_mcp_server.py" "C:\MCPServer\"
Copy-Item "ad_operations.ps1" "C:\MCPServer\"
Copy-Item "setup_credentials.ps1" "C:\MCPServer\"

# Install required modules
Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
Install-WindowsFeature -Name "RSAT-GroupPolicy" -IncludeAllSubFeature  # Optional for policy features

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 4: Configure Domain Settings
Edit `C:\MCPServer\ad_operations.ps1`:
```powershell
# Update these lines with your domain information
$TargetOU = "OU=ManagedUsers,DC=yourdomain,DC=com"  # Your target OU
$DomainName = "yourdomain.com"  # Your domain name
```

Also update `C:\MCPServer\setup_credentials.ps1`:
```powershell
# Update this line with your domain
$username = "yourdomain\MCPServiceAccount"  # Your domain username
```

### Step 5: Setup Credentials
```powershell
cd C:\MCPServer
.\setup_credentials.ps1
```
Enter your service account password when prompted.

### Step 6: Install Python Dependencies
```powershell
# Create virtual environment (optional but recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install asyncio  # Basic requirement
```

### Step 7: Test the Server
```powershell
# Create logs directory
New-Item -ItemType Directory -Path "C:\MCPServer\logs" -Force

# Test the MCP server
python simple_mcp_server.py
```

### Step 8: Configure Claude Desktop
Add to your Claude Desktop config file (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ad-management": {
      "command": "C:\\MCPServer\\venv\\Scripts\\python.exe",
      "args": ["C:\\MCPServer\\simple_mcp_server.py"],
      "cwd": "C:\\MCPServer"
    }
  }
}
```

Restart Claude Desktop after updating the configuration.

## 💡 Usage Examples

### Basic User Management
**Create a User:**
```
Create a new AD user with username "jsmith", name "John Smith", 
department "IT", and title "Software Engineer"
```

**Modify User:**
```
Update user "jsmith" to change their title to "Senior Software Engineer" 
and department to "Development"
```

**Get User Information:**
```
Get comprehensive information for AD user "jsmith" including group memberships
```

### Advanced Domain Operations
**Domain Analysis:**
```
Show me comprehensive information about our Active Directory domain including 
all FSMO roles and domain controllers
```

**Forest Information:**
```
Get detailed forest information including all domains, sites, and global catalogs
```

**Replication Health:**
```
Check the replication status of our domain controllers and identify any issues
```

**Trust Relationships:**
```
Show me all trust relationships in our domain
```

**Sites and Services:**
```
Get information about our AD sites, site links, and subnet configuration
```

### Deep Inspection
**User Attributes:**
```
Get all attributes for all users in our managed OU
```

**Computer Information:**
```
Show me all computer objects and their attributes in the managed OU
```

**Group Policy:**
```
Get information about our Default Domain Policy
```

## 📁 File Structure

```
C:\MCPServer\
├── simple_mcp_server.py      # Enhanced Python MCP server (14 tools)
├── ad_operations.ps1          # Enhanced PowerShell AD operations script
├── setup_credentials.ps1      # Credential setup script
├── logs\                      # Log files directory
│   └── mcp_server.log        # Server operation logs
└── venv\                     # Python virtual environment (optional)
```

## 🔒 Security Notes

- **Credentials**: Stored securely in Windows Credential Manager
- **Service Account**: Use dedicated account with minimal required permissions
- **Logging**: All operations are logged for audit purposes
- **Encryption**: All AD communications use secure protocols
- **Permissions**: Grant only necessary permissions to the service account

## 🔧 Troubleshooting

### Common Issues

**"Credentials not found"**
- Run `setup_credentials.ps1` again
- Verify the service account exists and is enabled
- Check that credentials are stored with target "MCPActiveDirectory"

**"AD Connection failed"**
- Check network connectivity to domain controllers
- Verify service account permissions
- Ensure machine is domain-joined
- Test with: `Test-ComputerSecureChannel -Verbose`

**"PowerShell execution failed"**
- Check execution policy: `Get-ExecutionPolicy`
- Verify AD PowerShell module: `Get-Module ActiveDirectory -ListAvailable`
- For GroupPolicy features: `Get-Module GroupPolicy -ListAvailable`

**"Python import errors"**
- Ensure Python is installed correctly
- Check PATH environment variable
- Verify script paths in configuration

**"Log files not created"**
- Ensure `C:\MCPServer\logs` directory exists
- Check write permissions on the directory
- Verify Python has access to create files

### Advanced Troubleshooting

**Test AD Connectivity:**
```powershell
# Test basic AD connectivity
Import-Module ActiveDirectory
Get-ADDomain

# Test service account
$Cred = Get-StoredCredential -Target "MCPActiveDirectory"
Get-ADDomain -Credential $Cred

# Test permissions
Get-ADUser -Identity "MCPServiceAccount" -Properties *
```

**Check Logs:**
```powershell
# View recent server logs
Get-Content "C:\MCPServer\logs\mcp_server.log" -Tail 50

# View PowerShell execution logs
Get-WinEvent -LogName "Windows PowerShell" | Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-1)}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly in a lab environment
5. Update documentation as needed
6. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Documentation**: Check existing issues for solutions
- **Logs**: Include relevant log files when reporting issues (redact sensitive information)

## 🙏 Acknowledgments

- Built for use with [Anthropic's Claude](https://claude.ai/)
- Uses the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- PowerShell Active Directory and Group Policy modules
- Windows Credential Manager for secure credential storage

---

**Note**: This tool provides comprehensive AD management capabilities. Always test in a non-production environment first and ensure you have proper backups before making changes to your Active Directory environment.