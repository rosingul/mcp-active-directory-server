        Install-Module -Name CredentialManager -Force -Scope CurrentUser
        Import-Module CredentialManager

        Write-Host "`nEnter your MCP Service Account credentials:" -ForegroundColor Cyan
        $username = "demo\MCPServiceAccount"  # Your domain username
        Write-Host "Username: $username"
        
        $password = Read-Host -Prompt "Enter password for $username" -AsSecureString

        # Store credentials in Windows Credential Manager
        New-StoredCredential -Target "MCPActiveDirectory" -UserName $username -Password $password -Type Generic -Persist LocalMachine