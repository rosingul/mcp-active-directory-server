param(
    [Parameter(Mandatory=$true)]
    [string]$Operation,
    
    [Parameter(Mandatory=$false)]
    [string]$JsonData,
    
    [Parameter(Mandatory=$false)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$Password
)

# Import required modules
Import-Module ActiveDirectory
try {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
} catch {
    Write-Warning "GroupPolicy module not available. Some features may be limited."
}

# Configuration
$TargetOU = "OU=ManagedUsers,DC=demo,DC=local"  # Update with your domain
$DomainName = "demo.local"  # Update with your domain
$DefaultPassword = ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force

# Create credentials if provided
if ($Username -and $Password) {
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
}

function Write-JsonResult {
    param($Success, $Message, $Data = $null)
    
    $result = @{
        success = $Success
        message = $Message
        data = $Data
        timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    Write-Output ($result | ConvertTo-Json -Depth 10)
}

function Create-User {
    param($UserData)
    
    try {
        $params = @{
            Name = $UserData.Name
            SamAccountName = $UserData.SamAccountName
            UserPrincipalName = "$($UserData.SamAccountName)@$DomainName"
            GivenName = $UserData.GivenName
            Surname = $UserData.Surname
            DisplayName = $UserData.DisplayName
            Path = $TargetOU
            AccountPassword = $DefaultPassword
            Enabled = $true
            ChangePasswordAtLogon = $true
        }
        
        if ($UserData.Department) { $params.Department = $UserData.Department }
        if ($UserData.Title) { $params.Title = $UserData.Title }
        if ($UserData.EmailAddress) { $params.EmailAddress = $UserData.EmailAddress }
        if ($UserData.Description) { $params.Description = $UserData.Description }
        if ($Credential) { $params.Credential = $Credential }
        
        New-ADUser @params
        
        $createdUser = Get-ADUser -Identity $UserData.SamAccountName -Properties *
        
        $userData = @{
            SamAccountName = $createdUser.SamAccountName
            Name = $createdUser.Name
            UserPrincipalName = $createdUser.UserPrincipalName
            DistinguishedName = $createdUser.DistinguishedName
            Enabled = $createdUser.Enabled
        }
        
        Write-JsonResult -Success $true -Message "User created successfully" -Data $userData
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to create user: $($_.Exception.Message)"
    }
}

function Modify-User {
    param($UserData)
    
    try {
        $params = @{
            Identity = $UserData.SamAccountName
        }
        
        if ($Credential) { $params.Credential = $Credential }
        
        if ($UserData.GivenName) { $params.GivenName = $UserData.GivenName }
        if ($UserData.Surname) { $params.Surname = $UserData.Surname }
        if ($UserData.DisplayName) { $params.DisplayName = $UserData.DisplayName }
        if ($UserData.Department) { $params.Department = $UserData.Department }
        if ($UserData.Title) { $params.Title = $UserData.Title }
        if ($UserData.EmailAddress) { $params.EmailAddress = $UserData.EmailAddress }
        if ($UserData.Description) { $params.Description = $UserData.Description }
        if ($UserData.PSObject.Properties['Enabled']) { $params.Enabled = $UserData.Enabled }
        
        Set-ADUser @params
        
        Write-JsonResult -Success $true -Message "User modified successfully"
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to modify user: $($_.Exception.Message)"
    }
}

function Add-UserToGroup {
    param($GroupData)
    
    try {
        $params = @{
            Identity = $GroupData.GroupName
            Members = $GroupData.SamAccountName
        }
        
        if ($Credential) { $params.Credential = $Credential }
        
        Add-ADGroupMember @params
        Write-JsonResult -Success $true -Message "User added to group successfully"
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to add user to group: $($_.Exception.Message)"
    }
}

function Remove-UserFromGroup {
    param($GroupData)
    
    try {
        $params = @{
            Identity = $GroupData.GroupName
            Members = $GroupData.SamAccountName
            Confirm = $false
        }
        
        if ($Credential) { $params.Credential = $Credential }
        
        Remove-ADGroupMember @params
        Write-JsonResult -Success $true -Message "User removed from group successfully"
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to remove user from group: $($_.Exception.Message)"
    }
}

function Get-UserInfo {
    param($UserData)
    
    try {
        $params = @{
            Identity = $UserData.SamAccountName
            Properties = "*"
        }
        
        if ($Credential) { $params.Credential = $Credential }
        
        $user = Get-ADUser @params
        $groupParams = @{
            Identity = $UserData.SamAccountName
        }
        if ($Credential) { $groupParams.Credential = $Credential }
        
        $groups = Get-ADPrincipalGroupMembership @groupParams | Select-Object Name
        
        $userData = @{
            SamAccountName = $user.SamAccountName
            Name = $user.Name
            GivenName = $user.GivenName
            Surname = $user.Surname
            DisplayName = $user.DisplayName
            EmailAddress = $user.EmailAddress
            Department = $user.Department
            Title = $user.Title
            Description = $user.Description
            Enabled = $user.Enabled
            UserPrincipalName = $user.UserPrincipalName
            DistinguishedName = $user.DistinguishedName
            LastLogonDate = $user.LastLogonDate
            PasswordLastSet = $user.PasswordLastSet
            Groups = $groups.Name
        }
        
        Write-JsonResult -Success $true -Message "User information retrieved" -Data $userData
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get user info: $($_.Exception.Message)"
    }
}

function Test-ADConnection {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        $domain = Get-ADDomain @params
        Write-JsonResult -Success $true -Message "Active Directory connection successful" -Data @{
            Domain = $domain.DNSRoot
            DomainMode = $domain.DomainMode
            ForestMode = $domain.Forest
        }
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to connect to Active Directory: $($_.Exception.Message)"
    }
}

# NEW ENHANCED FUNCTIONS

function Get-DomainInfo {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        $domain = Get-ADDomain @params
        
        $domainInfo = @{
            Name = $domain.Name
            DNSRoot = $domain.DNSRoot
            NetBIOSName = $domain.NetBIOSName
            DomainMode = $domain.DomainMode.ToString()
            DomainSID = $domain.DomainSID.ToString()
            Forest = $domain.Forest
            InfrastructureMaster = $domain.InfrastructureMaster
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            DomainControllersContainer = $domain.DomainControllersContainer
            UsersContainer = $domain.UsersContainer
            ComputersContainer = $domain.ComputersContainer
            ChildDomains = $domain.ChildDomains
            ParentDomain = $domain.ParentDomain
        }
        
        Write-JsonResult -Success $true -Message "Domain information retrieved successfully" -Data $domainInfo
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get domain info: $($_.Exception.Message)"
    }
}

function Get-ForestInfo {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        $forest = Get-ADForest @params
        
        $forestInfo = @{
            Name = $forest.Name
            ForestMode = $forest.ForestMode.ToString()
            RootDomain = $forest.RootDomain
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            Domains = $forest.Domains
            Sites = $forest.Sites
            GlobalCatalogs = $forest.GlobalCatalogs
            PartitionsContainer = $forest.PartitionsContainer
            SchemaContainer = $forest.SchemaContainer
            ConfigurationContainer = $forest.ConfigurationContainer
        }
        
        Write-JsonResult -Success $true -Message "Forest information retrieved successfully" -Data $forestInfo
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get forest info: $($_.Exception.Message)"
    }
}

function Get-TrustInfo {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        $trusts = Get-ADTrust -Filter * @params
        
        $trustInfo = @()
        foreach ($trust in $trusts) {
            $trustInfo += @{
                Name = $trust.Name
                Direction = $trust.Direction.ToString()
                TrustType = $trust.TrustType.ToString()
                UplevelOnly = $trust.UplevelOnly
                UsesAESKeys = $trust.UsesAESKeys
                UsesRC4Encryption = $trust.UsesRC4Encryption
                TGTDelegation = $trust.TGTDelegation
                SIDFilteringForestAware = $trust.SIDFilteringForestAware
                SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                SelectiveAuthentication = $trust.SelectiveAuthentication
            }
        }
        
        Write-JsonResult -Success $true -Message "Trust information retrieved successfully" -Data $trustInfo
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get trust info: $($_.Exception.Message)"
    }
}

function Get-DomainPasswordPolicy {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy @params
        
        $policyInfo = @{
            ComplexityEnabled = $passwordPolicy.ComplexityEnabled
            DistinguishedName = $passwordPolicy.DistinguishedName
            LockoutDuration = $passwordPolicy.LockoutDuration.ToString()
            LockoutObservationWindow = $passwordPolicy.LockoutObservationWindow.ToString()
            LockoutThreshold = $passwordPolicy.LockoutThreshold
            MaxPasswordAge = $passwordPolicy.MaxPasswordAge.ToString()
            MinPasswordAge = $passwordPolicy.MinPasswordAge.ToString()
            MinPasswordLength = $passwordPolicy.MinPasswordLength
            PasswordHistoryCount = $passwordPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled = $passwordPolicy.ReversibleEncryptionEnabled
            ObjectClass = $passwordPolicy.ObjectClass
            ObjectGUID = $passwordPolicy.ObjectGUID.ToString()
        }
        
        Write-JsonResult -Success $true -Message "Domain password policy retrieved successfully" -Data $policyInfo
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get domain password policy: $($_.Exception.Message)"
    }
}

function Get-ReplicationStatus {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        # Get replication failures
        $replFailures = @()
        try {
            $failures = Get-ADReplicationFailure -Target (Get-ADDomain).DNSRoot @params
            foreach ($failure in $failures) {
                $replFailures += @{
                    Server = $failure.Server
                    Partner = $failure.Partner
                    FailureType = $failure.FailureType
                    FailureCount = $failure.FailureCount
                    FirstFailureTime = $failure.FirstFailureTime
                    LastError = $failure.LastError
                    NamingContext = $failure.NamingContext
                }
            }
        } catch {
            # No failures or permission issues
        }
        
        # Get replication partner metadata
        $replPartners = @()
        try {
            $partners = Get-ADReplicationPartnerMetadata -Target (Get-ADDomain).DNSRoot @params
            foreach ($partner in $partners) {
                $replPartners += @{
                    Server = $partner.Server
                    Partner = $partner.Partner
                    PartnerType = $partner.PartnerType
                    NamingContext = $partner.NamingContext
                    LastReplicationAttempt = $partner.LastReplicationAttempt
                    LastReplicationSuccess = $partner.LastReplicationSuccess
                    LastReplicationResult = $partner.LastReplicationResult
                    ConsecutiveReplicationFailures = $partner.ConsecutiveReplicationFailures
                }
            }
        } catch {
            # Permission issues or no data
        }
        
        $replicationStatus = @{
            Failures = $replFailures
            Partners = $replPartners
            FailureCount = $replFailures.Count
            HealthStatus = if ($replFailures.Count -eq 0) { "Healthy" } else { "Has Issues" }
        }
        
        Write-JsonResult -Success $true -Message "Replication status retrieved successfully" -Data $replicationStatus
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get replication status: $($_.Exception.Message)"
    }
}

function Get-AllUserAttributes {
    try {
        $params = @{
            Filter = "*"
            SearchBase = $TargetOU
            Properties = "*"
        }
        
        if ($Credential) { $params.Credential = $Credential }
        
        $users = Get-ADUser @params
        
        $allUsers = @()
        foreach ($user in $users) {
            $userAttributes = @{}
            
            # Get all properties that have values
            $user.PSObject.Properties | ForEach-Object {
                if ($_.Value -ne $null -and $_.Value -ne "") {
                    $userAttributes[$_.Name] = $_.Value
                }
            }
            
            $allUsers += $userAttributes
        }
        
        Write-JsonResult -Success $true -Message "All user attributes retrieved successfully" -Data @{
            UserCount = $allUsers.Count
            SearchBase = $TargetOU
            Users = $allUsers
        }
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get all user attributes: $($_.Exception.Message)"
    }
}

function Get-AllComputerAttributes {
    try {
        $params = @{
            Filter = "*"
            SearchBase = $TargetOU
            Properties = "*"
        }
        
        if ($Credential) { $params.Credential = $Credential }
        
        $computers = Get-ADComputer @params
        
        $allComputers = @()
        foreach ($computer in $computers) {
            $computerAttributes = @{}
            
            # Get all properties that have values
            $computer.PSObject.Properties | ForEach-Object {
                if ($_.Value -ne $null -and $_.Value -ne "") {
                    $computerAttributes[$_.Name] = $_.Value
                }
            }
            
            $allComputers += $computerAttributes
        }
        
        Write-JsonResult -Success $true -Message "All computer attributes retrieved successfully" -Data @{
            ComputerCount = $allComputers.Count
            SearchBase = $TargetOU
            Computers = $allComputers
        }
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get all computer attributes: $($_.Exception.Message)"
    }
}

function Get-SitesAndServices {
    try {
        $params = @{}
        if ($Credential) { $params.Credential = $Credential }
        
        # Get AD Sites
        $sites = Get-ADReplicationSite -Filter * @params
        $siteInfo = @()
        foreach ($site in $sites) {
            $siteInfo += @{
                Name = $site.Name
                Description = $site.Description
                Location = $site.Location
                ManagedBy = $site.ManagedBy
                DistinguishedName = $site.DistinguishedName
            }
        }
        
        # Get Site Links
        $siteLinks = Get-ADReplicationSiteLink -Filter * @params
        $siteLinkInfo = @()
        foreach ($link in $siteLinks) {
            $siteLinkInfo += @{
                Name = $link.Name
                Description = $link.Description
                Cost = $link.Cost
                ReplicationFrequencyInMinutes = $link.ReplicationFrequencyInMinutes
                SitesIncluded = $link.SitesIncluded
                InterSiteTransportProtocol = $link.InterSiteTransportProtocol
                DistinguishedName = $link.DistinguishedName
            }
        }
        
        # Get Subnets
        $subnets = Get-ADReplicationSubnet -Filter * @params
        $subnetInfo = @()
        foreach ($subnet in $subnets) {
            $subnetInfo += @{
                Name = $subnet.Name
                Description = $subnet.Description
                Location = $subnet.Location
                Site = $subnet.Site
                DistinguishedName = $subnet.DistinguishedName
            }
        }
        
        $sitesAndServices = @{
            Sites = $siteInfo
            SiteLinks = $siteLinkInfo
            Subnets = $subnetInfo
            TotalSites = $siteInfo.Count
            TotalSiteLinks = $siteLinkInfo.Count
            TotalSubnets = $subnetInfo.Count
        }
        
        Write-JsonResult -Success $true -Message "Sites and Services information retrieved successfully" -Data $sitesAndServices
    }
    catch {
        Write-JsonResult -Success $false -Message "Failed to get Sites and Services info: $($_.Exception.Message)"
    }
}

# Parse JSON data if provided
$data = $null
if ($JsonData) {
    try {
        $data = $JsonData | ConvertFrom-Json
    }
    catch {
        Write-JsonResult -Success $false -Message "Invalid JSON data provided: $($_.Exception.Message)"
        exit 1
    }
}

# Execute operation
switch ($Operation) {
    "CreateUser" { Create-User -UserData $data }
    "ModifyUser" { Modify-User -UserData $data }
    "AddToGroup" { Add-UserToGroup -GroupData $data }
    "RemoveFromGroup" { Remove-UserFromGroup -GroupData $data }
    "GetUserInfo" { Get-UserInfo -UserData $data }
    "TestConnection" { Test-ADConnection }
    
    # NEW ENHANCED OPERATIONS
    "GetDomainInfo" { Get-DomainInfo }
    "GetForestInfo" { Get-ForestInfo }
    "GetTrustInfo" { Get-TrustInfo }
    "GetDomainPasswordPolicy" { Get-DomainPasswordPolicy }
    "GetReplicationStatus" { Get-ReplicationStatus }
    "GetAllUserAttributes" { Get-AllUserAttributes }
    "GetAllComputerAttributes" { Get-AllComputerAttributes }
    "GetSitesAndServices" { Get-SitesAndServices }
    
    default { Write-JsonResult -Success $false -Message "Unknown operation: $Operation" }
}