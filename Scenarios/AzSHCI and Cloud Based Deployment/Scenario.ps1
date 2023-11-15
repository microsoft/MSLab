#region Prepare Active Directory
    $AsHCIOUName="OU=ASClus01,DC=Corp,DC=contoso,DC=com"
    $Servers="ASNode1","ASNode2"
    $DomainFQDN=$env:USERDNSDOMAIN
    $ClusterName="ASClus01"
    $Prefix="ASClus01"
    $UserName="ASClus01-DeployUser"
    $Password="LS1setup!LS1setup!"
    $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credentials= New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)

    #install posh module for prestaging Active Directory
    Install-PackageProvider -Name NuGet -Force
    Install-Module AsHciADArtifactsPreCreationTool -Repository PSGallery -Force

    #add KDS Root Key
    if (-not (Get-KdsRootKey)){
        Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))
    }

    #make sure active directory module and GPMC is installed
    Install-WindowsFeature -Name RSAT-AD-PowerShell,GPMC

    #populate objects
    New-HciAdObjectsPreCreation -Deploy -AzureStackLCMUserCredential  $Credentials -AsHciOUName $AsHCIOUName -AsHciPhysicalNodeList $Servers -DomainFQDN $DomainFQDN -AsHciClusterName $ClusterName -AsHciDeploymentPrefix $Prefix

    #install management features to explore cluster,settings...
    Install-WindowsFeature -Name "RSAT-ADDS","RSAT-Clustering"
#endregion

#region prepare azure prerequisites
        #variables
        #$StorageAccountName="asclus01$(Get-Random -Minimum 100000 -Maximum 999999)"
        #$KeyVaultName=$StorageAccountName
        #$ServicePrincipal=$True #or false if you want to use MFA (and skip SP creation)
        #$ServicePrincipalName="Azure-Stack-Registration"
        $ResourceGroupName="ASClus01-RG"
        $Location="eastus" #make sure location is lowercase as in 2308 was not able to deploy with "EastUS"

        #login to azure
            #download Azure module
            if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
                Install-Module -Name Az.Accounts -Force
            }
            if (-not (Get-AzContext)){
                Connect-AzAccount -UseDeviceAuthentication
            }

        #select subscription if more available (will wait for subscription ID - not using Out-GridView in case you run this on one of the nodes)
            $subscriptions=Get-AzSubscription
            #list subscriptions
            $subscriptions
            if (($subscriptions).count -gt 1){
                $SubscriptionID=Read-Host "Please give me subscription ID"
                $Subscriptions | WHere-Object ID -eq $SubscriptionID | Select-AzSubscription
            }else{
                $SubscriptionID=$subscriptions.id
            }

        #install az resources module
        if (!(Get-InstalledModule -Name "az.resources" -ErrorAction Ignore)){
            Install-Module -Name "az.resources" -Force
        }

        #create resource group
        if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
            New-AzResourceGroup -Name $ResourceGroupName -Location $location
        }

        #make sure resource providers are registered (most likely not needed)
        <#
            $Providers="Microsoft.ResourceConnector","Microsoft.Authorization","Microsoft.AzureStackHCI","Microsoft.HybridCompute","Microsoft.GuestConfiguration"
            foreach ($Provider in $Providers){
                Register-AzResourceProvider -ProviderNamespace $Provider
                #wait for provider to finish registration
                do {
                    $Status=Get-AzResourceProvider -ProviderNamespace $Provider
                    Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
                    Start-Sleep 1
                } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))
            }
        #>
        
        #Create Storage Account for witness if deploying using ARM template
            <#
            if (!(Get-InstalledModule -Name "az.storage"-ErrorAction Ignore)){
                    Install-Module -Name "az.storage" -Force
                }

            #create Storage Account
            If (-not(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)){
                New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location $location -Kind StorageV2 -AccessTier Cool 
            }
            $StorageAccountAccessKey=(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName | Select-Object -First 1).Value
            #>

        #Create key vault if deploying using ARM template
        <#
        if (!(Get-InstalledModule -Name "az.keyvault"-ErrorAction Ignore)){
            Install-Module -Name "az.keyvault" -Force
        }
        If (-not(Get-AzStorageAccountKey -Name $KeyVaultName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)){
            New-AzKeyVault -Name $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $location
        }
        #>

        #create service principal if deploying using ARM template
        <#
        if ($ServicePrincipal){
            #Create Azure Stack HCI registration role https://learn.microsoft.com/en-us/azure-stack/hci/deploy/register-with-azure#assign-permissions-from-azure-portal
            #https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#azure-connected-machine-onboarding
            if (-not (Get-AzRoleDefinition -Name "Azure Stack HCI registration role - Custom" -ErrorAction Ignore)){
                $Content=@"
{
    "Name": "Azure Stack HCI registration role - Custom",
    "Id": null,
    "IsCustom": true,
    "Description": "Custom Azure role to allow subscription-level access to register Azure Stack HCI",
    "Actions": [
        "Microsoft.Resources/subscriptions/resourceGroups/read",
        "Microsoft.Resources/subscriptions/resourceGroups/write",
        "Microsoft.Resources/subscriptions/resourceGroups/delete", 
        "Microsoft.AzureStackHCI/register/action",
        "Microsoft.AzureStackHCI/Unregister/Action",
        "Microsoft.AzureStackHCI/clusters/*",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.HybridCompute/register/action",
        "Microsoft.GuestConfiguration/register/action",
        "Microsoft.HybridConnectivity/register/action",
        "Microsoft.HybridCompute/machines/extensions/write",
        "Microsoft.HybridCompute/machines/extensions/read",
        "Microsoft.HybridCompute/machines/read",
        "Microsoft.HybridCompute/machines/write",
        "Microsoft.HybridCompute/privateLinkScopes/read",
        "Microsoft.GuestConfiguration/guestConfigurationAssignments/read",
        "Microsoft.ResourceConnector/register/action",
        "Microsoft.Kubernetes/register/action",
        "Microsoft.KubernetesConfiguration/register/action",
        "Microsoft.ExtendedLocation/register/action",
        "Microsoft.HybridContainerService/register/action",
        "Microsoft.ResourceConnector/appliances/write",
        "Microsoft.ResourceConnector/appliances/delete,
        "Microsoft.ResourceConnector/appliances/listClusterUserCredential/action",
        "Microsoft.ResourceConnector/appliances/read",
        "Microsoft.ExtendedLocation/customLocations/read",
        "Microsoft.ExtendedLocation/customLocations/write",
        "Microsoft.KubernetesConfiguration/extensions/read",
        "Microsoft.KubernetesConfiguration/extensions/write",
        "Microsoft.KubernetesConfiguration/extensions/operations/read"
    ],
    "NotActions": [
    ],
    "AssignableScopes": [
        "/subscriptions/$SubscriptionID"
    ]
    }
"@
                $Content | Out-File "$env:USERPROFILE\Downloads\customHCIRole.json"
                New-AzRoleDefinition -InputFile "$env:USERPROFILE\Downloads\customHCIRole.json"
            }

            #Create AzADServicePrincipal for Azure Stack HCI registration (if it does not exist)
                $SP=Get-AZADServicePrincipal -DisplayName $ServicePrincipalName
                if (-not $SP){
                    $SP=New-AzADServicePrincipal -DisplayName $ServicePrincipalName -Role "Azure Stack HCI registration role - Custom"
                    #remove default cred
                    Remove-AzADAppCredential -ApplicationId $SP.AppId
                }

            #Create new SPN password
                $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential" -Property @{
                    "KeyID"         = (new-guid).Guid ;
                    "EndDateTime" = [DateTime]::UtcNow.AddYears(1)
                }
                $Creds=New-AzADAppCredential -PasswordCredentials $credential -ApplicationID $SP.AppID
                $SPNSecret=$Creds.SecretText
                $SPAppID=$SP.AppID
        }
#>
    #Disconnect-AzAccount

    #output variables
    Write-Host -ForegroundColor Cyan @"
        #Variables to copy
        `$SubscriptionID=`"$SubscriptionID`"
        `$SPAppID=`"$SPAppID`"
        `$SPNSecret=`"$SPNSecret`"
        `$ResourceGroupName=`"$ResourceGroupName`"
        `$StorageAccountName=`"$StorageAccountName`"
        `$KeyVaultName=`"$KeyVaultName`"
        `$StorageAccountAccessKey=`"$StorageAccountAccessKey`"
        `$Location=`"$Location`"
"@ 


#endregion

#region install ARC agent with extensions on nodes
    $ResourceGroupName="ASClus01-RG"
    $TenantID=(Get-AzContext).Tenant.ID
    $SubscriptionID=(Get-AzContext).Subscription.ID
    $Location="EastUS"
    $Cloud="AzureCloud"
    $ServicePrincipalName="Azure Stack HCI ARC Onboarding"

    #Since machines are not domain joined, let's do some preparation
    $UserName="Administrator"
    $Password="LS1setup!"
    $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credentials= New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)

    #configure trusted hosts to be able to communicate with servers (not secure)
    $TrustedHosts=@()
    $TrustedHosts+=$Servers
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($TrustedHosts -join ',') -Force

    #make sure Hyper-V and FailoverClustering is installed (FC will allow discovery using icmp -allows all clustering fw rules)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart
        Install-WindowsFeature -Name Failover-Clustering
    } -Credential $Credentials

    #region update all servers
        Invoke-Command -ComputerName $servers -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore -Credential $Credentials
        #sleep a bit
        Start-Sleep 2
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' -ScriptBlock {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            if ($SearchResult.Count -gt 0){
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Downloader = $Session.CreateUpdateDownloader()
                $Downloader.Updates = $SearchResult
                $Downloader.Download()
                $Installer = New-Object -ComObject Microsoft.Update.Installer
                $Installer.Updates = $SearchResult
                $Result = $Installer.Install()
                $Result
            }
        } -Credential $Credentials
        #remove temporary PSsession config
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }  -Credential $Credentials
    #endregion

    #restart servers to finish Installation
    Restart-Computer -ComputerName $Servers -Credential $Credentials -WsmanAuthentication Negotiate -Wait -For PowerShell
    Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
    #make sure computers are restarted
    Foreach ($Server in $Servers){
        do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
    }

    #region install arc agents with azshci.arcinstaller
        #make sure nuget is installed on nodes
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        } -Credential $Credentials

        #make sure azshci.arcinstaller is installed on nodes
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-Module -Name azshci.arcinstaller -Force
        } -Credential $Credentials

        #make sure Az.Resources module is installed on nodes
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-Module -Name Az.Resources  -Force
        } -Credential $Credentials

        #make sure az.accounts module is installed on nodes
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-Module -Name az.accounts  -Force
        } -Credential $Credentials

        #region Create AzADServicePrincipal for Arc Onboarding with custom permissions (jaromirk note: "Microsoft.Authorization/roleAssignments/write" needs to go away, however this is something that will as it's preview)
            #Create Azure Stack HCI ARC Onboarding role https://learn.microsoft.com/en-us/azure-stack/hci/deploy/register-with-azure#assign-permissions-from-azure-portal
            #https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#azure-connected-machine-onboarding
            if (-not (Get-AzRoleDefinition -Name "Azure Stack HCI ARC Onboarding - Custom" -ErrorAction Ignore)){
                $Content=@"
{
    "Name": "Azure Stack HCI ARC Onboarding - Custom",
    "Id": null,
    "IsCustom": true,
    "Description": "Custom Azure role to allow onboard Azure Stack HCI with azshci.arcinstaller",
    "Actions": [
        "Microsoft.HybridCompute/machines/read",
        "Microsoft.HybridCompute/machines/write",
        "Microsoft.HybridCompute/privateLinkScopes/read",
        "Microsoft.GuestConfiguration/guestConfigurationAssignments/read",
        "Microsoft.HybridCompute/machines/extensions/write",
        "Microsoft.Authorization/roleAssignments/write"
    ],
    "NotActions": [
    ],
    "AssignableScopes": [
        "/subscriptions/$SubscriptionID"
    ]
    }
"@
                $Content | Out-File "$env:USERPROFILE\Downloads\customHCIRole.json"
                New-AzRoleDefinition -InputFile "$env:USERPROFILE\Downloads\customHCIRole.json"
            }

            #Create AzADServicePrincipal for Azure Stack HCI registration (if it does not exist)
                $SP=Get-AZADServicePrincipal -DisplayName $ServicePrincipalName
                if (-not $SP){
                    $SP=New-AzADServicePrincipal -DisplayName $ServicePrincipalName -Role "Azure Stack HCI ARC Onboarding - Custom"
                    #remove default cred
                    Remove-AzADAppCredential -ApplicationId $SP.AppId
                }

            #Create new SPN password
                $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential" -Property @{
                    "KeyID"         = (new-guid).Guid ;
                    "EndDateTime" = [DateTime]::UtcNow.AddYears(1)
                }
                $Creds=New-AzADAppCredential -PasswordCredentials $credential -ApplicationID $SP.AppID
                $SPNSecret=$Creds.SecretText
                $SPAppID=$SP.AppID
                $SecuredPassword = ConvertTo-SecureString $SPNSecret -AsPlainText -Force
                $SPNCredentials= New-Object System.Management.Automation.PSCredential ($SPAppID,$SecuredPassword)
        #endregion

        #deploy ARC Agent (It's failing, cant figure out why)
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Invoke-AzStackHciArcInitialization -SubscriptionID $using:SubscriptionID -ResourceGroup $using:ResourceGroupName -TenantID $using:TenantID -Cloud $using:Cloud -Region $Using:Location -SpnCredential $Using:SPNCredentials
        } -Credential $Credentials

        #let's onboard ARC agent "manually"
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            $machineName = [System.Net.Dns]::GetHostName()
            $SPNCredentials=$using:SPNCredentials
            $SPNpassword=$SPNCredentials.GetNetworkCredential().Password
            & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --service-principal-id $using:SpnCredentials.UserName --service-principal-secret $SPNpassword --resource-group $using:ResourceGroupName  --resource-name "$machineName"  --tenant-id $using:TenantID --location $Using:Location --subscription-id $using:SubscriptionID --cloud $using:Cloud
        } -Credential $Credentials

        #and let's run deployment again
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Invoke-AzStackHciArcInitialization -SubscriptionID $using:SubscriptionID -ResourceGroup $using:ResourceGroupName -TenantID $using:TenantID -Cloud $using:Cloud -Region $Using:Location -SpnCredential $Using:SPNCredentials
        } -Credential $Credentials

    #endregion

    #region install arc agents with manually - I keep it here just for education purposes as I spent some time with troubleshooting azshci.arcinstaller
    <#
        $ServicePrincipalName="Arc-for-servers"
        # Download ARC agent installation package
        Start-BitsTransfer -Source https://aka.ms/AzureConnectedMachineAgent -Destination "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"

        #Copy ARC agent to nodes
        #increase max evenlope size first
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096} -Credential $Credentials

        #create temp folder
        Invoke-Command -ComputerName $servers -ScriptBlock {New-Item -Name Temp -Path C:\ -ItemType Directory -ErrorAction Ignore} -Credential $Credentials

        #create sessions
        $sessions=New-PSSession -ComputerName $servers -Credential $Credentials -Authentication Negotiate
        #copy ARC agent
        foreach ($session in $sessions){
            Copy-Item -Path "$env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi" -Destination "c:\temp\" -tosession $session -force
        }

        #install package
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i c:\temp\AzureConnectedMachineAgent.msi /l*v c:\temp\ACMinstallationlog.txt /qn" -Wait
        } -Credential $Credentials

        #make sure Resource Providers are registered
        Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridCompute"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.GuestConfiguration"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.HybridConnectivity"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.AzureStackHCI"

        #Create AzADServicePrincipal for Arc Onboarding
        $SP=Get-AZADServicePrincipal -DisplayName $ServicePrincipalName
        if (-not $SP){
            $SP=New-AzADServicePrincipal -DisplayName $ServicePrincipalName -Role "Azure Connected Machine Onboarding"
            #remove default cred
            Remove-AzADAppCredential -ApplicationId $SP.AppId
        }

        #Create new SPN password
        $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential" -Property @{
            "KeyID"         = (new-guid).Guid ;
            "EndDateTime" = [DateTime]::UtcNow.AddYears(1)
        }
        $Creds=New-AzADAppCredential -PasswordCredentials $credential -ApplicationID $SP.AppID
        $SPNSecret=$Creds.SecretText
        $SPAppID=$SP.AppID

        #sleep for 1m just to let SPNSecret to propagate
        Start-Sleep 60

        #configure Azure ARC agent on servers
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:SPAppID --service-principal-secret $using:SPNSecret --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location) --cloud $using:Cloud --subscription-id $using:SubscriptionID" -Wait
        } -Credential $Credentials

        #check if ARC Agent is connected
        $Output=Invoke-Command -ComputerName $Servers -ScriptBlock {
            & "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe" show -j | ConvertFrom-Json
        } -Credential $Credentials
        $Output | Select-Object Status,PSComputerName

        #add extensions
        #make sure nuget is installed on nodes (AzureEdgeLifecycleManager was failing for me)
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-PackageProvider -Name NuGet -Force
        } -Credential $Credentials

        if (!(Get-InstalledModule -Name "Az.ConnectedMachine"-ErrorAction Ignore)){
            Install-Module -Name "Az.ConnectedMachine" -Force
        }

        $Settings = @{ "CloudName" = $Cloud; "RegionName" = $Location; "DeviceType" = "AzureEdge" }
        foreach ($Server in $Servers){
            New-AzConnectedMachineExtension -Name "TelemetryAndDiagnostics" -ResourceGroupName $ResourceGroupName -MachineName $Server -Location $Location -Publisher "Microsoft.AzureStack.Observability" -Settings $Settings -ExtensionType "TelemetryAndDiagnostics" -NoWait
            New-AzConnectedMachineExtension -Name "AzureEdgeDeviceManagement" -ResourceGroupName $ResourceGroupName -MachineName $Server -Location $Location -Publisher "Microsoft.Edge" -ExtensionType "DeviceManagementExtension" -NoWait
            New-AzConnectedMachineExtension -Name "AzureEdgeLifecycleManager" -ResourceGroupName $ResourceGroupName -MachineName $Server -Location $Location -Publisher "Microsoft.AzureStack.Orchestration" -ExtensionType "LcmController" -NoWait
        }

        #validate extensions are installed
        foreach ($Server in $Servers){
            Get-AzConnectedMachineExtension -Name "TelemetryAndDiagnostics" -ResourceGroupName $ResourceGroupName -MachineName $Server
            Get-AzConnectedMachineExtension -Name "AzureEdgeDeviceManagement" -ResourceGroupName $ResourceGroupName -MachineName $Server
            Get-AzConnectedMachineExtension -Name "AzureEdgeLifecycleManager" -ResourceGroupName $ResourceGroupName -MachineName $Server
        }

        #wait until provisioning state is succeeded
        do {
            Start-Sleep 5
            $Status=@()
            foreach ($Server in $Servers){
                $Status+=Get-AzConnectedMachineExtension -Name "TelemetryAndDiagnostics" -ResourceGroupName $ResourceGroupName -MachineName $Server
                $Status+=Get-AzConnectedMachineExtension -Name "AzureEdgeDeviceManagement" -ResourceGroupName $ResourceGroupName -MachineName $Server
                $Status+=Get-AzConnectedMachineExtension -Name "AzureEdgeLifecycleManager" -ResourceGroupName $ResourceGroupName -MachineName $Server
            }
            Write-Host "." -NoNewline
        } until (
            $status.provisioningstate -notcontains "Creatingg"
        )

        #Assign role to ARC Objects
        $ResourceIDs=Invoke-Command -ComputerName $Servers -ScriptBlock {
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("metadata", "true")
            $headers.Add("UseDefaultCredentials","true")
            $response = Invoke-WebRequest -Uri "http://localhost:40342/metadata/instance/compute?api-version=2020-06-01" -Method GET -Headers $headers -UseBasicParsing
            $content = $response.Content | ConvertFrom-Json
            $resourceId = $content.resourceId
            return $resourceId
        } -Credential $Credentials

        foreach ($ResourceID in $ResourceIDs){
            $arcResource = Get-AzResource -ResourceId $ResourceID
            $objectId = $arcResource.Identity.PrincipalId
            New-AzRoleAssignment -ObjectId $ObjectId -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Azure Stack HCI Device Management Role"
            New-AzRoleAssignment -ObjectId $ObjectId -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Azure Connected Machine Resource Manager"
            New-AzRoleAssignment -ObjectId $ObjectId -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Reader"

        }

        #make sure environmental checker is installed on nodes
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-Module -Name AzStackHci.EnvironmentChecker -Force -AllowClobber
        } -Credential $Credentials

        #remove
        <#
        foreach ($ResourceID in $ResourceIDs){
            $arcResource = Get-AzResource -ResourceId $ResourceID
            $objectId = $arcResource.Identity.PrincipalId
            Remove-AzRoleAssignment -ObjectId $ObjectId -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Azure Stack HCI Device Management Role"
        }
        #>
    #>
    #endregion

#endregion

#region final touches

    #make sure there is only one management NIC with IP address (setup is complaining about multiple gateways)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $adapter=Get-NetIPConfiguration | Where-Object IPV4defaultGateway | Get-NetAdapter | Sort-Object Name | Select-Object -Skip 1
        #disable netbios (otherwise the apipa might be resolved instead of 10.x address)
        $query="select * From Win32_NetworkAdapterConfiguration where Description = `'$($Adapter.Interfacedescription)`'"
        $arguments = @{'TcpipNetbiosOptions' = [UInt32](2) }
        Invoke-CimMethod -Query $query -Namespace Root/CIMV2 -MethodName SetTcpipNetbios -Arguments $arguments
        #disable receiving address from dhcp
        $adapter | Set-NetIPInterface -Dhcp Disabled
    } -Credential $Credentials
    Clear-DnsClientCache

    #add key vault admin of current user to Resource Group
    $objectId = (Get-AzADUser -SignedIn).Id
    New-AzRoleAssignment -ObjectId $ObjectId -ResourceGroupName $ResourceGroupName -RoleDefinitionName "Key Vault Administrator"

    #change password of local admin to be at least 12 chars
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Set-LocalUser -Name Administrator -AccountNeverExpires -Password (ConvertTo-SecureString "LS1setup!LS1setup!" -AsPlainText -Force)
    } -Credential $Credentials


#endregion

#region do the magic in azure portal
<#
Basics:
    Resource Group: ASClus-01-RG
    ClusterName:    ASClus01
    Keyvaultname:   <Just generate new>

Configuration:
    New Configuration

Networking
    Network Switch for storage
    Group All traffic

    Network adapter 1:          Ethernet
    Network adapter 1 VLAN ID:  711 (default)
    Network adapter 2:          Ethernet 2
    Network adapter 2 VLAN ID:  712 (default)

    Starting IP:                10.0.0.100
    ENding IP:                  10.0.0.110
    Subnet mask:                255.255.255.0
    Default Gateway:            10.0.0.1
    DNS Server:                 10.0.0.1

Management
    Custom location name:       ASClus01CustomLocation (default)\
    Azure storage account name: <just generate new>

    Domain:                     corp.contoso.com
    Computer name prefix:       ASClus01
    OU:                         OU=ASClus01,DC=Corp,DC=contoso,DC=com

    Deployment account:
        Username:               ASClus01-DeployUser
        Password:               LS1setup!LS1setup!

    Local Administrator
        Username:               Administrator
    Password:                   LS1setup!LS1setup!

Security:
    Customized security settings
        Unselect Bitlocker for data volumes (would consume too much space)

Advanced:
    Create workload volumes (Default)

Tags:
    <keep default>

Let it validate... if you run into issues with key vault audit logging, make sure that there are not having too many linked accounts under key vault diagnostics. This can happen if you run validation multiple times
If it will timeout, try to run it again.
#>
#endregion

#region check progress
    #Create new password credentials
    $UserName="Administrator"
    $Password="LS1setup!LS1setup!"
    $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
    $Credentials= New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)

    #before domain join
    Invoke-Command -ComputerName $Servers[0] -ScriptBlock {
        ([xml](Get-Content C:\ecestore\efb61d70-47ed-8f44-5d63-bed6adc0fb0f\086a22e3-ef1a-7b3a-dc9d-f407953b0f84)) | Select-Xml -XPath "//Action/Steps/Step" | ForEach-Object { $_.Node } | Select-Object FullStepIndex, Status, Name, StartTimeUtc, EndTimeUtc, @{Name="Duration";Expression={new-timespan -Start $_.StartTimeUtc -End $_.EndTimeUtc } } | Format-Table -AutoSize
    } -Credential $Credentials

    #after domain join
    Invoke-Command -ComputerName $Servers[0] -ScriptBlock {
        ([xml](Get-Content C:\ecestore\efb61d70-47ed-8f44-5d63-bed6adc0fb0f\086a22e3-ef1a-7b3a-dc9d-f407953b0f84)) | Select-Xml -XPath "//Action/Steps/Step" | ForEach-Object { $_.Node } | Select-Object FullStepIndex, Status, Name, StartTimeUtc, EndTimeUtc, @{Name="Duration";Expression={new-timespan -Start $_.StartTimeUtc -End $_.EndTimeUtc } } | Format-Table -AutoSize
    }
#endregion

#Deployment using ARM Templates <TBD>