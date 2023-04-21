#region Prepare Active Directory - run from management VM!
    $AsHCIOUName="OU=ASClus01,DC=Corp,DC=contoso,DC=com"
    $Servers="ASNode1","ASNode2","ASNode3","ASNode4"
    $DomainFQDN=$env:USERDNSDOMAIN
    $ClusterName="ASClus01"
    $Prefix="ASClus01"
    $UserName="ASClus01-DeployUser"
    $Password="LS1setup!"
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
    New-HciAdObjectsPreCreation -Deploy -AsHciDeploymentUserCredential $Credentials -AsHciOUName $AsHCIOUName -AsHciPhysicalNodeList $Servers -DomainFQDN $DomainFQDN -AsHciClusterName $ClusterName -AsHciDeploymentPrefix $Prefix

    #install management features to explore cluster,settings...
    Install-WindowsFeature -Name "RSAT-ADDS","RSAT-Clustering"
#endregion

#region Deploy - run from ASNode1!
    #make D drives online
    $Servers="ASNode1","ASNode2","ASNode3","ASNode4"
    #add $Servers into trustedhosts
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($Servers -join ',') -Force
    #invoke command
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        get-disk -Number 1 | Set-Disk -IsReadOnly $false
        get-disk -Number 1 | Set-Disk -IsOffline $false
    }

    #Download files
    $downloadfolder="D:"
    $files=@()
    $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2210545" ; FileName="BootstrapCloudDeploymentTool.ps1" ; Description="Bootstrap PowerShell"}
    $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2210546" ; FileName="CloudDeployment_10.2303.0.36.zip" ; Description="Cloud Deployment Package"}
    $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2210608" ; FileName="Verify-CloudDeployment.zip_Hash.ps1" ; Description="Verify Cloud Deployment PowerShell"}

    foreach ($file in $files){
        if (-not (Test-Path "$downloadfolder\$($file.filename)")){
            Start-BitsTransfer -Source $file.uri -Destination "$downloadfolder\$($file.filename)" -DisplayName "Downloading: $($file.filename)"
        }
    }

    #Start bootstrap (script is looking for file "CloudDeployment_*.zip"
    & D:\BootstrapCloudDeploymentTool.ps1

    #create deployment credentials
    $UserName="ASClus01-DeployUser"
    $Password="LS1setup!"
    $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
    $AzureStackLCMUserCredential = New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)

    $UserName="Administrator"
    $Password="LS1setup!"
    $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
    $LocalAdminCred = New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)
    $CloudName="AzureCloud"
    $ServicePrincipalName="Azure-Stack-Registration"

    #login to azure
    #download Azure module
    if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
        Install-Module -Name Az.Accounts -Force
    }
    if (-not (Get-AzContext)){
        Connect-AzAccount -UseDeviceAuthentication
    }
    #select subscription if more available
    $subscriptions=Get-AzSubscription
    #list subscriptions
    $subscriptions
    if (($subscriptions).count -gt 1){
        $SubscriptionID=Read-Host "Please give me subscription ID"
    }else{
        $SubscriptionID=$subscriptions.id
    }

    if (!(Get-InstalledModule -Name az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }

    #Create Azure Stack HCI registration role https://learn.microsoft.com/en-us/azure-stack/hci/deploy/register-with-azure#assign-permissions-from-azure-portal
    if (-not (Get-AzRoleDefinition -Name "Azure Stack HCI registration role - Custom")){
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
        "Microsoft.HybridConnectivity/register/action"
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
    #Create AzADServicePrincipal for Azure Stack HCI registration
    $SP=Get-AZADServicePrincipal -DisplayName $ServicePrincipalName
    if (-not $SP){
        $SP=New-AzADServicePrincipal -DisplayName $ServicePrincipalName -Role "Azure Stack HCI registration role - Custom"
        #remove default cred
        Remove-AzADAppCredential -ApplicationId $SP.AppId
    }

    #Create new SPN password
    $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential" -Property @{
        "KeyID"         = (new-guid).Guid ;
        "EndDateTime" = [DateTime]::UtcNow.AddYears(10)
    }
    $Creds=New-AzADAppCredential -PasswordCredentials $credential -ApplicationID $SP.AppID
    $SPNSecret=$Creds.SecretText
    Write-Host "Your Password is: " -NoNewLine ; Write-Host $SPNSecret -ForegroundColor Cyan
    $SPNsecStringPassword = ConvertTo-SecureString $SPNSecret -AsPlainText -Force
    $SPNCred=New-Object System.Management.Automation.PSCredential ($SP.AppID, $SPNsecStringPassword)

    #create config.json
    $Content=@"
{
    "Version": "3.0.0.0",
    "ScaleUnits": [
        {
            "DeploymentData": {
                "SecuritySettings": {
                    "SecurityModeSealed": true,
                    "SecuredCoreEnforced": true,
                    "VBSProtection": true,
                    "HVCIProtection": true,
                    "DRTMProtection": true,
                    "KernelDMAProtection": true,
                    "DriftControlEnforced": true,
                    "CredentialGuardEnforced": false,
                    "SMBSigningEnforced": true,
                    "SMBClusterEncryption": false,
                    "SideChannelMitigationEnforced": true,
                    "BitlockerBootVolume": true,
                    "BitlockerDataVolumes": true,
                    "SEDProtectionEnforced": true,
                    "WDACEnforced": true
                },
                "Observability": {
                    "StreamingDataClient": true,
                    "EULocation": true,
                    "EpisodicDataUpload": true
                },
                "Cluster": {
                    "Name": "ASClus01",
                    "StaticAddress": [
                        ""
                    ]
                },
                "Storage": {
                    "ConfigurationMode": "Express"
                },
                "OptionalServices": {
                    "VirtualSwitchName": "",
                    "CSVPath": "",
                    "ARBRegion": "westeurope"
                },
                "TimeZone": "Pacific Standard Time",
                "NamingPrefix": "ASClus01",
                "DomainFQDN": "corp.contoso.com",
                "ExternalDomainFQDN": "corp.contoso.com",
                "InfrastructureNetwork": [
                    {
                        "VlanId": "0",
                        "SubnetMask": "255.255.255.0",
                        "Gateway": "10.0.0.1",
                        "IPPools": [
                            {
                                "StartingAddress": "10.0.0.100",
                                "EndingAddress": "10.0.0.199"
                            }
                        ],
                        "DNSServers": [
                            "10.0.0.1"
                        ]
                    }
                ],
                "PhysicalNodes": [
                    {
                        "Name": "ASNode1",
                        "IPv4Address": "$((Get-NetIPAddress -InterfaceAlias ethernet -AddressFamily ipv4 -CimSession ASNode1).IPAddress)"
                    },
                    {
                        "Name": "ASNode2",
                        "IPv4Address": "$((Get-NetIPAddress -InterfaceAlias ethernet -AddressFamily ipv4 -CimSession ASNode2).IPAddress)"
                    },
                    {
                        "Name": "ASNode3",
                        "IPv4Address": "$((Get-NetIPAddress -InterfaceAlias ethernet -AddressFamily ipv4 -CimSession ASNode3).IPAddress)"
                    },
                    {
                        "Name": "ASNode4",
                        "IPv4Address": "$((Get-NetIPAddress -InterfaceAlias ethernet -AddressFamily ipv4 -CimSession ASNode4).IPAddress)"
                    }
                ],
                "HostNetwork": {
                    "Intents": [
                        {
                            "Name": "Compute_Management_Storage",
                            "TrafficType": [
                                "Compute",
                                "Management",
                                "Storage"
                            ],
                            "Adapter": [
                                "Ethernet",
                                "Ethernet 2"
                            ],
                            "OverrideVirtualSwitchConfiguration": false,
                            "VirtualSwitchConfigurationOverrides": {
                                "EnableIov": "",
                                "LoadBalancingAlgorithm": ""
                            },
                            "OverrideQoSPolicy": false,
                            "QoSPolicyOverrides": {
                                "PriorityValue8021Action_Cluster": "",
                                "PriorityValue8021Action_SMB": "",
                                "BandwidthPercentage_SMB": ""
                            },
                            "OverrideAdapterProperty": false,
                            "AdapterPropertyOverrides": {
                                "JumboPacket": "",
                                "NetworkDirect": "",
                                "NetworkDirectTechnology": ""
                            }
                        }
                    ],
                    "StorageNetworks": [
                        {
                            "Name": "Storage1Network",
                            "NetworkAdapterName": "Ethernet",
                            "VlanId": 711
                        },
                        {
                            "Name": "Storage2Network",
                            "NetworkAdapterName": "Ethernet 2",
                            "VlanId": 712
                        }
                    ]
                },
                "ADOUPath": "OU=ASClus01,DC=Corp,DC=contoso,DC=com",
                "DNSForwarder": [
                    "10.0.0.1"
                ]
            }
        }
    ]
}
"@
$Content | Out-File -FilePath d:\config.json

#start deployment
#make sure some prereqs (that will be fixed in future) are set
    #Make sure Windows Update is disabled and ping enabled (https://learn.microsoft.com/en-us/azure-stack/hci/hci-known-issues-2303)
    Microsoft.PowerShell.Core\Invoke-Command -ComputerName $Servers -ScriptBlock {
        reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f
        reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 3 /f
        Set-Service "WUAUSERV" -StartupType Disabled
        #enable v4 and v6 ping on both domain and private/public profiles
        Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In,FPS-ICMP6-ERQ-In
    }
    #add hostnames and IPs to trusted hosts (bug that in BareMetal.psm1 is invoke-command with IP that is not in trusted hosts)
    $TrustedHosts=@()
    $TrustedHosts+=(Get-NetIPAddress -CimSession $Servers -InterfaceAlias Ethernet* -AddressFamily IPv4).IPAddress
    $TrustedHosts+=$Servers
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($TrustedHosts -join ',') -Force

#deploy
.\Invoke-CloudDeployment -JSONFilePath D:\config.json -AzureStackLCMUserCredential $AzureStackLCMUserCredential -LocalAdminCredential $LocalAdminCred -RegistrationSPCredential $SPNCred -RegistrationCloudName $CloudName -RegistrationSubscriptionID $SubscriptionID

#endregion

#region Validate deployment - run from management VM!
$SeedNode="ASNode1"

Invoke-Command -ComputerName $SeedNode -ScriptBlock {
    ([xml](Get-Content C:\ecestore\efb61d70-47ed-8f44-5d63-bed6adc0fb0f\086a22e3-ef1a-7b3a-dc9d-f407953b0f84)) | Select-Xml -XPath "//Action/Steps/Step" | ForEach-Object { $_.Node } | Select-Object FullStepIndex, Status, Name, StartTimeUtc, EndTimeUtc, @{Name="Duration";Expression={new-timespan -Start $_.StartTimeUtc -End $_.EndTimeUtc } } | ft -AutoSize
}
#endregion