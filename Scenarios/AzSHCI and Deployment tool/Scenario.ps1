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
    New-HciAdObjectsPreCreation -Deploy -AzureStackLCMUserCredential  $Credentials -AsHciOUName $AsHCIOUName -AsHciPhysicalNodeList $Servers -DomainFQDN $DomainFQDN -AsHciClusterName $ClusterName -AsHciDeploymentPrefix $Prefix

    #install management features to explore cluster,settings...
    Install-WindowsFeature -Name "RSAT-ADDS","RSAT-Clustering"
#endregion

#region prepare azure prerequisites - run from ASNode1 or Management (you can run from Management, just copy the resulting variables and use it in next region)
        #variables
        $StorageAccountName="asclus01$(Get-Random -Minimum 100000 -Maximum 999999)"
        $ServicePrincipal=$True #or false if you want to use MFA (and skip SP creation)
        $ServicePrincipalName="Azure-Stack-Registration"
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

        #select subscription if more available
            $subscriptions=Get-AzSubscription
            #list subscriptions
            $subscriptions
            if (($subscriptions).count -gt 1){
                $SubscriptionID=Read-Host "Please give me subscription ID"
            }else{
                $SubscriptionID=$subscriptions.id
            }

        #make sure resource providers are registered
            if (!(Get-InstalledModule -Name "az.resources" -ErrorAction Ignore)){
                Install-Module -Name "az.resources" -Force
            }
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
        
        #Create Storage Account
            if (!(Get-InstalledModule -Name "az.storage"-ErrorAction Ignore)){
                    Install-Module -Name "az.storage" -Force
                }

            #create resource group first
            if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
                New-AzResourceGroup -Name $ResourceGroupName -Location $location
            }
            #create Storage Account
            If (-not(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)){
                New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location $location -Kind StorageV2 -AccessTier Cool 
            }
            $StorageAccountAccessKey=(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName | Select-Object -First 1).Value

        #create service principal if requested
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
        "Microsoft.HybridContainerService/register/action"
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

    Disconnect-AzAccount
    #output variables
    Write-Host -ForegroundColor Cyan @"
        #Variables to copy
        `$SubscriptionID=`"$SubscriptionID`"
        `$SPAppID=`"$SPAppID`"
        `$SPNSecret=`"$SPNSecret`"
        `$ResourceGroupName=`"$ResourceGroupName`"
        `$StorageAccountName=`"$StorageAccountName`"
        `$StorageAccountAccessKey=`"$StorageAccountAccessKey`"
        `$Location=`"$Location`"
"@ 


#endregion

#region Deploy - run from ASNode1!
    #variables
        #create deployment credentials
        $UserName="ASClus01-DeployUser"
        $Password="LS1setup!"
        $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
        $AzureStackLCMUserCredential = New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)
        $UserName="Administrator"
        $Password="LS1setup!"
        $SecuredPassword = ConvertTo-SecureString $password -AsPlainText -Force
        $LocalAdminCred = New-Object System.Management.Automation.PSCredential ($UserName,$SecuredPassword)

        #the one you have to populate if you did not run above region from Seed node
        <#
        $SubscriptionID=""
        $SPAppID="" #not needed if you use MFA
        $SPNSecret="" #not needed if you use MFA
        $ResourceGroupName=""
        $StorageAccountName=""
        $StorageAccountAccessKey=""
        $Location=""
        #>

        #download folder
        $downloadfolder="c:\temp"

        $Servers="ASNode1","ASNode2","ASNode3","ASNode4"

    #Download files
        #create folder
        if (-not (Test-Path $downloadfolder)){New-Item -Path $downloadfolder -ItemType Directory}
        $files=@()
        $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2210545" ; FileName="BootstrapCloudDeploymentTool.ps1" ; Description="Bootstrap PowerShell"}
        $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2210546" ; FileName="CloudDeployment_10.2306.0.47.zip" ; Description="Cloud Deployment Package"}
        $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2210608" ; FileName="Verify-CloudDeployment.zip_Hash.ps1" ; Description="Verify Cloud Deployment PowerShell"}

        foreach ($file in $files){
            if (-not (Test-Path "$downloadfolder\$($file.filename)")){
                Start-BitsTransfer -Source $file.uri -Destination "$downloadfolder\$($file.filename)" -DisplayName "Downloading: $($file.filename)"
            }
        }

    #Start bootstrap (script is looking for file "CloudDeployment_*.zip"
    & $downloadfolder\BootstrapCloudDeploymentTool.ps1

    #create authentication token (Service Principal or MFA)
    if ($SPAppID){
        $SPNsecStringPassword = ConvertTo-SecureString $SPNSecret -AsPlainText -Force
        $SPNCred=New-Object System.Management.Automation.PSCredential ($SPAppID, $SPNsecStringPassword)
    }else{
        Set-AuthenticationToken -RegistrationCloudName AzureCloud -RegistrationSubscriptionID $SubscriptionID
    }

    #create config.json
    #add servers to trusted hosts so you can query IP address dynamically (in the lab we dont exactly now which adapter is first and what IP was assigned
    $TrustedHosts=@()
    $TrustedHosts+=$Servers
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($TrustedHosts -join ',') -Force

    $Content=@"
{
    "Version": "10.0.0.0",
    "ScaleUnits": [
        {
            "DeploymentData": {
                "SecuritySettings": {
                    "HVCIProtection": true,
                    "DRTMProtection": true,
                    "DriftControlEnforced": true,
                    "CredentialGuardEnforced": true,
                    "SMBSigningEnforced": true,
                    "SMBClusterEncryption": false,
                    "SideChannelMitigationEnforced": true,
                    "BitlockerBootVolume": true,
                    "BitlockerDataVolumes": false,
                    "WDACEnforced": true
                },
                "Observability": {
                    "StreamingDataClient": true,
                    "EULocation": true,
                    "EpisodicDataUpload": true
                },
                "Cluster": {
                    "Name": "ASClus01",
                    "WitnessType": "Cloud",
                    "WitnessPath": "",
                    "CloudAccountName": "$StorageAccountName",
                    "AzureServiceEndpoint": "core.windows.net",
                    "StaticAddress": [
                        ""
                    ]
                },
                "Storage": {
                    "ConfigurationMode": "Express"
                },
                "TimeZone": "Pacific Standard Time",
                "NamingPrefix": "ASClus01",
                "DomainFQDN": "corp.contoso.com",
                "InfrastructureNetwork": [
                    {
                        "VlanId": "0",
                        "SubnetMask": "255.255.255.0",
                        "Gateway": "10.0.0.1",
                        "IPPools": [
                            {
                                "StartingAddress": "10.0.0.100",
                                "EndingAddress": "10.0.0.110"
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
$Content | Out-File -FilePath c:\config.json

#set trusted hosts back
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force

#create secured storage access key
$StorageAccountAccessKeySecured = ConvertTo-SecureString $StorageAccountAccessKey -AsPlainText -Force

#deploy
if ($SPAppID){
    .\Invoke-CloudDeployment -JSONFilePath c:\config.json -AzureStackLCMUserCredential $AzureStackLCMUserCredential -LocalAdminCredential $LocalAdminCred -RegistrationSPCredential $SPNCred -RegistrationCloudName AzureCloud -RegistrationSubscriptionID $SubscriptionID -RegistrationResourceGroupName $ResourceGroupName -WitnessStorageKey $StorageAccountAccessKeySecured -RegistrationRegion $Location
}else{
    .\Invoke-CloudDeployment -JSONFilePath c:\config.json -AzureStackLCMUserCredential $AzureStackLCMUserCredential -LocalAdminCredential $LocalAdminCred -RegistrationCloudName AzureCloud -RegistrationSubscriptionID $SubscriptionID -RegistrationResourceGroupName $ResourceGroupName -WitnessStorageKey $StorageAccountAccessKeySecured -RegistrationRegion $Location 
}
#endregion

#region Validate deployment - run from management VM!
$SeedNode="ASNode1"

Invoke-Command -ComputerName $SeedNode -ScriptBlock {
    ([xml](Get-Content C:\ecestore\efb61d70-47ed-8f44-5d63-bed6adc0fb0f\086a22e3-ef1a-7b3a-dc9d-f407953b0f84)) | Select-Xml -XPath "//Action/Steps/Step" | ForEach-Object { $_.Node } | Select-Object FullStepIndex, Status, Name, StartTimeUtc, EndTimeUtc, @{Name="Duration";Expression={new-timespan -Start $_.StartTimeUtc -End $_.EndTimeUtc } } | Format-Table -AutoSize
}
#endregion