<# 
Not needed anymore. Keeping it if someone wants to recycle

#############################
### Run from Hyper-V Host ###
#############################

#run from Host to expand C: drives in VMs to 120GB. This is required as Install-AKSHCI checks free space on C (should check free space in CSV)
#script grabs all VMs starting with "MSLab" (and containing azshci), so modify line below accordingly
$VMs=Get-VM -VMName MSLab*azshci*
$VMs | Get-VMHardDiskDrive -ControllerLocation 0 | Resize-VHD -SizeBytes 120GB
#VM Credentials
$secpasswd = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$VMCreds = New-Object System.Management.Automation.PSCredential ("corp\LabAdmin", $secpasswd)
Foreach ($VM in $VMs){
    Invoke-Command -VMname $vm.name -Credential $VMCreds -ScriptBlock {
        $part=Get-Partition -DriveLetter c
        $sizemax=($part |Get-PartitionSupportedSize).SizeMax
        $part | Resize-Partition -Size $sizemax
    }
}
#>


###################################
### Run from Management machine ###
###################################

#region Create 2 node cluster (just simple. Not for prod - follow hyperconverged scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/S2D%20Hyperconverged)

# LabConfig
$Servers="AksHCI1","AksHCI2"
$ClusterName="AksHCI-Cluster"

# Install features for management on server
Install-WindowsFeature -Name RSAT-DHCP,RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

# Update servers
Invoke-Command -ComputerName $servers -ScriptBlock {
    New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
    Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
} -ErrorAction Ignore
# Run Windows Update via ComObject.
Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                            IsPresent=1 and DeploymentAction='Uninstallation' or
                            IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                            IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
    $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $SearchResult
    $Downloader.Download()
    $Installer = New-Object -ComObject Microsoft.Update.Installer
    $Installer.Updates = $SearchResult
    $Result = $Installer.Install()
    $Result
}
#remove temporary PSsession config
Invoke-Command -ComputerName $servers -ScriptBlock {
    Unregister-PSSessionConfiguration -Name 'VirtualAccount'
    Remove-Item -Path $env:TEMP\VirtualAccount.pssc
}

# Update servers with all updates (including preview)
<#
Invoke-Command -ComputerName $servers -ScriptBlock {
    New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
    Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
} -ErrorAction Ignore
# Run Windows Update via ComObject.
Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                            IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                            IsPresent=1 and DeploymentAction='Uninstallation' or
                            IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                            IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
    $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $SearchResult
    $Downloader.Download()
    $Installer = New-Object -ComObject Microsoft.Update.Installer
    $Installer.Updates = $SearchResult
    $Result = $Installer.Install()
    $Result
}
#remove temporary PSsession config
Invoke-Command -ComputerName $servers -ScriptBlock {
    Unregister-PSSessionConfiguration -Name 'VirtualAccount'
    Remove-Item -Path $env:TEMP\VirtualAccount.pssc
}
#>

# Install features on servers
Invoke-Command -computername $Servers -ScriptBlock {
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell"
}

# restart servers
Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
#failsafe - sometimes it evaluates, that servers completed restart after first restart (hyper-v needs 2)
Start-sleep 20

# create vSwitch
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name vSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

#create cluster
New-Cluster -Name $ClusterName -Node $Servers
Start-Sleep 5
Clear-DNSClientCache

#add file share witness
#Create new directory
    $WitnessName=$ClusterName+"Witness"
    Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
    $accounts=@()
    $accounts+="corp\$($ClusterName)$"
    $accounts+="corp\Domain Admins"
    New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
#Set NTFS permissions
    Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
#Set Quorum
    Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

#Enable S2D
Enable-ClusterS2D -CimSession $ClusterName -Verbose -Confirm:0
#endregion

#region Register Azure Stack HCI to Azure - if not registered, VMs are not added as cluster resources = AKS script will fail
$ClusterName="AksHCI-Cluster"

#download Azure module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
    Install-Module -Name Az.StackHCI -Force
}

#5.1.0 version is required because of this bug https://github.com/Azure/azure-powershell/issues/16764
if (!( Get-InstalledModule -Name Az.Resources -RequiredVersion "5.1.0" -ErrorAction Ignore)){
    Install-Module -Name Az.Resources -Force -RequiredVersion "5.1.0"
}

#login to azure
#download Azure module
if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
    Install-Module -Name Az.Accounts -Force
}
Connect-AzAccount -UseDeviceAuthentication
<# or download edge and do it without device authentication
#download
Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
Connect-AzAccount
#>
<#or use IE for autentication
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2
Connect-AzAccount
#>
#select subscription if more available
$subscription=Get-AzSubscription
if (($subscription).count -gt 1){
    $subscription | Out-GridView -OutputMode Single | Set-AzContext
}

#grab subscription ID
$subscriptionID=(Get-AzContext).Subscription.id

<# Register AZSHCi without prompting for creds, 
   Notes: As Dec. 2021, in Azure Stack HCI 21H2,  if you Register-AzStackHCI the cluster multiple times in same ResourceGroup (e.g. default
   resource group name is AzSHCI-Cluster-rg) without run UnRegister-AzStackHCI first, although you may succeed in cluster registration, but
   sever node Arc integration will fail, even if you have deleted the ResourceGroup in Azure Portal before running Register-AzStackHCI #>

   $armTokenItemResource = "https://management.core.windows.net/"
   $graphTokenItemResource = "https://graph.windows.net/"
   $azContext = Get-AzContext
   $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
   $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
   $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
   $id = $azContext.Account.Id
   Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

# or register Azure Stack HCI with device authentication
#Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication

<# or with standard authentication
#add some trusted sites (to be able to authenticate with Register-AzStackHCI)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2
#and register
Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName
#>
<# or with location picker
#grab location
if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
    Install-Module -Name Az.Resources -Force
}
$Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single
Register-AzStackHCI -SubscriptionID $subscriptionID -Region $location.location -ComputerName $ClusterName -UseDeviceAuthentication
#>

#Install Azure Stack HCI RSAT Tools to all nodes
$Servers=(Get-ClusterNode -Cluster $ClusterName).Name
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Install-WindowsFeature -Name RSAT-Azure-Stack-HCI
}

#Validate registration (query on just one node is needed)
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-AzureStackHCI
}
#endregion

#region Install required modules for AKSHCI https://docs.microsoft.com/en-us/azure-stack/aks-hci/kubernetes-walkthrough-powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
Update-Module -Name PowerShellGet
#Install-Module -Name Az.Accounts -Repository PSGallery -RequiredVersion 2.2.4 -Force
#Install-Module -Name Az.Resources -Repository PSGallery -RequiredVersion 3.2.0 -Force
#Install-Module -Name AzureAD -Repository PSGallery -RequiredVersion 2.0.2.128 -Force
#to be able to install AKSHCI, powershellget 2.2.5 needs to be used - to this posh restart is needed
Start-Process -Wait -FilePath PowerShell -ArgumentList {
    Install-Module -Name AksHci -Repository PSGallery -Force -AcceptLicense
}
#add required modules (parsing required modules from kva.psd - it also requires certain version of modules)
#JaromirK note: it would be great if this dependency was downloaded automagically or if you would be ok with latest version (or some minimumversion)
$item=Get-ChildItem -Path "C:\Program Files\WindowsPowerShell\Modules\Kva" -Recurse | Where-Object name -eq kva.psd1
$RequiredModules=(Import-LocalizedData -BaseDirectory $item.Directory -FileName $item.Name).RequiredModules
foreach ($RequiredModule in $RequiredModules){
    if (!(Get-InstalledModule -Name $RequiredModule.ModuleName -RequiredVersion $RequiredModule.RequiredVersion -ErrorAction Ignore)){
        Install-Module -Name $RequiredModule.ModuleName -RequiredVersion $RequiredModule.RequiredVersion -Force
    }
}

#distribute modules to cluster nodes
$ClusterName="AksHCI-Cluster"
$Servers=(Get-ClusterNode -Cluster $Clustername).Name
$ModuleNames="AksHci","Moc","Kva","TraceProvider"
$PSSessions=New-PSSession -ComputerName $Servers
Foreach ($PSSession in $PSSessions){
    Foreach ($ModuleName in $ModuleNames){
        Copy-Item -Path $env:ProgramFiles\windowspowershell\modules\$ModuleName -Destination $env:ProgramFiles\windowspowershell\modules -ToSession $PSSession -Recurse -Force
    }
    Foreach ($ModuleName in $RequiredModules.ModuleName){
        Copy-Item -Path $env:ProgramFiles\windowspowershell\modules\$ModuleName -Destination $env:ProgramFiles\windowspowershell\modules -ToSession $PSSession -Recurse -Force
    }
}
#endregion

#region prepare subnet for static deployment
    #since lab was prepared with one extra subnet (10.0.1.0/24) on VLAN 11 (see labconfig), this one will be used for Kubernetes, we will just disable scope in DHCP, so it will not assign IP Addresses
    $DHCPServer="DC"
    $DHCPScopeID="10.0.1.0"
    #inactivate DHCP for scope where AKS will be deployed
    Set-DhcpServerv4Scope -State InActive -CimSession $DHCPServer -ScopeID $DHCPScopeID
#endregion

#region setup AKS (PowerShell)
    #set variables
    $ClusterName="AksHCI-Cluster"
    $vSwitchName="vSwitch"
    $vNetName="aksvnet"
    $VolumeName="AKS"
    $Servers=(Get-ClusterNode -Cluster $ClusterName).Name
    $DHCPServer="DC"
    $DHCPScopeID="10.0.0.0"
    $VIPPoolStart="10.0.1.2"
    $VIPPoolEnd="10.0.1.100"
    $k8sNodeIpPoolStart="10.0.1.101"
    $k8sNodeIpPoolEnd="10.0.1.254"
    $IPAddressPrefix="10.0.1.0/24"
    $DNSServers="10.0.1.1"
    $Gateway="10.0.1.1"
    $VLANID=11
    $resourcegroupname="$ClusterName-rg"

    #JaromirK note: it would be great if I could simply run "Initialize-AksHciNode -ComputerName $ClusterName". I could simply skip credssp. Same applies for AksHciConfig and AksHciRegistration

    #Enable CredSSP
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    foreach ($Server in $servers){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Server -Force
    }
    Invoke-Command -ComputerName $servers -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    Invoke-Command -ComputerName $servers -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Initialize-AksHciNode
    }

    #configure thin volumes a default if available (because why not :)
    $OSInfo=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    }
    if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuildNumber -ge 20348){
        Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
    }

    #Create volume for AKS if does not exist
    if (-not (Get-Volume -FriendlyName $VolumeName -CimSession $ClusterName -ErrorAction SilentlyContinue)) {
        New-Volume -FriendlyName $VolumeName -CimSession $ClusterName -Size 1TB -StoragePoolFriendlyName S2D*
    }

    #make sure failover clustering management tools are installed on nodes
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Install-WindowsFeature -Name RSAT-Clustering-PowerShell
    }
    #configure aks
    Invoke-Command -ComputerName $servers[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        #DHCP
        #$vnet = New-AksHciNetworkSetting -Name $using:vNetName -vSwitchName $using:vSwitchName -vippoolstart $using:vippoolstart -vippoolend $using:vippoolend
        #Static
        $vnet = New-AksHciNetworkSetting -Name $using:vNetName -ipAddressPrefix $using:IPAddressPrefix -vSwitchName $using:vSwitchName -vippoolstart $using:vippoolstart -vippoolend $using:vippoolend -k8sNodeIpPoolStart $using:k8sNodeIpPoolStart -k8sNodeIpPoolEnd $using:k8sNodeIpPoolEnd -vlanID $using:VLANID -DNSServers $using:DNSServers -gateway $Using:Gateway
        Set-AksHciConfig -vnet $vnet -workingDir c:\clusterstorage\$using:VolumeName\ImagesStore -imageDir c:\clusterstorage\$using:VolumeName\Images -cloudConfigLocation c:\clusterstorage\$using:VolumeName\Config -ClusterRoleName "$($using:ClusterName)_AKS" -controlPlaneVmSize 'default' # Get-AksHciVmSize
    }

    #validate config
    Invoke-Command -ComputerName $servers[0] -ScriptBlock {
        Get-AksHciConfig
    }

    #register in Azure
    if (-not (Get-AzContext)){
        Connect-AzAccount -UseDeviceAuthentication
    }
    $subscription=Get-AzSubscription
    if (($subscription).count -gt 1){
        $subscription | Out-GridView -OutputMode Single | Set-AzContext
    }
    $subscriptionID=(Get-AzContext).Subscription.id

    #make sure Kubernetes resource providers are registered
    #5.1.0 version is required because of this bug https://github.com/Azure/azure-powershell/issues/16764
    if (!( Get-InstalledModule -Name Az.Resources -RequiredVersion "5.1.0" -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force -RequiredVersion "5.1.0"
    }
    Register-AzResourceProvider -ProviderNamespace Microsoft.Kubernetes
    Register-AzResourceProvider -ProviderNamespace Microsoft.KubernetesConfiguration

    #wait until resource providers are registered
    $Providers="Microsoft.Kubernetes","Microsoft.KubernetesConfiguration"
    foreach ($Provider in $Providers){
        do {
            $Status=Get-AzResourceProvider -ProviderNamespace $Provider
            Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
            Start-Sleep 1
        } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))
    }

    #Register AZSHCi without prompting for creds
    $armTokenItemResource = "https://management.core.windows.net/"
    $graphTokenItemResource = "https://graph.windows.net/"
    $azContext = Get-AzContext
    $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
    $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id

    Invoke-Command -computername $servers[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Set-AksHciRegistration -SubscriptionID $using:subscriptionID -GraphAccessToken $using:graphToken -ArmAccessToken $using:armToken -AccountId $using:id -ResourceGroupName $using:resourcegroupname
    }

    #or with Device Authentication
    <#
    Invoke-Command -computername $servers[0] -ScriptBlock {
        Set-AksHciRegistration -SubscriptionID $using:subscriptionID -ResourceGroupName $using:resourcegroupname -UseDeviceAuthentication
    }
    #>

    #validate registration
    Invoke-Command -computername $servers[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Get-AksHciRegistration
    }

    #Install
    Invoke-Command -ComputerName $servers[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Install-AksHci -Verbose
    }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $servers -ScriptBlock { Disable-WSManCredSSP Server }
#endregion

#region create AKS HCI cluster
#note: in nested environment I had to increase vCPU count to 8 and I used Standard_D4s_v3 as datacontroller deployment ended up in endless loop
#Jaromirk note: it would be great if I could specify HCI Cluster (like New-AksHciCluster -ComputerName)
$ClusterName="AksHCI-Cluster"
$ClusterNode=(Get-ClusterNode -Cluster $clustername).Name | Select-Object -First 1
$KubernetesClusterName="demo"
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    # default size (data controller will not be deployed)
    New-AksHciCluster -Name $using:KubernetesClusterName -NodePoolName linux-pool

    # or Create new cluster with 1 linux node with D4s VM size (needed for Data Controller, but in nested virtualization I also needed to adjust cpu number - increased to 8)
    # New-AksHciCluster -Name $using:KubernetesClusterName -NodePoolName linux-pool -nodeCount 1 -NodeVmSize Standard_D4s_v3 -osType linux

    # or Create new cluster with 1 linux node in 1 node pool, with AD AuthZ and Monitoring enabled (Optionally)
    # New-AksHciCluster -Name demo -NodePoolName linux-pool -enableAdAuth -enableMonitoring
    # Add 1 Windows node in 1 Windows node pool to existing Cluster
    # New-AksHciNodePool -ClusterName demo -Name windows-pool -osType Windows
}

#distribute kubeconfig to other nodes (just to make it symmetric)
#Jaromirk note: I think this would be useful to do with new-akshcicluster
$ClusterNodes=(Get-ClusterNode -Cluster $clustername).Name
$FirstSession=New-PSSession -ComputerName ($ClusterNodes | Select-Object -First 1)
$OtherSessions=New-PSSession -ComputerName ($ClusterNodes | Select-Object -Skip 1)
#copy kube locally
Copy-Item -Path "$env:userprofile\.kube" -Destination "$env:userprofile\Downloads" -FromSession $FirstSession -Recurse -Force
#copy kube to other nodes
Foreach ($OtherSession in $OtherSessions){
    Copy-Item -Path "$env:userprofile\Downloads\.kube" -Destination $env:userprofile -ToSession $OtherSession -Recurse -Force
}

#VM Sizes
<#
Get-AksHciVmSize

          VmSize CPU MemoryGB
          ------ --- --------
         Default 4   4
  Standard_A2_v2 2   4
  Standard_A4_v2 4   8
 Standard_D2s_v3 2   8
 Standard_D4s_v3 4   16
 Standard_D8s_v3 8   32
Standard_D16s_v3 16  64
Standard_D32s_v3 32  128
 Standard_DS2_v2 2   7
 Standard_DS3_v2 2   14
 Standard_DS4_v2 8   28
 Standard_DS5_v2 16  56
Standard_DS13_v2 8   56
 Standard_K8S_v1 4   2
Standard_K8S2_v1 2   2
Standard_K8S3_v1 4   6

#>

#destroy AKS Cluster
<#
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    Remove-AksHciCluster -Name $using:KubernetesClusterName -Confirm:0
}
#>

#endregion

#region onboard AKS cluster to Azure ARC
$ClusterName="AksHCI-Cluster"

#register AKS
#https://docs.microsoft.com/en-us/azure-stack/aks-hci/connect-to-arc

#5.1.0 version is required because of this bug https://github.com/Azure/azure-powershell/issues/16764
if (!( Get-InstalledModule -Name Az.Resources -RequiredVersion "5.1.0" -ErrorAction Ignore)){
    Install-Module -Name Az.Resources -Force -RequiredVersion "5.1.0"
}
if (!(Get-Azcontext)){
    Connect-AzAccount -UseDeviceAuthentication
}
$tenantID=(Get-AzContext).Tenant.Id
#grab subscription ID
$subscriptionID=(Get-AzContext).Subscription.id

$resourcegroup="$ClusterName-rg"
$location="eastUS"
$KubernetesClusterName="demo"
$servicePrincipalDisplayName="ArcRegistration" #you can use existing
$password="" #if blank, password will be created

#create new service principal for registering AKS Clusters
#Connect-AzAccount -Tenant $tenantID

#Create AzADServicePrincipal if it does not already exist
    $SP=Get-AZADServicePrincipal -DisplayName $servicePrincipalDisplayName
    if (-not $SP){
        $SP=New-AzADServicePrincipal -DisplayName $servicePrincipalDisplayName
        #remove default cred
        Remove-AzADAppCredential -ApplicationId $SP.AppId
    }
    #add roles
    New-AzRoleAssignment -ObjectId $SP.Id -RoleDefinitionName "Kubernetes Cluster - Azure Arc Onboarding"
    New-AzRoleAssignment -ObjectId $SP.Id -RoleDefinitionName "Azure Connected Machine Onboarding"

    #Create new password
    if (-not ($password)){
        $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential" -Property @{
            "KeyID"         = (new-guid).Guid ;
            "EndDateTime" = [DateTime]::UtcNow.AddYears(10)
        }
        $Creds=New-AzADAppCredential -PasswordCredentials $credential -ApplicationID $SP.AppID
        $password=$Creds.SecretText
        Write-Host "Your Password is: " -NoNewLine ; Write-Host $password -ForegroundColor Cyan
    }

#sleep for 1m just to let ADApp password to propagate
    Start-Sleep 60

#create credentials
$ClientID=$sp.AppId
$SecureSecret= ConvertTo-SecureString $password -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ($ClientID , $SecureSecret)

#register namespace Microsoft.KubernetesConfiguration and Microsoft.Kubernetes
Register-AzResourceProvider -ProviderNamespace Microsoft.Kubernetes
Register-AzResourceProvider -ProviderNamespace Microsoft.KubernetesConfiguration

#onboard cluster
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    #Generate kubeconfig
    Get-AksHciCredential -Name $using:KubernetesClusterName -confirm:0
    #onboard
    Enable-AksHciArcConnection -Name $using:KubernetesClusterName -tenantId $using:tenantID -subscriptionId $using:subscriptionID -resourcegroup $using:resourcegroup -Location $using:location -credential $using:Credentials
}


#check onboarding
#generate kubeconfig (this step was already done)
<#
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-AksHciCredential -Name $using:KubernetesClusterName -Confirm:0
}
#>
#copy kubeconfig
$session=New-PSSession -ComputerName $ClusterName
Copy-Item -Path "$env:userprofile\.kube" -Destination $env:userprofile -FromSession $session -Recurse -Force
#install kubectl
$uri = "https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/"
$req = Invoke-WebRequest -UseBasicParsing -Uri $uri
$downloadlink = ($req.Links | where href -Match "kubectl.exe").href
$downloadLocation="c:\Program Files\AksHci\"
New-Item -Path $downloadLocation -ItemType Directory -Force
Start-BitsTransfer $downloadlink -DisplayName "Getting KubeCTL from $downloadlink" -Destination "$Downloadlocation\kubectl.exe"
#add to enviromental variables
[System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
#alternatively copy kubectl from cluster
#Copy-Item -Path $env:ProgramFiles\AksHCI\ -Destination $env:ProgramFiles -FromSession $session -Recurse -Force
#validate
kubectl -n azure-arc get deployments,pods
#endregion

#region add sample configuration to the cluster https://docs.microsoft.com/en-us/azure/azure-arc/kubernetes/use-gitops-connected-cluster
    $ClusterName="AksHCI-Cluster"
    $KubernetesClusterName="demo"
    $resourcegroup="$ClusterName-rg"
    $servers=(Get-ClusterNode -Cluster $ClusterName).Name

    #install az cli and log into az
        Start-BitsTransfer -Source https://aka.ms/installazurecliwindows -Destination $env:userprofile\Downloads\AzureCLI.msi
        Start-Process msiexec.exe -Wait -ArgumentList "/I  $env:userprofile\Downloads\AzureCLI.msi /quiet"
        #add az to enviromental variables so no posh restart is needed
        [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin')

        <#login with credentials
        #add some trusted sites (to be able to authenticate with Register-AzStackHCI)
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2

        az login
        #>
        #login with device authentication
        az login --use-device-code
        $allSubscriptions = (az account list | ConvertFrom-Json).ForEach({$_ | Select-Object -Property Name, id, tenantId })
        if (($allSubscriptions).Count -gt 1){
            $subscription = ($allSubscriptions | Out-GridView -OutputMode Single)
            az account set --subscription $subscription.id
        }

    #create configuration
        az extension add --name k8s-configuration
        az k8s-configuration create --name cluster-config --cluster-name $KubernetesClusterName --resource-group $resourcegroup --operator-instance-name cluster-config --operator-namespace cluster-config --repository-url https://github.com/Azure/arc-k8s-demo --scope cluster --cluster-type connectedClusters
        #az connectedk8s delete --name cluster-config --resource-group $resourcegroup

    #validate
        az k8s-configuration show --name cluster-config --cluster-name $KubernetesClusterName --resource-group $resourcegroup --cluster-type connectedClusters
        #add kubectl to system environment variable, so it can be run by simply typing kubectl
        [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
        kubectl get ns --show-labels
        kubectl -n cluster-config get deploy -o wide
        kubectl -n team-a get cm -o yaml
        kubectl -n itops get all
#endregion

#region deploy sample app
    #add kubectl to system environment variable, so it can be run by simply typing kubectl
    [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
    kubectl apply -f https://raw.githubusercontent.com/Azure-Samples/azure-voting-app-redis/master/azure-vote-all-in-one-redis.yaml
    kubectl get service
#endregion

#region Create Log Analytics workspace (skip if you already have one)
    #Install module
    if (!(Get-InstalledModule -Name Az.OperationalInsights -ErrorAction Ignore)){
        Install-Module -Name Az.OperationalInsights -Force
    }

    #remove old az.accounts module https://github.com/Azure/azure-powershell/issues/16951
    $module=Get-Module -Name Az.Accounts | where-object Version -LT $([System.Version]"2.7.0") 
    $module | Remove-Module -Force

    #Grab Insights Workspace if some already exists
    $Workspace=Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | Out-GridView -OutputMode Single

    #Create Log Analytics Workspace if not available
    if (-not ($Workspace)){
        $SubscriptionID=(Get-AzContext).Subscription.ID
        $WorkspaceName="MSLabWorkspace-$SubscriptionID"
        $ResourceGroupName="MSLabAzureArc"
        #Pick Region
        $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.OperationalInsights" | Out-GridView -OutputMode Single
        if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)){
            New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
        }
        $Workspace=New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -Location $location.Location
    }
#endregion

#region Enable Monitoring https://docs.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-enable-arc-enabled-clusters#create-extension-instance-using-azure-resource-manager
    $ClusterName="AksHCI-Cluster"
    $resourcegroup="$ClusterName-rg"
    $KubernetesClusterName="demo"
    if (-not (Get-AzContext)){
        Connect-AzAccount -UseDeviceAuthentication
    }

    #remove old az.accounts module https://github.com/Azure/azure-powershell/issues/16951
    $module=Get-Module -Name Az.Accounts | where-object Version -LT $([System.Version]"2.7.0") 
    $module | Remove-Module -Force

    $SubscriptionID=(Get-AzContext).Subscription.ID
    $Workspace=Get-AzOperationalInsightsWorkspace | Out-GridView -OutputMode Single -Title "Please select Log Analytics Workspace"
    $TemplateURI="https://aka.ms/arc-k8s-azmon-extension-arm-template"
    $AzureCloudName = "AzureCloud" #or AzureUSGovernment
    if ($AzureCloudName -eq "AzureCloud"){$omsAgentDomainName="opinsights.azure.com"}
    if ($AzureCloudName -eq "AzureUSGovernment"){$omsAgentDomainName="opinsights.azure.us"}

    $AKSClusterResourceId = "/subscriptions/$subscriptionID/resourceGroups/$resourcegroup/providers/Microsoft.Kubernetes/connectedClusters/$KubernetesClustername"
    $AKSClusterResource = Get-AzResource -ResourceId $AKSClusterResourceId
    $AKSClusterRegion = $AKSClusterResource.Location.ToLower()
    #$PrimarySharedKey=($Workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey 

    #Add Azure Monitor Containers solution to Workspace
        $DeploymentName = "ContainerInsightsSolutionOnboarding-" + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
        $Parameters = @{ }
        $Parameters.Add("workspaceResourceId", $Workspace.ResourceId)
        $Parameters.Add("workspaceRegion", $Workspace.Location)
        $Parameters.Add("workspaceDomain", $omsAgentDomainName)
        $Parameters.Add("clusterResourceId", $AKSClusterResourceId)
        $Parameters.Add("clusterRegion", $AKSClusterRegion)


        New-AzResourceGroupDeployment -Name $DeploymentName `
        -ResourceGroupName $Workspace.ResourceGroupName `
        -TemplateUri  $TemplateURI `
        -TemplateParameterObject $Parameters

    #validate extension deployment
    az extension add --name k8s-extension
    az k8s-extension show --name azuremonitor-containers --cluster-name $KubernetesClusterName --resource-group $resourcegroup --cluster-type connectedClusters -n azuremonitor-containers

    <# OLD, deprecated, did not work.. 
    #Install HEML Chart
        #install helm
            #install chocolatey
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            #install helm
            choco feature enable -n allowGlobalConfirmation
            cinst kubernetes-helm

            <#
            $ClusterName="AksHCI-Cluster"
            $servers=(Get-ClusterNode -Cluster $ClusterName).name
            $ProgressPreference="SilentlyContinue"
            Invoke-WebRequest -Uri https://get.helm.sh/helm-v3.3.4-windows-amd64.zip -OutFile $env:USERPROFILE\Downloads\helm-v3.3.4-windows-amd64.zip
            $ProgressPreference="Continue"
            Expand-Archive -Path $env:USERPROFILE\Downloads\helm-v3.3.4-windows-amd64.zip -DestinationPath $env:USERPROFILE\Downloads
            $sessions=New-PSSession -ComputerName $servers
            foreach ($session in $sessions){
                Copy-Item -Path $env:userprofile\Downloads\windows-amd64\helm.exe -Destination $env:SystemRoot\system32\ -ToSession $session
            }
            #>
    #>
    <#
        #Install Chart to current kube context
            #helm config
            $helmChartReleaseName = "azmon-containers-release-1"
            $helmChartName = "azuremonitor-containers"
            $microsoftHelmRepo="https://microsoft.github.io/charts/repo"
            $microsoftHelmRepoName="microsoft"
            $helmChartRepoPath = "${microsoftHelmRepoName}" + "/" + "${helmChartName}"
            #Add azure charts repo
            helm repo add ${microsoftHelmRepoName} ${microsoftHelmRepo}
            #update to latest release
            helm repo update ${microsoftHelmRepoName}
            #Install CHart to current kube context
            $helmParameters = "omsagent.domain=$omsAgentDomainName,omsagent.secret.wsid=$($workspace.CustomerID.GUID),omsagent.secret.key=$PrimarySharedKey,omsagent.env.clusterId=$AKSClusterResourceId,omsagent.env.clusterRegion=$AKSClusterRegion"
            helm upgrade --install $helmChartReleaseName --set $helmParameters $helmChartRepoPath
    #>

#endregion

#region Deploy Policies Extension https://docs.microsoft.com/en-us/azure/governance/policy/concepts/policy-for-kubernetes#install-azure-policy-extension-for-azure-arc-enabled-kubernetes
    $ClusterName="AksHCI-Cluster"
    $resourcegroup="$ClusterName-rg"
    $KubernetesClusterName="demo"

    $ExtensionName="azurepolicy-ext"
    #register provider
    $Provider="Microsoft.PolicyInsights"
    Register-AzResourceProvider -ProviderNamespace $Provider
    #wait for provider to finish registration
    do {
        $Status=Get-AzResourceProvider -ProviderNamespace $Provider
        Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
        Start-Sleep 1
    } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))

    #deploy extension
    az k8s-extension create --cluster-type connectedClusters --cluster-name $KubernetesClusterName --resource-group $resourcegroup --extension-type Microsoft.PolicyInsights --name $ExtensionName

    #validate deployment (show azurepolicy extension)
    az k8s-extension show --name $ExtensionName --cluster-name $KubernetesClusterName --resource-group $resourcegroup --cluster-type connectedClusters | ConvertFrom-Json

    #list all extensions
    az k8s-extension list --cluster-name $KubernetesClusterName --resource-group $resourcegroup --cluster-type connectedClusters | ConvertFrom-Json

#endregion

#region create Arc app service extension
#https://docs.microsoft.com/en-us/azure/app-service/manage-create-arc-environment?tabs=powershell
#looks like exstension fails https://github.com/Azure/azure-cli-extensions/issues/3661

$ClusterName="AksHCI-Cluster"
$resourcegroup="$ClusterName-rg"
$KubernetesClusterName="demo"

$AppServiceNamespace="arc-services-ns"
$extensionName="appservice-ext"
$kubeEnvironmentName=$KubernetesClusterName
$aksClusterGroupName=$resourcegroup

$CustomLocationName="AzSHCI-MyDC-EastUS" #existing, or if does not exists, it will be created
$CustomLocationNamespace=$AppServiceNamespace #namespace has to be same as appservice environment (or it fails to create)

$SubscriptionID=(Get-AzContext).Subscription.ID
$Workspace=Get-AzOperationalInsightsWorkspace | Out-GridView -OutputMode Single -Title "Please select Log Analytics Workspace"
$logAnalyticsWorkspaceIdEnc=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($workspace.customerid.guid))
$logAnalyticsKeyEnc=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey))

    #install az extensions
    az extension add --upgrade --yes --name connectedk8s
    az extension add --upgrade --yes --name k8s-extension
    az extension add --upgrade --yes --name customlocation
    az provider register --namespace Microsoft.ExtendedLocation --wait
    az provider register --namespace Microsoft.Web --wait
    az provider register --namespace Microsoft.KubernetesConfiguration --wait
    az extension remove --name appservice-kube
    az extension add --upgrade --yes --name appservice-kube

    az k8s-extension create `
    --resource-group $resourcegroup `
    --name $extensionName `
    --cluster-type connectedClusters `
    --cluster-name $KubernetesClusterName `
    --extension-type 'Microsoft.Web.Appservice' `
    --release-train stable `
    --auto-upgrade-minor-version true `
    --scope cluster `
    --release-namespace $AppServiceNamespace `
    --configuration-settings "Microsoft.CustomLocation.ServiceAccount=default" `
    --configuration-settings "appsNamespace=${AppServiceNamespace}" `
    --configuration-settings "clusterName=${kubeEnvironmentName}" `
    --configuration-settings "keda.enabled=true" `
    --configuration-settings "buildService.storageClassName=default" `
    --configuration-settings "buildService.storageAccessMode=ReadWriteOnce" `
    --configuration-settings "customConfigMap=${AppServiceNamespace}/kube-environment-config" `
    --configuration-settings "envoy.annotations.service.beta.kubernetes.io/azure-load-balancer-resource-group=${aksClusterGroupName}" `
    --configuration-settings "logProcessor.appLogs.destination=log-analytics" `
    --configuration-protected-settings "logProcessor.appLogs.logAnalyticsConfig.customerId=${logAnalyticsWorkspaceIdEnc}" `
    --configuration-protected-settings "logProcessor.appLogs.logAnalyticsConfig.sharedKey=${logAnalyticsKeyEnc}"

    #grab extension id and wait for install
    <#
    $extensionId=$(az k8s-extension show `
    --cluster-type connectedClusters `
    --cluster-name $KubernetesClusterName `
    --resource-group $resourcegroup `
    --name $extensionName `
    --query id `
    --output tsv)
    az resource wait --ids $extensionId --custom "properties.installState!='Pending'" --api-version "2020-07-01-preview"
    #>

    #deployment results in error, but after some time it succeeds. Following code will wait
    #https://github.com/Azure/azure-cli-extensions/issues/3661
    do {
        Write-Host "." -NoNewLine
        Start-Sleep 10
        $Extension=az k8s-extension show --resource-group $resourcegroup --cluster-name $KubernetesClusterName --cluster-type connectedClusters --name $extensionName | convertfrom-json
    } until (
        $extension.provisioningstate -eq "Succeeded"
    )

    #add kubectl to system environment variable, so it can be run by simply typing kubectl
    [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
    #display pods
    kubectl get pods -n $AppServiceNamespace
    #display all resources
    kubectl get all -n $AppServiceNamespace
    #display extension
    az k8s-extension show --resource-group $resourcegroup --cluster-name $KubernetesClusterName --cluster-type connectedClusters --name $extensionName | convertfrom-json

    #register provider
        $Provider="Microsoft.ExtendedLocation"
        Register-AzResourceProvider -ProviderNamespace $Provider
        #wait for provider to finish registration
        do {
            $Status=Get-AzResourceProvider -ProviderNamespace $Provider
            Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
            Start-Sleep 1
        } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))

    #enable custom locations on cluster
    az connectedk8s enable-features --name $KubernetesClusterName --resource-group $resourcegroup --features cluster-connect custom-locations

    #create custom location
        $CustomLocations=az customlocation list | ConvertFrom-Json
        $CustomLocation=$CustomLocations | Where-Object Name -eq $CustomLocationName | Where-Object Namespace -eq $CustomLocationNamespace
        $extensionId=$(az k8s-extension show `
        --cluster-type connectedClusters `
        --cluster-name $KubernetesClusterName `
        --resource-group $resourcegroup `
        --name $extensionName `
        --query id `
        --output tsv)

        if ($CustomLocation){
            $connectedClusterId=$(az connectedk8s show --resource-group $resourcegroup --name $KubernetesClusterName --query id --output tsv)
            #if custom locatin exists, just add clusterextensionid
            az customlocation patch `
            --resource-group $resourcegroup `
            --name $customLocationName `
            --cluster-extension-ids $extensionId $Customlocation.clusterextensionids
        }else{
            #Create new location
            $connectedClusterId=$(az connectedk8s show --resource-group $resourcegroup --name $KubernetesClusterName --query id --output tsv)
            az customlocation create `
            --resource-group $resourcegroup `
            --name $customLocationName `
            --host-resource-id $connectedClusterId `
            --namespace $CustomLocationNamespace `
            --cluster-extension-ids $extensionId
        }
        #validate
        az customlocation list -o table

    #Create the App Service Kubernetes environment
        #grab ID
        $customLocationId=$(az customlocation show `
        --resource-group $resourcegroup `
        --name $customLocationName `
        --query id `
        --output tsv)
        #create environment
        az appservice kube create `
        --resource-group $resourcegroup `
        --name $kubeEnvironmentName `
        --custom-location $customLocationId

    #Wait for appservice to be provisioned
    do {
        $Status=az appservice kube show --resource-group $resourcegroup --name $kubeEnvironmentName | ConvertFrom-Json
        Write-Host "Status is: $($Status.provisioningState)" -ForegroundColor Yellow
        Start-Sleep 10
    } while (($status.provisioningState -ne "Succeeded"))

    #validate
    az appservice kube show --resource-group $resourcegroup --name $kubeEnvironmentName | ConvertFrom-Json
#endregion

#region create Arc data services extension (deploying azure arc data controller fails if kubernetes cluster VM size is small)
#https://docs.microsoft.com/en-us/azure/azure-arc/data/create-data-controller-direct-cli
#https://docs.microsoft.com/en-us/azure/azure-arc/kubernetes/custom-locations
#https://docs.microsoft.com/en-us/azure-stack/aks-hci/container-storage-interface-disks#create-a-custom-storage-class-for-an-aks-on-azure-stack-hci-disk

$ClusterName="AksHCI-Cluster"
$resourcegroup="$ClusterName-rg"
$KubernetesClusterName="demo"

$SubscriptionID=(Get-AzContext).Subscription.ID
$Location=(Get-AzResourceGroup -Name $resourcegroup).Location

$DataControllerName="arc-dc1"
$DataControllerNamespace="arc-services-ns" #extension and data controller namespace
$extensionName="datacontroller-ext"

$CustomLocationNamespace=$DataControllerNamespace
$CustomLocationName="AzSHCI-MyDC-EastUS"  #existing, or if does not exists, it will be created

$StorageContainerName="AKSStorageContainer"
$StorageContainerPath="c:\ClusterStorage\AKSContainer"
$StorageContainerVolumeName=$StorageContainerPath | Split-Path -Leaf
$StorageContainerSize=1TB

    #Create volume for AKS if does not exist
    if (-not (Get-Volume -FriendlyName $StorageContainerVolumeName -CimSession $ClusterName -ErrorAction SilentlyContinue)) {
        New-Volume -FriendlyName $StorageContainerVolumeName -CimSession $ClusterName -Size $StorageContainerSize -StoragePoolFriendlyName S2D*
    }

    #deploy extension (check if it was created, might fail for first time, so it will need to rerun)
        #add extension
        az extension add --name k8s-extension
        #deploy
        az k8s-extension create --cluster-name $KubernetesClusterName --resource-group $resourcegroup --name $extensionName --cluster-type connectedClusters --extension-type microsoft.arcdataservices --auto-upgrade false --scope cluster --release-namespace $DataControllerNamespace --config Microsoft.CustomLocation.ServiceAccount=sa-arc-bootstrapper
    #wait
    $extensionId=$(az k8s-extension show --cluster-type connectedClusters --cluster-name $KubernetesClusterName --resource-group $resourcegroup --name $extensionName --query id --output tsv)
    az resource wait --ids $extensionId --custom "properties.installState!='Pending'" --api-version "2020-07-01-preview"
    #validate
    az k8s-extension show --resource-group $resourcegroup --cluster-name $KubernetesClusterName --name $extensionName --cluster-type connectedclusters

    #retrieve identity of Arc data controller extension
    $objectID=(az k8s-extension show --resource-group $resourcegroup  --cluster-name $KubernetesClusterName --cluster-type connectedClusters --name $extensionName | convertFrom-json).identity.principalId
    #assign roles to managed identity
    az role assignment create --assignee $objectID --role "Contributor" --scope "/subscriptions/$SubscriptionID/resourceGroups/$resourcegroup"
    az role assignment create --assignee $objectID --role "Monitoring Metrics Publisher" --scope "/subscriptions/$SubscriptionID/resourceGroups/$resourcegroup"

    #create custom location
        #add extensions
        az extension add --name k8s-extension
        az extension add --name customlocation
        az extension add --name connectedk8s
        #register provider
            $Provider="Microsoft.ExtendedLocation"
            Register-AzResourceProvider -ProviderNamespace $Provider
            #wait for provider to finish registration
            do {
                $Status=Get-AzResourceProvider -ProviderNamespace $Provider
                Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
                Start-Sleep 1
            } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))
        #enable custom locations on cluster
        az connectedk8s enable-features --name $KubernetesClusterName --resource-group $resourcegroup --features cluster-connect custom-locations

        #create custom location
        $CustomLocations=az customlocation list | ConvertFrom-Json
        $CustomLocation=$CustomLocations | Where-Object Name -eq $CustomLocationName
        if ($CustomLocation){
            $connectedClusterId=$(az connectedk8s show --resource-group $resourcegroup --name $KubernetesClusterName --query id --output tsv)
            #if custom locatin exists, just add clusterextensionid
            az customlocation patch `
            --resource-group $resourcegroup `
            --name $customLocationName `
            --cluster-extension-ids $extensionId $Customlocation.clusterextensionids
        }else{
            #Create new location
            $connectedClusterId=$(az connectedk8s show --resource-group $resourcegroup --name $KubernetesClusterName --query id --output tsv)
            az customlocation create `
            --resource-group $resourcegroup `
            --name $customLocationName `
            --host-resource-id $connectedClusterId `
            --namespace $CustomLocationNamespace `
            --cluster-extension-ids $extensionId
        }

        #validate
        az customlocation list -o table

    #Create the Azure Arc data controller 

        #add extensions
        az extension add --name arcdata
        #register provider
            $Provider="Microsoft.AzureArcData"
            Register-AzResourceProvider -ProviderNamespace $Provider
            #wait for provider to finish registration
            do {
                $Status=Get-AzResourceProvider -ProviderNamespace $Provider
                Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
                Start-Sleep 1
            } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))

        #create storage container
            #create
            Invoke-Command -ComputerName $ClusterName -ScriptBlock {
                New-AksHciStorageContainer -Name $using:StorageContainerName -Path $using:StorageContainerPath
            }
            #validate
            Invoke-Command -ComputerName $ClusterName -ScriptBlock {
                Get-AksHciStorageContainer -Name $using:StorageContainerName
            }

        #create custom storage class
        $defaultclass=kubectl get storageclass default -o json | convertfrom-json
        $yaml=@"
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
    name: aks-hci-disk-custom
provisioner: disk.csi.akshci.com
parameters:
    blocksize: "33554432"
    container: $StorageContainerName
    dynamic: "true"
    group: $($defaultclass.parameters.group) # same as the default storageclass
    hostname: $($defaultclass.parameters.hostname) # same as the default storageclass
    logicalsectorsize: "4096"
    physicalsectorsize: "4096"
    port: "55000"
    fsType: ext4 # refer to the note above to determine when to include this parameter
allowVolumeExpansion: true
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer # or Immediate https://docs.microsoft.com/en-us/azure-stack/aks-hci/container-storage-interface-disks#create-a-custom-storage-class-for-an-aks-on-azure-stack-hci-disk
"@
        #create class
        $file=New-TemporaryFile
        $file | Set-Content -Value $Yaml
        kubectl apply -f $file.FullName

        #configure new class in custom deployment
        set-location $env:UserProfile
        az arcdata dc config init --source azure-arc-aks-hci --path ./custom
        az arcdata dc config replace --path ./custom/control.json --json-values "spec.storage.data.className=aks-hci-disk-custom"
        az arcdata dc config replace --path ./custom/control.json --json-values "spec.storage.logs.className=aks-hci-disk-custom"

        #deploy
        az arcdata dc create --path ./custom --name $DataControllerName --resource-group $resourcegroup --location $location --connectivity-mode direct --auto-upload-logs true --auto-upload-metrics true --custom-location $CustomLocationName
        #az arcdata dc delete --name $DataControllerName --resource-group $resourcegroup

        #monitor deployment
        kubectl get datacontrollers --namespace $DataControllerNamespace
        az arcdata dc status show --k8s-namespace $DataControllerNamespace --use-k8s

#endregion

#region get admin token and use it in Azure Portal to view resources in AKS HCI https://docs.microsoft.com/en-us/azure/azure-arc/kubernetes/cluster-connect#option-2-service-account-bearer-token
    #add kubectl to system environment variable, so it can be run by simply typing kubectl
    [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
    kubectl create serviceaccount admin-user
    kubectl create clusterrolebinding admin-user-binding --clusterrole cluster-admin --serviceaccount default:admin-user
    $SecretName = $(kubectl get serviceaccount admin-user -o jsonpath='{$.secrets[0].name}')
    $EncodedToken = $(kubectl get secret ${SecretName} -o=jsonpath='{.data.token}')
    $Token = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($EncodedToken))
    $Token
    #copy token to clipboard
    $Token | Set-Clipboard
#endregion

#region install Azure Data tools (already installed tools are commented) https://www.cryingcloud.com/blog/2020/11/26/azure-arc-enabled-data-services-on-aks-hci
#download and install Azure Data CLI
Start-BitsTransfer -Source https://aka.ms/azdata-msi -Destination "$env:USERPROFILE\Downloads\azdata-cli.msi"
Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\azdata-cli.msi /quiet"

#download and install Azure Data Studio https://docs.microsoft.com/en-us/sql/azure-data-studio/download-azure-data-studio?view=sql-server-ver15
Start-BitsTransfer -Source https://go.microsoft.com/fwlink/?linkid=2148607 -Destination "$env:USERPROFILE\Downloads\azuredatastudio-windows-user-setup.exe"
Start-Process "$env:USERPROFILE\Downloads\azuredatastudio-windows-user-setup.exe" -Wait -ArgumentList "/SILENT /MERGETASKS=!runcode"

#download and install Azure CLI
<#
Start-BitsTransfer -Source https://aka.ms/installazurecliwindows -Destination $env:userprofile\Downloads\AzureCLI.msi
Start-Process msiexec.exe -Wait -ArgumentList "/I  $env:userprofile\Downloads\AzureCLI.msi /quiet"
#>

#download and install Kubernetes CLI
<#
$uri = "https://kubernetes.io/docs/tasks/tools/install-kubectl/"
$req = Invoke-WebRequest -UseBasicParsing -Uri $uri
$downloadlink = ($req.Links | where href -Match "kubectl.exe").href
$downloadLocation="c:\Program Files\AksHci\"
New-Item -Path $downloadLocation -ItemType Directory -Force
Start-BitsTransfer $downloadlink -DisplayName "Getting KubeCTL from $downloadlink" -Destination "$Downloadlocation\kubectl.exe"
#add to enviromental variables
[System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
#>
#endregion

#region cleanup azure resources
<#
$ClusterName="AksHCI-Cluster"

if (-not (Get-AzContext)){
    Connect-AzAccount -UseDeviceAuthentication
}

#unregister azure stack hci cluster
    $subscriptionID=(Get-AzContext).Subscription.id
    $armTokenItemResource = "https://management.core.windows.net/"
    $graphTokenItemResource = "https://graph.windows.net/"
    $azContext = Get-AzContext
    $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
    $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id

    UnRegister-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -Confirm:0

#remove resource groups
    if (-not (Get-AzContext)){
        Connect-AzAccount -UseDeviceAuthentication
    }
    #where AKS clusters are
    Get-AzResourceGroup -Name "$ClusterName-rg" | Remove-AzResourceGroup -Force
    #residue after Resource group where Arc agents were located
    Get-AzResourceGroup -Name "$ClusterName-*" | Remove-AzResourceGroup -Force

#and registration principal
    $servicePrincipalDisplayName="ArcRegistration"
    $principal=Get-AzADServicePrincipal -DisplayName $servicePrincipalDisplayName
    Remove-AzADServicePrincipal -ObjectId $principal.id
    Get-AzADApplication -DisplayName $servicePrincipalDisplayName | Remove-AzADApplication

#remove Log Analytics Workspace
    Get-AzResourceGroup -Name "MSLabAzureArc" | Remove-AzResourceGroup -Force

#>
#endregion

#region Windows Admin Center on GW

#Install Edge
if (-not (test-path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")){
    Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
    #start install
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
    #start Edge
    start-sleep 5
    & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
}

#install WAC
$GatewayServerName="WACGW"

#Download Windows Admin Center if not present
Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

#Create PS Session and copy install files to remote server
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
}

$Session | Remove-PSSession

#add certificate to trusted root certs (not recommended for production)
start-sleep 10
$cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
$cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

#Configure Resource-Based constrained delegation
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter *).Name

foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}

#endregion