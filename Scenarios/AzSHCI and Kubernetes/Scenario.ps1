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


###################
### Run from DC ###
###################

#region Create 2 node cluster (just simple. Not for prod - follow hyperconverged scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/S2D%20Hyperconverged)

# Set DHCP Server lease time to 90 days for reserving IP dynamicly allocated to AKS management/working cluster control plane & working nodes.
Invoke-Command -ComputerName DC -ScriptBlock {
    Set-DhcpServerv4Scope -ScopeId 10.0.0.0 -LeaseDuration 90.00:00:00
}

# LabConfig
$Servers="AzsHCI1","AzSHCI2"
$ClusterName="AzSHCI-Cluster"

# Install features for management on server
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

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
$ClusterName="AzSHCI-Cluster"

#download Azure module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
    Install-Module -Name Az.StackHCI -Force
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
$ClusterName="AzSHCI-Cluster"
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

#region setup AKS (PowerShell)
    #set variables
    $ClusterName="AzSHCI-Cluster"
    $vSwitchName="vSwitch"
    $vNetName="aksvnet"
    $VolumeName="AKS"
    $Servers=(Get-ClusterNode -Cluster $ClusterName).Name
    $VIPPoolStart="10.0.0.100"
    $VIPPoolEnd="10.0.0.200"
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
        $vnet = New-AksHciNetworkSetting -Name $using:vNetName -vSwitchName $using:vSwitchName -vippoolstart $using:vippoolstart -vippoolend $using:vippoolend
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
    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
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
#Jaromirk note: it would be great if I could specify HCI Cluster (like New-AksHciCluster -ComputerName)
$ClusterName="AzSHCI-Cluster"
$ClusterNode=(Get-ClusterNode -Cluster $clustername).Name | Select-Object -First 1
$KubernetesClusterName="demo"
Invoke-Command -ComputerName $ClusterNode -ScriptBlock {
    # Create new cluster with 1 linux node pool in 1 node pool
    New-AksHciCluster -Name $using:KubernetesClusterName -NodePoolName linux-pool
    
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
#endregion

#region onboard AKS cluster to Azure ARC
$ClusterName="AzSHCI-Cluster"

#register AKS
#https://docs.microsoft.com/en-us/azure-stack/aks-hci/connect-to-arc

if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
    Install-Module -Name Az.Resources -Force
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
    $ClusterName="AzSHCI-Cluster"
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

#region Create Log Analytics workspace
    #Install module
    if (!(Get-InstalledModule -Name Az.OperationalInsights -ErrorAction Ignore)){
        Install-Module -Name Az.OperationalInsights -Force
    }

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

#region Enable Monitoring https://docs.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-hybrid-setup and script https://aka.ms/enable-monitoring-powershell-script
    $ClusterName="AzSHCI-Cluster"
    $resourcegroup="$ClusterName-rg"
    $KubernetesClusterName="demo"
    if (-not (Get-AzContext)){
        Connect-AzAccount -UseDeviceAuthentication
    }
    $SubscriptionID=(Get-AzContext).Subscription.ID
    $Workspace=Get-AzOperationalInsightsWorkspace | Out-GridView -OutputMode Single -Title "Please select Log Analytics Workspace"
    $TemplateURI="https://raw.githubusercontent.com/microsoft/Docker-Provider/ci_dev/scripts/onboarding/templates/azuremonitor-containerSolution.json"
    $AzureCloudName = "AzureCloud" #or AzureUSGovernment

    $AKSClusterResourceId = "/subscriptions/$subscriptionID/resourceGroups/$resourcegroup/providers/Microsoft.Kubernetes/connectedClusters/$KubernetesClustername"
    $AKSClusterResource = Get-AzResource -ResourceId $AKSClusterResourceId
    $AKSClusterRegion = $AKSClusterResource.Location.ToLower()
    $PrimarySharedKey=($Workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey 

    #Add Azure Monitor Containers solution to Workspace
        $DeploymentName = "ContainerInsightsSolutionOnboarding-" + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
        $Parameters = @{ }
        $Parameters.Add("workspaceResourceId", $Workspace.ResourceId)
        $Parameters.Add("workspaceRegion", $Workspace.Location)

        New-AzResourceGroupDeployment -Name $DeploymentName `
        -ResourceGroupName $Workspace.ResourceGroupName `
        -TemplateUri  $TemplateURI `
        -TemplateParameterObject $Parameters

    #Install HEML Chart
        #install helm
            #install chocolatey
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            #install helm
            choco feature enable -n allowGlobalConfirmation
            cinst kubernetes-helm

            <#
            $ClusterName="AzSHCI-Cluster"
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
        #Install Chart to current kube context
            #helm config
            if ($AzureCloudName -eq "AzureCloud"){$omsAgentDomainName="opinsights.azure.com"}
            if ($AzureCloudName -eq "AzureUSGovernment"){$omsAgentDomainName="opinsights.azure.us"}
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
#endregion

#region deploy app
    #add kubectl to system environment variable, so it can be run by simply typing kubectl
    [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';c:\program files\AksHci')
    kubectl apply -f https://raw.githubusercontent.com/Azure-Samples/azure-voting-app-redis/master/azure-vote-all-in-one-redis.yaml
    kubectl get service
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
$ClusterName="AzSHCI-Cluster"

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
    #where log analytics workspace resides
    Get-AzResourceGroup -Name "MSLabAzureArc" | Remove-AzResourceGroup -Force

#and registration principal
    $servicePrincipalDisplayName="ArcRegistration"
    $principal=Get-AzADServicePrincipal -DisplayName $servicePrincipalDisplayName
    Remove-AzADServicePrincipal -ObjectId $principal.id
    Get-AzADApplication -DisplayName $servicePrincipalDisplayName | Remove-AzADApplication
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