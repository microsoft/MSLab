<!-- TOC -->

- [S2D and Azure Arc](#s2d-and-azure-arc)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Setup Azure ARC](#setup-azure-arc)
        - [Install Management tools](#install-management-tools)
        - [Optional: install Windows Admin Center](#optional-install-windows-admin-center)
        - [Install Edge Dev](#install-edge-dev)
        - [Login to Azure](#login-to-azure)
        - [Create Azure Resources](#create-azure-resources)
        - [Install Azure Arc agent to servers](#install-azure-arc-agent-to-servers)
        - [Configure and validate Arc](#configure-and-validate-arc)
        - [Validate if agents are connected](#validate-if-agents-are-connected)
    - [Deploy Policy Definition (not effective ?yet)](#deploy-policy-definition-not-effective-yet)
        - [Explore available Policy Definitions](#explore-available-policy-definitions)
        - [Create definition that tests if Log Analytics agent is installed](#create-definition-that-tests-if-log-analytics-agent-is-installed)
        - [Cleanup from Azure if resources are no longer needed](#cleanup-from-azure-if-resources-are-no-longer-needed)

<!-- /TOC -->

# S2D and Azure Arc

## About the lab

In following lab you deploy Azure Arc for servers agents to servers using PowerShell remoting. 

You can learn more about Azure ARC at [Microsoft Docs](https://docs.microsoft.com/en-us/azure/azure-arc/servers/overview) or [Ignite Session](https://myignite.techcommunity.microsoft.com/sessions/83989?source=sessions)

You can deploy S2D Cluster, but it is not necessary as Azure Arc for Servers does not differentiate between regular server and S2D node. 

## LabConfig

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 

#optional Windows Admin Center gateway
$LabConfig.VMs += @{ VMName = 'WACGW' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB } #Hybrid Runbook Worker

#optional Windows 10 management machine
#$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win1019H1_G2.vhdx'   ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True ; DisableWCF=$True ; MGMTNICs=1}

 
```

## Setup Azure ARC

Run all scripts from Windows 10 management machine (management) or DC. To deploy Windows 10 management machine, create parent disk first (with createparentdisk.ps1 located in Parent Disks folder) and uncomment line in Labconfig that defines management machine.

### Install Management tools

```PowerShell
#Install RSAT Clustering (to query clusters) and AD PowerShell (to grab computers from AD to configure kerberos delegation for Windows Admin Center)
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -like "Server*"){
        Install-WindowsFeature -Name RSAT-Clustering-PowerShell,RSAT-AD-PowerShell
    }elseif (($WindowsInstallationType -eq "Client")){
        #Install RSAT tools
            $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            foreach ($Capability in $Capabilities){
                Add-WindowsCapability -Name $Capability -Online
            }
    }

#download and install Azure PowerShell module
if (!(get-module -Name AZ)){
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AZ -Force
}
 
```

### Optional: install Windows Admin Center

To install Windows Admin Center including trusted certificate you can follow [Windows Admin Center and Enterprise CA scenario](/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA)

```PowerShell
$GatewayServerName="WACGW"
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
    $ProgressPreference='Continue' #return progress preference back
}
#Create PS Session and copy install files to remote server
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
}

$Session | Remove-PSSession

#Configure Resource-Based constrained delegation to all Windows Server computers in Active Directory
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name
foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
 
```

### Install Edge Dev

To be able to login to Azure Portal, you may want to have modern browser (as Windows Server has IE only)

```PowerShell
#Install Edge Dev
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2093376" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi"
#Install Edge Beta
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi /q"
#start Edge
& "C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe"
 
```

### Login to Azure

```PowerShell
#Login to Azure (set execution policy on Win10 if needed)
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
Login-AzAccount -UseDeviceAuthentication
#select context if more available
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context | Out-GridView -OutpuMode Single | Set-AzContext
}
 
```

### Create Azure Resources

```PowerShell
$ResourceGroupName="WSLabAzureArc"
$ServicePrincipalName="Arc-for-servers"

#Register ARC Resource provider
Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
 
#Pick Region
$Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.HybridCompute" | Out-GridView -OutputMode Single

#Create RG if not exist
if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)){
    New-AzResourceGroup -Name $ResourceGroupName -Location $location.location
}
#Create AzADServicePrincipal
if (-not(Get-AZADServicePrincipal -DisplayName $ServicePrincipalName)){
    New-AzADServicePrincipal -DisplayName "Arc-for-servers" -Role "Azure Connected Machine Onboarding"
    #remove default cred
    Get-AzADApplication -DisplayName $ServicePrincipalName | Remove-AzADAppCredential -Force
}
 
```

As result you will see Azure AD app registered and also new Resource Group

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/ResourceGroup01.png)

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/AppRegistrations01.png)


### Install Azure Arc agent to servers

```PowerShell
$Servers="S2D1","S2D2","S2D3","S2D4"

# Download the package
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"
$ProgressPreference='Continue' #return progress preference back

#distribute to servers
#$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name
#$servers=(Get-ClusterNode -Cluster $ClusterName).Name
$ClusterName="S2D-Cluster"
$servers=1..4 | ForEach-Object {"S2D$_"}
#Copy ARC agent to nodes
#increase max evenlope size first
Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
#create sessions
$sessions=New-PSSession -ComputerName $servers
#copy ARC agent
foreach ($session in $sessions){
    Copy-Item -Path "$env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force
}

#install package
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /l*v $env:USERPROFILE\Downloads\ACMinstallationlog.txt /qn" -Wait
}

<#uninstall if needed
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/uninstall $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /qn" -Wait
}
#>
 
```

### Configure and validate Arc

```PowerShell
$ResourceGroupName="WSLabAzureArc"
$ServicePrincipalName="Arc-for-servers"
$TenantID=(Get-AzContext).Tenant.ID
$SubscriptionID=(Get-AzContext).Subscription.ID
$ServicePrincipalID=(Get-AzADServicePrincipal -DisplayName $ServicePrincipalName).applicationid.guid
$location=(Get-AzResourceGroup -Name $ResourceGroupName).Location
$servers="S2D1","S2D2","S2D3","S2D4"
$tags="ClusterName=S2D-Cluster"
$password="" #here goes ADApp password. If empty, script will generate new secret. Make sure this secret is the same as in Azure

#Create new password
    if (-not ($password)){
        $ADApp = Get-AzADApplication -DisplayName $ServicePrincipalName
        #create secret (you can save it somewhere as you will not be able to retrieve it from Azure anymore)
        #generate password
        $chars='a','b','c','d','e','f','g','h','i','k','l','m','n','o','p','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','K','L','M','N','O','P','R','S','T','U','V','W','X','Y','Z','1','2','3','4','5','6','7','8','9','0','!','§','$','%','&','/','(',')','=','?','}',']','[','{','@','#','*','+'
        [string]$password=$chars | get-random -count 64
        $password=$password.replace(" ","")
        Write-Host "Your Password is: " -NoNewLine ; Write-Host $password -ForegroundColor Cyan
        $secpassword=ConvertTo-SecureString $password -AsPlainText -Force
        #add new password
        Get-AzADApplication -DisplayName $ServicePrincipalName | New-AzADAppCredential -Password $secpassword -EndDate 12/31/2999
    }

#configure Azure ARC agent
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:ServicePrincipalID --service-principal-secret $using:password --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location) --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
}
 
```

### Validate if agents are connected

```PowerShell
$servers="S2D1","S2D2","S2D3","S2D4"
Invoke-Command -ComputerName $Servers -ScriptBlock {
    & "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe" show
}
 
```

Querying agents on servers will result in following output

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/ConnectedAgents01.png)

You will also see Azure Arc machines in Azure Portal

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/AzureArcResources01.png)


## Deploy Policy Definition (not effective ?yet)


### Explore available Policy Definitions

```PowerShell
Get-AzPolicyDefinition | select -ExpandProperty Properties | Out-GridView
 
```

### Create definition that tests if Log Analytics agent is installed

```PowerShell
#https://docs.microsoft.com/en-us/azure/governance/policy/assign-policy-powershell
#display all definitions
#$Definitions=Get-AzPolicyDefinition | select -ExpandProperty Properties | Out-GridView
$DefinitionName="The Log Analytics agent should be installed on virtual machines"
$ResourceGroupName="WSLabAzureArc"
$rg = Get-AzResourceGroup -Name $ResourceGroupName

#assign definition
$Definition=Get-AzPolicyDefinition | Where-Object { $_.Properties.DisplayName -eq 'The Log Analytics agent should be installed on virtual machines'}
New-AzPolicyAssignment -Name $Definition.Properties.displayname -DisplayName $Definition.Properties.displayname -Scope $rg.ResourceId -PolicyDefinition $definition
 
```

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/AzureArcPolicies01.png)

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/AzureArcPolicies02.png)


### Cleanup from Azure if resources are no longer needed

```PowerShell
#remove resource group
Get-AzResourceGroup -Name "WSLabAzureArc" | Remove-AzResourceGroup -Force
#remove ServicePrincipal
Remove-AzADServicePrincipal -DisplayName Arc-for-servers -Force
Remove-AzADApplication -DisplayName Arc-for-servers -Force
 
```