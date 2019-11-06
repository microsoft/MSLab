<!-- TOC -->

- [S2D and Cloud Services Onboarding](#s2d-and-cloud-services-onboarding)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [The lab - setup Log Analytics](#the-lab---setup-log-analytics)
        - [Connect to Azure and create Log Analytics workspace if needed](#connect-to-azure-and-create-log-analytics-workspace-if-needed)
        - [Download and deploy MMA Agent](#download-and-deploy-mma-agent)
    - [Setup Azure ARC](#setup-azure-arc)
    - [Cleanup Azure resources](#cleanup-azure-resources)

<!-- /TOC -->

# S2D and Cloud Services Onboarding

## About the lab

This lab will help onboarding multiple servers to cloud services (such as Azure Monitor, Azure Security Center and Azure Update Management) at scale as in Windows Admin Center you can onboard your servers only one by one.

You will learn how to download and install Microsoft Monitoring Agent and what steps needs to be done to create new workspace (if needed)

## LabConfig

As prerequisite, deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged) just to have some cluster to play with. 

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@()}
1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```
## The lab - setup Log Analytics

### Connect to Azure and create Log Analytics workspace if needed

```PowerShell
#download Azure module
if (!(get-module -Name AZ)){
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AZ -Force
}

#Login to Azure
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
#select context if more available
if ((Get-AzContext -ListAvailable).count -gt 1){
    get-azcontent -ListAvailable | Out-GridView -OutpuMode Single | Set-AzContent
}

#Grab Insights Workspace
$Workspace=Get-AzOperationalInsightsWorkspace | Out-GridView -OutputMode Single

#Create workspace if not available
if (-not ($Workspace)){
    $WorkspaceName="WSLabWorkspace"
    $ResourceGroupName="WSLabWinAnalytics"
    #Pick Region
    $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.OperationalInsights" | Out-GridView -OutputMode Single
    if (-not(Get-AzResourceGroup -Name $ResourceGroupName)){
        New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
    }
    $Workspace=New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -Location $location.Location
}
 
```

### Download and deploy MMA Agent

```PowerShell
#Download MMA Agent
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?LinkId=828603 -OutFile "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -UseBasicParsing
$ProgressPreference='Continue' #return progress preference back

#Grab cluster you want to onboard
#install cluster and AD powershell (just cluster is needed in following examples)
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
$cluster=Get-Cluster -Domain $env:USERDOMAIN
$servers=($cluster | Get-ClusterNode).Name

#Copy MMA agent to nodes
#increase max evenlope size first
Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
#create sessions
$sessions=New-PSSession -ComputerName $servers
#copy mma agent
foreach ($session in $sessions){
    Copy-Item -Path "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force
}

#install MMA
#grab WorkspaceID
$WorkspaceID=$Workspace.CustomerId
#Grab WorkspacePrimaryKey
$WorkspacePrimaryKey=($Workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey

#install MMA
Invoke-Command -ComputerName $servers -ScriptBlock {
    #extract MMA
    $extractFolder = Join-Path -Path "$env:USERPROFILE\Downloads" -ChildPath 'SmeMMAInstaller'
    if (Test-Path $extractFolder) {
        Remove-Item $extractFolder -Force -Recurse
    }
    Start-Process -FilePath "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -ArgumentList "/c /t:$extractFolder" -Wait
    Start-Process -FilePath "$extractFolder\Setup.exe" -ArgumentList "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$using:workspaceId OPINSIGHTS_WORKSPACE_KEY=$using:workspacePrimaryKey AcceptEndUserLicenseAgreement=1" -Wait
}
 
```

## Setup Azure ARC

https://docs.microsoft.com/en-us/azure/azure-arc/servers/quickstart-onboard-powershell

```PowerShell
#login to auzre
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
Login-AzAccount

#select context if more available
if ((Get-AzContext -ListAvailable).count -gt 1){
    Get-AzContent -ListAvailable | Out-GridView -OutpuMode Single | Set-AzContent
}
#register ARC
Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
 
```

```PowerShell
# Download the package
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"
$ProgressPreference='Continue' #return progress preference back

#distribute to S2D Cluster Nodes
$cluster=Get-Cluster -Domain $env:USERDOMAIN
$servers=($cluster | Get-ClusterNode).Name

#Copy ARC agent to nodes
#increase max evenlope size first
Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
#create sessions
$sessions=New-PSSession -ComputerName $servers
#copy ARC agent
foreach ($session in $sessions){
    Copy-Item -Path "$env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force
}
 
```

```PowerShell
#Install the package
$TenantID=(Get-AzContext).Tenant.ID
$SubscriptionID=(Get-AzContext).Subscription.ID
$ResourceGroupName="WSLabWinAnalytics"
$Location="westeurope"

$ClusterName="S2D-Cluster"
$Servers=($cluster | Get-ClusterNode).Name

$Tags="ClusterName=$ClusterName"

#install package
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /l*v $env:USERPROFILE\Downloads\ACMinstallationlog.txt /qn" -Wait
}

#configure ARC
$sp = New-AzADServicePrincipal -DisplayName "Arc-for-servers" -Role "Azure Connected Machine Onboarding"
$credential = New-Object pscredential -ArgumentList "temp", $sp.Secret
$ServicePrincipalID=$sp.applicationid.guid
$ServicePrincipalSecret=$credential.GetNetworkCredential().password

Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:ServicePrincipalID --service-principal-secret $using:ServicePrincipalSecret --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $using:Location --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
}
 
```

## Cleanup Azure resources

```PowerShell
#remove resource group
$AZResourceGroupToDelete="WSLabWinAnalytics"
Get-AzResourceGroup -Name "WSLabWinAnalytics" | Remove-AzResourceGroup -Force

#remove ServicePrincipal for ARC
Remove-AzADServicePrincipal -DisplayName Arc-for-servers -Force

#remove ServicePrincipal for WAC (all)
Remove-AzADServicePrincipal -DisplayName WindowsAdminCenter* -Force
 
```