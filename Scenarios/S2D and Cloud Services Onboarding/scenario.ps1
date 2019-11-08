#region Prereqs

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

#download Azure module
if (!(get-module -Name AZ)){
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AZ -Force
}
 
#endregion

#region Install Edge Beta

#install edge for azure portal and authentication (if code is running from DC)
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2093376" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi"
#Install Edge Beta
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi /q"
#start Edge
& "C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe"
#endregion

#region Connect to Azure and create Log Analytics workspace if needed
#Login to Azure
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
Login-AzAccount -UseDeviceAuthentication
#select context if more available
if ((Get-AzContext -ListAvailable).count -gt 1){
    get-azcontent -ListAvailable | Out-GridView -OutpuMode Single | Set-AzContent
}

#Grab Insights Workspace
$Workspace=Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | Out-GridView -OutputMode Single

#Create workspace if not available
if (-not ($Workspace)){
    $SubscriptionID=(Get-AzContext).Subscription.ID
    $WorkspaceName="WSLabWorkspace-$SubscriptionID"
    $ResourceGroupName="WSLabWinAnalytics"
    #Pick Region
    $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.OperationalInsights" | Out-GridView -OutputMode Single
    if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)){
        New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
    }
    $Workspace=New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -Location $location.Location
}
#endregion

#region setup Log Analytics Gateway
#https://docs.microsoft.com/en-us/azure/azure-monitor/platform/gateway
$LAGatewayName="LAGateway01"

#Download Log Analytics Gateway
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://download.microsoft.com/download/B/7/8/B78D4346-E25E-4923-AB71-3824E2480929/OMS%20Gateway.msi -OutFile "$env:USERPROFILE\Downloads\OMSGateway.msi" -UseBasicParsing
#Download MMA Agent
Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?LinkId=828603 -OutFile "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -UseBasicParsing
$ProgressPreference='Continue' #return progress preference back

#Increase MaxEvenlope and create session to copy files to
Invoke-Command -ComputerName $LAGatewayName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$session=New-PSSession -ComputerName $LAGatewayName

#Install MMA agent first (requirement for Log Analytics Gateway)
#copy mma agent
Copy-Item -Path "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force

#grab WorkspaceID
$WorkspaceID=$Workspace.CustomerId.guid
#Grab WorkspacePrimaryKey
$WorkspacePrimaryKey=($Workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey

#install MMA agent
Invoke-Command -ComputerName $LAGatewayName -ScriptBlock {
    $ExtractFolder="$env:USERPROFILE\Downloads\MMAInstaller"
    #extract MMA
    if (Test-Path $extractFolder) {
        Remove-Item $extractFolder -Force -Recurse
    }
    Start-Process -FilePath "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -ArgumentList "/c /t:$ExtractFolder" -Wait
    Start-Process -FilePath "$ExtractFolder\Setup.exe" -ArgumentList "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$using:workspaceId OPINSIGHTS_WORKSPACE_KEY=$using:workspacePrimaryKey AcceptEndUserLicenseAgreement=1" -Wait
}
#you can now validate if your MMA agent communicates https://docs.microsoft.com/en-us/azure/azure-monitor/platform/agent-windows#verify-agent-connectivity-to-log-analytics

#install Log Analytics Gateway
#copy msi
Copy-Item -Path "$env:USERPROFILE\Downloads\OMSGateway.msi" -Destination "$env:USERPROFILE\Downloads\OMSGateway.msi" -ToSession $session
#install
#https://docs.microsoft.com/en-us/azure/azure-monitor/platform/gateway#install-the-log-analytics-gateway-using-the-command-line
Invoke-Command -ComputerName $LAGatewayName -ScriptBlock {
    Start-Process -FilePath msiexec.exe -ArgumentList "/I $env:USERPROFILE\Downloads\OMSGateway.msi /qn LicenseAccepted=1" -Wait
}
#endregion

#region download and deploy MMA Agent to S2D cluster nodes
#$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name
#$servers=(Get-ClusterNode -Cluster $ClusterName).Name
$ClusterName="S2D-Cluster"
$servers=1..4 | ForEach-Object {"S2D$_"}

#Download MMA Agent (if not yet downloaded)
if (-not (Test-Path "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?LinkId=828603 -OutFile "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -UseBasicParsing
    $ProgressPreference='Continue' #return progress preference back
}

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
$WorkspaceID=$Workspace.CustomerId.guid
#Grab WorkspacePrimaryKey
$WorkspacePrimaryKey=($Workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey
#todo:add Load balancer and add multiple servers
Invoke-Command -ComputerName $servers -ScriptBlock {
    $ExtractFolder="$env:USERPROFILE\Downloads\MMAInstaller"
    #extract MMA
    if (Test-Path $extractFolder) {
        Remove-Item $extractFolder -Force -Recurse
    }
    Start-Process -FilePath "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -ArgumentList "/c /t:$ExtractFolder" -Wait
    Start-Process -FilePath "$ExtractFolder\Setup.exe" -ArgumentList "/qn OPINSIGHTS_PROXY_URL=`"$($using:LAGatewayName):8080`" NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$using:workspaceId OPINSIGHTS_WORKSPACE_KEY=$using:workspacePrimaryKey AcceptEndUserLicenseAgreement=1" -Wait
    #"/i $extractFolder\MOMAgent.msi /qn OPINSIGHTS_PROXY_URL=`"$($using:LAGatewayName):8080`" NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$using:workspaceId OPINSIGHTS_WORKSPACE_KEY=$using:workspacePrimaryKey AcceptEndUserLicenseAgreement=1"
}
#uninstall (if tshooting is needed)
#Invoke-Command -ComputerName $servers -ScriptBlock {Start-Process -FilePath "msiexec" -ArgumentList "/uninstall $env:USERPROFILE\Downloads\MMAInstaller\MOMAgent.msi /qn" -Wait}

#endregion

#region Setup Azure ARC prerequisites
#https://docs.microsoft.com/en-us/azure/azure-arc/servers/quickstart-onboard-powershell

<#login to auzre
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
Login-AzAccount

#select context if more available
if ((Get-AzContext -ListAvailable).count -gt 1){
    Get-AzContent -ListAvailable | Out-GridView -OutpuMode Single | Set-AzContent
}
#>

#register ARC
Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration
 
# Download the package
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"
$ProgressPreference='Continue' #return progress preference back

#endregion

#region distribute to S2D Cluster Nodes
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

#endregion

#region Install the ARC package
#$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name
#$servers=(Get-ClusterNode -Cluster $ClusterName).Name
$ClusterName="S2D-Cluster"
$servers=1..4 | ForEach-Object {"S2D$_"}
$Tags="ClusterName=$ClusterName"

$TenantID=(Get-AzContext).Tenant.ID
$SubscriptionID=(Get-AzContext).Subscription.ID
$ResourceGroupName="WSLabAzureArc"

#Pick Region
$Location=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.HybridCompute" | Out-GridView -OutputMode Single).Location
if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)){
    New-AzResourceGroup -Name $ResourceGroupName -Location $location
}

#install package
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /l*v $env:USERPROFILE\Downloads\ACMinstallationlog.txt /qn" -Wait
}
<#uninstall
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/uninstall $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /qn" -Wait
}
#>
#configure ARC
$sp = New-AzADServicePrincipal -DisplayName "Arc-for-servers" -Role "Azure Connected Machine Onboarding"
$credential = New-Object pscredential -ArgumentList "temp", $sp.Secret
$ServicePrincipalID=$sp.applicationid.guid
$ServicePrincipalSecret=$credential.GetNetworkCredential().password

Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:ServicePrincipalID --service-principal-secret $using:ServicePrincipalSecret --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location.location) --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
}

#endregion

#region Cleanup Azure resources

<#
#remove resource group
$AZResourceGroupsToDelete="WSLabWinAnalytics","WSLabAzureArc"
foreach ($AZResourceGroupToDelete in $AZResourceGroupsToDelete){
    Get-AzResourceGroup -Name $AZResourceGroupToDelete | Remove-AzResourceGroup -Force
}
#remove ServicePrincipal for ARC
Remove-AzADServicePrincipal -DisplayName Arc-for-servers -Force
Remove-AzADApplication -DisplayName Arc-for-servers -Force

#remove ServicePrincipal for WAC (all)
Remove-AzADServicePrincipal -DisplayName WindowsAdminCenter* -Force
Get-AzADApplication -DisplayNameStartWith WindowsAdmin |Remove-AzADApplication -Force
 
#>

#endregion