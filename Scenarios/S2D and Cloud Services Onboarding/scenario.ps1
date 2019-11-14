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

#region (optional) Install Windows Admin Center in a GW mode 
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

#Configure Resource-Based constrained delegation
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name

foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
 
#endregion

#region Connect to Azure and create Log Analytics workspace if needed
#Login to Azure
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
Login-AzAccount -UseDeviceAuthentication
#select context if more available
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context | Out-GridView -OutpuMode Single | Set-AzContext
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

#region deploy a Windows Hybrid Runbook Worker
#https://docs.microsoft.com/en-us/azure/automation/automation-windows-hrw-install

#Workspace/Resource Group Name (same as Log Analytics)
$SubscriptionID=(Get-AzContext).Subscription.ID
$WorkspaceName="WSLabWorkspace-$SubscriptionID"
$ResourceGroupName="WSLabWinAnalytics"
$HRWorkerServerName="HRWorker01"
$AutomationAccountName="WSLabAutomationAccount"
$HybridWorkerGroupName="WSLabHRGroup01"

#Add solutions to the Log Analytics workspace
#Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
$solutions="Security","Updates","LogManagement","AlertManagement","AzureAutomation","ServiceMap","InfrastructureInsights"
foreach ($solution in $solutions){
    Set-AzOperationalInsightsIntelligencePack -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -IntelligencePackName $solution -Enabled $true
}

#Add Automation Account
$location=(Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName).Location
New-AzAutomationAccount -Name $AutomationAccountName -ResourceGroupName $ResourceGroupName -Location $Location -Plan Free 

#link workspace to Automation Account <tbd>
<#
$json=@"
{
    "type": "Microsoft.OperationalInsights/workspaces",
    "name": "[variables('namespace')]",
    "apiVersion": "2017-03-15-preview",
    "location": "[resourceGroup().location]",
    "properties": {
        "sku": {
            "name": "Standalone"
        }
    },
    "resources": [
        {
            "name": "Automation", # this onboards automation to oms, which is what you need
            "type": "linkedServices",
            "apiVersion": "2015-11-01-preview",
            "dependsOn": [
                "[variables('automation')]",
                "[variables('namespace')]"
            ],
            "properties": {
                "resourceId": "[resourceId('Microsoft.Automation/automationAccounts/', variables('automation'))]"
            }
        }
    ]
}
"@
$TemplateObject = ConvertFrom-Json $json -AsHashtable
New-AzDeployment -Location $Location -TemplateObject $json
#>

#Install MMA to Hybrid Runbook worker server
#Download MMA Agent (if not yet downloaded)
if (-not (Test-Path "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?LinkId=828603 -OutFile "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -UseBasicParsing
    $ProgressPreference='Continue' #return progress preference back
}

#Increase MaxEvenlope and create session to copy files to
Invoke-Command -ComputerName $HRWorkerServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$session=New-PSSession -ComputerName $HRWorkerServerName

#copy mma agent
Copy-Item -Path "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force

#grab WorkspaceID
$WorkspaceID=$Workspace.CustomerId.guid
#Grab WorkspacePrimaryKey
$WorkspacePrimaryKey=($Workspace | Get-AzOperationalInsightsWorkspaceSharedKey).PrimarySharedKey

#install MMA agent
Invoke-Command -ComputerName $HRWorkerServerName -ScriptBlock {
    $ExtractFolder="$env:USERPROFILE\Downloads\MMAInstaller"
    #extract MMA
    if (Test-Path $extractFolder) {
        Remove-Item $extractFolder -Force -Recurse
    }
    Start-Process -FilePath "$env:USERPROFILE\Downloads\MMASetup-AMD64.exe" -ArgumentList "/c /t:$ExtractFolder" -Wait
    Start-Process -FilePath "$ExtractFolder\Setup.exe" -ArgumentList "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$using:workspaceId OPINSIGHTS_WORKSPACE_KEY=$using:workspacePrimaryKey AcceptEndUserLicenseAgreement=1" -Wait
}

#Register the hybrid runbook worker
$AutomationInfo = Get-AzAutomationRegistrationInfo -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
$AutomationPrimaryKey = $AutomationInfo.PrimaryKey
$AutomationEndpoint = $AutomationInfo.Endpoint
Invoke-Command -ComputerName $HRWorkerServerName -ScriptBlock {
    $PoshModule=(get-childitem -Path "$env:programfiles\Microsoft Monitoring Agent\Agent\AzureAutomation" -Recurse  | Where-Object name -eq HybridRegistration.psd1 | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    Import-Module $PoshModule
    Add-HybridRunbookWorker -Name $using:HybridWorkerGroupName -EndPoint $using:AutomationEndpoint -Token $using:AutomationPrimaryKey
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

#region Cleanup Azure resources

<#
#remove resource group
Get-AzResourceGroup -Name "WSLabWinAnalytics" | Remove-AzResourceGroup -Force


#remove ServicePrincipal for WAC (all)
Remove-AzADServicePrincipal -DisplayName WindowsAdminCenter* -Force
Get-AzADApplication -DisplayNameStartWith WindowsAdmin |Remove-AzADApplication -Force
 
#>

#endregion