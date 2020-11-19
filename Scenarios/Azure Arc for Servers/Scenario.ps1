#region prerequisites

#install Azure modules
$ModuleNames="Az.Accounts","Az.ConnectedMachine","Az.Resources","Az.OperationalInsights","Az.Automation","Az.Compute","Az.KeyVault"

#download Azure module
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
foreach ($ModuleName in $ModuleNames){
    if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
        Install-Module -Name $ModuleName -Force
    }
}

#login to azure
Login-AzAccount -UseDeviceAuthentication

#select context if more available
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context | Out-GridView -OutputMode Single | Set-AzContext
}

#select subscription
$subscriptions=Get-AzSubscription
if (($subscriptions).count -gt 1){
    $subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription
}

#$subscriptionID=(Get-AzContext).Subscription.ID
#endregion

#region Create Azure Resources
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
#endregion

#region Install Azure Arc to servers
$servers="Server1","Server2","Server3"

# Download the package
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"
$ProgressPreference='Continue' #return progress preference back

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
#endregion

#region Configure and validate Arc on remote servers
$ResourceGroupName="WSLabAzureArc"
$ServicePrincipalName="Arc-for-servers"
$TenantID=(Get-AzContext).Tenant.ID
$SubscriptionID=(Get-AzContext).Subscription.ID
$ServicePrincipalID=(Get-AzADServicePrincipal -DisplayName $ServicePrincipalName).applicationid.guid
$location=(Get-AzResourceGroup -Name $ResourceGroupName).Location
$servers="Server1","Server2","Server3"
$tags="Platform=Windows"
$password="" #here goes ADApp password. If empty, script will generate new secret. Make sure this secret is the same as in Azure

#Create new password
    if (-not ($password)){
        Get-AzADApplication -DisplayName $ServicePrincipalName
        #create secret (you can save it somewhere as you will not be able to retrieve it from Azure anymore)
        #generate password https://opentechtips.com/random-password-generator-in-powershell/
        $chars=(48..57) + (65..90) + (97..122)
        $length = 64
        [string]$Password = $null
        $chars | Get-Random -Count $length | ForEach-Object { $Password += [char]$_ }
        Write-Host "Your Password is: " -NoNewLine ; Write-Host $password -ForegroundColor Cyan
        $secpassword=ConvertTo-SecureString $password -AsPlainText -Force
        #add new password
        Get-AzADApplication -DisplayName $ServicePrincipalName | New-AzADAppCredential -Password $secpassword -EndDate 12/31/2999
    }

#sleep for 1m just to let ADApp password to propagate
Start-Sleep 60

#configure Azure ARC agent on servers
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:ServicePrincipalID --service-principal-secret $using:password --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location) --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
}
#endregion

#region Validate if agents are connected

$servers="Server1","Server2","Server3"
Invoke-Command -ComputerName $Servers -ScriptBlock {
    & "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe" show
}

#endregion

#region Create Log Analytics workspace
#Grab Insights Workspace if some already exists
$Workspace=Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | Out-GridView -OutputMode Single

#Create workspace if not available
if (-not ($Workspace)){
    $SubscriptionID=(Get-AzContext).Subscription.ID
    $WorkspaceName="WSLabWorkspace-$SubscriptionID"
    $ResourceGroupName="WSLabAzureArc"
    #Pick Region
    $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.OperationalInsights" | Out-GridView -OutputMode Single
    if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)){
        New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
    }
    $Workspace=New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -Location $location.Location
}
#endregion

#region add Automation Account
$SubscriptionID=(Get-AzContext).Subscription.ID
$WorkspaceName="WSLabWorkspace-$SubscriptionID"
$ResourceGroupName="WSLabWinAnalytics"
$AutomationAccountName="WSLabAutomationAccount"

$location=(Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName).Location
New-AzAutomationAccount -Name $AutomationAccountName -ResourceGroupName $ResourceGroupName -Location $Location -Plan Free 

#link workspace to Automation Account (via an ARM template deployment)
$json = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace_name": {
            "type": "string"
        },
        "automation_name": {
            "type": "string"
        }
    },
    "resources": [
        {
            "type": "Microsoft.OperationalInsights/workspaces",
            "name": "[parameters('workspace_name')]",
            "apiVersion": "2015-11-01-preview",
            "location": "[resourceGroup().location]",
            "resources": [
                {
                    "name": "Automation",
                    "type": "linkedServices",
                    "apiVersion": "2015-11-01-preview",
                    "dependsOn": [
                        "[parameters('workspace_name')]"
                    ],
                    "properties": {
                        "resourceId": "[resourceId(resourceGroup().name, 'Microsoft.Automation/automationAccounts', parameters('automation_name'))]"
                    }
                }
            ]
        },
        {
            "type": "Microsoft.OperationsManagement/solutions",
            "name": "[concat('Updates', '(', parameters('workspace_name'), ')')]",
            "apiVersion": "2015-11-01-preview",
            "location": "[resourceGroup().location]",
            "plan": {
                "name": "[concat('Updates', '(', parameters('workspace_name'), ')')]",
                "promotionCode": "",
                "product": "OMSGallery/Updates",
                "publisher": "Microsoft"
            },
            "properties": {
                "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace_name'))]"
            },
            "dependsOn": [
                "[parameters('workspace_name')]"
            ]
        }
    ]
}
"@

$templateFile = New-TemporaryFile
Set-Content -Path $templateFile.FullName -Value $json

$templateParameterObject = @{
    workspace_name = $WorkspaceName
    automation_name = $AutomationAccountName
}
New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFile.FullName -TemplateParameterObject $templateParameterObject
Remove-Item $templateFile.FullName
#endregion

#region add Monitoring extension and dependency agent extension https://docs.microsoft.com/en-us/azure/azure-arc/servers/manage-vm-extensions-powershell
$WorkspaceName="WSLabWorkspace-$SubscriptionID"
$ResourceGroupName="WSLabAzureArc"
$server="Server1"

$workspace=Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName
$keys=Get-AzOperationalInsightsWorkspaceSharedKey -Name $WorkspaceName -ResourceGroupName $ResourceGroupName

$Setting = @{ "workspaceId" = "$($workspace.CustomerId.GUID)" }
$protectedSetting = @{ "workspaceKey" = "$($keys.PrimarySharedKey)" }

New-AzConnectedMachineExtension -Name "MicrosoftMonitoringAgent" -ResourceGroupName $ResourceGroupName -MachineName $server -Location $location -Publisher "Microsoft.EnterpriseCloud.Monitoring" -Settings $Setting -ProtectedSetting $protectedSetting -ExtensionType "MicrosoftMonitoringAgent" #-TypeHandlerVersion "1.0.18040.2"
New-AzConnectedMachineExtension -Name "DependencyAgentWindows" -ResourceGroupName $ResourceGroupName -MachineName $server -Location $location -Publisher "Microsoft.Azure.Monitoring.DependencyAgent" -Settings $Setting -ProtectedSetting $protectedSetting -ExtensionType "DependencyAgentWindows"


#endregion

#region add extension at scale https://docs.microsoft.com/en-us/azure/azure-monitor/insights/vminsights-enable-policy
#TBD with Posh
#endregion

#Add Key Vault Extension
$ResourceGroupName="WSLabAzureArc"
$KeyVaultName="WSLabKeyVault"+"$(1..10000 | Get-Random)"
$Location="westeurope"
$ADUser=Get-AzADUser | Out-GridView -OutputMode Single #ADUser who will get rights to create cert
$ServerName="Server1" #server that will be granted permissions to retrieve certificate
$CertificateName="ExampleCertificate"
New-AzKeyVault -Name $KeyVaultName -Location $location -ResourceGroupName $ResourceGroupName

Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -PermissionsToCertificates create,list,get -UserPrincipalName $aduser.UserPrincipalName

$Policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=contoso.com" -IssuerName "Self" -ValidityInMonths 6 -ReuseKeyOnRenewal
Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -CertificatePolicy $Policy

#assign permissions to server1
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -PermissionsToSecrets get,list -ObjectId (Get-AzADServicePrincipal -DisplayName $ServerName).Id

#Deploy the extension https://techcommunity.microsoft.com/t5/azure-arc/in-preview-azure-key-vault-extension-for-arc-enabled-servers/ba-p/1888739
$Settings = @{
    secretsManagementSettings = @{
      observedCertificates = @(
        "https://$KeyVaultName.vault.azure.net/secrets/$CertificateName"
        # Add more here in a comma separated list
      )
      certificateStoreLocation = "LocalMachine"
      certificateStoreName = "My"
      pollingIntervalInS = "10" # every hour (3600) is recommended. 10s here is just for lab
    }
    authenticationSettings = @{
      # Don't change this line, it's required for Arc enabled servers
      msiEndpoint = "http://localhost:40342/metadata/identity"
    }
  }

New-AzConnectedMachineExtension -ResourceGroupName $ResourceGroupName -MachineName $ServerName -Name "KeyVaultForWindows" -Location $Location -Publisher "Microsoft.Azure.KeyVault" -ExtensionType "KeyVaultForWindows" -Setting (ConvertTo-Json $Settings)
#endregion

#region validate deployed cert
$servername="Server1"
Invoke-Command -ComputerName $servername -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\}
#endregion

#region cleanup
<#
$ResourceGroupName="WSLabAzureArc"
Remove-AzResourceGroup -Name $ResourceGroupName -Force
Remove-AzADServicePrincipal -DisplayName Arc-for-servers -Force
Remove-AzADApplication -DisplayName Arc-for-servers -Force
#>
#endregion