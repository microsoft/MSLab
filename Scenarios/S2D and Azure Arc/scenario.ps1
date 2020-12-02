#region install management tools
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
if (!(Get-module -Name AZ -ListAvailable)){
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AZ -Force
}
#endregion

#region Optional: install Windows Admin Center
$GatewayServerName="WACGW"
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
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

#add certificate to trusted root certs
$cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
$cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

#Configure Resource-Based constrained delegation to all Windows Server computers in Active Directory
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name
foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
#endregion

#region Install Edge
Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
#endregion

#region Login to Azure
If ((Get-ExecutionPolicy) -ne "RemoteSigned"){Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force}
Login-AzAccount -UseDeviceAuthentication
#select context if more available
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context | Out-GridView -OutpuMode Single | Set-AzContext
}
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
$servers=1..4 | ForEach-Object {"S2D$_"} #or $servers="s2d1","s2d2","s2d3","s2d4"

# Download the package
Start-BitsTransfer -Source https://aka.ms/AzureConnectedMachineAgent -Destination "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"

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
$servers="S2D1","S2D2","S2D3","S2D4"
$tags="ClusterName=S2D-Cluster"
$password="" #here goes ADApp password. If empty, script will generate new secret. Make sure this secret is the same as in Azure

#Create new password
    if (-not ($password)){
        Get-AzADApplication -DisplayName $ServicePrincipalName
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

#sleep for 1m just to let ADApp password to propagate
Start-Sleep 60

#configure Azure ARC agent on servers
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:ServicePrincipalID --service-principal-secret $using:password --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location) --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
}
#endregion

#region Validate if agents are connected

$servers="S2D1","S2D2","S2D3","S2D4"
Invoke-Command -ComputerName $Servers -ScriptBlock {
    & "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe" show
}

<#
#configure Azure ARC agent on servers
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $using:ServicePrincipalID --service-principal-secret $using:password --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location) --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
}
#>

#endregion

#region Download Secguide GPOs and convert it to DSC
$BaselinePath="$env:UserProfile\Downloads\Windows-10-1809-Security-Baseline-FINAL"
$DSCDestinationFolder="$BaselinePath\DSC"
#download GPOs and unzip
Start-BitsTransfer -Source https://msdnshared.blob.core.windows.net/media/2018/11/Windows-10-1809-Security-Baseline-FINAL.zip -Destination "$env:UserProfile\Downloads\Windows-10-1809-Security-Baseline-FINAL.zip"
Expand-Archive -Path "$env:UserProfile\Downloads\Windows-10-1809-Security-Baseline-FINAL.zip" -DestinationPath $BaselinePath

#install BaselineManagement module
Install-Module BaselineManagement -Force

#create mof files
[xml]$manifest=Get-Content "$BaselinePath\GPOs\manifest.xml"
$instances=$manifest.Backups.BackupInst
foreach ($instance in $instances){
    $GPOGUID=$instance.ID.'#cdata-section'
    $GPODisplayName=$instance.GPODisplayName.'#cdata-section'
    New-Item -Path $DSCDestinationFolder -Name $GPODisplayName -ItemType Directory
    ConvertTo-DSC -Path "$BaselinePath\GPOs\$GPOGUID" -OutputPath "$DSCDestinationFolder\$GPODisplayName"
}
#endregion

#region create Guestconfig policies
$DSCFolder="$env:UserProfile\Downloads\Windows-10-1809-Security-Baseline-FINAL\DSC"
$OutputFolder="$env:UserProfile\Downloads\Configurations\"

# Install NuGet
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
# Install the Guest Configuration DSC resource module from PowerShell Gallery
Install-Module -Name GuestConfiguration -Force
# Get a list of commands for the imported GuestConfiguration module
Get-Command -Module 'GuestConfiguration'

$mofs=Get-ChildItem -Path $DSCFolder -Recurse | where name -eq "localhost.mof"

#replace "PSDesiredStateConfiguration" with 'PSDscResources' in mof files
Install-Module -Name PSDscResources -Force
$version=(get-module PSDscResources -ListAvailable).Version.tostring()
foreach ($mof in $mofs){
    $content=get-content -Path $mof.fullname
    $content=$content.Replace("PSDesiredStateConfiguration","PSDscResources")
    $content=$content.Replace("ModuleVersion = `"1.0`"","ModuleVersion = `"$version`"")
    $content | set-content -Path $mof.fullname
}

foreach ($mof in $mofs){
    $Name=($mof.Directory.name).split("\") | select-object -last 1
    New-GuestConfigurationPackage -Name $Name -Configuration $mof.fullname -Path $OutputFolder
}

#endregion

#region Register Guest configurations

$ResourceGroupName="ArcConfigTest"
$StorageAccountName="arcconfigtest$(Get-Random -Minimum 100000 -Maximum 999999)"
$ContainerName="test"
$ConfigurationsFolder="$env:UserProfile\Downloads\Configurations\"

#Create resource group
$Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.Storage" | Out-GridView -OutputMode Single
#create resource group first
if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
    New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
}

#create Storage Account
If (-not(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)){
   $StorageAccount=New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location $location.location -Kind StorageV2 -AccessTier Cool
}

#create container
New-AzStorageContainer -Name $containerName -Context $storageAccount.Context -permission Off

#upload compiled package
$zipfiles=Get-Childitem -Path $ConfigurationsFolder -Recurse | where extension -eq .zip
foreach ($zipfile in $zipfiles){
    Set-AzStorageBlobContent -File $zipfile.fullname -Container $ContainerName -Blob $zipfile.name -Context $StorageAccount.Context
}


foreach ($zipfile in $zipfiles){
    #grab blob uri
    $uri=New-AzStorageBlobSASToken -Context $StorageAccount.Context -Container $containerName -Blob $zipfile.name -Permission r -FullUri
    New-GuestConfigurationPolicy `
        -ContentUri $uri `
        -DisplayName "Test-$($zipfile.BaseName)" `
        -Description "Test-$($zipfile.BaseName)" `
        -Path "c:\temp\Test-$($zipfile.BaseName)" `
        -Platform 'Windows' `
        -Version 1.2.3.4 `
        -Verbose
}

#publish policy
foreach ($zipfile in $zipfiles){
    Publish-GuestConfigurationPolicy -Path "c:\temp\Test-$($zipfile.BaseName)" -Verbose
}
#endregion