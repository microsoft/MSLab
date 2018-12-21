# S2D and Validate-DCB

## About the lab

http://aka.ms/Validate-DCB can be used to validate DCB configuration. Following scenario will demonstrate how to run Validate-DCB in enterprise environment to detect misconfigurations. Guide for DCB Deployment is located at http://aka.ms/ConvergedRDMA

## Prereq

Finish S2D Hyperconverged scenario. Just make sure $DCB=$true in Variables. Run all following code from DC or Management machine

## Download required files

```PowerShell
$ProgressPreference='SilentlyContinue' #for faster download
#configure TLS1.2 if needed
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

#Download Validate-DCB
Invoke-WebRequest -UseBasicParsing -Uri https://github.com/Microsoft/Validate-DCB/archive/master.zip -OutFile $env:USERPROFILE\Downloads\Validate-DCB.zip
#Unzip Validate-DCB
Expand-Archive -Path $env:USERPROFILE\Downloads\Validate-DCB.zip -DestinationPath $env:USERPROFILE\Downloads\

#Download example config that fits WSLab
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Validate-DCB/Config.ps1 -OutFile $env:USERPROFILE\Downloads\Config.ps1
 
```

## Install RSAT tools

```PowerShell
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
if ($WindowsInstallationType -eq "Client"){
    Enable-WindowsOptionalFeature -Online -FeatureName "DataCenterBridging","Microsoft-Hyper-V-All" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V"
}else{
    Install-WindowsFeature -Name "Data-Center-Bridging","RSAT-Hyper-V-Tools"
}
 
```

## Fix NetAdapters names on S2D cluster

For example rename from vEthernet (SMB_1) to just SMB_1 as validate-dcb validate if NetAdapter and VMNetworkAdapter names are the same.

```PowerShell
$servers="S2D1","S2D2","S2D3","S2D4"
$adapters=Get-NetAdapter -CimSession $servers | where name -like "vEthernet (*"
foreach ($adapter in $adapters){
    $newname=$adapter.name.Replace("vEthernet (","").Replace(")","")
    $adapter | Rename-NetAdapter -NewName $newname
}
 
```

## Run Validate-DCB

```PowerShell
Set-Location $env:USERPROFILE\Downloads
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
#validate tool prerequisites and basic config
.\Validate-DCB-master\initiate.ps1 -ConfigFilePath .\Config.ps1 -TestScope Global

#Validate DCB settings (in virtual environment you should see errors related to the fact there are no real RDMA adapters)
.\Validate-DCB-master\initiate.ps1 -ConfigFilePath .\Config.ps1 -TestScope Modal
 
```

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/GlobalResults.png)

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/ModalResults.png)

## Some notes

It's a good idea to run script from ISE as it tries to exit after it's done. In ISE you can click Cancel.

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Exit.png)