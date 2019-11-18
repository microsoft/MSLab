<!-- TOC -->

- [S2D and Cluster Creation Extension](#s2d-and-cluster-creation-extension)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [The lab](#the-lab)
        - [Install Edge Beta](#install-edge-beta)
        - [Install Windows Admin Center in GW mode](#install-windows-admin-center-in-gw-mode)
        - [Add extension to Windows Admin Center](#add-extension-to-windows-admin-center)

<!-- /TOC -->

# S2D and Cluster Creation Extension

## About the lab

In following lab you deploy S2D Cluster using Cluster Deployment Extension

## LabConfig

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; NestedVirt=$true }} 

#Windows Admin Center gateway
$LabConfig.VMs += @{ VMName = 'WACGW' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

#optional Windows 10 management machine
#$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win1019H1_G2.vhdx'   ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True ; DisableWCF=$True ; MGMTNICs=1}
 
```

## The lab

Run all code from DC

### Install Edge Beta

```PowerShell
#Download Edge Beta if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2093376" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi"
    $ProgressPreference='Continue' #return progress preference back
}
#Install Edge Beta
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeBetaEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe"
 
```

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/EdgeBeta.png)


### Install Windows Admin Center in GW mode

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
 
```

### Add extension to Windows Admin Center

In Edge Beta, navigate to https://wacgw. To open you need to expand advanced and select continue to wacgw (unsafe) as certificate was not configured. Log in with corp\LABAdmin LS1setup! credentials.

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC01.png)

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC02.png)

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC03.png)

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC04.png)

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC05.png)

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC06.png)

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC07.png)

```PowerShell
$servers="s2d1","s2d2","s2d3","s2d4"
Invoke-Command -ComputerName $servers -ScriptBlock {
    Install-WindowsFeature -Name RSAT-Clustering-PowerShell
}
 
```

![](/Scenarios/S2D%20and%20Cluster%20Creation%20Extension/Screenshots/WAC08.png)