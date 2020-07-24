<!-- TOC -->

- [AzSHCI and Cluster Creation Extension](#azshci-and-cluster-creation-extension)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Prereq for stretch](#prereq-for-stretch)
    - [The lab](#the-lab)
        - [Install Edge on DC](#install-edge-on-dc)
        - [Install Windows Admin Center in GW mode](#install-windows-admin-center-in-gw-mode)
        - [Or Install Windows Admin Center on Windows 10 machine](#or-install-windows-admin-center-on-windows-10-machine)
        - [Create cluster](#create-cluster)

<!-- /TOC -->

# AzSHCI and Cluster Creation Extension

## About the lab

In following lab you deploy Azure Stack HCI Cluster using Cluster Creation in Windows Admin Center.

Note: there is a known issue, that exposed virtualization extensions are not detected, so install Hyper-V feature (and Hyper-V PowerShell, or WAC Will not create vSwitches) first

```powershell
Invoke-Command -computername (1..4 | % {"1AzSHCI$_"}) -ScriptBlock {
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Management-PowerShell -Online -NoRestart
}
 
```

## LabConfig

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'<#; Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

#pre-domain joined
1..4 | ForEach-Object {$VMNames="1AzSHCI" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB; MGMTNICs=4 ; NestedVirt=$true}} 

#not domain joined
1..4 | ForEach-Object {$VMNames="2AzSHCI" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB; MGMTNICs=4 ; NestedVirt=$true ; Unattend="NoDjoin"}}

#stretch pre-domain joined
1..2 | ForEach-Object {$VMNames="Site1AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; MGMTNICs=4 ; ManagementSubnetID=0}}
1..2 | ForEach-Object {$VMNames="Site2AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; MGMTNICs=4 ; ManagementSubnetID=1}}

#Windows Admin Center gateway
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MGMTNICs=1 }

#Windows 10 management machine
$LabConfig.VMs += @{ VMName = 'Win10'; ParentVHD = 'Win1020H1_G2.vhdx' ; AddToolsVHD = $True ; MGMTNICs=1 }
 
```

## Prereq for stretch

```Powershell
    #configure sites and subnets in Active Directory
    New-ADReplicationSite -Name "Site1-Redmond"
    New-ADReplicationSite -Name "Site2-Seattle"
    New-ADReplicationSubnet -Name "10.0.0.0/24" -Site "Site1-Redmond" -Location "Redmond, WA"
    New-ADReplicationSubnet -Name "10.0.1.0/24" -Site "Site2-Seattle" -Location "Seattle, WA"
```

## The lab

Run all code from DC or Win 10 (depends if you) want Windows Admin Center in Gateway mode or on Windows 10.

You will need to create Win10 and Azure Stack HCI parent disks using CreateParentDisk.ps1 located in ParentDisks folder.

### Install Edge on DC

```PowerShell
#Install Edge
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/40e309b4-5d46-4AE8-b839-bd74b4cff36e/MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
 
```

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/Edge.png)

### Install Windows Admin Center in GW mode

To install Windows Admin Center including trusted certificate from CA you can follow [Windows Admin Center and Enterprise CA scenario](/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA). Following guide imports self-signed certificate to local trusted root cert store.

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

#add certificate to trusted root certs
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

```

### Or Install Windows Admin Center on Windows 10 machine

```PowerShell
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
    $ProgressPreference='Continue' #return progress preference back
}

#Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

#Open Windows Admin Center
    Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
 
```

### Create cluster

In Edge, navigate to https://wacgw. Log in with corp\LABAdmin LS1setup! credentials.

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC01.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC02.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC03.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC04.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC05.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC06.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC07.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC08.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC09.png)

```powershell
Invoke-Command -computername (1..4 | % {"1AzSHCI$_"}) -ScriptBlock {
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Management-PowerShell -Online -NoRestart
}
 
```

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC10.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC11.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC12.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC13.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC14.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC15.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC16.png)

![](/Scenarios/AzSHCI%20and%20Cluster%20Creation%20Extension/Screenshots/WAC17.png)
