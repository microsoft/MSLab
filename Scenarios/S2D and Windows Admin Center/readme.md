<!-- TOC -->

- [S2D and Windows Admin Center](#s2d-and-windows-admin-center)
    - [About the lab](#about-the-lab)
    - [LabConfig and Prerequisites](#labconfig-and-prerequisites)
    - [Install Windows Admin Center](#install-windows-admin-center)
    - [Adding 2016 S2D cluster into Windows Admin Center](#adding-2016-s2d-cluster-into-windows-admin-center)
    - [Exploring Performance history in Windows Server 2019](#exploring-performance-history-in-windows-server-2019)
    - [Managing S2D cluster using JEA](#managing-s2d-cluster-using-jea)
        - [Installing RoleBased Access remotely](#installing-rolebased-access-remotely)
        - [Adding users for RBAC Management](#adding-users-for-rbac-management)

<!-- /TOC -->

# S2D and Windows Admin Center

## About the lab

In this lab you will learn how to manage Hyper-Converged infrastructure built on Windows Server 2016 and 2019 with Windows Admin Center. You will also deep dive into how we configure Role-Based Access Control (RBAC), and how it works. All steps are done with PowerShell to demonstrate automation and also to demonstrate, how easy is maintaining documentation if all is done with PowerShell.

Related Microsoft Docs:

[Windows Admin Center](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/understand/windows-admin-center)
[Performance History](https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/performance-history)

## LabConfig and Prerequisites

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
````

Finish [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged/) with Windows Server 2016 or [Windows Server 2019 Insider Preview](/Insider/) before proceeding. In above labconfig is Management machine that requires Win10RS4_G2.vhdx. You can create Win10 image with CreateParentDisk.ps1 located in Tools folder.

LAB VMs

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/LABVMs.png)

Note: Deduplication really helps. If you want to see it in Windows 10, please vote here: https://windowsserver.uservoice.com/forums/295056-storage/suggestions/9011008-add-deduplication-support-to-client-os

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/DedupStatus.png)

## Install Windows Admin Center

Note: You can run following code to download Windows Admin Center from management machine if you provided Internet=$true in LabConfig. If not, copy it over to Management machine manually (ctrl+c, ctrl+v with Enhanced Session Mode) and run Install scripts.

````PowerShell
#Create Temp directory
    New-Item -Path c:\ -Name temp -ItemType Directory -Force

#Download Windows Admin Center
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "c:\temp\WindowsAdminCenter.msi"

#Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
    Start-Process msiexec.exe -Wait -ArgumentList "/i c:\temp\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

#Open Windows Admin Center
    Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
 
````

Certificate popup in Edge. Select Windows Admin Center Client certificate and click OK. 

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/CertificatePopUp.png)

Adding S2D cluster into Windows Admin Center

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/AddingS2DCluster.png)

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/AddingS2DCluster1.png)

## Adding 2016 S2D cluster into Windows Admin Center

Notice, that if you add Windows Server 2016 into Windows Admin Center, you will see following message

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/2016_S2D_Cluster_Error.png)

Let's run suggested command remotely

````PowerShell
Add-ClusterResourceType -Name "SDDC Management" -dll "$env:SystemRoot\Cluster\sddcres.dll" -DisplayName "SDDC Management" -Cluster s2d-cluster
 
````

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/AddSDDCManagement.png)

As you can see, you can now manage your Windows Server 2016 HCI Cluster.

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/HCClusterManager2016.png)

## Exploring Performance history in Windows Server 2019

For more information about Performance History visit this link: http://aka.ms/ClusterPerformanceHistory

Performance history in Dashboard.

Note: critical errors are there because it's virtual environment and each node has limited amount of memory.

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/HCClusterManager2019.png)

Performance History Virtual disk

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/ClusterPerformanceHistoryVolume.png)

Performance History Drive

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/PerformanceHistoryDrive.png)

Performance History Server

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/PerformanceHistoryServer.png)

Performance History VM

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/PerformanceHistoryVM.png)

Performance History Volumes

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/PerformanceHistoryVolumes.png)

Performance History Volume

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/PerformanceHistoryVolume.png)

## Managing S2D cluster using JEA

Run following code from management machine. Make sure aka.ms/RSAT is installed.

### Installing RoleBased Access remotely

Note: following examples are done on Windows Server 2016 S2D cluster as it's already available for our valuable customers.

Docs: https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/configure/user-access-control

To install JEA manually, you can navigate to server settings. It's not enough cool, since it's quite some clicking as you can see on following screenshots.

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/JEASettings1.png)

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/JEASettings2.png)

Let's see if we can script it.

````PowerShell
#invoke rest method first to generate RBAC zip
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq 'CN=Windows Admin Center Client' | Select-Object -First 1
Invoke-RestMethod -Uri "https://localhost:6516/api/nodes/all/features/jea/endpoint/export" -Method POST -Certificate $cert  -OutFile "C:\Temp\WindowsAdminCenter.Jea.zip"

#Grab computers and create sessions
$Computers=(Get-ClusterNode -Cluster S2D-Cluster).Name
$Sessions=New-PSSession -ComputerName $Computers

#Distribute zip to remote machines
foreach ($Session in $sessions) {Copy-Item -Path "C:\Temp\WindowsAdminCenter.Jea.zip" -ToSession $session -Destination "c:\windows\Temp" -Force}

#extract zip and install (you can see this code in PowerShell transcript if you enable it and Apply RBAC in Windows Admin Center GUI)
Invoke-Command -ComputerName $computers -scriptblock {
    $location = Join-Path $env:SystemRoot Temp
    $zip = Join-Path $location WindowsAdminCenter.Jea.zip
    $location = Join-Path $location ([System.IO.Path]::GetFileNameWithoutExtension($zip))
    if (Test-Path $location) {Remove-Item $location -Recurse -Force}
    Expand-Archive -Path $zip -DestinationPath $location
    Remove-Item $zip -Force
    $source = Join-Path $location Modules
    $destination = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $ConfigData = @{AllNodes=@();ModuleBasePath=@{Source=$source;Destination=$destination}}
    Copy-Item -Path (Join-Path $location JustEnoughAdministration) -Destination (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') -Recurse -Force
    Set-Location $location
    $script = Join-Path $location InstallJeaFeature.ps1
    . $script
    InstallJeaFeature -ConfigurationData $ConfigData | Out-Null
    Start-DscConfiguration -Path (Join-Path $location InstallJeaFeature) -JobName 'Installing JEA for Windows Admin Center' -Force
    Wait-Job -Name 'Installing JEA for Windows Admin Center'
}

#Remove sessions
$sessions | Remove-PSSession
 
````

Result. Note: error is expected, since session disconnected

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/RBACResult.png)

To validate DSC Configuration success, you can run following command

````PowerShell
Get-DscConfigurationStatus -CimSession (get-clusternode -Cluster s2d-cluster).Name
 
````

Result

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/DSCResult.png)

So let's take a look what was configured

````PowerShell
$Computers=(Get-ClusterNode -Cluster S2D-Cluster).Name

#Modules are imported on machines
foreach ($Computer in $Computers){
    "SME Module Count on $Computer : $((Get-Module -CimSession $Computer -ListAvailable Microsoft.sme*).Count)"
}

#Groups are present on machines
Invoke-Command -ComputerName $Computers -ScriptBlock {
    Get-LocalGroup -Name "Windows Admin Center*"
}
 
````

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/ModulesAndGroups.png)

### Adding users for RBAC Management

Let's create some users and groups. Let's say EldenC as full-blown admin, StevenEk as Hyper-V admin and CosDar as read-only admin.

````PowerShell
#Create users with password LS1setup!
New-ADUser -Name EldenC -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
New-ADUser -Name StevenEk -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
New-ADUser -Name CosDar -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"

#Create domain groups and add users.
    #Admins
    New-ADGroup -Name "Windows Admin Center Administrators" -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global
    Add-ADGroupMember -Identity "Windows Admin Center Administrators" -Members EldenC
    #Hyper-V Admins
    New-ADGroup -Name "Windows Admin Center Hyper-V Administrators" -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global
    #Readers
    Add-ADGroupMember -Identity "Windows Admin Center Hyper-V Administrators" -Members StevenEk
    New-ADGroup -Name "Windows Admin Center Readers" -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global
    Add-ADGroupMember -Identity "Windows Admin Center Readers" -Members CosDar

````

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/CreateUsersAndGroups.png)

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/CreateUsersAndGroupsDSA.msc.png)

And let's add Domain groups to Local groups on S2D nodes.

````PowerShell
$Computers=(Get-ClusterNode -Cluster S2D-Cluster).Name

Invoke-Command -ComputerName $Computers -ScriptBlock {
    Add-LocalGroupMember -Group "Windows Admin Center Administrators"  -Member "corp\Windows Admin Center Administrators"
    Add-LocalGroupMember -Group "Windows Admin Center Hyper-V Administrators"  -Member "corp\Windows Admin Center Hyper-V Administrators"
    Add-LocalGroupMember -Group "Windows Admin Center Readers"  -Member "corp\Windows Admin Center Readers"
}
 
````

Time to play!

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/ManageAs.png)

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/EldenCcreds.png)

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/AllAdmins.png)

Unfortunately cluster management is not possible

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/AllAdminsError.png)

But node management works great!

![](/Scenarios/S2D%20and%20Windows%20Admin%20Center/Screenshots/AllAdminsNodes.png)

I hope you enjoyed. If this is too much, we (Premier Field Engineers) can help you out! (If you have premier contract)
