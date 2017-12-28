<!-- TOC -->

- [Scenario Introduction](#scenario-introduction)
    - [LabConfig Windows Server 1709](#labconfig-windows-server-1709)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [The lab](#the-lab)
- [Scenario](#scenario)
    - [Setup LAPS from Windows 10 management Machine.](#setup-laps-from-windows-10-management-machine)

<!-- /TOC -->

# Scenario Introduction

In this scenario will be LAPS lab deployed. It contains of DC, Management machine and 3 managed servers.
The complete documentation and operation guide is available here: https://technet.microsoft.com/en-us/mt227395.aspx

## LabConfig Windows Server 1709

**Note:** to make things easier, provide RSAT msu together with cumulative update for client OS.

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab1709-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; PullServerDC=$false; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'WinServer1709_G2.vhdx'  ; MemoryStartupBytes= 512MB} }

$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="WinServer1709_G2.vhdx";
    Size=40GB
}
 
````

## LabConfig Windows Server 2016

**Note:** If you dont have Win10, you can use CreateParentDisk.ps1 in tools folder to create Win10 VHD without creating all parent disks

````PowerShell

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$True ; CreateClientParent=$true}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 512MB} }
 
````

## The lab

As you can notice, in this scenario is lab connected to internet. It's not mandatory, but in script is PowerShell command to download installation files. All admin tasks will be done from Windows 10 machine, just to demonstrate security best practices. You may also notice that all servers are without graphical interface.

**Deploy.ps1 result**
![](/Scenarios/LAPS/Screenshots/DeployResultWS2016.png)
![](/Scenarios/LAPS/Screenshots/DeployResultWS1709.png)

# Scenario

Start VMs and then log into Management VM. (default credentials are LabAdmin/LS1setup! as always). 
**Note:** To kick in enhanced session mode login, logoff and login again.

````PowerShell
#Run from Host
"*Management","*server*" | Foreach-Object {Start-VM -VMName $_}
 
````

## Setup LAPS from Windows 10 management Machine.

**Note:** All actions are performed from Management VM (Windows 10)

First check if RSAT is installed (it's necessary to work with Active Directory). If you did not provide RSAT msu during lab hydration, download it from http://aka.ms/RSAT and install manually.
````PowerShell
if ((Get-HotFix).hotfixid -contains "KB2693643"){
    Write-Host "RSAT is installed" -ForegroundColor Green
}else{
    Write-Host "RSAT is not installed. Please download and install latest Windows 10 RSAT from aka.ms/RSAT" -ForegroundColor Yellow
}
 
````
![](/Scenarios/LAPS/Screenshots/RSATCheckResult.png)

Next step is to download LAPS install files. Following script will download it into c:\temp. If you did not connect Lab to internet, download it manually from here https://www.microsoft.com/en-us/download/details.aspx?id=46899 and copy to c:\temp.
````PowerShell
#Download files
    #create temp directory
    New-Item -Path c:\ -Name temp -ItemType Directory
    #download LAPS install file x64
    Invoke-WebRequest -UseBasicParsing -Uri https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi -OutFile "c:\temp\LAPS.x64.msi"

    #optional: download documentation
    "LAPS_TechnicalSpecification.docx","LAPS_OperationsGuide.docx" | ForEach-Object {
        Invoke-WebRequest -UseBasicParsing -Uri "https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/$_" -OutFile "c:\temp\$_"
    }
 
````

Setup LAPS
````PowerShell
#install PowerShell management tools, Management UI and copy ADMX template to policy store on management machine
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\LAPS.x64.msi ADDLOCAL=Management.PS,Management.ADMX,Management.UI /q"

#Create LAPS groups 
    #OU path where Groups will be created
    $OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"

    #create groups
    New-ADGroup -Name LAPS_Readers -GroupScope Global -Path $OUPath
    New-ADGroup -Name LAPS_Resetters -GroupScope Global -Path $OUPath

#create empty GPO
New-Gpo -Name 'LAPS' | New-GPLink -Target $OUPath

#extend AD schema (Schema Admins and Enterprise Admins membership needed)
Update-AdmPwdADSchema

#note: if you are not member of required groups, add your account as member. Logoff/login is needed to update security token.
#Add-ADGroupMember -Identity "Schema Admins" -Members LabAdmin
#Add-ADGroupMember -Identity "Enterprise Admins" -Members LabAdmin

#Set delegation model
    #OU path where Readers and resetters will be granted permissions and Computers will have self delegation
    $OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
    
    #Add machine rights to report passwords to AD
    Set-AdmPwdComputerSelfPermission -Identity $OUPath

    #User perms to read and reset passwords
    Set-AdmPwdReadPasswordPermission -Identity $OUPath -AllowedPrincipals LAPS_Readers
    Set-AdmPwdResetPasswordPermission -Identity $OUPath -AllowedPrincipals LAPS_Resetters
 
````
![](/Scenarios/LAPS/Screenshots/LAPS_Install_Result.png)

Now it is needed to install GPO extension into managed machines. There are several ways - like distribute it using GPO. In this case, we will push it using PowerShell.

````PowerShell
$Servers="Server1","Server2","Server3"
$Sessions=New-PSSession -ComputerName $servers

Invoke-Command -Session $sessions -ScriptBlock {new-item -ItemType Directory -Path c:\ -Name Temp}
foreach ($session in $sessions){
    Copy-Item -Path C:\temp\LAPS.x64.msi -ToSession $session -Destination c:\temp
}

Invoke-Command -Session $sessions -ScriptBlock {
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\LAPS.x64.msi /q"
}
 
````
![](/Scenarios/LAPS/Screenshots/GPOExtensionInstallResult.png)

The last step would be to configure password policy using GPO that was created and push the settings into managed servers (or wait for GPO refresh).

**gpmc.msc**
![](/Scenarios/LAPS/Screenshots/GPO.png)


Once GPO is in place, extension is installed, you can refresh GPO on servers 
````PowerShell
$Servers="Server1","Server2","Server3"
Invoke-Command -ComputerName $servers -ScriptBlock {
    gpupdate /force
}
 
````

To check LAPS logs on configured servers (should be empty if no errors as HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}\ExtensionDebugLevel is 0 by default)
````PowerShell
$Servers="Server1","Server2","Server3"
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-WinEvent -LogName Application } | Where-Object ProviderName -eq AdmPwd | Sort-Object PSComputerName | Format-Table -AutoSize
 
````

To be able to query local passwords, you need to be in group password readers. To add LabAdmin into the correct group, run following PowerShell code.
**Note:** you need to logoff and login to get new security token.
````PowerShell
Add-ADGroupMember -Identity LAPS_Readers   -Members LabAdmin
Add-ADGroupMember -Identity LAPS_Resetters -Members LabAdmin
 
````

Run AdmPwd.E UI to query password or run following PowerShell command
````PowerShell
$servers="Server1","Server2","server3"
foreach ($server in $servers) {Get-AdmPwdPassword -ComputerName $server}
 
````
![](/Scenarios/LAPS/Screenshots/PasswordQueryPowerShell.png)

Or you can use LAPS UI Tool

![](/Scenarios/LAPS/Screenshots/LAPS_UI.png)
