# LabConfig Windows Server 1709

**Note:** to make things easier, provide RSAT msu together with cumulative update for client OS.

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab1709-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; PullServerDC=$false; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
$LabConfig.VMs += @{ VMName = 'ADMPWD-E' ; Configuration = 'Simple' ; ParentVHD = 'WinServer1709_G2.vhdx'  ; MemoryStartupBytes= 1GB }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'WinServer1709_G2.vhdx'  ; MemoryStartupBytes= 512MB} }

$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="WinServer1709_G2.vhdx";
    Size=40GB
}
 
````

# LabConfig Windows Server 2016

**Note:** If you dont have Win10, you can use CreateParentDisk.ps1 in tools folder to create Win10 VHD without creating all parent disks

````PowerShell

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$True ; CreateClientParent=$true}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
$LabConfig.VMs += @{ VMName = 'ADMPWD-E' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 1GB }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 512MB} }
 
````

# The lab

As you can notice, in this scenario is lab connected to internet. It's not mandatory, but in script is PowerShell command to download installation files. All admin tasks will be done from Windows 10 machine, just to demonstrate security best practices. You may also notice that all servers are without grapical interface.

**Deploy.ps1 result**
![](/Scenarios/ADMPWD.E/Screenshots/DeployResultWS2016.png)
![](/Scenarios/ADMPWD.E/Screenshots/DeployResultWS1709.png)

# Scenario

Start Management and ADMPWD-E VMs. Then log into Management VM. (default credentials are LabAdmin/LS1setup! as always). 
**Note:** To kick in enhanced session mode login, logoff and login again.

````PowerShell
#Run from Host
"*ADMPWD-E","*Management" | Foreach-Object {Start-VM -VMName $_}
 
````

## Setup ADMPWD.E infrastructure from Windows 10 management Machine.

First check if RSAT is installed (it's necessary to work with Active Directory)

````PowerShell
if ((Get-HotFix).hotfixid -contains "KB2693643"){
    Write-Host "RSAT is installed" -ForegroundColor Green
}else{
    Write-Host "RSAT is not installed. Please download latest Windows 10 RSAT from aka.ms/RSAT" -ForegroundColor Yellow
}
 
````

Next step is to download ADMPWD-E install files. We will download it into c:\temp. If you did not connect Lab to internet, download it manually from here http://admpwd.com/downloads/ and copy to c:\temp. Then you can unzip it with PowerShell or manually

````PowerShell
#Download files
New-Item -Path c:\ -Name temp -ItemType Directory
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/7.5.3.0/AdmPwd.E.CSE.Setup.x64.zip -OutFile "c:\temp\AdmPwd.E.CSE.Setup.x64.zip"
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/7.5.3.0/AdmPwd.E.Tools.Setup.x64.zip -OutFile "c:\temp\AdmPwd.E.Tools.Setup.x64.zip"

#Unzip downloaded files
$files=Get-ChildItem -Path c:\temp
foreach ($file in $files){
    Expand-Archive -Path $file.FullName -DestinationPath c:\temp
}
 
````

Next step would be to install PDS service to ADMPWD-E server and also installe management tools into Management machine.

````PowerShell
$ADMPWDServerName="ADMPWD-E"

#install ADMPWD service and PowerShell tools to server.
$session=New-PSSession -ComputerName $ADMPWDServerName
Invoke-Command -Session $session -ScriptBlock {new-item -ItemType Directory -Path c:\ -Name Temp}
Copy-Item -Path C:\temp\AdmPwd.E.Tools.Setup.x64.msi -ToSession $session -Destination c:\temp

Invoke-Command -Session $session -ScriptBlock {
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,PDS /q"
}

#check if ADMPWD service was installed sucessfullly
Invoke-Command -ComputerName $ADMPWDServerName -ScriptBlock {Get-Service -Name AdmPwd.E.PDS}

#install PowerShell management tools and ADMX templates to policy store
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,Management.ADMX /q"

````

Next step is to create ADMPW.E groups for Readers and Password Resetters.

````PowerShell
#OU path where Groups will be created
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"

#create groups
New-ADGroup -Name ADMPWD.E_Readers -GroupScope Global -Path $OUPath
New-ADGroup -Name ADMPWD.E_Resetters -GroupScope Global -Path $OUPath
 
````

The next step is to update schema and set delegation model. Also empty GPO that will specify ADMPWD settings will be created and linked.
**Note:** you might need to add your account to schema admins.

````PowerShell
#OU path to servers/clients to apply delegation model
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"

#admpwd server
$ADMPWDServerName="ADMPWD-E"

#create empty GPO
New-Gpo -Name ADMPWDE | New-GPLink -Target $OUPath

#extend schema
Update-AdmPwdADSchema

#note: if you are not schema admin, add your account to group Schema Admins. Logoff/login is needed to update security token.
#Add-ADGroupMember -Identity "Schema Admins" -Members LabAdmin

#Set delegation model
Set-AdmPwdComputerSelfPermission -Identity $OUPath
Set-AdmPwdPdsPermission -Identity $OUPath -AllowedPrincipals "$ADMPWDServerName$"

#Take ownership ower deleted objects
dsacls "CN=Deleted Objects,DC=Corp,DC=Contoso,DC=com" /takeownership
Set-AdmPwdPdsDeletedObjectsPermission -AllowedPrincipals "$ADMPWDServerName$"
 
#User perms
Set-AdmPwdReadPasswordPermission -Identity $OUPath -AllowedPrincipals ADMPWD.E_Readers
Set-AdmPwdResetPasswordPermission -Identity $OUPath -AllowedPrincipals ADMPWD.E_Resetters

#generate first decryption key
invoke-Command -ComputerName $ADMPWDServerName -ScriptBlock {
    New-AdmPwdKeyPair -KeySize 2048
}

 
````


