# Scenario Description

In this scenario will be ADMPWD.E deployed. Its just LAPS on steroids, extended with Password Decryption Service. So all secrets are encrypted in Active Directory and all password requests are logged.

The complete documentation and operation guide is available here: http://admpwd.com/documentation/

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
"*ADMPWD-E","*Management","*server*" | Foreach-Object {Start-VM -VMName $_}
 
````

## Setup ADMPWD.E infrastructure from Windows 10 management Machine.

**Note:** All actions are performed from Management VM (Windows 10)

First check if RSAT is installed (it's necessary to work with Active Directory)
````PowerShell
if ((Get-HotFix).hotfixid -contains "KB2693643"){
    Write-Host "RSAT is installed" -ForegroundColor Green
}else{
    Write-Host "RSAT is not installed. Please download latest Windows 10 RSAT from aka.ms/RSAT" -ForegroundColor Yellow
}
 
````

Next step is to download ADMPWD-E install files. Following script will download it into c:\temp. If you did not connect Lab to internet, download it manually from here http://admpwd.com/downloads/ and copy to c:\temp. Then you can unzip it with PowerShell or manually

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

Next step would be to install Password Decryption Server (PDS) service to ADMPWD-E server and also install management tools into Management machine.

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

#check if srv record was added
nslookup -type=srv _admpwd._tcp

#check if CNG is set in config (in older releases it's CryptoAPI)
Invoke-Command -ComputerName $ADMPWDServerName -scriptblock {
    [xml]$xml=Get-Content -Path 'C:\Program Files\AdmPwd\PDS\AdmPwd.Service.exe.config'
    if ($xml.configuration.KeyStore.cryptoForNewKeys -ne "CNG"){
        $xml.configuration.KeyStore.cryptoForNewKeys="CNG"
        $xml.save('C:\Program Files\AdmPwd\PDS\AdmPwd.Service.exe.config')
        Restart-Service -Name AdmPwd.E.PDS
    }
}

#install PowerShell management tools, Management UI and copy ADMX template to policy store
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,Management.ADMX,Management.UI /q"
 
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
**Note:** you might need to add your account to schema and enterprise admins. ws2016lab was recently updated to add LabAdmin to these groups during 2_createparentdisks.ps1

````PowerShell
#OU path to servers/clients to apply delegation model
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
#admpwd server
$ADMPWDServerName="ADMPWD-E"

#create empty GPO
New-Gpo -Name ADMPWDE | New-GPLink -Target $OUPath

#extend AD schema (Schema Admins membership needed)
Update-AdmPwdADSchema

#note: if you are not schema admin, add your account to group Schema Admins. Logoff/login is needed to update security token.
#Add-ADGroupMember -Identity "Schema Admins" -Members LabAdmin
#Add-ADGroupMember -Identity "Enterprise Admins" -Members LabAdmin

#Set delegation model

#Add machine rights
Set-AdmPwdComputerSelfPermission -Identity $OUPath
Set-AdmPwdPdsPermission -Identity $OUPath -AllowedPrincipals "$ADMPWDServerName$"

#Take ownership over deleted objects
dsacls "CN=Deleted Objects,DC=Corp,DC=Contoso,DC=com" /takeownership
Set-AdmPwdPdsDeletedObjectsPermission -AllowedPrincipals "$ADMPWDServerName$"

#User perms
Set-AdmPwdReadPasswordPermission -Identity $OUPath -AllowedPrincipals ADMPWD.E_Readers
Set-AdmPwdResetPasswordPermission -Identity $OUPath -AllowedPrincipals ADMPWD.E_Resetters

#generate first decryption key (Enterprise Admin membership needed)
New-AdmPwdKeyPair -KeySize 2048
 
````

Now it is needed to install GPO extension into managed machines. There are several ways - like distribute it using GPO. In this case, we will push it using PowerShell.

````PowerShell
$Servers="Server1","Server2","Server3"
$Sessions=New-PSSession -ComputerName $servers

Invoke-Command -Session $sessions -ScriptBlock {new-item -ItemType Directory -Path c:\ -Name Temp}
foreach ($session in $sessions){
    Copy-Item -Path C:\temp\AdmPwd.E.CSE.Setup.x64.msi -ToSession $session -Destination c:\temp
}

Invoke-Command -Session $sessions -ScriptBlock {
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.CSE.Setup.x64.msi /q"
}
 
````

The last step would be to configure password policy using GPO that was created and push the settings into managed servers (or wait for GPO refresh).

**gpmc.msc**
![](/Scenarios/ADMPWD.E/Screenshots/GPO.png)

**Note**
You need to fill in Encryption Key to encrypt passwords in AD
![](/Scenarios/ADMPWD.E/Screenshots/EncryptionKeyInGPO.png)

````PowerShell
#to grab encryption key ID 1 using PowerShell
(Get-AdmPwdPublicKey -KeyId 1).Key | clip
 
````

Once GPO is in place, extension is installed, you can refresh GPO on servers 

````PowerShell
$Servers="Server1","Server2","Server3"
Invoke-Command -ComputerName $servers -ScriptBlock {
    gpupdate /force
}
 
````

To check ADMPWD logs on configured servers

````PowerShell
$Servers="Server1","Server2","Server3"
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-WinEvent -LogName Application } | where ProviderName -eq AdmPwd | Sort-Object PSComputerName | Format-Table -AutoSize
 
````

To be able to query local passwords, you need to be in group password readers. To add LabAdmin into the correct group, run following PowerShell code.
**Note:** you need to logoff and login to get new security token.

````PowerShell
Add-ADGroupMember -Identity ADMPWD.E_Readers -Members LabAdmin
Add-ADGroupMember -Identity ADMPWD.E_Resetters -Members LabAdmin
 
````

Run ADMPWD.E UI to query password or run following PowerShell command

````PowerShell
$servers="Server1","Server2","server3"
foreach ($server in $servers) {Get-AdmPwdPassword -ComputerName $server}
 
````