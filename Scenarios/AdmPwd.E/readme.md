<!-- TOC -->

- [Scenario Introduction](#scenario-introduction)
    - [LabConfig Windows Server 1709](#labconfig-windows-server-1709)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [The lab](#the-lab)
- [Scenario](#scenario)
    - [AdmPwd.E infrastructure setup from Windows 10 management Machine.](#admpwde-infrastructure-setup-from-windows-10-management-machine)
    - [Managed Domain Accounts](#managed-domain-accounts)

<!-- /TOC -->

# Scenario Introduction

In this scenario will be AdmPwd.E deployed. Its just [LAPS](/Scenarios/LAPS/) on steroids, with many additional features, and architecture extended with Password Decryption Service (PDS). So all passwords can be stored encrypted in Active Directory and all password requests are logged. Additionally you can manage password for domain accounts and using RunAsAdmin tool run process with the credential without typing password. 

The complete documentation and operation guide is available here: http://AdmPwd.com/documentation/
This scenario works with AdmPwd.E version 7.5.4.0 and newer

## LabConfig Windows Server 1709

**Note:** to make things easier, provide RSAT msu together with cumulative update for client OS.

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab1709-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; PullServerDC=$false; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
$LabConfig.VMs += @{ VMName = 'AdmPwd-E' ; Configuration = 'Simple' ; ParentVHD = 'WinServer1709_G2.vhdx'  ; MemoryStartupBytes= 1GB }
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
$LabConfig.VMs += @{ VMName = 'AdmPwd-E' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 1GB }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 512MB} }
 
````

## The lab

As you can notice, in this scenario is lab connected to internet. It's not mandatory, but in script is PowerShell command to download installation files. All admin tasks will be done from Windows 10 machine, just to demonstrate security best practices. You may also notice that all servers are without graphical interface.

**Deploy.ps1 result**
![](/Scenarios/AdmPwd.E/Screenshots/DeployResultWS2016.png)
![](/Scenarios/AdmPwd.E/Screenshots/DeployResultWS1709.png)

# Scenario

Start Lab VMs. Then log into Management VM. (default credentials are LabAdmin/LS1setup! as always). 
**Note:** To kick in enhanced session mode login, logoff and login again.

````PowerShell
#Run from Host
"*AdmPwd-E","*Management","*server*" | Foreach-Object {Start-VM -VMName $_}
 
````

## AdmPwd.E infrastructure setup from Windows 10 management Machine.

**Note:** All actions are performed from Management VM (Windows 10)

First check if RSAT is installed (it's necessary to work with Active Directory). If you did not provide RSAT msu during lab hydration, download it from http://aka.ms/RSAT and install manually.
````PowerShell
if ((Get-HotFix).hotfixid -contains "KB2693643"){
    Write-Host "RSAT is installed" -ForegroundColor Green
}else{
    Write-Host "RSAT is not installed. Please download and install latest Windows 10 RSAT from aka.ms/RSAT" -ForegroundColor Yellow
}
 
````
![](/Scenarios/AdmPwd.E/Screenshots/RSATCheckResult.png)

Next step is to download AdmPwd-E install files. Following script will download it into c:\temp. If you did not connect Lab to internet, download it manually from here http://AdmPwd.com/downloads/ and copy to c:\temp. Then you can unzip it with PowerShell or manually
````PowerShell
#Download files
New-Item -Path c:\ -Name temp -ItemType Directory
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/Latest/AdmPwd.E.CSE.Setup.x64.zip -OutFile "c:\temp\AdmPwd.E.CSE.Setup.x64.zip"
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/Latest/AdmPwd.E.Tools.Setup.x64.zip -OutFile "c:\temp\AdmPwd.E.Tools.Setup.x64.zip"

#Unzip downloaded files
$files=Get-ChildItem -Path c:\temp
foreach ($file in $files){
    Expand-Archive -Path $file.FullName -DestinationPath c:\temp
}
 
````

Next step would be to install Password Decryption Server (PDS) service to AdmPwd-E server and also install management tools into Management machine.

````PowerShell
$AdmPwdServerName="AdmPwd-E"

#install PDS and PowerShell management tools to server.
$session=New-PSSession -ComputerName $AdmPwdServerName
Invoke-Command -Session $session -ScriptBlock {new-item -ItemType Directory -Path c:\ -Name Temp}
Copy-Item -Path C:\temp\AdmPwd.E.Tools.Setup.x64.msi -ToSession $session -Destination c:\temp

Invoke-Command -Session $session -ScriptBlock {
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,PDS /q"
}

#check if PDS service was installed sucessfullly
Invoke-Command -ComputerName $AdmPwdServerName -ScriptBlock {Get-Service -Name AdmPwd.E.PDS}

#check if DNS SRV record was added - this indicates that PDS service started successfully and work as expected
nslookup -type=srv _AdmPwd._tcp

#check if CNG is set in config (in older releases it was CryptoAPI) for newly created key pairs
Invoke-Command -ComputerName $AdmPwdServerName -scriptblock {
    [xml]$xml=Get-Content -Path 'C:\Program Files\AdmPwd\PDS\AdmPwd.PDS.exe.config'
    if ($xml.configuration.KeyStore.cryptoForNewKeys -ne "CNG"){
        $xml.configuration.KeyStore.cryptoForNewKeys="CNG"
        $xml.save('C:\Program Files\AdmPwd\PDS\AdmPwd.PDS.exe.config')
        Restart-Service -Name AdmPwd.E.PDS
    }
}

#install PowerShell management tools, Management UI and copy ADMX template to policy store on management machine
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,Management.ADMX,Management.UI /q"
 
````
![](/Scenarios/AdmPwd.E/Screenshots/PDSInstallResult.png)

Next step is to create AdmPwd.E groups for Password Readers and Resetters.

````PowerShell
#OU path where Groups will be created
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"

#create groups
New-ADGroup -Name AdmPwd.E_Readers -GroupScope Global -Path $OUPath
New-ADGroup -Name AdmPwd.E_Resetters -GroupScope Global -Path $OUPath
 
````

The next step is to update schema and set delegation model. Also empty GPO that you will use to define AdmPwd.E settings will be created and linked.
**Note:** you might need to add your account to schema and enterprise admins. ws2016lab was recently updated to add LabAdmin to these groups during 2_createparentdisks.ps1

````PowerShell
#OU path to servers/clients to apply delegation model
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
#AdmPwd server
$AdmPwdServerName="AdmPwd-E"

#create empty GPO
New-Gpo -Name 'AdmPwd.E' | New-GPLink -Target $OUPath

#extend AD schema (Schema Admins and Enterprise Admins membership needed)
Update-AdmPwdADSchema

#note: if you are not member of required groups, add your account as member. Logoff/login is needed to update security token.
#Add-ADGroupMember -Identity "Schema Admins" -Members LabAdmin
#Add-ADGroupMember -Identity "Enterprise Admins" -Members LabAdmin

#Set delegation model

#Add machine rights to report passwords to AD
Set-AdmPwdComputerSelfPermission -Identity $OUPath

#Add permissions to PDS to interact with AD
Set-AdmPwdPdsPermission -Identity $OUPath -AllowedPrincipals "$AdmPwdServerName$"
#Take ownership over deleted objects - you need to do it before  granting PDS permission to look into Deleted Objects container
dsacls "CN=Deleted Objects,DC=Corp,DC=Contoso,DC=com" /takeownership
Set-AdmPwdPdsDeletedObjectsPermission -AllowedPrincipals "$AdmPwdServerName$"

#User perms to read and reset passwords
Set-AdmPwdReadPasswordPermission -Identity $OUPath -AllowedPrincipals AdmPwd.E_Readers
Set-AdmPwdResetPasswordPermission -Identity $OUPath -AllowedPrincipals AdmPwd.E_Resetters

#generate first decryption key (Enterprise Admin membership needed by default; role can be changed in PDS config)
New-AdmPwdKeyPair -KeySize 2048
 
````
![](/Scenarios/AdmPwd.E/Screenshots/DelegationResult1.png)
![](/Scenarios/AdmPwd.E/Screenshots/DelegationResult2.png)

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
![](/Scenarios/AdmPwd.E/Screenshots/GPOExtensionInstallResult.png)

The last step would be to configure password policy using GPO that was created and push the settings into managed servers (or wait for GPO refresh).

**gpmc.msc**
![](/Scenarios/AdmPwd.E/Screenshots/GPO.png)

**Note**
You need to fill in Encryption Key to encrypt passwords in AD
![](/Scenarios/AdmPwd.E/Screenshots/EncryptionKeyInGPO.png)

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

To check AdmPwd logs on configured servers
````PowerShell
$Servers="Server1","Server2","Server3"
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-WinEvent -LogName Application } | Where-Object ProviderName -eq AdmPwd | Sort-Object PSComputerName | Format-Table -AutoSize
 
````
![](/Scenarios/AdmPwd.E/Screenshots/ServerLogs.png)

To be able to query local passwords, you need to be in group password readers. To add LabAdmin into the correct group, run following PowerShell code.
**Note:** you need to logoff and login to get new security token.
````PowerShell
Add-ADGroupMember -Identity AdmPwd.E_Readers -Members LabAdmin
Add-ADGroupMember -Identity AdmPwd.E_Resetters -Members LabAdmin
 
````

Run AdmPwd.E UI to query password or run following PowerShell command
````PowerShell
$servers="Server1","Server2","server3"
foreach ($server in $servers) {Get-AdmPwdPassword -ComputerName $server}
 
````
![](/Scenarios/AdmPwd.E/Screenshots/ServerPasswords.png)

Lastly you can view who (and when) was viewing passwords.
````PowerShell
$AdmPwdServer = "AdmPwd-E"
$PasswordLog=Invoke-Command -ComputerName $AdmPwdServer -ScriptBlock {
    $events=Get-WinEvent -FilterHashtable @{"ProviderName"="GreyCorbel-AdmPwd.E-PDS";Id=1001}
    $PasswordLog=@()
    ForEach ($Event in $Events) {
        # Convert the event to XML
        $eventXML = [xml]$Event.ToXml()
        # create custom object for all values
        $PasswordLog += [PSCustomObject]@{
            "Forest" = $eventxml.Event.EventData.data[0].'#text'
            "Computer" = $eventxml.Event.EventData.data[1].'#text'
            "IsDeleted" = $eventxml.Event.EventData.data[2].'#text'
            "User" = $eventxml.Event.EventData.data[3].'#text'
            "TimeRequested" = $event.TimeCreated
        }
    }
    return $PasswordLog
}

$PasswordLog | ft User,Computer,TimeRequested
 
````
![](/Scenarios/AdmPwd.E/Screenshots/PasswordLog.png)


## Managed Domain Accounts

Managed Domain Accounts is feature of AdmPwd.E that automatically manages password of chosen domain user accounts, ensures for password randomness and regular change, and allows their simple retrieval by eligible users. Also, toolset that comes with AdmPwd.E makes use of automatic password retrieval, allowing users to use those accounts to run processes or connect to RDP without the need to even know and type the password.
In following example will be one managed account created and then demonstrated, how to use it different ways.

First create OU, Managed Domain Accounts, modify PDS config file to have accounts in that OU managed by PDS and restart service to apply changes.
````PowerShell
$AdmPwdServer = "AdmPwd-E"
#Create OU for Managed accounts
New-ADOrganizationalUnit -Name "Managed Domain Accounts"

#grant PDS proper perms to manage password on managed accounts
Set-AdmPwdPdsManagedAccountsPermission -Identity "Managed Domain Accounts" -AllowedPrincipals "$AdmPwdServer$"
#Grant users Read+Reset Password Permission
Set-AdmPwdReadPasswordPermission -Identity "Managed Domain Accounts" -AllowedPrincipals "AdmPwd.E_Readers"
Set-AdmPwdResetPasswordPermission -Identity "Managed Domain Accounts" -AllowedPrincipals "AdmPwd.E_Resetters"

#Create an account and add to domain admins
$AccountName="MyManagedAccount"
New-ADUser -Name $AccountName -UserPrincipalName $AccountName -Path "OU=Managed Domain Accounts,DC=corp,DC=Contoso,DC=com" -Enabled $true -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)
Add-ADGroupMember -Identity "Domain admins" -Members MyManagedAccount
#Note: be aware of AdminSDHolder feature that rewrites ACL on privileged accounts!

#Configure managed account OU on PDS server - allow password management on user accounts in this OU
Invoke-Command -ComputerName $AdmPwdServer -Scriptblock {
    [xml]$xml=Get-Content -Path 'C:\Program Files\AdmPwd\PDS\AdmPwd.PDS.exe.config'
    $xml.configuration.ManagedAccounts.containers.add.distinguishedName="OU=Managed Domain Accounts,DC=corp,DC=Contoso,DC=com"
    $xml.configuration.ManagedAccounts.containers.add.passwordAge="14400" #10 days
    $xml.save('C:\Program Files\AdmPwd\PDS\AdmPwd.PDS.exe.config')
    Restart-Service -Name AdmPwd.E.PDS
}
 
````

Then check logs on AdmPwd server if it changed password on managed account.
````PowerShell
$AdmPwdServer = "AdmPwd-E"
$Log=Invoke-Command -ComputerName $AdmPwdServer -ScriptBlock {
    $events=Get-WinEvent -FilterHashtable @{"ProviderName"="GreyCorbel-AdmPwd.E-PDS";Id=3000}
    $Log=@()
    ForEach ($Event in $Events) {
        # Convert the event to XML
        $eventXML = [xml]$Event.ToXml()
        # create custom object for all values
        $Log += [PSCustomObject]@{
            "Accounts" = $eventxml.Event.EventData.data.'#text'
            "Time" = $event.TimeCreated
        }
    }
    return $Log
}

#Changed Accounts where password was changed
$Log | Format-Table Accounts,Time
````
![](/Scenarios/AdmPwd.E/Screenshots/ManagedAccountsLog.png)

To retrieve password, there are multiple options. Either PowerShell **Note:** since this is freeware version, you can only have one account in OU. If multiple accounts are present, you will get an error message when getting managed password as this is free version.

````PowerShell
Get-AdmPwdManagedAccountPassword -AccountName MyManagedAccount
````
![](/Scenarios/AdmPwd.E/Screenshots/ManagedAccountPassword.png)

Or you can run PowerShell instance with using that account directly using RunAsAdmin tool from here https://github.com/jformacek/AdmPwd-e/releases/tag/v8.0 (latest binaries also available at https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/Latest/RunAsAdmin.zip)

````PowerShell
#Download RunAsAdmin
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/Latest/RunAsAdmin.zip -OutFile "c:\temp\RunAsAdmin.zip"

#Unzip downloaded files
Expand-Archive -Path c:\temp\RunAsAdmin.zip -DestinationPath c:\temp

& "c:\temp\RunAsAdmin.exe" /user:corp\MyManagedAccount /noLocalProfile /path:Powershell.exe
````
![](/Scenarios/AdmPwd.E/Screenshots/ManagedAccountRunAsAdmin.png)

Or you can use RDP client
````PowerShell
#Download RDPCLient
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/Latest/RDPClient.zip -OutFile "c:\temp\RDPClient.zip"

#Unzip downloaded files
Expand-Archive -Path c:\temp\RDPClient.zip -DestinationPath c:\temp\RDPClient

#enable RDP on Server1
Enable-NetFirewallRule -CimSession Server1 -Name RemoteDesktop*
Invoke-Command –Computername Server1 –ScriptBlock {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0}

#connect to Server1
& "c:\temp\RDPClient\RDPClient.exe" /Server:Server1 /user:corp\MyManagedAccount
````
![](/Scenarios/AdmPwd.E/Screenshots/ManagedAccountRDP.png)
