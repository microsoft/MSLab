<!-- TOC -->

- [Bitlocker management with JEA](#bitlocker-management-with-jea)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Lets play with Bitlocker a bit](#lets-play-with-bitlocker-a-bit)
    - [JEA](#jea)
    - [BitLocker event log](#bitlocker-event-log)
    - [PowerShell Logging](#powershell-logging)
    - [PowerShell JEA Logging](#powershell-jea-logging)

<!-- /TOC -->

# Bitlocker management with JEA

## About the lab

In this lab you will learn about benefits of JEA for day-to-day administration and not only for Securing the environment, but also for [double-hop mitigation](https://blogs.technet.microsoft.com/ashleymcglone/2016/08/30/powershell-remoting-kerberos-double-hop-solved-securely/).


## LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = 'Bitlocker1' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'Bitlocker2' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
````
## Lets play with Bitlocker a bit

All tasks will be done from Management (Windows 10) machine. Note the labconfig - WinRM is enabled on all machines, therefore PowerShell remoting will work from very beginning.

First make sure that RSAT is installed (if not, download it from aka.ms/RSAT and install).

````PowerShell
if ((Get-HotFix).hotfixid -contains "KB2693643"){
    Write-Host "RSAT is installed" -ForegroundColor Green
}else{
    Write-Host "RSAT is not installed. Please download and install latest Windows 10 RSAT from aka.ms/RSAT" -ForegroundColor Yellow
}
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/RSATCheckResult.png)

Run following command to enable Bitlocker on management machine

````PowerShell
    Enable-BitLocker -MountPoint c: -SkipHardwareTest -UsedSpaceOnly -RecoveryPasswordProtector
 
````

That was smooth

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/EnableBitlockerManagement.png)

Lets try the same on remote computers. Since Enable-Bitlocker does not have -ComputerName or -Cimsession parameter, we will have to use Invoke-Command

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -ScriptBlock {
    Enable-BitLocker -MountPoint c: -SkipHardwareTest -UsedSpaceOnly -RecoveryPasswordProtector
}
 
````

That's not nice!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/EnableBitlockerRemote.png)

It's because TPM gets initialized after user logon, see? (note TpmReady column)

````PowerShell
Invoke-Command -ComputerName "Management","Bitlocker1","Bitlocker2" -ScriptBlock {Get-TPM} | ft
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/Get-TPM.png)

Let's initialize it first and then enable Bitlocker

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -ScriptBlock {
    Initialize-Tpm
    Enable-BitLocker -MountPoint c: -SkipHardwareTest -UsedSpaceOnly -RecoveryPasswordProtector
}
 
````

That's better

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/EnableBitlockerRemoteSuccess.png)


OK, now we need to backup recovery information to AD. Let's do it first on Management machine.

````PowerShell
$KeyProtectorID=((Get-BitLockerVolume -MountPoint c:).KeyProtector | where KeyProtectorType -eq RecoveryPassword).KeyProtectorID
Backup-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $KeyProtectorID
 
````

huh, nothing in AD!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/RecoveryKeyNotInAD.png)

and here is some PowerShell to read that info

````PowerShell
$ComputerObject = Get-ADComputer -Filter {cn -eq "Management"} -Property msTPM-OwnerInformation, msTPM-TpmInformationForComputer
Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $ComputerObject.DistinguishedName -Properties 'msFVE-RecoveryPassword'
 
````

Let's try again, but now with some registries added

````PowerShell
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery -Value 1 -PropertyType DWORD -Force
$KeyProtectorID=((Get-BitLockerVolume -MountPoint c:).KeyProtector | where KeyProtectorType -eq RecoveryPassword).KeyProtectorID
Backup-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $KeyProtectorID
$ComputerObject = Get-ADComputer -Filter {cn -eq "Management"} -Property msTPM-OwnerInformation, msTPM-TpmInformationForComputer
Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $ComputerObject.DistinguishedName -Properties 'msFVE-RecoveryPassword'
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitlockerKeyInADPosh.png)

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitlockerKeyInADGUI.png)


And let's try it on Bitlocker1 and 2

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -ScriptBlock {
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery -Value 1 -PropertyType DWORD -Force
    $KeyProtectorID=((Get-BitLockerVolume -MountPoint c:).KeyProtector | where KeyProtectorType -eq RecoveryPassword).KeyProtectorID
    Backup-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $KeyProtectorID
}
 
````

Not good! We just hit [double-hop](https://blogs.technet.microsoft.com/ashleymcglone/2016/08/30/powershell-remoting-kerberos-double-hop-solved-securely/) issue!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BackupKeyRemoteError.png)


## JEA

So let's try some JEA. Following example is based on [this blog](https://blogs.technet.microsoft.com/datacentersecurity/2017/03/07/step-by-step-creating-a-jea-endpoint-for-dns-management/
)

First let's create some users and groups.
````PowerShell
#Create group for JEA-Bitlocker Admins and Viewers
New-ADGroup -Name JEA-BitlockerAdmins  -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global
New-ADGroup -Name JEA-BitlockerViewers -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global

#Create users with password LS1setup!
New-ADUser -Name JohnDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
New-ADUser -Name JaneDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"

#add users to groups
Add-ADGroupMember -Identity "JEA-BitlockerAdmins"  -Members JohnDoe
Add-ADGroupMember -Identity "JEA-BitlockerViewers" -Members JaneDoe
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/ADGroupsAndUsersResult.png)

And let's configure JEA on computers Bitlocker1 and Bitlocker2

````PowerShell
$computers="Bitlocker1","Bitlocker2"

Invoke-Command -ComputerName $computers -ScriptBlock {
    $Modules="Bitlocker"
    $AdminVisibleCommands ="Bitlocker\*","Get-CimInstance","New-ItemProperty","New-Item","Out-String","Where-Object","Select-Object"    #All commands from bitlocker module + all others since Enable-Bitlocker and Backup-BitLockerKeyProtector needs it.
    $AdminVisibleExternalCommands = "C:\Windows\System32\where.exe","C:\Windows\System32\whoami.exe"
    $AdminVisibleProviders= "registry","Variable"
    $ViewerVisibleCommands="Bitlocker\Get-*","Get-CimInstance" #All commands from Bitlocker module that start with Get-
    $AdminRoleName= "BitlockerAdmin"
    $ViewerRoleName="BitlockerViewer"
    $ConfigurationName="JEA-Bitlocker"
    $AdminGroup= "JEA-BitlockerAdmins"
    $ViewerGroup="JEA-BitlockerViewers"

    #Create folders for JEA
    $Folders="$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\","$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities","$env:ProgramData\JEAConfiguration"
    foreach ($Folder in $Folders){
        New-Item -Path $Folder -ItemType Directory -force
    }
    #Create JEA Manifest
    New-ModuleManifest -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\JEARoles.psd1" -Description "Contains custom JEA Role Capabilities"

    #Create RoleCapabilityFile and SessionConfigurationFile
    New-PSRoleCapabilityFile -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities\$AdminRoleName.psrc" -ModulesToImport $Modules -VisibleCmdlets $AdminVisibleCommands -VisibleExternalCommands $AdminVisibleExternalCommands -VisibleProviders $AdminVisibleProviders
    New-PSRoleCapabilityFile -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities\$ViewerRoleName.psrc" -ModulesToImport $Modules -VisibleCmdlets $ViewerVisibleCommands
    New-PSSessionConfigurationFile -Path $env:ProgramData\JEAConfiguration\$ConfigurationName.pssc -SessionType RestrictedRemoteServer -LanguageMode FullLanguage -RunAsVirtualAccount -RoleDefinitions @{"$env:USERDOMAIN\$AdminGroup" = @{ RoleCapabilities = "$AdminRoleName" };"$env:USERDOMAIN\$ViewerGroup" = @{ RoleCapabilities = "$ViewerRoleName" }}

    #RegisterPSsessionConfiguration
    Register-PSSessionConfiguration -Path $env:ProgramData\JEAConfiguration\$ConfigurationName.pssc -Name $ConfigurationName -Force
}
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/JEAResult.png)

Note: error in the end is expected
Now lets try if JEA was applied successfully. Note: type password "LS1setup!" for user JohnDoe

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -Credential JohnDoe -ConfigurationName JEA-Bitlocker -ScriptBlock {Get-Command}
 
````

That's great! JohnDoe can do just Bitlocker administration!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/Get-CommandResult.png)

Let's backup bitlocker now with JEA!

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -Credential JohnDoe -ConfigurationName JEA-Bitlocker -ScriptBlock {
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery -Value 1 -PropertyType DWORD -Force
    $KeyProtectorID=((Get-BitLockerVolume -MountPoint c:).KeyProtector | where-object KeyProtectorType -eq RecoveryPassword).KeyProtectorID
    Backup-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $KeyProtectorID
}
 
````

And let's check the keys

````PowerShell
$ComputerObjects = Get-ADComputer -Filter {cn -like "Bitlocker*"} -Property msTPM-OwnerInformation, msTPM-TpmInformationForComputer
foreach ($ComputerObject in $ComputerObjects){
    Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $ComputerObject.DistinguishedName -Properties 'msFVE-RecoveryPassword'
}
 
````

Success!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitlockerKeysInADPosh.png)

So how was this possible?

It's easy, because you are using virtual account. It also means your identity is remote computer itself

````PowerShell
Enter-PSSession -ComputerName Bitlocker1 -Credential JohnDoe -ConfigurationName JEA-Bitlocker
whoami
exit
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/whoami.png)

So let's encrypt also D drives with autounlock and also backup to AD with JEA

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -Credential JohnDoe -ConfigurationName JEA-Bitlocker -ScriptBlock {
    Enable-BitLocker -MountPoint d: -UsedSpaceOnly -RecoveryPasswordProtector
    Enable-BitLockerAutoUnlock -MountPoint d:
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery -Value 1 -PropertyType DWORD -Force
    $KeyProtectorID=((Get-BitLockerVolume -MountPoint d:).KeyProtector | where-object KeyProtectorType -eq RecoveryPassword).KeyProtectorID
    Backup-BitLockerKeyProtector -MountPoint d: -KeyProtectorId $KeyProtectorID
}
 
````

Note: there is some error complaining about "A parameter cannot be found that matches parameter name 'First'." (I need to investigate what it requires to run, but all seems to be OK)

And now let's ask Jane to check if all is ok on PC's Bitlocker1 and Bitlocker2

````PowerShell
Invoke-Command -ComputerName "Bitlocker1","Bitlocker2" -Credential JaneDoe -ConfigurationName JEA-Bitlocker -ScriptBlock {
    Get-BitlockerVolume
}
 
````

Seems OK!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/JaneGet-BitlockerVolume.png)

## BitLocker event log

Now let's see if bitlocker was backed up into AD

````PowerShell
#Grab events from remote computers
$Computers="Bitlocker1","Bitlocker2"
$allevents=Invoke-Command -ComputerName $Computers -ScriptBlock {
    $events=Get-WinEvent -FilterHashtable @{"ProviderName"="Microsoft-Windows-Bitlocker-API";Id=784}
    ForEach ($Event in $Events) {
        # Convert the event to XML
        $eventXML = [xml]$Event.ToXml()
        # create custom object for all values
        for ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {
            # Append these as object properties
            Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'
        }
    }
    return $events
}
$allevents | select * | ogv
 
````

Events displayed in Out-GridView

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitlockerEvents.png)

## PowerShell Logging

<TBD>

https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/

````PowerShell
#Enable ScriptBlock logging
$Computers="Bitlocker1","Bitlocker2"
Invoke-Command -Computername $Computers -ScriptBlock {
    New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
    New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging           -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockInvocationLogging -Value 1 -PropertyType DWORD -Force
}
 
````

## PowerShell JEA Logging

<TBD>