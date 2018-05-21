<!-- TOC -->

- [BitLocker management with JEA](#bitlocker-management-with-jea)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Let's play with BitLocker a bit](#lets-play-with-bitlocker-a-bit)
    - [JEA](#jea)
    - [BitLocker event log](#bitlocker-event-log)
    - [PowerShell Logging](#powershell-logging)
    - [JEA transcription](#jea-transcription)

<!-- /TOC -->

# BitLocker management with JEA

## About the lab

In this lab you will learn about benefits of JEA for day-to-day administration - not only for Securing the environment, but also for [double-hop mitigation](https://blogs.technet.microsoft.com/ashleymcglone/2016/08/30/powershell-remoting-kerberos-double-hop-solved-securely/). To create Win10 image, use CreateParentDisk script located in tools folder.

## LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = 'BitLocker1' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'BitLocker2' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
 
````

## Let's play with BitLocker a bit

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

Run following command to enable BitLocker on management machine

````PowerShell
    Enable-BitLocker -MountPoint c: -SkipHardwareTest -UsedSpaceOnly -RecoveryPasswordProtector
 
````

That was smooth

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/EnableBitLockerManagement.png)

Let's try the same on remote computers. Since Enable-BitLocker does not have -ComputerName or -Cimsession parameter, we will have to use Invoke-Command

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -ScriptBlock {
    Enable-BitLocker -MountPoint c: -SkipHardwareTest -UsedSpaceOnly -RecoveryPasswordProtector
}
 
````

That's not nice!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/EnableBitLockerRemote.png)

It's because TPM gets initialized after user logon, see? (note TpmReady column)

````PowerShell
Invoke-Command -ComputerName "Management","BitLocker1","BitLocker2" -ScriptBlock {Get-TPM} | ft
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/Get-TPM.png)

Let's initialize it first and then enable BitLocker

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -ScriptBlock {
    Initialize-Tpm
    Enable-BitLocker -MountPoint c: -SkipHardwareTest -UsedSpaceOnly -RecoveryPasswordProtector
}
 
````

That's better

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/EnableBitLockerRemoteSuccess.png)

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

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitLockerKeyInADPosh.png)

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitLockerKeyInADGUI.png)


And let's try it on BitLocker1 and 2

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -ScriptBlock {
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
#Create group for JEA-BitLocker Admins and Viewers
New-ADGroup -Name JEA-BitLockerAdmins  -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global
New-ADGroup -Name JEA-BitLockerViewers -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global

#Create users with password LS1setup!
New-ADUser -Name JohnDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
New-ADUser -Name JaneDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"

#add users to groups
Add-ADGroupMember -Identity "JEA-BitLockerAdmins"  -Members JohnDoe
Add-ADGroupMember -Identity "JEA-BitLockerViewers" -Members JaneDoe
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/ADGroupsAndUsersResult.png)

And let's configure JEA on computers BitLocker1 and BitLocker2. Note how many commands are needed. It's because commandlets in BitLocker module are using it (I did not test all, therefore the list might be bigger). The only extra command is wmoami just to demonstrate whoami output.

````PowerShell
$computers="BitLocker1","BitLocker2"

Invoke-Command -ComputerName $computers -ScriptBlock {
    $Modules="BitLocker"
    $AdminVisibleCmdLets ="BitLocker\*","Get-CimInstance","New-ItemProperty","New-Item","Out-String","Where-Object","Select-Object"    #All commands from BitLocker module + all others since Enable-BitLocker and Backup-BitLockerKeyProtector needs it.
    $AdminVisibleExternalCommands = "C:\Windows\System32\where.exe","C:\Windows\System32\whoami.exe"
    $AdminVisibleProviders= "registry","Variable"
    $ViewerVisibleCmdLets="BitLocker\Get-*","Get-CimInstance" #All commands from BitLocker module that start with Get-
    $AdminRoleName= "BitLockerAdmin"
    $ViewerRoleName="BitLockerViewer"
    $ConfigurationName="JEA-BitLocker"
    $AdminGroup= "JEA-BitLockerAdmins"
    $ViewerGroup="JEA-BitLockerViewers"

    #Create folders for JEA
    $Folders="$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\","$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities","$env:ProgramData\JEAConfiguration"
    foreach ($Folder in $Folders){
        New-Item -Path $Folder -ItemType Directory -force
    }
    #Create JEA Manifest
    New-ModuleManifest -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\JEARoles.psd1" -Description "Contains custom JEA Role Capabilities"

    #Create RoleCapabilityFile and SessionConfigurationFile
    New-PSRoleCapabilityFile -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities\$AdminRoleName.psrc" -ModulesToImport $Modules -VisibleCmdlets $AdminVisibleCmdLets -VisibleExternalCommands $AdminVisibleExternalCommands -VisibleProviders $AdminVisibleProviders
    New-PSRoleCapabilityFile -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities\$ViewerRoleName.psrc" -ModulesToImport $Modules -VisibleCmdlets $ViewerVisibleCmdLets
    New-PSSessionConfigurationFile -Path $env:ProgramData\JEAConfiguration\$ConfigurationName.pssc -SessionType RestrictedRemoteServer -LanguageMode FullLanguage -RunAsVirtualAccount -RoleDefinitions @{"$env:USERDOMAIN\$AdminGroup" = @{ RoleCapabilities = "$AdminRoleName" };"$env:USERDOMAIN\$ViewerGroup" = @{ RoleCapabilities = "$ViewerRoleName" }}

    #RegisterPSsessionConfiguration
    Register-PSSessionConfiguration -Path $env:ProgramData\JEAConfiguration\$ConfigurationName.pssc -Name $ConfigurationName -Force
}
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/JEAResult.png)

Note: error in the end is expected
Now Let's try if JEA was applied successfully. Note: type password "LS1setup!" for user JohnDoe

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -Credential JohnDoe -ConfigurationName JEA-BitLocker -ScriptBlock {Get-Command}
 
````

That's great! JohnDoe can do just BitLocker administration!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/Get-CommandResult.png)

Let's backup BitLocker key, but now with JEA!

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -Credential JohnDoe -ConfigurationName JEA-BitLocker -ScriptBlock {
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery -Value 1 -PropertyType DWORD -Force
    $KeyProtectorID=((Get-BitLockerVolume -MountPoint c:).KeyProtector | where-object KeyProtectorType -eq RecoveryPassword).KeyProtectorID
    Backup-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $KeyProtectorID
}
 
````

And let's check the keys in AD

````PowerShell
$ComputerObjects = Get-ADComputer -Filter {cn -like "BitLocker*"} -Property msTPM-OwnerInformation, msTPM-TpmInformationForComputer
foreach ($ComputerObject in $ComputerObjects){
    Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $ComputerObject.DistinguishedName -Properties 'msFVE-RecoveryPassword'
}
 
````

Success!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitLockerKeysInADPosh.png)

So how was this possible?

It's easy, because you are using virtual account. It also means your identity is remote computer itself

````PowerShell
Enter-PSSession -ComputerName BitLocker1 -Credential JohnDoe -ConfigurationName JEA-BitLocker
whoami
exit
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/whoami.png)

So let's encrypt also D drives with autounlock and also backup to AD with JEA

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -Credential JohnDoe -ConfigurationName JEA-BitLocker -ScriptBlock {
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

And now let's ask Jane to check if all is ok on PC's BitLocker1 and BitLocker2

````PowerShell
Invoke-Command -ComputerName "BitLocker1","BitLocker2" -Credential JaneDoe -ConfigurationName JEA-BitLocker -ScriptBlock {
    Get-BitLockerVolume
}
 
````

Seems OK!

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/JaneGet-BitLockerVolume.png)

## BitLocker event log

Now let's see if we can see event about BitLocker key successfully backed up into AD. Note: I borrowed following code from [this](https://blogs.technet.microsoft.com/ashleymcglone/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs/) blog.

````PowerShell
#Grab events from remote computers
$Computers="BitLocker1","BitLocker2"
$allevents=Invoke-Command -ComputerName $Computers -ScriptBlock {
    $events=Get-WinEvent -FilterHashtable @{"ProviderName"="Microsoft-Windows-BitLocker-API";Id=784}
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

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/BitLockerEvents.png)

## PowerShell Logging

In this part we will enable PowerShell logging into event log as documented in [this](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
) article

First let's enable scriptblocklogging with following registries.

````PowerShell
#Enable ScriptBlock logging
$Computers="BitLocker1","BitLocker2"
Invoke-Command -Computername $Computers -ScriptBlock {
    New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
    New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging           -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockInvocationLogging -Value 1 -PropertyType DWORD -Force
}
 
````

And let's run get-bitlockervolume command in normal and then in JEA session

````PowerShell
Invoke-Command -computername "BitLocker1", "BitLocker2" -ScriptBlock {
    Get-BitlockerVolume
}

Invoke-Command -computername "BitLocker1", "BitLocker2" -Credential JohnDoe -ConfigurationName JEA-BitLocker -ScriptBlock {
    Get-BitlockerVolume
}
 
````

Let's check what's in EventLog under eventID 4104

````PowerShell
$Computers="BitLocker1","BitLocker2"
$allevents=Invoke-Command -ComputerName $Computers -ScriptBlock {
    $events=Get-WinEvent -FilterHashtable @{"ProviderName"="Microsoft-Windows-PowerShell";Id=4104}
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

OK, that is a bit mess. But as you can see, BitLocker is not well recorded, while script for grabbing events is nicely recorded. Let's try another transcripting.

## JEA transcription

(optional) first let's create transcript directory and secure it as described in [this](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
) article

````PowerShell
$Computers="BitLocker1","BitLocker2"
Invoke-Command -ComputerName $Computers -ScriptBlock {
    md c:\Transcripts
    ## Kill all inherited permissions
    $acl = Get-Acl c:\Transcripts
    $acl.SetAccessRuleProtection($true, $false)
    ## Grant Administrators full control
    $administrators = [System.Security.Principal.NTAccount] "Administrators"
    $permission = $administrators,"FullControl","ObjectInherit,ContainerInherit","None","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    ## Grant everyone else Write and ReadAttributes. This prevents users from listing
    ## transcripts from other machines on the domain.
    $everyone = [System.Security.Principal.NTAccount] "Everyone"
    $permission = $everyone,"Write,ReadAttributes","ObjectInherit,ContainerInherit","None","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    ## Deny "Creator Owner" everything. This prevents users from
    ## viewing the content of previously written files.
    $creatorOwner = [System.Security.Principal.NTAccount] "Creator Owner"
    $permission = $creatorOwner,"FullControl","ObjectInherit,ContainerInherit","InheritOnly","Deny"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    ## Set the ACL
    $acl | Set-Acl c:\Transcripts\
}
 
````

Let's configure transcription now using psrc file (does not require restart). It's the same as we used before, just with one more parameter (transcriptdirectory)

````PowerShell
$Computers="BitLocker1","BitLocker2"
Invoke-Command -ComputerName $Computers -ScriptBlock {
    $Modules="BitLocker"
    $AdminVisibleCmdLets ="BitLocker\*","Get-CimInstance","New-ItemProperty","New-Item","Out-String","Where-Object","Select-Object"    #All commands from BitLocker module + all others since Enable-BitLocker and Backup-BitLockerKeyProtector needs it.
    $AdminVisibleExternalCommands = "C:\Windows\System32\where.exe","C:\Windows\System32\whoami.exe"
    $AdminVisibleProviders= "registry","Variable"
    $ViewerVisibleCmdLets="BitLocker\Get-*","Get-CimInstance" #All commands from BitLocker module that start with Get-
    $AdminRoleName= "BitLockerAdmin"
    $ViewerRoleName="BitLockerViewer"
    $ConfigurationName="JEA-BitLocker"
    $AdminGroup= "JEA-BitLockerAdmins"
    $ViewerGroup="JEA-BitLockerViewers"
    $TranscriptDirectory="C:\Transcripts"

    #Create folders for JEA
    $Folders="$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\","$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities","$env:ProgramData\JEAConfiguration"
    foreach ($Folder in $Folders){
        New-Item -Path $Folder -ItemType Directory -force
    }
    #Create JEA Manifest
    New-ModuleManifest -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\JEARoles.psd1" -Description "Contains custom JEA Role Capabilities"

    #Create RoleCapabilityFile and SessionConfigurationFile
    New-PSRoleCapabilityFile -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities\$AdminRoleName.psrc" -ModulesToImport $Modules -VisibleCmdLets $AdminVisibleCmdLets -VisibleExternalCommands $AdminVisibleExternalCommands -VisibleProviders $AdminVisibleProviders
    New-PSRoleCapabilityFile -Path "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles\RoleCapabilities\$ViewerRoleName.psrc" -ModulesToImport $Modules -VisibleCmdLets $ViewerVisibleCmdLets
    New-PSSessionConfigurationFile -Path $env:ProgramData\JEAConfiguration\$ConfigurationName.pssc -SessionType RestrictedRemoteServer -LanguageMode FullLanguage -RunAsVirtualAccount -RoleDefinitions @{"$env:USERDOMAIN\$AdminGroup" = @{ RoleCapabilities = "$AdminRoleName" };"$env:USERDOMAIN\$ViewerGroup" = @{ RoleCapabilities = "$ViewerRoleName" }} -TranscriptDirectory $TranscriptDirectory

    #RegisterPSsessionConfiguration
    Register-PSSessionConfiguration -Path $env:ProgramData\JEAConfiguration\$ConfigurationName.pssc -Name $ConfigurationName -Force
}
 
````

Let's shoot some more PowerShell just to see what's recorded in text files.

````PowerShell
$Computers="BitLocker1","BitLocker2"
Invoke-Command -computername $Computers -ScriptBlock {
    Get-BitlockerVolume
}

Invoke-Command -computername $Computers -Credential JohnDoe -ConfigurationName JEA-BitLocker -ScriptBlock {
    Get-BitlockerVolume
}
 
````

And let's check the transcript. Notice just JEA sessions are recorded

````PowerShell
$Computers="BitLocker1","BitLocker2"
Invoke-Command -computername $Computers -ScriptBlock {
    $logfiles=Get-ChildItem -Path "C:\Transcripts" -recurse | where name -like *.txt
    Foreach ($logfile in $logfiles){
         $logfile.FullName
         Get-Content -Path $logfile.FullName
    }
}
 
````

![](/Scenarios/BitLocker%20with%20JEA/Screenshots/PowerShell_JEA_Transcript.png)
