
#setup file share
$ComputerName="FileServer"
$FolderName="FSLogix"
Invoke-Command -ComputerName $ComputerName -ScriptBlock {new-item -Path c:\Shares -Name $using:FolderName -ItemType Directory}
$accounts=@()
$accounts+="corp\Domain Users"
New-SmbShare -Name $FolderName -Path "c:\Shares\$FolderName" -FullAccess $accounts -CimSession $ComputerName

#setup NTFS permissions https://docs.microsoft.com/en-us/fslogix/fslogix-storage-config-ht
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module ntfssecurity -Force

$item=Get-Item -Path "\\$ComputerName\c$\shares\$foldername"
$item | Disable-NTFSAccessInheritance
$item | Get-NTFSAccess | Remove-NTFSAccess -Account "Corp\Domain Users"
$item | Get-NTFSAccess | Remove-NTFSAccess -Account "BUILTIN\Users"
$item | Get-NTFSAccess | Add-NTFSAccess -Account "corp\Domain Users" -AccessRights Modify -AppliesTo ThisFolderOnly
$item | Get-NTFSAccess | Add-NTFSAccess -Account "Creator owner" -AccessRights Modify -AppliesTo SubfoldersAndFilesOnly

#Download FSLogix and expand
$ProgressPreference="SilentlyContinue"
Invoke-WebRequest -Uri https://aka.ms/fslogix_download -OutFile $env:USERPROFILE\Downloads\FSLogix_Apps.zip -UseBasicParsing
Expand-Archive -Path $env:USERPROFILE\Downloads\FSLogix_Apps.zip -DestinationPath $env:USERPROFILE\Downloads\FSLogix_Apps -Force

#install fslogix admx template
Copy-Item -Path $env:UserProfile\Downloads\FSLogix_Apps\fslogix.admx -Destination C:\Windows\PolicyDefinitions
Copy-Item -Path $env:UserProfile\Downloads\FSLogix_Apps\fslogix.adml -Destination C:\Windows\PolicyDefinitions\en-US

#grab recommended GPOs (original source https://github.com/shawntmeyer/WVD/tree/master/Image-Build/Customizations/GPOBackups)
Invoke-WebRequest -Uri https://github.com/microsoft/WSLab/raw/dev/Scenarios/FSLogix/WVD-GPO-Backups.zip -OutFile $env:USERPROFILE\Downloads\WVD-GPO-Backups.zip -UseBasicParsing
#extract
Expand-Archive -Path $env:USERPROFILE\Downloads\WVD-GPO-Backups.zip -DestinationPath $env:USERPROFILE\Downloads\WVDBackups\ -Force
#import GPOs (and link)
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$names=(Get-ChildItem -Path "$env:UserProfile\Downloads\WVDBackups" -Filter *.htm).BaseName
foreach ($name in $names) {
    New-GPO -Name $name  | New-GPLink -Target $OUPath
    Import-GPO -BackupGpoName $name -TargetName $name -path "$env:UserProfile\Downloads\WVDBackups"
}

#install FSLogix to remote computer
$computers="win10","Win10_1"

#create sessions
$Sessions=New-PSSession -ComputerName $computers
foreach ($session in $Sessions){
    Copy-Item -Path $env:Userprofile\downloads\FSLogix_Apps\x64\Release\FSLogixAppsSetup.exe -Destination $env:Userprofile\downloads\ -ToSession $session
}
#install fslogix
Invoke-Command -ComputerName $computers -ScriptBlock {
    Start-Process -FilePath $env:Userprofile\downloads\FSLogixAppsSetup.exe -ArgumentList "/install /quiet / norestart" -Wait
}

#reboot win10 machines
Restart-Computer -ComputerName $computers -Protocol WSMan -Wait -For PowerShell

#Create users with password LS1setup!
New-ADUser -Name JohnDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
New-ADUser -Name JaneDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
