# LabConfig

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


````PowerShell
$ADMPWDServerName="ADMPWD-E"
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$ServersToPushAgent="Server1","Server2","Server3"

md c:\temp
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/7.5.3.0/AdmPwd.E.CSE.Setup.x64.zip -OutFile "c:\temp\AdmPwd.E.CSE.Setup.x64.zip"
Invoke-WebRequest -UseBasicParsing -Uri https://gcstoragedownload.blob.core.windows.net/download/AdmPwd.E/7.5.3.0/AdmPwd.E.Tools.Setup.x64.zip -OutFile "c:\temp\AdmPwd.E.Tools.Setup.x64.zip"

$files=Get-ChildItem -Path c:\temp

foreach ($file in $files){
    Expand-Archive -Path $file.FullName -DestinationPath c:\temp
}

$session=New-PSSession -ComputerName $ADMPWDServerName
Invoke-Command -Session $session -ScriptBlock {new-item -ItemType Directory -Path c:\ -Name Temp}
Copy-Item -Path C:\temp\AdmPwd.E.Tools.Setup.x64.msi -ToSession $session -Destination c:\temp

Invoke-Command -Session $session -ScriptBlock {
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,PDS /q"
}

#install PowerShell management tools and ADMX templates to policy store
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\temp\AdmPwd.E.Tools.Setup.x64.msi ADDLOCAL=Management.PS,Management.ADMX /q"

#create empty GPO
new-gpo -name ADMPWDE | new-gplink -target $OUPath
gpmc.msc

#extend schema
Update-AdmPwdADSchema

#create groups
New-ADGroup -Name ADMPWD.E_Readers -GroupScope Global
New-ADGroup -Name ADMPWD.E_Resetters -GroupScope Global

#Set delegation model
Set-AdmPwdComputerSelfPermission -Identity $OUPath
Set-AdmPwdPdsPermission -Identity $OUPath -AllowedPrincipals $ADMPWDServerName$

dsacls "CN=Deleted Objects,DC=Corp,DC=Contoso,DC=com" /takeownership
Set-AdmPwdPdsDeletedObjectsPermission -AllowedPrincipals $ADMPWDServerName$

````