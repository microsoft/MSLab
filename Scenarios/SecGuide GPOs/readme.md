# Security Guidance GPOs lab

## About the lab

This lab is just a quick way how to deploy secguide policies on Win10. It will just download and import policies from https://blogs.technet.microsoft.com/secguide/ , extract and import.


## LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; DCVMProcessorCount=4 ; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$true; CreateClientParent=$true}

$LabConfig.VMs += @{ VMName = 'Win10' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }

````

## The lab

````PowerShell
#easiest is to run the script in DC. You can download GPOs on another machine and just file copy into dc c:\temp\

#download GPOs and unzip
New-Item -Name Temp -Path c:\ -ItemType Directory -ErrorAction SilentlyContinue
Invoke-WebRequest -UseBasicParsing -Uri https://msdnshared.blob.core.windows.net/media/2018/03/DRAFT-Windows-10-v1803-RS4.zip -OutFile c:\temp\DRAFT-Windows-10-v1803-RS4.zip
Expand-Archive -Path C:\temp\DRAFT-Windows-10-v1803-RS4.zip -DestinationPath c:\temp\DRAFT-Windows-10-v1803-RS4

#create GPOs
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$names=(Get-ChildItem "c:\Temp\DRAFT-Windows-10-v1803-RS4\GP Reports").BaseName
foreach ($name in $names) {
    New-GPO -Name $name  | New-GPLink -Target $OUPath
    Import-GPO -BackupGpoName $name -TargetName $name -path "c:\Temp\DRAFT-Windows-10-v1803-RS4\GPOs"
}
 
````

Result:

![](/Scenarios/SecGuide%20GPOs/screenshots/GPOs.png)

