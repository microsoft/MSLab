# Security Guidance GPOs lab

## About the lab

This lab is just a quick way how to deploy secguide policies on Win10. It will just download, extract and import policies from https://blogs.technet.microsoft.com/secguide/2018/04/30/security-baseline-for-windows-10-april-2018-update-v1803-final/

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; DCVMProcessorCount=4 ; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$true; CreateClientParent=$true}

$LabConfig.VMs += @{ VMName = 'Win10' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }

```

## The lab

```PowerShell
#easiest is to run the script in DC. You can download GPOs on another machine and just file copy into dc Downloads

#download GPOs and unzip
Invoke-WebRequest -UseBasicParsing -Uri https://msdnshared.blob.core.windows.net/media/2018/04/Windows-10-RS4-Security-Baseline-FINAL.zip -OutFile "$env:UserProfile\Downloads\Windows-10-RS4-Security-Baseline-FINAL.zip"
Expand-Archive -Path "$env:UserProfile\Downloads\Windows-10-RS4-Security-Baseline-FINAL.zip" -DestinationPath "$env:UserProfile\Downloads\"

#create GPOs
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$names=(Get-ChildItem "$env:UserProfile\Downloads\Windows-10-RS4-Security-Baseline-FINAL\GP Reports").BaseName
foreach ($name in $names) {
    New-GPO -Name $name  | New-GPLink -Target $OUPath
    Import-GPO -BackupGpoName $name -TargetName $name -path "$env:UserProfile\Downloads\Windows-10-RS4-Security-Baseline-FINAL\GPOs"
}
 
```

Result:

![](/Scenarios/SecGuide%20GPOs/screenshots/GPOs.png)

