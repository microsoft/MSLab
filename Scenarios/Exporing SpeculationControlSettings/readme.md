# Exploring SpeculationControlSettings

## About Scenario
This scenario will explain how to query SpeculationControl settings from multiple remote computers and will explain different options

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

1..4 | % { $VMNames="Server" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB } }
 
```

## The lab

### Option 1: Install PowerShell module and export script

```PowerShell
#install Nuget (to be able to install SpeculationControl module)
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force
#make PSGallery trusted
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
#install SpeculationControl
Install-Module SpeculationControl

#Grab speculation control script
$script=Get-Command Get-SpeculationControlSettings |Select-Object -ExpandProperty ScriptBlock
#make it quiet by default
$script=$script.tostring().replace('[switch]$Quiet','[switch]$Quiet = $true')
#save script to downloads folder
$script | Out-File -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

#run script against multiple servers
$Servers="Server1","Server2","Server3","Server4" 
#or if you are lazy to type, you can just create variable like this:
#$Servers=1..4 | % {"Server$_"}
$output=Invoke-Command -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1 -ComputerName $Servers

#to display output you can out it to Out-GridView
$output | Out-GridView

#or to CSV
$output | Export-CSV
 
```




$content=(Invoke-WebRequest -Uri https://raw.githubusercontent.com/microsoft/SpeculationControl/master/SpeculationControl.psm1 -UseBasicParsing).Content

$content | Out-File -FilePath $env:USERPROFILE\Downloads\Get-SpeculationControlSettings.ps1
```