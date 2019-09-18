# Exploring SpeculationControlSettings

## About Scenario
This scenario will explain how to query SpeculationControl settings from multiple remote computers and will explain different options

### Links

* [GitHub project](https://github.com/Microsoft/SpeculationControl)

* [Understanding script output](https://support.microsoft.com/en-us/help/4074629/understanding-the-output-of-get-speculationcontrolsettings-powershell)

* [PowerShell Gallery](https://www.powershellgallery.com/packages/SpeculationControl/)

* [How to configure settings](https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in)

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

### Option 2: Import PowerShell function from github and export script

Sometimes you dont want to install modules to servers, therefore we can download script with function directly from GitHub.

```PowerShell
$content=(Invoke-WebRequest -Uri https://raw.githubusercontent.com/microsoft/SpeculationControl/master/SpeculationControl.psm1 -UseBasicParsing).Content

#remove signature
$content=$content.substring(0,$content.IndexOf("# SIG # Begin signature block"))

#save it as file
$content | Out-File -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1 -Force

#since in script is just a function, let's add there a line that will execute the function
Add-Content -Value "Get-SpeculationControlSettings -Quiet" -Path $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

#and now we are able to execute it locally
& $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

#and now against list of servers
$Servers=1..4 | % {"Server$_"}
$output=Invoke-Command -ComputerName $servers -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

#to display output you can out it to Out-GridView
$output | Out-GridView

#or to CSV
$output | Export-CSV
 
```