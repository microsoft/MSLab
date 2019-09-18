# Exploring SpeculationControlSettings

## About Scenario

This scenario will explain how to query SpeculationControl settings from multiple remote computers and will explain different options enabled by default on fully patched Hyper-V VM.

### Links

* [GitHub project](https://github.com/Microsoft/SpeculationControl)

* [Understanding script output](https://support.microsoft.com/en-us/help/4074629/understanding-the-output-of-get-speculationcontrolsettings-powershell)

* [PowerShell Gallery](https://www.powershellgallery.com/packages/SpeculationControl/)

* [How to configure settings](https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in)

## LabConfig

Prereq: generate 19H1 Windows 10 VHD with CreateParentDisk.ps1 located in ParentDisks folder.

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

1..3 | % { $VMNames="Server" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB } }
1..3 | % { $VMNames="Client" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx' ; MemoryStartupBytes= 1GB ; DisableWCF=$true ; EnableWinRM=$true } }
 
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
$ComputerNames="Server1","Server2","Server3","Client1","Client2","Client3"
#or if you are lazy to type, you can just create variable like this:
<#
$ComputerNames=@()
$ComputerNames+=(1..3 | % {"Server$_"})
$ComputerNames+=(1..3 |%{"Client$_"})
#>
$output=Invoke-Command -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1 -ComputerName $ComputerNames

#to display output you can out it to Out-GridView
$output | Out-GridView

#or to CSV
$output | Export-CSV -Path $env:USERPROFILE\Downloads\SpeculationControlScriptOutput.csv -Delimiter ";" -NoTypeInformation
 
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
$ComputerNames="Server1","Server2","Server3","Client1","Client2","Client3"
$output=Invoke-Command -ComputerName $ComputerNames -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

#to display output you can send it to Out-GridView
$output | Out-GridView

#or to CSV
$output | Export-CSV -Path $env:USERPROFILE\Downloads\SpeculationControlScriptOutput.csv -Delimiter ";" -NoTypeInformation
 
```

Example output in VM with Core scheduler enabled on Host (Windows 10 19H1)

![](/Scenarios/Exploring%20SpeculationControlSettings/Screenshots/SpeculationControlOutputOnVM.png)

### Explore the results

Since both options generate SpeculationControlScript that can be run remotely with Invoke-Command, let's start with querying informatin to $output variable

```PowerShell
$ComputerNames="Server1","Server2","Server3","Client1","Client2","Client3"
$output=Invoke-Command -ComputerName $ComputerNames -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1
 
```

To display if features are enabled in Windows or not, you can run following script:

```PowerShell
$output | Select-Object PSComputerName,*windowssupportenabled* | Format-Table -AutoSize
 
```

![](/Scenarios/Exploring%20SpeculationControlSettings/Screenshots/WindowsSupportEnabled01.png)

As you can see, BTIWindowsSupportEnabled is automatically enabled on Windows Client (CVE-2017-5715 - branch target injection), while on Windows Server it's disabled. On both Server and Client are Microarchitectural Data Sampling enabled (CVE-2018-11091,CVE-2018-12126,CVE-2018-12127,CVE-2018-12130). However its enabled only if on Host is Core Scheduler enabled. SSBDWindowsSupportEnabledSystemWide (CVE-2018-3639 - speculative store bypass) is disabled.




### Enable mitigations (BTIWindowsSupportEnabled) for CVE-2017-5715 (Spectre Variant 2) and CVE-2017-5754 (Meltdown)

```PowerShell
$ComputerNames="Server1","Server2","Server3"
Invoke-Command -ComputerName $ComputerNames -ScriptBlock {
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
}

#restart computers
Restart-Computer -ComputerName $ComputerNames -Wait -For PowerShell -Protocol WSMan
 
```

Validate

```PowerShell
$ComputerNames="Server1","Server2","Server3","Client1","Client2","Client3"
$output=Invoke-Command -ComputerName $ComputerNames -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

$output | Select-Object PSComputerName,*windowssupportenabled* | Format-Table -AutoSize
 
```

![](/Scenarios/Exploring%20SpeculationControlSettings/Screenshots/WindowsSupportEnabled02.png)


### Enable All mitigations (SSBDWindowsSupportEnabledSystemWide)

```PowerShell
$ComputerNames="Server1","Server2","Server3","Client1","Client2","Client3"
Invoke-Command -ComputerName $ComputerNames -ScriptBlock {
    #Detect HT
    $processor=Get-WmiObject win32_processor | Select-Object -First 1
    if ($processor.NumberOfCores -eq $processor.NumberOfLogicalProcessors/2){
        $HT=$True
    }
    if ($HT -eq $True){
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 72
    }else{
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8264
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
}

#restart servers
Restart-Computer -ComputerName $ComputerNames -Wait -For PowerShell -Protocol WSMan
 
```

Validate

```PowerShell
$ComputerNames="Server1","Server2","Server3","Client1","Client2","Client3"
$output=Invoke-Command -ComputerName $ComputerNames -FilePath $env:USERPROFILE\Downloads\SpeculationControlScript.ps1

$output | Select-Object PSComputerName,*windowssupportenabled* | Format-Table -AutoSize
 
```

![](/Scenarios/Exploring%20SpeculationControlSettings/Screenshots/WindowsSupportEnabled03.png)
