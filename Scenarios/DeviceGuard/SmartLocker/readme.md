<!-- TOC -->

- [Configuring Windows Defender Application Control](#configuring-windows-defender-application-control)
    - [LabConfig](#labconfig)
- [The lab](#the-lab)
    - [Create WDAC policy on single machine](#create-wdac-policy-on-single-machine)
    - [Create WDAC policy on Domain VMs](#create-wdac-policy-on-domain-vms)

<!-- /TOC -->

# Configuring Windows Defender Application Control

Recently I was playing with Intune and I found setting, that will enable your Windows 10 to trust only known binaries as you can see on screenshot below

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/WDAC_Intune.png)

I decided to do more research, and I found PM who sent me an example script to enable UMCI. Lets take a look how to enable this cool feature with just PowerShell.

## LabConfig

**Note :** If you dont have Win10, you can use CreateParentDisk.ps1 in tools folder to create Win10 VHD (use RS3 and newer) without creating all parent disks. You can also use insider previews to test new features!
**Note2 :** During hydration of Win10 image, provide [RSAT package](http://aka.ms/RSAT), so you don't have to install it.
````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$True ; CreateClientParent=$true}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Win10_$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$false ; DisableWCF=$True } }
 
````

# The lab

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/VMs.png)

All actions will be performed from management machine. First we will configure policy on that machine and then distribute to other 3 VMs using GPO. Therefore start it, and log in using LabAdmin creds.

## Create WDAC policy on single machine

````PowerShell
#Run from hyper-V host to start Management machine

Start-VM -VMName ws2016lab-Management
 
````

In Windows 10 you can notice, that there are default policies located at C:\Windows\schemas\CodeIntegrity\ExamplePolicies\

````PowerShell
Get-ChildItem -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\
 
````

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/DefaultPolicies.png)

So what we can do is we can copy DefaultWindows_Enforced or Audit, so we can manipulate it and apply.

````PowerShell
#create temp directory for policy
New-Item -Type Directory -Name Temp -Path C:\

#copy DefaultWindows_Enforced.xml to Temp\MyPolicy.xml
Copy-Item C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml c:\Temp\MyPolicy.xml
 
````

You can check whats configured with following PowerShell script (too lazy to open it with notepad :)

````PowerShell
#load file into variable as XML
[xml]$Policy=get-content -Path C:\temp\MyPolicy.xml
#list rules
$Policy.sipolicy.Rules | Select-Object -ExpandProperty rule
 
````

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/DefaultWindowsPolicyRules.png)


The next step would be to modify policy [options 13-16](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/deploy-windows-defender-application-control-policy-rules-and-file-rules#windows-defender-application-control-policy-rules) 13 to enable [Managed Installer](https://docs.microsoft.com/en-us/sccm/core/get-started/capabilities-in-technical-preview-1606), 14 for Intelligent Security Graph Authorization (to enable just good apps), 15 for Invalidate EAs on Reboot (To periodically re-validate the reputation for files that were authorized by the ISG) and 16 for WDAC policy updates to apply without requiring a system reboot.

````PowerShell
13..16 | Foreach-Object{
    Set-RuleOption -o $_ -f c:\temp\MyPolicy.xml
}
 
````

Result

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/DefaultWindowsPolicyRulesModified.png)

If this is a gold machine, you can also scan all driver files (I placed result from the VM into [DefaultPolicies folder]![](/Scenarios/DeviceGuard/SmartLocker/DefaultPolicies)), to add it into policy

````PowerShell
#scan for drivers (takes some time)
$rules = @()
$fileInfo = Get-SystemDriver -ScanPath $env:SystemDrive -UserPEs -OmitPaths "$env:windir\WinSxS"
$rules = New-CIPolicyRule -DriverFiles $fileInfo -Level FilePublisher -Fallback Hash
New-CIPolicy -FilePath c:\temp\GoldMachineDrivers.xml -Rules $rules -UserPEs

#add to MyPolicy.xml
$mergedPolicyRules = Merge-CIPolicy -PolicyPaths "c:\temp\GoldMachineDrivers.xml","c:\Temp\MyPolicy.xml" -OutputFilePath "c:\Temp\MyPolicy.xml"
Write-Host ('Merged policy contains {0} rules' -f $mergedPolicyRules.Count)
 
````

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/PolicyScanInProgress.png)

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/PolicyMergeResult.png)

To create binary policy run following script. You can copy it into C:\Windows\System32\CodeIntegrity\SiPolicy.p7b and then just refresh using update method on UpdateAndCompareCIPolicy Class , or copy it to your policy and apply

````PowerShell
#create binary policy file
ConvertFrom-CIPolicy c:\Temp\MyPolicy.xml c:\Temp\MyPolicy.bin

#copy to Code Integrity folder
Copy-Item c:\Temp\MyPolicy.bin -Destination C:\Windows\System32\CodeIntegrity\

#update policy
Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = "C:\Windows\System32\CodeIntegrity\MyPolicy.bin" }
 
#check CI status
Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
 
````

Notice CodeIntegrityPolicyEnforcementStatus and UsermodeCodeIntegrityPolicyEnforcementStatus is 2 (enforced)

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/UpdatePolicyResult.png)

MSInfo32 status - notice UMCI is running even KMCI/VBS is not. It's probably the biggest confusion as per this blog: 

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/MSInfo32.png)

````PowerShell
#start services
Get-Service -Name applockerfltr,appidsvc,appid | Start-Service
#make it autostart
Get-Service -Name applockerfltr,appid | Set-Service -StartupType Automatic
 
````

Now you can try to run some apps and see how it works

Nice apps keep working

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/NiceApp.png)

Bad app is no chance

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/BadApp.png)

You can see blocked programs in following log

````PowerShell
Get-WinEvent -FilterHashtable @{"ProviderName"="Microsoft-Windows-CodeIntegrity";Id=3077} | Out-GridView
.
````

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/ErrorMessages.png)

## Create WDAC policy on Domain VMs

Create empty GPO and copy MyPolicy.bin to DC (to be able to distribute it to VMs)

````PowerShell
#create empty GPO]
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
New-Gpo -Name 'SmartLocker' | New-GPLink -Target $OUPath
 
#copy policy to DC
New-Item -Type Directory -Name SmartLocker -Path \\dc\c$\Windows\SYSVOL\domain\Policies\
Copy-Item -Path c:\Temp\MyPolicy.bin -Destination \\dc\c$\Windows\SYSVOL\domain\Policies\SmartLocker\
 
````

Edit GPO with gpmc.msc and set following settings 

Set Code integrity policy binary to this location :\\corp.contoso.com\SYSVOL\Corp.contoso.com\Policies\SmartLocker\MyPolicy.bin

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/DeviceGuardCI.png)

Enable AppID Service in System Services (note, SmartLocker Filter driver is missing), will need to start it with script. (will be added)

![](/Scenarios/DeviceGuard/SmartLocker/Screenshots/AppIDSVC.png)

And you can start other VMs and see if settings are applied.

````PowerShell
#Run from hyper-V host to start Management machine

Start-VM -VMName ws2016lab-Win10_*
 
````

