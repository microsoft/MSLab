<!-- TOC -->

- [Scenario Introduction](#scenario-introduction)
    - [LabConfig Windows Server 1709](#labconfig-windows-server-1709)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
- [Configuring VBS](#configuring-vbs)

<!-- /TOC -->

# Scenario Introduction

In this scenario will be Device Guard Virtualization-based security deployed to remote servers. It is just a demonstration on how to lockdown remote servers from Management machine. You don't have to spin Win10 machine (you can use DC), but since I want to demonstrate security best practices, all is done from there.

Windows Defender Device Guard is composed of two technologies. Virtualization-based security and Windows Defender Application Control. You will find more information [in our docs](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control) and [in channel9 videos](channel9.msdn.com/tags/kernel)


## LabConfig Windows Server 1709

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab1709-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; PullServerDC=$false; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'WinServer1709_G2.vhdx'  ; MemoryStartupBytes= 512MB} }

$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="WinServer1709_G2.vhdx";
    Size=40GB
}
 
````
## LabConfig Windows Server 2016

**Note:** If you dont have Win10, you can use CreateParentDisk.ps1 in tools folder to create Win10 VHD without creating all parent disks

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$True ; CreateClientParent=$true ; ClientEdition='Enterprise'}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Server$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 512MB} }
 
````

# Configuring VBS

The lab is same as for LAPS. therefore we will be configuring 3 servers... 

First step would be to configure VBS on 3 servers specified in variable $servers. It will enable Isolated User Mode(enabling Hyper-V to be able to run VTL0 and VTL1), KMCI secure MOR and Credential Guard.

Registry keys used in following PowerShell match following settings in Group Policy. **Note:** locks are commented as to unlock settings is physical presence needed. Therefore if you may want to configure it after environment is running well for some time)

![](/Scenarios/DeviceGuard/VBS/Screenshots/VBS_GPO.png)

````PowerShell
$Servers=1..3 | Foreach-Object {"Server$_"}

#configure VBS & Cred Guard
    Invoke-Command -ComputerName $servers -ScriptBlock {
        #Device Guard
        #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 1 /f 
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 3 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d 1 /f

        #Cred Guard  
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

        #HVCI
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f
        #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 1 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d 1 /f
    }
#restart servers to apply changes
Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -for PowerShell

````

To check if VBS is running you can run following CIM query as documented [here](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity). 

````PowerShell
$Servers=1..3 | Foreach-Object {"Server$_"}

Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard -CimSession $servers
 
````

![](/Scenarios/DeviceGuard//VBS/Screenshots/DG_Status1.png)

