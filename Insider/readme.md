# Server Insider lab 17074

## Howto
To create Insider lab, hydrate regular 2016 lab (to have dc), [download](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver) insider VHD and add it to parent disks. Following labconfig will hydrate 4 s2d nodes with VHD from insider and also machine, where you will paste script (as you need to have RS4 RSAT that was not provided this time).

You can create Win10 VHD with script provided in tools folder (please download latest prereq from dev as I just modified it, that if you hit cancel when asked for MSU, it will continue)

[YouTube Video](https://youtu.be/Rj_uhDN0tN4) on how to setup Windows Server Insider preview lab.

## Notes
* in version 17074 is performance history missing (internal performance volume is not created). It is expected. It will be added back in next few releases.
* hydration from scratch using insider ISO will fail (because of DHCP service does not start automatically during configuration using DSC)

## LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Windows_InsiderPreview_Server_VHDX_17074.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }}
$LabConfig.VMs += @{ VMName = 'PasteScriptsHere' ; Configuration = 'Simple' ; ParentVHD = 'Windows_InsiderPreview_Server_VHDX_17074.vhdx'; MemoryStartupBytes= 1GB ;MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Honolulu' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
````

Deployment result

![](/Insider/Screenshots/17035with14393DC.png)

Continue with [S2D scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged). To PowerShell in new window in server core, type "Start PowerShell" and paste script there. After finish, you can install Honolulu into Windows 10 machine to manage HyperConverged cluster.

## Result

![](/Insider/Screenshots/17035Honolulu.png)
