<!-- TOC -->

- [About the scenario](#about-the-scenario)
    - [Description](#description)
    - [Scenario requirements](#scenario-requirements)
- [LabConfig.ps1](#labconfigps1)
- [The lab](#the-lab)

<!-- /TOC -->

# About the scenario

## Description
* In this scenario you will create a Storage Migration Service lab
* It will create the default DC, WS2019 SMS server, one or several older servers to migrate storage off
* This lab uses several diffrent Images from 2008R2 to 2019 RS5
* Labscript takes 5-10 minutes to finish (dependins what hardware is used)


## Scenario requirements

* Windows 10 1511 with enabled Hyper-V or Windows 10 1607+ 
* 8+ GB RAM is required for this scenario
* SSD (with HDD it is really slow, barely usable)


# LabConfig.ps1

in following labconfig you can see, that 5 machines are created.

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2019Migration-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; PullServerDC=$false ;Internet=$true; InstallSCVMM='no'; CreateClientParent=$false ; ClientEdition='Enterprise'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@() }  

$LabConfig.VMs = @(
            @{ VMName = 'SMS_2019'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2019_17639.vhdx'     ; MemoryStartupBytes= 1024MB }, 
            @{ VMName = 'WAC'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2019_17639.vhdx'     ; MemoryStartupBytes= 1024MB },
            @{ VMName = 'SMS2008R2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2008R2.vhd'     ; MemoryStartupBytes= 1024MB; Win2012Djoin=$True },
            #@{ VMName = 'SMS_2012'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2012.vhdx'     ; MemoryStartupBytes= 1024MB },
            @{ VMName = 'SMS_2012R2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2012R2.vhdx'     ; MemoryStartupBytes= 1024MB; Win2012Djoin=$True }
            #@{ VMName = 'SMS_2016'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016.vhdx'     ; MemoryStartupBytes= 1024MB }
        )
 
````
**Deploy.ps1 result**

![](/Scenarios/StorageMigrationService/Screenshots/lab.png)

# The lab

The lab begins with setting up the servers you defined in the Labconfig.ps1 script and running the Deploy.ps1 script.

After this copy in the files Scenario.ps1, installchrome.ps1 and iisstart.htm to c:\scripts on ws2019Migration-DC

Then run from computer

Get-VM | Where-Object {$_.State –EQ 'Off'} | Start-VM

Continue with [Scenario.ps1](/Scenarios/StorageMigrationService/scenario.ps1) script while reading comments.

*  This will open up powershell 
*  This will install features to the server
*  Install Windows Admin Center
*  Install Chrome on Domain Controller
*  Copy in a Hello World HTM file to the webserver you defined.


