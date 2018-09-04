# fun with VMFleet

WSLab now downloads VMFleet into ToolsVHD during 1_Prereq.ps1. (the VHD with Windows Server is copied manually from ParentDisks folder)

![](/Scenarios/VMFleet/Screenshots/ToolsVHD.png)

## LabConfig Windows Server 2016

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
1..4 | % { $VMNames="S2D"; $LABConfig.VMs += @{VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ;  MemoryStartupBytes= 4GB; NestedVirt=$True }}
 
```

## LabConfig Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17744.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }}

$LabConfig.ServerVHDs += @{
    Edition="4"
    VHDName="Win2019_17744.vhdx"
    Size=60GB
}
$LabConfig.ServerVHDs += @{
    Edition="3"
    VHDName="Win2019Core_17744.vhdx"
    Size=30GB
}
 
```

## Prerequisites

Create Windows Server image using CreateParentDisk.ps1 located in tools folder and copy it to tools disk (tools.vhdx located in ParentDisks folder). This image will be used for VMFleet VMs. It has to be different VHD than used for S2D VMs as you would hit issue (see [known issues](/Scenarios/VMFleet#known-issues))

Copy [S2D Hyperconverged scenario script](https://raw.githubusercontent.com/Microsoft/WSLab/master/Scenarios/S2D%20Hyperconverged/Scenario.ps1) and inside DC run first 9 regions.

![](/Scenarios/VMFleet/Screenshots/scenario.png)

## The lab

In DC, right-click SetupVMFleet.ps1 and select run with PowerShell

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step1.png)

Script will run, asks you to select your S2D cluster

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step2.png)

Script will also ask you for Password, that will be injected in answer file into VHD for VMFleet.

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step3.png)

Will also ask you for VHD with windows server you copied into tools.vhdx as part of prerequisites step. It will inject answer file and create users\administrator folder, so VMFleet will be able to use it.

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step4.png)

And after it will create Volumes, copy VHD into collect volume, and install failover clustering PowerShell, it will provide you commands, you will run in first node (s2d1 in this case)

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step5.png)

Provisioning VMs will take some time, I usually dedup volumes during this process, as it quickly fills all available space. But after this, you will be able to play with VMFleet

![](/Scenarios/VMFleet/Screenshots/VMfleetInAction.png)

For additional commands take a look here https://blogs.technet.microsoft.com/larryexchange/2016/08/17/leverage-vm-fleet-testing-the-performance-of-storage-space-direct/

## Known issues

Make sure you use different VHD than for s2d cluster node. Following screenshot shows disk, that fails to go online as there is same GUID/UniqueID as OS Disk.

![](/Scenarios/VMFleet/Screenshots/Error_wrongVHD.png)

Therefore you use the same as OS, OS wil fail to online volume and vmfleet will fail to add drive letter. You will also see following errors.

![](/Scenarios/VMFleet/Screenshots/Error_wrongVHD1.png)