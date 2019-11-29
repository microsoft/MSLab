<!-- TOC -->

- [LabConfig Windows Server Insider preview LTSC](#labconfig-windows-server-insider-preview-ltsc)
- [About the lab](#about-the-lab)
- [The Lab](#the-lab)
    - [Install roles and features](#install-roles-and-features)
    - [Create](#create)

<!-- /TOC -->

## LabConfig Windows Server Insider preview LTSC

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab19522.1000-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

#Notice NestedVirt and aditional networks
1..2 | ForEach-Object {$VMNames="Site1S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_19522.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True}} 
1..2 | ForEach-Object {$VMNames="Site2S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_19522.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True}} 

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.11.'; NetVLAN='0'; Subnet='255.255.255.0'}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet2'; NetAddress='172.16.12.'; NetVLAN='0'; Subnet='255.255.255.0'}
 
```

## About the lab

To focus on differences between regular and stretch s2d cluster in this lab are only key parts without details that are needed for real world deployments as demonstrated in [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged)

In this lab are dedicated networks for Storage Replica and to run VMs you can use NanoServer just to have something small. You can create NanoServer images using CreateParentDisk.ps1 in ParentDisks folder. Just make sure you use older Cumulative Update (or none).

## The Lab

### Install roles and features

### Create 