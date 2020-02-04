# WSLab Deployment Process

## Prerequisites

This guide assumes you already [Hydrated](../WSLab-Hydration/wslab-hydration.md) VHDs and Domain Controller using first 2 scripts and the result is folder with following files:

![](WSLab-Deployment/media/Explorer01.png)

![](WSLab-Deployment/media/PowerShell01.png)

As you can see, in LAB folder is DC, that is ready to be imported. Entire VM configuration is backed up in Virtual Machines.zip. You can also see, that in ParentDisks folder are Windows Server 2019 VHDs, tools.vhdx and tools for creating additional parent disks (such as Windows 10, Windows Server 2016, or Windows Insider) and downloading Cumulative Update.

## Lab Deployment

![](WSLab-Deployment/media/Explorer02.png)

The process is simple as right-click and selecting Run with PowerShell. The script will read configuration located in LabConfig.ps1 and will deploy as specified. If default LabConfig is used, it will deploy Domain Controller and four servers for Azure Stack HCI simulation.

During Deployment Process you might see red errors, but these are safe to ignore as it's result of testing Active Directory availability inside Domain Controller.

![](WSLab-Deployment/media/PowerShell02.png)

> [!NOTE]
> If this part loops forever, you probably changed password. The mechanism to detect wrong password specified in LabConfig is not implemented.

The script will finish in ~5 minutes.

![](WSLab-Deployment/media/PowerShell03.png)

![](WSLab-Deployment/media/Hyper-V_Manager01.png)

All virtual machines are created under LAB folder

![](WSLab-Deployment/media/PowerShell04.png)

## Lab Cleanup

Once you want to discard lab, you can simply run cleanup by running Cleanup.ps1. Script will prompt you for confirmation. Once confirmed, all VMs will be removed and Domain Controller reverted.

![](WSLab-Deployment/media/Explorer03.png)

![](WSLab-Deployment/media/PowerShell05.png)

![](WSLab-Deployment/media/Hyper-V_Manager02.png)