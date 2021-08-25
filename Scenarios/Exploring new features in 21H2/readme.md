# Exploring new features in 21H2

<!-- TOC -->

- [Exploring new features in 21H2](#exploring-new-features-in-21h2)
    - [About lab](#about-lab)
        - [Requirements](#requirements)
    - [Rolling Cluster Upgrade](#rolling-cluster-upgrade)
        - [Region Rolling Cluster Upgrade - Prereqs](#region-rolling-cluster-upgrade---prereqs)
        - [Region Rolling Cluster Upgrade - The Lab](#region-rolling-cluster-upgrade---the-lab)
    - [Azure Arc](#azure-arc)
        - [Region Azure Arc - Prereqs](#region-azure-arc---prereqs)
        - [Region Azure Arc - The Lab](#region-azure-arc---the-lab)
    - [Network ATC](#network-atc)
        - [Region Network ATC - Prereqs](#region-network-atc---prereqs)
        - [Region Network ATC - The Lab](#region-network-atc---the-lab)
    - [Thin provisioned volumes](#thin-provisioned-volumes)
        - [Region Thin provisioned volumes - Prereqs](#region-thin-provisioned-volumes---prereqs)
        - [Region Thin provisioned volumes - The Lab](#region-thin-provisioned-volumes---the-lab)
    - [Other features](#other-features)
        - [Other features - Prereqs](#other-features---prereqs)
        - [Other features - The Lab](#other-features---the-lab)
            - [Dynamic Processor Compatibility](#dynamic-processor-compatibility)
            - [Adjustable repair speed](#adjustable-repair-speed)
            - [Kernel Soft Reboot](#kernel-soft-reboot)
    - [Storage bus cache with Storage Spaces on standalone servers](#storage-bus-cache-with-storage-spaces-on-standalone-servers)
        - [SBC: The Lab](#sbc-the-lab)

<!-- /TOC -->

## About lab

In this lab we will demonstrate new featues in Windows Server 2022 and Azure Stack HCI 21H2. 

Recommended reading:

* https://docs.microsoft.com/en-us/azure-stack/hci/manage/preview-channel
* https://www.youtube.com/watch?v=TsCOQu0bksA

The lab is bit large, but clusters can be deployed individually and modified to be 2 node only.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/HVManager01.png)

Every lab has "Prereqs" and "The Lab" region. Prereqs is just a minimum amount of steps to get you into functioning cluster (for prod, use "Deploying Azure Stack HCI scenario" as these steps are simplified just for purpose of this lab). As always, run scripts section by section as it's not optimized to run all end-to-end (no try-catch ...)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ISE01.png)

### Requirements

Create lab with Windows Server 2022 DC (you can download Windows Server 2022 [here](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022))

You will need to create additional parent disk (using CreateParentDisks.ps1 located in ParentDisks folder)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Explorer01.png)

You can download Azure Stack HCI 20H2 ISO [here](https://software-download.microsoft.com/download/pr/AzureStackHCI_17784.1408_EN-US.iso)

And with Azure Stack HCI 21H2 it's bit more complicated, so only way (unofficial, please use in labs only!) is to use [UUPDump.net](https://uupdump.net/known.php?q=Azure+Stack+HCI).

Don't forget do download latest Cumulative Update for 20H2 (use DownloadLatestCUs.ps1 in ParentDisks folder)

Windows 11 can be downloaded from [Windows Insider page](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewiso)

## Rolling Cluster Upgrade

This lab will demonstrate process of rolling cluster upgrade using Cluster Aware Upgrading from Azure Stack HCI 20H2 to Azure Stack HCI 21H2. It will also demonstrate steps that are needed to update Cluster, Pool and VM versions.

### Region Rolling Cluster Upgrade - Prereqs

Prereqs will create simple cluster with one Volume and 3 VMs. It will register Azure Stack HCI cluster to Azure, so you can then compare differences between 20H2 and 21H2.

You will see Azure Stack HCI cluster registered under Azure Arc in Portal. However Arc capabilities are not yet available as it's only Azure Stack HCI build 17784.1884 (20H2)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal01.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal02.png)

You can also notice, that there is no Server Arc Agent installed

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal03.png)

More details about cluster you can find in Cluadmin.msc

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Cluadmin01.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Cluadmin02.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Cluadmin03.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Cluadmin04.png)

Or if you will deploy Windows Admin Center (see two last scenario regions), you can connect to your cluster and manage it from there.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_WAC01.png)

### Region Rolling Cluster Upgrade - The Lab

Lab demonstrates how to update to latest update using CAU (it's commented section as lab is assuming you patched your 20H2 VHD when it was created), it will also show you how to enable preview channel and then roll the upgrade using CAU.

Rolling upgrade in progress

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell01.png)

Rolling upgrade in finished

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell02.png)

As you can see, all nodes were upgraded

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell03.png)

Cluster version needs to be updated

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell04.png)

Also Pool version

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell05.png)

VM version

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell06.png)

And Cluster registration

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell07.png)

Before

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal02.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal03.png)

After (enable monitoring is available and Arc Agent is installed)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal04.png)

Also notice, that during registration App identity was created (to be able to register Arc Agents using a secret)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal05.png)


## Azure Arc

In this lab you will explore how to register Azure Stack HCI to Azure at scale and with different options.

Unlike Rolling Cluster, this cluster will demonstrate registration to Azure without prompting credentials again. It will ultimately fail, because cluster is configured with Distributed Server Name. [Az.StackHCI](https://www.powershellgallery.com/packages/Az.StackHCI/0.9.0) has a bug that uses invoke-command against clustername and inside script is again clustername. This works if clustername resolves to one IP, but not if it resolves to multiple as it will introduce double-jump.

This will enable us to explore registration process more in detail.

### Region Azure Arc - Prereqs

Prereqs region is simplified cluster deployment with enabled S2D and File Share witness. Notice, that cluster name is configured as Distributed Server Name.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Cluadmin01.png)

### Region Azure Arc - The Lab

Before registration the debug log is enabled using wevtutil.exe

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_mmc01.png)

The registration process itself will (most likely) fail with error registering clustered scheduled task 

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_PowerShell01.png)

Let's explore what was configured before the task failed.

Available commands (unfortunately there is not much documentation available)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_PowerShell02.png)

And as you can see all seems to be fine

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_PowerShell03.png)

However Scheduled Task is not there

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_PowerShell04.png)

After manual registration it's there and cluster is fine in portal

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal01.png)

After script will Log Analytics workspace, you can enable monitoring by clicking on Enable on Monitoring tab

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal02.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal03.png)

It will simply push Arc Extensions to nodes (with Workspace configuration)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal04.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal05.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal06.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Arc_Portal07.png)

## Network ATC

In this lab you will explore new Azure Stack HCI 21H2 feature [Network ATC](https://docs.microsoft.com/en-us/azure-stack/hci/deploy/network-atc). It's bit complicated to simulate in virtual environment (it will ultimately fail to apply configuration due to lack of features available in physical environment) but it will give you nice overview of how the feature works and how different it is from configuring network "manually"

### Region Network ATC - Prereqs

Prereqs region is very simple cluster with enabled S2D.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_Cluadmin01.png)

### Region Network ATC - The Lab

Configuration created with module copied from Azure Stack HCI nodes to Windows Server 2022

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell01.png)

Converged intent will be provisioned

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell02.png)

And script will wait until configuration will be fully applied, or eventually fail (will take some time)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell03.png)

Notice failed ConfigurationStatus

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell04.png)

Let's explore what was configured

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell05.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell06.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell07.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell08.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell09.png)

Since it did not end well (and there are still several network configurations that netATC does not cover) config will be cleaned up and deployed manually.

Manual configuration result:

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell10.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell11.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell12.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell13.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/ATC_PowerShell14.png)

## Thin provisioned volumes

In this lab you will explore new Azure Stack HCI 21H2 feature [Storage Thin Provisioning](https://docs.microsoft.com/en-us/azure-stack/hci/manage/thin-provisioning).

### Region Thin provisioned volumes - Prereqs

This region will create simplest Cluster as possible. The only thing we want is to be able to create a volume.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Thin_Cluadmin01.png)

### Region Thin provisioned volumes - The Lab

Let's create 1TB fixed volume. As expected, it will consume 3TB (three-way mirror)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Thin_PowerShell01.png)

On other hand, 1TB thin volume is consuming much less.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Thin_PowerShell02.png)

Once Pool property ProvisioningTypeDefault is modified, if provisioningtype not specified, thin volume is created

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Thin_PowerShell03.png)

## Other features

This lab just combines all knowledge mentioned above, so you can experiment with "Other features" - such as [Dynamic CPU Compatibility](https://docs.microsoft.com/en-us/azure-stack/hci/manage/processor-compatibility-mode), [Adjustable Repair Speed](https://docs.microsoft.com/en-us/azure-stack/hci/manage/storage-repair-speed) and [Kernel Soft Reboot](https://docs.microsoft.com/en-us/azure-stack/hci/manage/kernel-soft-reboot), 

It deploys cluster almost like the real (production) cluster. However if you want to see real scenario, take a look at [AzSHCI Deployment](/Scenarios/AzSHCI%20Deployment/)

### Other features - Prereqs

Prereqs region will setup cluster end-to-end - with CSVs, VMs, CAU, complete network config...

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_Cluadmin01.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_Cluadmin02.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_Cluadmin03.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_Cluadmin04.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_Cluadmin05.png)

### Other features - The Lab

#### Dynamic Processor Compatibility

As you can see, by default is processor compatibility disabled and configured for CommonClusterFeatureSet

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell01.png)

If you try to modify the settings while VMs running, it will fail

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell02.png)

You can simply shut down VMs one by one and configure settings while VM is off.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell03.png)

#### Adjustable repair speed

The lab is simple - it will show you current QD, you will try some different number than supported and then supported value.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell04.png)

#### Kernel Soft Reboot

Let's explore KSR configuration

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell05.png)

And let's scan for some updates to test KSR

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell06.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell07.png)

As you can see on below screenshot, boottype is SoftBoot and SoftBootStatus is Succeeded.

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell08.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell09.png)

Exploring results in report

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell10.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Other_PowerShell11.png)

## Storage bus cache with Storage Spaces on standalone servers

This lab is just for "academic" tryout. As the standalone storage space with SBC refuses to create, it will be attempted manuallu (without success). BUt it is good enough to provide insights into how SBC on Standalone server works

As this is hyper-v environment, we will attempt to simulate different mediatype by setting smaller disk to SSD mediatype and larger to HDD. Unfortunately this "trick" will not work

### SBC: The Lab

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell01.png)

and all disks will fall back to unspecified mediatype again

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell02.png)

Anyway, let's see if we can enable SBC Manually (please, don't do this in production, totally unsupported!)

As you can see, the process is very similar to enabling S2D. We will create Pool that contains both SSDs and HDDs. Unlike S2D, the disks are all listed as Auto-Select usage (in S2D is faster tier dedicated to cache = Journal)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell03.png)

Since we are doing everything manually, let's also create tiers

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell04.png)

Let's see if SBC is using any disks.. Well, there are no bindings since disks are virtual and fails when tried to update

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell05.png)

And it did not help as well

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell06.png)

But here these examples will work the same way in real environments

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/SBC_PowerShell07.png)
