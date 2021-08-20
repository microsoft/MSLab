# Exploring new features in 21H2

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

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal01.png)

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

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_PowerShell05.png)

And Cluster registration

Before

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal02.png)

![](/Scenarios/Exploring%20new%20features%20in%2021H2/Screenshots/Roll_Portal03.png)

After

## Azure Arc

## Network ATC

## Thin provisioned volumes

## Other features

