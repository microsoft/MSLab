<!-- TOC -->

- [LabConfig Windows Server Insider preview LTSC (not yet released - stay tuned)](#labconfig-windows-server-insider-preview-ltsc-not-yet-released---stay-tuned)
- [About the lab](#about-the-lab)
- [The Lab](#the-lab)
    - [Region install prereqs](#region-install-prereqs)
    - [Region install features and configure hw timeout for virtual environment](#region-install-features-and-configure-hw-timeout-for-virtual-environment)
    - [Region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA)](#region-configure-networking-best-practices-are-covered-in-this-guide-httpakamsconvergedrdma)
    - [Region Create cluster and configure witness (file share or Azure)](#region-create-cluster-and-configure-witness-file-share-or-azure)
    - [Region Configure Cluster Networks](#region-configure-cluster-networks)
    - [Region configure Cluster-Aware-Updating](#region-configure-cluster-aware-updating)
    - [Region Configure Fault Domains (just an example)](#region-configure-fault-domains-just-an-example)
    - [Region Enable Cluster S2D and check Pool and Tiers](#region-enable-cluster-s2d-and-check-pool-and-tiers)
    - [Region create volumes](#region-create-volumes)
    - [Region Enable SR for volumes](#region-enable-sr-for-volumes)
    - [Region create some VMs](#region-create-some-vms)
    - [Region move odd CSVs and it's respective VMs to site1 and even to site2](#region-move-odd-csvs-and-its-respective-vms-to-site1-and-even-to-site2)

<!-- /TOC -->

## LabConfig Windows Server Insider preview LTSC (not yet released - stay tuned)

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab19522.1000-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

#Notice NestedVirt and aditional networks
1..2 | ForEach-Object {$VMNames="Site1S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_19522.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True}} 
1..2 | ForEach-Object {$VMNames="Site2S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_19522.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True}} 

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.11.'; NetVLAN='0'; Subnet='255.255.255.0'}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet2'; NetAddress='172.16.12.'; NetVLAN='0'; Subnet='255.255.255.0'}
 
```

## About the lab

This lab demonstrates Stretch Cluster functionality (announced at [Ignite](https://myignite.techcommunity.microsoft.com/sessions/83962)) without going into huge details details that are needed for real world deployments as demonstrated in [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged)

In this lab are dedicated networks for Storage Replica and to run VMs you can use NanoServer just to have something small (as every byte quardruples). You can create NanoServer images using CreateParentDisk.ps1 in ParentDisks folder. Just make sure you use older Cumulative Update than february 2019 (or none).

The lab contains regions. Each region has it's own variables to easier track what's happening.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Regions01.png)

Since all functionality is under construction, your feedback is important! The scenario is likely about to change as product will evolve.

## The Lab

Run all code from DC

### Region install prereqs

This region just installs Clustering and Hyper-V tools to management machine (in this case DC). 

### Region install features and configure hw timeout for virtual environment

In this region, Hyper-V,Failover Clustering and Storage Replica features are installed. As it's virtual environment, HWTimeout value is increased to prevent disk disconnects because of timeouts.

### Region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA)

Since Storage Replica networks are already present (thanks to Labconfig and Additional networks), just vSwitch with Mgmt,SMB01 and SMB02 vNICs is created. SMB01 and SMB02 are in different VLANs and located in different subnet (in case you want to control flow going throught switches, separate subnets are needed). Sometimes setting static IP addresses takes some time. It's possible to accelerate using clear-dnsclientcache.

Script also configures pNIC to vNIC mapping for SMB vNICs.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/ServerManager01.png)

### Region Create cluster and configure witness (file share or Azure)

If Azure is specified, AZ PowerShell module is downloaded and ResourceGroup with Storage Account created.

Failover Cluster is created with -ManagementPointNetworkType Distributed. This means that it adds all IP addresses into DNS as A record with ClusterName. Notice, that in CluAdmin screenshot is no IP Address and Name is Distributed Network Name. If Azure witness is specified in variable, then Storage Account is used and witness configured

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/DNS01.png)

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin01.png)

Since in vNext is AutoAssignNodeSite cluster parameter configured to 1 by default (in 2016/2019 it was 0), sites are populated automatically.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell01.png)

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin02.png)

### Region Configure Cluster Networks

To name networks correctly in Failover Cluster

Before

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin03.png)

After

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin04.png)

### Region configure Cluster-Aware-Updating

Just to have a role to play with.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell02.png)

### Region Configure Fault Domains (just an example)

This part will just configure simple XML. Note commented sections - it's also possible to use PowerShell, where it is easier to create fault domains more dynamic.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell03.png)

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin05.png)

### Region Enable Cluster S2D and check Pool and Tiers

Notice, that there are 2 separate pools created for each site. Also Naming convention changed.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell04.png)

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell05.png)

Notice, that Storage Tiers created twice (for each pool). This is also probably going to change in future releases.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell06.png)

### Region create volumes

In this region, multiple volumes will be created (2 data + 2 log volumes for each node). In single S2D cluster you want to have the same amount of virtual disks as you have nodes to evenly distribute workload. In this case, there is one virtual disk online on every node + it's replica + 2 log disks.

Notice, that in the code is Cluster Available Storage role moved to site, where virtual disks are being created.

You might want to configure smaller disks as all data needs to be replicated first.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin06.png)

### Region Enable SR for volumes

This code just makes sure, that disks of the same name are replicated to each other. In variables you can specify if it should be synchronous or asynchronous replica.

The code will also configure network constraints, so Storage Replica will use ReplicaNet01 and 02.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/Cluadmin07.png)

As you can see, Storage Replica Constraints are configured.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell07.png)

And also that volumes are being replicated. It also takes some time to finish.

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell08.png)

You can see, that communication is constrained to it's interfaces

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/PowerShell09.png)


### Region create some VMs

In this region you might want to create NanoServer image first - thats because to have some small VM you can live migrate around your lab. Due to it's small size, it will not consume much in your lab - as all data quardruples (2-way mirror + Storage Replica to another 2-way mirror volume).

Scenario script will ask you for VHDx, so you can just copy it to lab (or before deploying lab you could place it into tools.vhdx)

![](/Scenarios/S2D%20and%20Stretch%20Cluster/Screenshots/NanoServerCreation.gif)

### Region move odd CSVs and it's respective VMs to site1 and even to site2

Script will move half of the VMs and CSVs to Site2 to evenly distribute workload.