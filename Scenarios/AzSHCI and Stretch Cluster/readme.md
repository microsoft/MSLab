<!-- TOC -->

- [LabConfig with enabled telemetry (full)](#labconfig-with-enabled-telemetry-full)
- [About the lab](#about-the-lab)
- [The Lab](#the-lab)
    - [Region install prereqs](#region-install-prereqs)
    - [Region install features and configure hw timeout for virtual environment](#region-install-features-and-configure-hw-timeout-for-virtual-environment)
    - [Region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA)](#region-configure-networking-best-practices-are-covered-in-this-guide-httpakamsconvergedrdma)
    - [Region Create cluster and configure witness (file share or Azure)](#region-create-cluster-and-configure-witness-file-share-or-azure)
    - [Region Configure Cluster Networks](#region-configure-cluster-networks)
    - [Region configure Cluster-Aware-Updating](#region-configure-cluster-aware-updating)
    - [Region Configure Fault Domains (just an example)](#region-configure-fault-domains-just-an-example)
    - [Region Configure Fault Domains (commented - just an example)](#region-configure-fault-domains-commented---just-an-example)
    - [Region Enable Cluster S2D and check Pool and Tiers](#region-enable-cluster-s2d-and-check-pool-and-tiers)
    - [Region create volumes](#region-create-volumes)
    - [Region Enable SR for volumes](#region-enable-sr-for-volumes)
    - [Region create some VMs](#region-create-some-vms)
    - [Region move odd CSVs and it's respective VMs to site1 and even to site2](#region-move-odd-csvs-and-its-respective-vms-to-site1-and-even-to-site2)
    - [Region configure Affinity rules](#region-configure-affinity-rules)
    - [Region install Windows Admin Center Gateway](#region-install-windows-admin-center-gateway)
    - [Region Register Azure Stack HCI with Azure](#region-register-azure-stack-hci-with-azure)

<!-- /TOC -->

## LabConfig with enabled telemetry (full)

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab19522.1000-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#Management machine
$LABConfig.VMs += @{ VMName = "Management" ; ParentVHD = 'Win2019_G2.vhdx' ; MGMTNICs=1}

#optional WacGW
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx'; MGMTNICs=1}

#AzSHCI Nodes. Notice NestedVirt and aditional networks
1..2 | ForEach-Object {$VMNames="Site1AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True ; ManagementSubnetID=0}} 
1..2 | ForEach-Object {$VMNames="Site2AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True ; ManagementSubnetID=1}}

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.11.'; NetVLAN='0'; Subnet='255.255.255.0'}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet2'; NetAddress='172.16.12.'; NetVLAN='0'; Subnet='255.255.255.0'}
 
```

## About the lab

This lab demonstrates Stretch Cluster functionality that is included in Azure Stack HCI OS. All without going into huge details details that are needed for real world deployments as demonstrated in [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged). No worries, there are a lot of nice details anyway and this scenario can be used for deploying real-world clusters

In this lab are dedicated networks for Storage Replica and to run VMs you can use NanoServer just to have something small (as every byte quardruples). You can create NanoServer images using CreateParentDisk.ps1 in ParentDisks folder. Just make sure you use older Cumulative Update than february 2019 (or none).

In this lab will be multiple sites configured.
![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/ADSites01.png)

The lab contains regions. Each region has it's own variables to easier track what's happening.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Regions01.png)

Lab uses Azure Stack HCI OS, so [download ISO](https://azure.microsoft.com/en-us/products/azure-stack/hci/hci-download/) and create VHD using CreateParentDisk.ps1 located in ParentDisks folder.

## The Lab

**Run all code from Management machine!** With 2 networks connected to DC, copying VHDs into \\ClusterName\ClusterStorage$ is extremely slow.

### Region install prereqs

This region just installs Clustering and Hyper-V tools to management machine.

### Region install features and configure hw timeout for virtual environment

In this region, Hyper-V,Failover Clustering and Storage Replica features are installed. As it's virtual environment, HWTimeout value is increased to prevent disk disconnects because of timeouts.

### Region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA)

Since Storage Replica networks are already present (thanks to Labconfig and Additional networks), just vSwitch with Mgmt,SMB01 and SMB02 vNICs is created. SMB01 and SMB02 are in different VLANs and located in different subnet (in case you want to control flow going throught switches, separate subnets are needed). Sometimes setting static IP addresses takes some time. It's possible to accelerate using clear-dnsclientcache.

Script also configures pNIC to vNIC mapping for SMB vNICs.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/ServerManager01.png)

### Region Create cluster and configure witness (file share or Azure)

If Azure is specified, AZ PowerShell module is downloaded and ResourceGroup with Storage Account created.

Failover Cluster is created with -ManagementPointNetworkType Distributed. This means that it adds all IP addresses into DNS as A record with ClusterName. Notice, that in CluAdmin screenshot is no IP Address and Name is Distributed Network Name. If Azure witness is specified in variable, then Storage Account is used and witness configured

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/DNS01.png)

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin01.png)

Since in vNext is AutoAssignNodeSite cluster parameter configured to 1 by default (in 2016/2019 it was 0), sites are populated automatically.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell01.png)

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin02.png)

### Region Configure Cluster Networks

To name networks correctly in Failover Cluster

Before

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin03.png)

After

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin04.png)

### Region configure Cluster-Aware-Updating

Just to have a role to play with.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell02.png)
<<<<<<< HEAD:Scenarios/AzSHCI and Stretch Cluster/readme.md
=======

### Region Configure Fault Domains (just an example)
>>>>>>> a1d831a7aff5dd0edd31de2bae1d870f17ca945e:Scenarios/S2D and Stretch Cluster/readme.md

### Region Configure Fault Domains (commented - just an example)

<<<<<<< HEAD:Scenarios/AzSHCI and Stretch Cluster/readme.md
This part will just demonstrates simple XML. It is all commented since fault domains are automatically populated because cluster exists in two different sites.
=======
![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell03.png)

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin05.png)
>>>>>>> a1d831a7aff5dd0edd31de2bae1d870f17ca945e:Scenarios/S2D and Stretch Cluster/readme.md

### Region Enable Cluster S2D and check Pool and Tiers

Notice, that there are 2 separate pools created for each site. Also Naming convention changed.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell04.png)

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell05.png)

Notice, that Storage Tiers created twice (for each pool). This is also probably going to change in future releases.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell06.png)

### Region create volumes

In this region, multiple volumes will be created (2 data + 2 log volumes for each node). In single S2D cluster you want to have the same amount of virtual disks as you have nodes to evenly distribute workload. In this case, there is one virtual disk online on every node + it's replica + 2 log disks.

Notice, that in the code is Cluster Available Storage role moved to site, where virtual disks are being created.

You might want to configure smaller disks as all data needs to be replicated first.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin06.png)

### Region Enable SR for volumes

This code just makes sure, that disks of the same name are replicated to each other. In variables you can specify if it should be synchronous or asynchronous replica.

The code will also configure network constraints, so Storage Replica will use ReplicaNet01 and 02.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin07.png)

As you can see, Storage Replica Constraints are configured.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell07.png)
<<<<<<< HEAD:Scenarios/AzSHCI and Stretch Cluster/readme.md
=======

And also that volumes are being replicated. It also takes some time to finish.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell08.png)
>>>>>>> a1d831a7aff5dd0edd31de2bae1d870f17ca945e:Scenarios/S2D and Stretch Cluster/readme.md

And also here is neat script to validate replication status

<<<<<<< HEAD:Scenarios/AzSHCI and Stretch Cluster/readme.md
![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell08.png)
=======
![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/PowerShell09.png)
>>>>>>> a1d831a7aff5dd0edd31de2bae1d870f17ca945e:Scenarios/S2D and Stretch Cluster/readme.md


### Region create some VMs

In this region you might want to create NanoServer image first - thats because to have some small VM you can live migrate around your lab. Due to it's small size, it will not consume much in your lab - as all data quardruples (2-way mirror + Storage Replica to another 2-way mirror volume).

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/NanoServerCreation.gif)

Scenario script will ask you for VHDx, so you can just copy it to lab (or before deploying lab you could place it into tools.vhdx). After this region finishes, you will see 4 VMs running.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin08.png)

### Region move odd CSVs and it's respective VMs to site1 and even to site2

Script will move half of the VMs and CSVs to Site2 to evenly distribute workload.

Before

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin08.png)

After

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/Cluadmin10.png)

### Region configure Affinity rules

This region is just commented sample. It is not needed, since there is a watchdog that moves VMs to it's CSVs

### Region install Windows Admin Center Gateway

In this region will install Windows Admin Center into WACGW server and install Edge browser into Management machine. You can explore your Stretch  Cluster in fancy graphical interface. Notice, that script will also configure kerberos constrained delegation and will import WACGW self-signed certificate to local Trusted Root Certificates store, so https://wacgw will not return any error.

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/WAC01.png)

![](/Scenarios/AzSHCI%20and%20Stretch%20Cluster/Screenshots/WAC02.png)

### Region Register Azure Stack HCI with Azure

In this region your Azure Stack HCI cluster will be registered to Azure

