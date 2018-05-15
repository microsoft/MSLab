<!-- TOC -->

- [Rolling Cluster Upgrade with Hyper-V Replica](#rolling-cluster-upgrade-with-hyper-v-replica)
    - [Scenario Description](#scenario-description)
    - [Scenario requirements](#scenario-requirements)
    - [LabConfig](#labconfig)
    - [Scenario Highlights](#scenario-highlights)

<!-- /TOC -->

# Rolling Cluster Upgrade with Hyper-V Replica

## Scenario Description

* In this scenario where you have 3 clusters on 2012R2 rolling to 2016. It simulates reinstalation of each node to 2016, but in this case both 2012 and 2016 have connected the same shared VHD.
* There is Hyper-V replica configured from Cluster1 to Cluster2 and extended to Cluster3 before rolling cluster upgrade
* for sake of complexity, networking is not configured


## Scenario requirements

* Windows Server 2016 with enabled Hyper-V (Windows 10 cannot run shared VHD -please backup [this](https://windowsserver.uservoice.com/forums/295056-storage/suggestions/32618456-add-shared-vhd-support-to-client-os) idea if you want to run it in win10)

* 16GB Memory 
* SSD (with HDD it is really slow)
* Windows 2012R2 VHD (you can create it using CreateParentDisk.ps1 located in Tools folder)

## LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'RCUHVRep-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; VMs=@()}

1..2 | ForEach-Object { $VMNames="S1_W2012_" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx' ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'RCU_Site1' ; Unattend="DjoinCred" } }
1..2 | ForEach-Object { $VMNames="S1_W2016_" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'RCU_Site1' } }
1..2 | ForEach-Object { $VMNames="S2_W2012_" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx' ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'RCU_Site2' ; Unattend="DjoinCred" } }
1..2 | ForEach-Object { $VMNames="S2_W2016_" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'RCU_Site2' } }
1..2 | ForEach-Object { $VMNames="S3_W2012_" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx' ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'RCU_Site3' ; Unattend="DjoinCred" } }
1..2 | ForEach-Object { $VMNames="S3_W2016_" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'RCU_Site3' } }
 
````

## Scenario Highlights

**Cluster nodes**
![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/Clusters2012R2.png)

**Cluster disks**
![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/Clusters2012R2disks.png)

**Cluster VMs**
![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/Clusters2012R2VMs.png)

**Hyper-V replica on Cluster2**
![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/ReplicationOnCluster2.png)

**Replication Health before Rolling Upgrade**
![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/ReplicationHealth.png)

**Replication Health after rolling Cluster2 and Cluster3**

Notice that there are 2 replication missed. But replication is healthy and on left are replication partners 2012 and 2016 servers

![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/ReplicationHealth2ClustersRolled.png)

**Replication folders before consolidation**

Notice that all VM files are under one folder

![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/VMStorageBeforeMove.png)

**Replication folders after consolidation**

All VMs are moved to its folders

![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/VMStorageAfterMove.png)

![](/Scenarios/Rolling%20Cluster%20Upgrade/RCU%20and%20Hyper-V%20Replica/Screenshots/VMStorageAfterMove1.png)
