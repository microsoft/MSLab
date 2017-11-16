# Understanding Enable-ClusterS2D autoconfiguration

*Historically in Storage spaces you had to configure Pool. If you had NTFS tiered volume, you also had to create tiers. This relatively complex process already blogged on Jose Barreto blog. Life is now easier thanks to Enable-ClusterS2D autoconfiguration. However, there are still several scenarios when autoconfig must be disabled and all this must be configured the old way.*

## Pool

We recognize Primordial pool and named Pool. Primordial is list of disks, that are eligible to add to storage spaces. When you run wizard, or better, run PowerShell code, you will create named Pool. Enable-ClusterS2D automatically creates pool named "S2D on ClusterName"

**Primordial pools and list of eligible disks in Server Manager**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/ServerManagerPrimordialPool.png)


**Primordial pool in PowerShell**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/PrimardialPoolPowerShell.png)


**List of available disks in PowerShell**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/ListOfAvailDiskPowerShell.png)

When pool is created and disks are claimed, special partition is created to claim the space. This partition is called "Storage Spaces Protective Partition". On the below screenshot you can also see, that delete is greyed out. This is just to prevent accidental deletion. Normally you are not able to see this partition as when storage spaces are enabled, disk "disappears" from system. This is possible as it was mounted externally. Also notice, that the partition has the same name as Pool - in this case "S2D on S2D-Cluster" 

**Storage Spaces Protective Partition in disk management**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/SSProtectivePartition.png)

**Storage pool in PowerShell after Enable-ClusterS2D. Notice -CimSession. The command is running remotely against cluster S2D-Cluster.**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/PoolPowerShell.png)


## Tiers

Another piece, that is automatically created during Enable-ClusterS2D are tiers. Tier is just a template, that is copied when “Tiered” volume (also called virtual disk) is created. Tiered is quoted, as it is not really tiering, but volume can contain one, or two different sets of templates.
Following table summarizes what tiers are created depending on number of nodes in Windows Server 2016

Number of Fault Domains (nodes) | Capacity Media Types | Capacity Tier | Performance Tier
-|-|-|-
2| HDD | 2-way mirror
2| HDD & SSD |2-way mirror HDD | 2-way mirror SSD
3| HDD | 3-way mirro
3| HDD & SSD |3-way mirror HDD | 3-way mirror SSD
4+ | HDD | "Dual Parity" | 3-way mirror
4+ | HDD & SSD |  "Dual Parity" | 3-way SSD


**Tiers created in 4 node cluster with HDDs (notice 2 new "templates" as this is RS3 insider preview). PhysicalDiskRedundancy 2 means, that Mirror is 3-way mirror and Parity is "Dual Parity"**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/StorageTierListRS3.png)


## Enable-ClusterS2D inside Hyper-V

But wait, in Hyper-V all disks have MediaType Unknown! How is it possible as tiers definition says Mediatype HDD or SSD?

**Physical disk inside Virtual Machine in Hyper-V**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/pDISKInsideHyper-V.png)

If you run Enable-ClusterS2D in Hyper-V, the logic will take a look on physical disks and if MediaType is Unspecified, Manufacturer Msft and Model is Virtual Disk, it knows its running in Hyper-V and manually set MediaType to HDD.

**Disks in the pool inside 4 node s2d cluster running under Hyper-V**

![](/Scenarios/S2D%20on%20AWS%20and%20VMware/screenshots/S2DPoolHyper-V.png)

## Enable-ClusterS2D inside AWS or VMware

Until now, it was easy, but how about S2D clusters inside AWS or VMware? Enable-ClusterS2D will fail as it will not find any eligible disk as MediaType is unknown. Therefore, all needs to be specified manually.
The main difference is that during enable-clusters2d must be autoconfig disabled

```PowerShell
Enable-ClusterS2D -CimSession MyClusterName -Autoconfig:0
```

You can either invoke-command to create tiers into the servers, or register remote storage subsystem. In end-to-end [script](/Scenarios/S2D%20on%20AWS%20and%20VMware/scenario.ps1) is covered registering storage subsystem. Let's do it with invoking command instead.

```PowerShell
Invoke-Command -ComputerName MyClusterNode -ScriptBlock {
    #Create Pool
        $phydisks = Get-StorageSubSystem -FriendlyName *MyClusterName | Get-PhysicalDisk -CanPool $true
        $pool=New-StoragePool -FriendlyName  "S2D on MyClusterName" -PhysicalDisks $phydisks -StorageSubSystemFriendlyName *MyClusterName 
    #set mediatype to HDD
        $pool | get-physicaldisk | Set-PhysicalDisk -MediaType HDD
}
```
That’s it! I hope you enjoyed it.