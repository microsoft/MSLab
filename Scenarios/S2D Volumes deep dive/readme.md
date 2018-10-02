<!-- TOC -->

- [S2D Volumes deep dive](#s2d-volumes-deep-dive)
    - [LabConfig](#labconfig)
    - [About the lab](#about-the-lab)
    - [Prereq](#prereq)
    - [The lab](#the-lab)
    - [New-Volume](#new-volume)
    - [Tiers](#tiers)
        - [Introduction to tiers](#introduction-to-tiers)
        - [Capacity and Performance tiers](#capacity-and-performance-tiers)
        - [MirrorOnSSD/HDD ParityOnSSD/HDD tiers](#mirroronssdhdd-parityonssdhdd-tiers)
        - [Creating volumes with tiers](#creating-volumes-with-tiers)
        - [Creating your own tier](#creating-your-own-tier)
    - [Nested resiliency volumes](#nested-resiliency-volumes)
        - [Create Nested tiers](#create-nested-tiers)
        - [Create Nested Volume](#create-nested-volume)
    - [Displaying volumes](#displaying-volumes)
    - [Resizing volumes](#resizing-volumes)
        - [Resize volume without tiers](#resize-volume-without-tiers)
        - [Resize volume with tiers](#resize-volume-with-tiers)
    - [Bonus - Creating virtual disk old style](#bonus---creating-virtual-disk-old-style)

<!-- /TOC -->

# S2D Volumes deep dive

## LabConfig

```PowerShell
#Labconfig is same as insider preview, just with both SSDs and HDDs
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider-'; SwitchName = 'LabSwitch'; DCEdition='4' ; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | % {$VMNames="4node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17744.vhdx'; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}

1..2 | % {$VMNames="2node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17744.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 8; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}

#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'WinAdminCenter' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }

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

## About the lab

This lab is deep dive into volumes, tiers and pools. You will deploy 2 node and 4 node system to see difference between created tiers. Scoped volumes and Fault Domains are covered in different labs. 2 node system will simulate 1 capacity tier (HDDs) while 4 node system will simulate 2 capacity tiers (ssds, hdds).

If you find this information confusing, please forget it and just use Windows Admin Center. It takes in account (almost) all of these options.

Run all scripts from DC or management machine.

## Prereq

Run following script to configure necessary. Note: it's way simplified (no networking, no best practices, no CAU, no Hyper-V...).

```PowerShell
# LabConfig
    $Clusters=@()
    $Clusters+=@{Nodes=1..4 | % {"4node$_"} ; Name="4nodeCluster" ; IP="10.0.0.111" }
    $Clusters+=@{Nodes="2node1","2node2" ; Name="2nodeCluster" ; IP="10.0.0.112"}

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }

# Install features on servers
    Invoke-Command -computername $Clusters.nodes -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell"
    }

#create cluster
    foreach ($Cluster in $Clusters){
        New-Cluster -Name $cluster.Name -Node $Cluster.Nodes -StaticAddress $cluster.IP
        Start-Sleep 5
        Clear-DNSClientCache
    }

#add file share witness
     foreach ($Cluster in $Clusters){
        $ClusterName=$Cluster.Name
        #Create new directory
            $WitnessName=$ClusterName+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$($ClusterName)$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
     }
#Enable S2D
    Enable-ClusterS2D -CimSession $Clusters.Name -Verbose -Confirm:0

#Modify tiers and mediatype to simulate 3 tier system
    $4nodeCluster=($clusters | Where-Object {$_.nodes.count -eq 4}).Name
    #Modify media type
    invoke-command -computername $4nodeCluster -scriptblock {
    get-physicaldisk | where size -eq 800GB | set-physicaldisk -mediatype SSD
}

    #modify performance tier media type to SSD
    Set-StorageTier -CimSession $4nodeCluster -FriendlyName Performance -MediaType SSD
 
```

## The lab

Let's introduce various ways how to create volume. All tasks will be done from DC or management machine.

## New-Volume

The simplest way to create volume in Windows Server 2019 (not available in 2016), is just to run new-volume with name and size parameters. However this does not work remotely.

```PowerShell
#new volume with Cimsession
New-Volume -FriendlyName MyVolume -Size 1TB -CimSession 2nodeCluster

#new volume invoked
Invoke-Command -ComputerName 2nodeCluster -scriptblock {New-Volume -FriendlyName MyVolume -Size 1TB}
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/SimplestCommand.png)

As you can see, the above command is creating 1TB CSV. Let's take a look what other parameters are there with command Get-VirtualDisk. You may ask, why not get-volume? Why Virtual disk? It's because originally (in 2012 days), volume was created with new-virtualdisk command and then it was needed to format it, add to CSV and then rename mountpoint. We will get back to this.

OK, so to get all volume information you can run following command

```PowerShell
Get-VirtualDisk -CimSession 2nodeCluster -FriendlyName MyVolume
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/GetVirtualDisk.png)

You can notice, that information presented with this command is much better than it used to be in Windows Server 2016 as [showprettyvolume](https://blogs.technet.microsoft.com/filecab/2016/08/29/deep-dive-volumes-in-spaces-direct/) is now built-in.

From values you can see, that it's 2-way mirror and it's healthy.

To be able to see all attributes, you can run following command

```PowerShell
Get-VirtualDisk -CimSession 2nodeCluster -FriendlyName MyVolume | fl *
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/GetVirtualDisk1.png)

Notice few attributes, that defines resiliency: 
* NumberOfDatacopies (2=2-way Mirror, 3=3-way Mirror)
* PhysicalDiskRedundancy (1=2-way Mirror, 2=3-way Mirror)
* ResiliencySettingName (Mirror or Parity)

The complete command in 2016 would be following

```PowerShell
New-Volume -StoragePoolFriendlyName S2D* -FriendlyName MyVolume -FileSystem CSVFS_ReFS -Size 1TB -ResiliencySettingName Mirror -CimSession 2nodeCluster
 
```

Let's try the same, but now on 4NodeCluster

```PowerShell
Invoke-Command -ComputerName 4nodeCluster -scriptblock {New-Volume -FriendlyName MyVolume -Size 1TB}
 
```

I can now tell you, that what we did is wrong. Let me explain why. In 4NodeCluster we have 2 capacity tiers. We have both SSDs and HDDs available. Let's explore, where are slabs located.

```PowerShell
Get-VirtualDisk -CimSession 4nodeCluster -FriendlyName MyVolume | get-physicaldisk -CimSession 4nodeCluster
 
```

That's not good! You can see, that volume spans all disks - both HDDs and SSDs.

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/GetVirtualDisk2.png)

So for most cases, just new-volume works great. But to be sure, you should use commands like this

```PowerShell
New-Volume -StoragePoolFriendlyName S2D* -FriendlyName MyVolumeSSDs -FileSystem CSVFS_ReFS -Size 100GB -ResiliencySettingName Mirror -MediaType ssd -CimSession 4nodeCluster
 
```

As you can see, this Virtual disk is using SSDs only.

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/GetVirtualDisk3.png)

## Tiers

### Introduction to tiers

If you want to use some templates to create volumes (if you dont want to repeat what resiliencysettingname, mediatype, faultdomain... should be used), you can use templates we call tiers. We introduced tiers in Windows Server 2012 R2, to be able to create virtual disk with NTFS tiering. It made sense to call it tiers then. In Windows Server 2016 we introduced ReFS real time tiering, that was again confusing, so we prefer to call it Mirror-Accelerated parity (MAP). For both NTFS tiering and MAP it's necessary to use these templates. It's not much known, that you can use tiers also for creating regular virtual disks.

There is another confusing part, which is tiers naming. In Windows Server 2016, we used Capacity and Performance tier. However we also started calling physical disks Capacity Media (this defines capacity) and Performance media (this is S2D cache) and these are 2 different worlds.

And to be even more confusing, Performance was most of the time Mirror, but sometimes Capacity tier was also mirror.

So let's deep dive into this topic little bit more.

### Capacity and Performance tiers

Attributes of each tier depends on 2 factors. If it's 2-3 node system or 4+node system and also if 1 or 2 capacity mediatypes are used.

* For 2-3 node systems with 1 capacity mediatype (just SSDs or just HDDs for capacity) is Capacity tier only created.

* For 2-3 node systems with 2 capacity mediatype (SSDs and HDDs for capacity) are both Performance and Capacity tiers created. Both have mirror resiliency, but MediaType differs. (Performance=SSDs,Capacity=HDDs)

* for 4+ node systems is always Performance mirror and Capacity parity. If 2 capacity tiers are used, then faster is Performance (SSD) and slower is Capacity (HDD)

### MirrorOnSSD/HDD ParityOnSSD/HDD tiers

To help with confusion we introduced new tiers in Windows Server 2019.

```PowerShell
Get-StorageTier -CimSession 2nodecluster
Get-StorageTier -CimSession 4nodecluster
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/StorageTiers.png)

### Creating volumes with tiers

To create simple mirror volume using tier you can run following command

```PowerShell
#2node system
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName MyVolume1 -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes 1TB -CimSession 2nodecluster

#4node system, volume on SSD
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName MyVolume1 -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Performance -StorageTierSizes 100GB -CimSession 4nodecluster
#or alternatively
#New-Volume -StoragePoolFriendlyName s2d* -FriendlyName MyVolume1 -FileSystem CSVFS_ReFS -StorageTierFriendlyNames MirrorOnSSD -StorageTierSizes 1TB -CimSession 4nodecluster

#4node system, volume on HDD (capacity tier is Parity, MirrorOnHDD is used)
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName MyVolume1 -FileSystem CSVFS_ReFS -StorageTierFriendlyNames MirrorOnHDD -StorageTierSizes 1TB -CimSession 4nodecluster
 
```

To create Mirror-Accelerated parity volume you can run following command

```PowerShell
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName MAP -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Performance,Capacity -StorageTierSizes 500GB,2TB -CimSession 4nodecluster
 
```

Or in case you would like to create SSD/HDD volume with mirror only, it might make sense to use new tier names.

```PowerShell
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName MirrorMirror -FileSystem CSVFS_ReFS -StorageTierFriendlyNames MirrorOnSSD,MirrorOnHDD -StorageTierSizes 500GB,2TB -CimSession 4nodecluster
 
```

### Creating your own tier

Sometimes it might make sense to create your own tier. Like you would like to have 4-way mirror on HDDs (not tested in production)

```PowerShell
New-StorageTier -StoragePoolFriendlyName s2d* -FriendlyName 4wayMirror -MediaType HDD -ResiliencySettingName Mirror -NumberOfDataCopies 4 -CimSession 4nodecluster
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName 4wayMirror -FileSystem CSVFS_ReFS -StorageTierFriendlyNames 4wayMirror -StorageTierSizes 2TB -CimSession 4nodecluster
 
```

## Nested resiliency volumes

As announced on Ignite 2018, on 2 node configurations is possible to create "special volumes" that can tolerate multiple failures. Let's create some.

### Create Nested tiers

```PowerShell
#create NestedMirror tier
New-StorageTier -StoragePoolFriendlyName S2D* -FriendlyName NestedMirror -ResiliencySettingName Mirror -NumberOfDataCopies 4 -MediaType HDD -CimSession 2nodecluster

#create NestedParity tier
New-StorageTier -StoragePoolFriendlyName S2D* -FriendlyName NestedParity -ResiliencySettingName Parity -NumberOfDataCopies 2 -PhysicalDiskRedundancy 1 -NumberOfGroups 1 -FaultDomainAwareness StorageScaleUnit -ColumnIsolation PhysicalDisk -MediaType HDD -CimSession 2nodecluster
 
```

### Create Nested Volume

```PowerShell
#Create Mirror Nested Volume
New-Volume -StoragePoolFriendlyName S2D* -FriendlyName MyMirrorNestedVolume -StorageTierFriendlyNames NestedMirror -StorageTierSizes 500GB -CimSession 2nodecluster

#Create Parity Nested Volume
New-Volume -StoragePoolFriendlyName S2D* -FriendlyName MyParityNestedVolume -StorageTierFriendlyNames NestedMirror,NestedParity -StorageTierSizes 200GB, 1TB -CimSession 2nodecluster
 
```

## Displaying volumes

To display volumes you can use get-virtualdisk or get-storagetier (bit confusing, isn't it? :) )

```PowerShell
get-virtualdisk -CimSession 2nodecluster,4nodecluster
get-storagetier -CimSession 2nodecluster,4nodecluster
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/GetVirtualDisk4.png)

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/GetStorageTier.png)

## Resizing volumes

To resize volumes it might seem simple, but it's not. It depends if you use tiers or not. We have great documentation located [here](https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/resize-volumes)

### Resize volume without tiers

First is needed to resize virtual disk itself

```PowerShell
Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MyVolumeSSDs
Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MyVolumeSSDs | Resize-VirtualDisk -Size 150GB
Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MyVolumeSSDs
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/Resize.png)

The second step is to resize partition

```PowerShell
# Choose virtual disk
$VirtualDisk = Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MyVolumeSSDs

# Get its partition
$Partition = $VirtualDisk | Get-Disk | Get-Partition | Where PartitionNumber -Eq 2

# Resize to its maximum supported size 
$Partition | Resize-Partition -Size ($Partition | Get-PartitionSupportedSize).SizeMax

# Display result
$VirtualDisk | Get-Disk | Get-Partition | Where PartitionNumber -Eq 2
 
```

### Resize volume with tiers

To resize volume with tiers it's bit more tricky as instead of resizing virtual disk itself, you need to resize tiers. Let's demonstrate resizing on 2 different volumes - MAP and MyVolume1

```PowerShell
Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MyVolume1 | Get-StorageTier
Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MAP | Get-StorageTier
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/ResizingTiers1.png)

Let's resize MyVolume1 first

```PowerShell
# Choose virtual disk
$VirtualDisk = Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MyVolume1
# resize tier (as there is only one, following command can be used)
$VirtualDisk | Get-StorageTier | resize-storagetier -Size 150GB
# Get its partition
$Partition = $VirtualDisk | Get-Disk | Get-Partition | Where PartitionNumber -Eq 2
# Resize to its maximum supported size 
$Partition | Resize-Partition -Size ($Partition | Get-PartitionSupportedSize).SizeMax
# Display result
$VirtualDisk | Get-Disk | Get-Partition | Where PartitionNumber -Eq 2
 
```
![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/ResizingTiers2.png)

And now let's resize MAP

```PowerShell
# Choose virtual disk
$VirtualDisk = Get-VirtualDisk -CimSession 4nodecluster -FriendlyName MAP
# grab tiers
$tiers=$VirtualDisk | Get-StorageTier | Sort Size
#resize smaller tier
$tiers[0] | resize-storagetier -Size 550GB
#resize larger tier
$tiers[1] | resize-storagetier -Size 2.2TB
# Get its partition
$Partition = $VirtualDisk | Get-Disk | Get-Partition | Where PartitionNumber -Eq 2
# Resize to its maximum supported size 
$Partition | Resize-Partition -Size ($Partition | Get-PartitionSupportedSize).SizeMax
# Display result
$VirtualDisk | Get-Disk | Get-Partition | Where PartitionNumber -Eq 2
 
```

![](/Scenarios/S2D%20Volumes%20deep%20dive/Screenshots/ResizingTiers3.png)

## Bonus - Creating virtual disk old style

As I mentioned in beginning, if there is get-virtualdisk, there must be also new-virtualdisk. So let's deep dive into that one.

Let's first create virtual disk. Notice, I'm using full storagepoolfriendlyname. In 2012R2 times this was even harder as StoragePoolFriendlyName did not exist and you had to store it in variable too.

```PowerShell
$ClusterName="4NodeCluster"
$vDiskName="MirrorAcceleratedParity"
$performancetier=get-storagetier -cimsession "4NodeCluster" -friendlyname Performance
$capacitytier=get-storagetier -cimsession "4NodeCluster" -friendlyname Capacity
$virtualDisk = New-VirtualDisk -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $vDiskName -StorageTiers $performancetier,$capacitytier -StorageTierSizes 0.5TB,4TB -CimSession $ClusterName
 
```

Since it was virtual disk only, it was not formatted. So you needed to create partition and format it. Since it was already added to cluster, cluster resource had to be suspended.

```PowerShell
$virtualDisk | get-disk | New-Partition -UseMaximumSize
Get-ClusterResource -Cluster $ClusterName -Name "Cluster Virtual Disk ($vDiskName)" | Suspend-ClusterResource
$virtualdisk | Get-Disk | Get-Partition | get-volume | Initialize-Volume -FileSystem REFS -AllocationUnitSize 4KB -NewFileSystemLabel $vdiskname -confirm:$False
Get-ClusterResource -Cluster $ClusterName -Name "Cluster Virtual Disk ($vDiskName)" | Resume-ClusterResource
Get-ClusterResource -Cluster $ClusterName -Name "Cluster Virtual Disk ($vDiskName)" | Add-ClusterSharedVolume

```

Thanks to Cosmos Darwin and his team, in 2019 there is no need to rename CSV path as it inherits volume name. In 2016 you needed to rename it. Let me also show script for renaming.

```PowerShell
$CSV=Get-ClusterSharedVolume -Cluster $ClusterName -Name "Cluster Virtual Disk ($vDiskName)"
$volumepath=$CSV.sharedvolumeinfo.friendlyvolumename
$newname=$CSV.name.Substring(22,$CSV.name.Length-23)
$CSV_Owner=(Get-ClusterSharedVolume -Cluster $ClusterName -Name $CSV.Name).ownernode
Invoke-Command -ComputerName $CSV_Owner -ScriptBlock {Rename-Item -Path $using:volumepath -NewName $using:newname} -ErrorAction SilentlyContinue
 
```

That's it! I hope you enjoyed.