<!-- TOC -->

- [Storage Replica - Stretch Cluster scenario](#storage-replica---stretch-cluster-scenario)
    - [LabConfig for Windows Server 2016](#labconfig-for-windows-server-2016)
    - [Labconfig for Windows Server Insider](#labconfig-for-windows-server-insider)
    - [Scenario.ps1](#scenariops1)
        - [Region LabConfig](#region-labconfig)
        - [Region install features for management](#region-install-features-for-management)
        - [Region install roles and features to servers](#region-install-roles-and-features-to-servers)
        - [Region create and configure cluster](#region-create-and-configure-cluster)
        - [Region format disks](#region-format-disks)
        - [Region list storage and add paths to Diskconfig variable](#region-list-storage-and-add-paths-to-diskconfig-variable)
        - [Region rename cluster disk resources for easier identification](#region-rename-cluster-disk-resources-for-easier-identification)
        - [Region add Data disks to CSVs](#region-add-data-disks-to-csvs)
        - [Region enable replication](#region-enable-replication)
        - [Region Create VMs](#region-create-vms)
        - [Script result](#script-result)
    - [Test failover in Windows Server 2019 (insider preview)](#test-failover-in-windows-server-2019-insider-preview)
    - [Known issues](#known-issues)

<!-- /TOC -->

# Storage Replica - Stretch Cluster scenario

WORK IN PROGRESS

This scenario will set up stretch cluster, while some VMs are running in site1 and some in site2. All is replicated from site1 to site2 and from site 2 to site 1.

Additionally, you can test failover in Windows Server Insider

## LabConfig for Windows Server 2016

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'SR-'; SwitchName = 'LabSwitch'; DCEdition='4';AdditionalNetworksConfig=@();VMs=@()}

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

#$LabConfig.VMs += @{ VMName = 'WAC' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True }

1..2 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'  ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 2; SSDSize=200GB ; HDDNumber = 2  ; HDDSize= 2TB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSite1' ; NestedVirt=$True ; AdditionalNetworks = $True} }
3..4 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'  ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 2; SSDSize=200GB ; HDDNumber = 2  ; HDDSize= 2TB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSite2' ; NestedVirt=$True ; AdditionalNetworks = $True} }
 
````

## Labconfig for Windows Server Insider

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider17650-'; SwitchName = 'LabSwitch'; DCEdition='4'; CreateClientParent=$false ; ClientEdition='Enterprise'; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

#$LabConfig.VMs += @{ VMName = 'WAC' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True }

1..2 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'  ; ParentVHD = 'Win2019Core_17650.vhdx'  ; SSDNumber = 2; SSDSize=200GB ; HDDNumber = 3  ; HDDSize= 2TB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSite1' ; NestedVirt=$True ; AdditionalNetworks = $True} }
3..4 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'  ; ParentVHD = 'Win2019Core_17650.vhdx'  ; SSDNumber = 2; SSDSize=200GB ; HDDNumber = 3  ; HDDSize= 2TB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSite2' ; NestedVirt=$True ; AdditionalNetworks = $True} }

$LabConfig.ServerVHDs += @{
    Edition="4"
    VHDName="Win2019_17650.vhdx"
    Size=60GB
}
$LabConfig.ServerVHDs += @{
    Edition="3"
    VHDName="Win2019Core_17650.vhdx"
    Size=30GB
}
 

````
## Scenario.ps1

Collapsed sections in scenario.ps1 (ctrl+m in PowerShell ISE)
![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/ScenarioCollapsed.png)

### Region LabConfig

You will be asked for VHD for VMs that will be created. The smallest and most convenient is NanoServer image. Just copy it over and select.

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/VHDPrompt.png)

### Region install features for management

This region is same as in other scenarios. Just checks for RSAT/RSAT features and if missing, it will install it (or notify on Win10)

### Region install roles and features to servers

This region installs SR and Hyper-V to destination servers. In the end, it reboots all.

### Region create and configure cluster

This region creates cluster, configures fault domains, renames replica network and creates and configures file share witness on DC

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/Witness.png)

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/FaultDomains.png)

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/ReplicaNetwork.png)

### Region format disks

Disks will be formatted and will populate in cluster as available storage

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/FormatDisksResult.png)

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/FormatDisksResultCluadmin.png)

### Region list storage and add paths to Diskconfig variable

DiskConfig variable Before

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/DiskConfigBefore.png)

DiskConfig variable After

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/DiskConfigAfter.png)

### Region rename cluster disk resources for easier identification

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/DiskRenameBefore.png)

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/DiskRenameAfter.png)

### Region add Data disks to CSVs

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/DisksInCSVs.png)

### Region enable replication

In this region SR is configured and also SR constraint is added to Replica network.

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/SRStatus.png)


### Region Create VMs

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/VMs.png)

### Script result

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/FinishedScript.png)

## Test failover in Windows Server 2019 (insider preview)

https://blogs.technet.microsoft.com/filecab/2018/04/24/storage-replica-updates-in-windows-server-2019-insider-preview-build-17650/

You can run all code from DC

Format disks, and rename it in cluster

````PowerShell
#Format Disks
New-Volume -DiskNumber 5 -FriendlyName "TestFailoverSite1" -FileSystem ReFS -CimSession Replica1 -ErrorAction SilentlyContinue
New-Volume -DiskNumber 5 -FriendlyName "TestFailoverSite2" -FileSystem ReFS -CimSession Replica3 -ErrorAction SilentlyContinue

#function to rename Cluster disks
function Rename-ClusterDisk ($ClusterName,$FileSystemLabel,$ClusterNodeName,$NewName){
    #move available disks to $ClusterNodeName
    if ((Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage").OwnerNode -ne $ClusterNodeName){
        Move-ClusterGroup -Cluster $ClusterName -Name "Available Storage" -Node $ClusterNodeName
    }
    $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        if (Get-Disk -CimSession $ClusterNodeName | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume | where filesystemlabel -eq $FileSystemLabel){
            $ClusterDiskName=$DiskResource.name
        }
    }
    (Get-ClusterResource -Cluster $ClusterName -name $ClusterDiskName).Name=$NewName
}

#rename TestFailoverSite1 and TestFailoverSite2 disks
Rename-ClusterDisk -ClusterName Stretch-Cluster -FileSystemLabel TestFailoverSite1 -clusternodename Replica1 -NewName TestFailoverSite1
Rename-ClusterDisk -ClusterName Stretch-Cluster -FileSystemLabel TestFailoverSite2 -clusternodename Replica3 -NewName TestFailoverSite2
 
````

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/FailoverDisksRenamed.png)

Get SR Partnerships

````PowerShell
Get-SRGroup -CimSession stretch-cluster | select Name -ExpandProperty Replicas | ft Name, DataVolume,ReplicationMode,ReplicationStatus,IsMounted
 
````

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/Replicas.png)

Mount

````PowerShell
Function Mount-SRDestinationClusterDisk ($ClusterName,$ClusterNodeName,$RGName,$ClusterDiskName,$DriveLetter){
    #move available disks to $ClusterNodeName
    if ((Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage").OwnerNode -ne $ClusterNodeName){
        Move-ClusterGroup -Cluster $ClusterName -Name "Available Storage" -Node $ClusterNodeName
    }

    #move clustergroup to $clusterNodeName be able to see mounted disk online on that node
    $PartitionID=(Get-SRGroup -CimSession $ClusterName | where Name -eq $RGName).Replicas.PartitionId
    $Partition=get-disk -CimSession $ClusterNodeName | Get-Partition | where GUID -eq "{$partitionID}"
    $DiskGuid=$Partition.DiskID.Replace("\\?\Disk","")
    $ClusterResourceName=Get-ClusterResource -Cluster $clustername | where resourcetype -eq "Physical Disk" | Get-ClusterParameter | where value -eq $DiskGuid
    $ClusterResourceName.ClusterObject.OwnerGroup | Move-ClusterGroup -Node $ClusterNodeName

    #grab disk with specified name
    $DiskIDGuid = Get-ClusterResource -Cluster $ClusterName -Name $ClusterDiskName | Get-ClusterParameter DiskIdGuid
    #Find path
    $path=(Get-Disk -CimSession $ClusterNodeName | where Guid -eq $DiskIDGuid.Value | Get-Partition | Get-Volume).path
    #MountSRDestination
    Mount-SRDestination -ComputerName $ClusterNodeName -Name $RGName -TemporaryPath $path -Confirm:0
    #assign letter to SRDestination path
    $DataVolumePath=(Get-SRGroup -CimSession $ClusterName | where Name -eq $RGName).Replicas.DataVolume
    $partition=get-volume -CimSession $clusterNodeName | where path -eq $DataVolumePath | get-partition
    if ($partition.Driveletter -and $partition.driveletter -ne $driveletter){
        $partition | Set-Partition -NewDriveLetter $DriveLetter
    }elseif (-not $partition.driveletter){
        $partition | Add-PartitionAccessPath -AccessPath "$($DriveLetter):\"
    }

}

#mount cluster disk. Just make sure DriveLetter is not used. No error will be thrown. Needs to be different for each volume mounted.
Mount-SRDestinationClusterDisk -ClusterName stretch-cluster -ClusterNodeName replica3 -RGName Data1Destination -ClusterDiskName TestFailoverSite2 -DriveLetter M
Mount-SRDestinationClusterDisk -ClusterName stretch-cluster -ClusterNodeName replica1 -RGName Data2Destination -ClusterDiskName TestFailoverSite1 -DriveLetter N
 
````

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/FailoverDisksMounted.png)


Dismount

````PowerShell
#to dismount destination without errors its needed to move available storage to the same site as SRDestination Volume
Move-ClusterGroup -Cluster stretch-cluster -Name "Available Storage" -Node Replica3
Dismount-SRDestination -ComputerName Replica3 -Name Data1Destination -Confirm:0
#to be able to move available storage to another site (where first disk is not connected), disk TestFailoverSite1 needs to be Offlined.
(Get-ClusterResource -Cluster stretch-cluster | where ownergroup -eq "Available Storage") | Stop-ClusterResource
Move-ClusterGroup -Cluster stretch-cluster -Name "Available Storage" -Node Replica1
Dismount-SRDestination -ComputerName Replica1 -Name Data2Destination -Confirm:0
 
````

## Known issues

VMs refuses to be created before replication is enabled in insider preview. So scenario script creates VMs after SR is enabled. Following snip is from version of script, where VMs were created before enabling SR

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/VMsNotCreated.png)

