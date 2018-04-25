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
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016labInsider17650-'; SwitchName = 'LabSwitch'; DCEdition='4'; CreateClientParent=$false ; ClientEdition='Enterprise'; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

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
## Scenario.ps1 result

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/VMs.png)

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/Disks.png)

## Test failover in Windows Server 2019 (insider preview)

https://blogs.technet.microsoft.com/filecab/2018/04/24/storage-replica-updates-in-windows-server-2019-insider-preview-build-17650/

You can run all code from DC

Format volumes and assign DriveLetters (so volumes are visible)

````PowerShell
New-Volume -DiskNumber 5 -FriendlyName "TestFailover" -FileSystem "REFS" -CimSession Replica1 -DriveLetter "T"
New-Volume -DiskNumber 5 -FriendlyName "TestFailover" -FileSystem "REFS" -CimSession Replica3 -DriveLetter "T"
 
````

Get SR Partnerships

````PowerShell
Get-SRGroup -CimSession stretch-cluster | select Name -ExpandProperty Replicas | ft Name, DataVolume,ReplicationMode,ReplicationStatus
 
````

![](/Scenarios/StorageReplica/Stretch_Cluster/screenshots/Replicas.png)

Mount

````PowerShell
Mount-SRDestination -ComputerName Replica3 -Name Data1Destination -TemporaryPath T:\ -Confirm:0
Mount-SRDestination -ComputerName Replica1 -Name Data2Destination -TemporaryPath T:\ -Confirm:0
 
````

Dismount

````PowerShell
Dismount-SRDestination -ComputerName Replica3 -Name Data1Destination -Confirm:0
Dismount-SRDestination -ComputerName Replica1 -Name Data2Destination -Confirm:0
 
````


