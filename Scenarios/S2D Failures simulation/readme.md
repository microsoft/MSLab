# Scenario Description

This scenario will simulate disk failure and disk replacement in random node.

You can watch this scenario in detail on YouTube [tbd](http://aka.ms/ws2016labvideos)

**Prereq:** Deploy [S2D Hyperconverged Scenario](/Scenarios/S2D%20Hyperconverged/)

# Cluster status when healthy

````PowerShell
#Run from DC or Management machine

#grab SS
    $storagesubsystem=Get-StorageSubSystem -CimSession s2d-cluster -FriendlyName Cl*

#display storage subsystem
    $storagesubsystem

#debug storage subsystem
    $storagesubsystem | Debug-StorageSubSystem -CimSession s2d-cluster

#display action
    $storagesubsystem | Get-StorageHealthAction -CimSession s2d-cluster

#display virtual disks
    Get-VirtualDisk -CimSession s2d-cluster | Sort-Object FriendlyName
 
````

**Result**
Notice everything is healthy
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/S2D_Healthy.png)


# Pulling and returning random drive

## Pull random drive

**Note** keep this window open for returning the drive (to keep variables)

````PowerShell
#run from the host
    $DiskToPull=Get-VM -Name ws2016lab-s2d* | Get-VMHardDiskDrive | where ControllerLocation -ge 1 | Get-Random
    $DiskToPull
    $PulledDiskPath=$DiskToPull.Path
    $DiskToPull | Remove-VMHardDiskDrive
 
````

**Result**
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RandomDiskPulledResult.png)

Virtual disks will go immediately into warning state

````PowerShell
#Run from DC or Management machine

#display virtual disks
    Get-VirtualDisk -CimSession s2d-cluster | Sort-Object FriendlyName
 
````

![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RandomDiskPulledResult-VirtualDisks.png)

After some time, Health service will register the failure
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RandomDiskPulledResult-HealthService.png)


You can notice one disk is in lost communication state
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RandomDiskPulledResult-DiskLostCommunication.png)

````PowerShell
#Run from DC or Management machine

#list all disks from all nodes
$clusterName="S2D-Cluster"

$nodes=Get-StorageSubSystem -CimSession $clusterName -FriendlyName Clus* | Get-StorageNode
$disks=@()
foreach ($node in $nodes) {
    $disks+=Invoke-Command -ComputerName $node.Name -ArgumentList $node -ScriptBlock {
        param($node);
        $node | Get-PhysicalDisk -PhysicallyConnected
        }
     }

$disks | select PSComputerName,friendlyname,SerialNumber,healthstatus,OperationalStatus,CanPool,physicallocation,slotnumber | Out-GridView

<#or all attributes
$disks | select * | Out-GridView
#>
 
````

Notice disk is not present on node3
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RandomDiskPulledResult-DiskNotConnected1.png)

## Return disk

````PowerShell
#run from the host

#add disk back
    Add-VMHardDiskDrive -VMName $disktopull.VMName -Path $PulledDiskPath

````

**Result**
Virtual Disks will be healthy again
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/VirtualDisksHealthy.png)


Storage subsystem is healthy again (after ~5 minutes)
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/SSHealthy.png)

# Pulling disk again and replacing with different

````PowerShell
#run from the host to pull drive
    $DiskToPull=Get-VM -Name ws2016lab-s2d* | Get-VMHardDiskDrive | where ControllerLocation -ge 1 | Get-Random
    $DiskToPull
    $PulledDiskPath=$DiskToPull.Path
    $DiskToPull | Remove-VMHardDiskDrive
#add new drive
    $NewDiskPath="$(($PulledDiskPath).Substring(0,$PulledDiskPath.Length-5))_NEW.vhdx"
    New-VHD -Path $NewDiskPath -SizeBytes 4TB
    Add-VMHardDiskDrive -VMName $disktopull.VMName -Path $NewDiskPath
 
````

**result**
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/DiskReplaced.png)

**health in cluster**
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/HealthDiskReplaced.png)

**repair in progress**
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/HealthDiskReplacedRepairJob.png)

After some time Disk will be retired. You will see following job and actions.
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/PhysicalDiskRetired.png)

![](/Scenarios/S2D%20Failures%20simulation/Screenshots/PhysicalDiskRetiredJob.png)

![](/Scenarios/S2D%20Failures%20simulation/Screenshots/PhysicalDiskRetiredAction.png)

# Remove retired disk

```PowerShell
#Run from DC or Management machine

#remove failed disk (where usage is retired)
    $FailedDisk=Get-PhysicalDisk -CimSession s2d-cluster -Usage retired
    $FailedDisk
    $Pool=$FailedDisk | Get-StoragePool -CimSession s2d-cluster | where FriendlyName -like S2D*
    $Pool
    Remove-PhysicalDisk -StoragePool $pool -PhysicalDisks $FailedDisk
 
````

![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RemoveRetiredDisk.png)

Everything is healthy again
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RemoveRetiredDiskResult.png)

Notice that there is no output of debug-storagesubsystem anymore.
![](/Scenarios/S2D%20Failures%20simulation/Screenshots/RemoveRetiredDiskResult1.png)
