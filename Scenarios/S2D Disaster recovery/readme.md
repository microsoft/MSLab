# Scenario Description

This scenario will simulate OS replacement in one node and then OS replacement in entire cluster. The only thing left will be disks. So entire environment will be rebuilt. 

You can watch this scenario in detail on YouTube [here](https://youtu.be/Gd9_rzePrhI) and [here](https://youtu.be/uTzXEFVd16o)

# LabConfig

Following LabConfig will create standard 4 node configuration. It will also create VMs with new OS. So we will not be reinstalling, we will just reuse OS VHDs that will be created using this script.

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 
$LabConfig.VMs += @{ VMName = 'S2D1NewOS' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB }
1..4 | % {$VMNames="NewS2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes= 512MB }}
 
````
**Deploy.ps1 result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/Deploy.ps1_result.png)

# One node OS failure simulation

Deploy [S2D Hyperconverged Scenario](/Scenarios/S2D%20Hyperconverged/) and turn off one node to simulate OS failure.

After successful deployment turn off node S2D1

````PowerShell
#run from the host
Stop-VM -VMName ws2016lab-s2d1 -TurnOff

````

**Result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/TurnOff_S2D1_result.png)
![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/result_turnoff_s2d1_cluadmin.png)

**you can also notice disks missing**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/missing_disks_in_pool.png)

As we are simulating OS failure, we will "reinstall" OS by just replacing OS vhd with vhd from S2D1NewOS VM.

````PowerShell
#run from the host
Get-VMHardDiskDrive -VMName ws2016lab-s2d1 | where Path -like *S2D1.vhdx | Remove-VMHardDiskDrive
$NewHardDisk=Get-VMHardDiskDrive -VMName ws2016lab-s2d1NewOS
Add-VMHardDiskDrive -VMName ws2016lab-s2d1 -Path $NewHardDisk.Path
Start-vm -VMName ws2016lab-s2d1
 
````

**Result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/OS_replaced_s2d1_result.png)

Run first 4 regions of s2d Hyper-Converged script again to configure basic settings and networking on S2D1NewOS machine. Just add line $servers="S2D1NewOS" between regions to let only new server configure

**Regions to run to configure S2D1NewOS machine**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/regions_to_run.png)

After node is configured, you can add it to cluster and remove the old one by running following commands

````PowerShell
Add-ClusterNode    -Cluster s2d-cluster -Name S2D1NewOS
Remove-ClusterNode -Cluster s2d-cluster -Name S2D1 -Force
 
````

**Result: Notice all disks are now healthy**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/pool_healthy_again.png)

The last step would be to modify fault domain xml (as we used it)

````PowerShell
$xml =  @"
<Topology>
        <Site Name="SEA" Description="" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
                <Rack Name="Rack01" Description="" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
                        <Node Name="S2D1NewOS" Description="" Location=""/>
                        <Node Name="S2D2" Description="" Location=""/>
                        <Node Name="S2D3" Description="" Location=""/>
                        <Node Name="S2D4" Description="" Location=""/>
                </Rack>
        </Site>
</Topology>
"@

Set-ClusterFaultDomainXML -XML $xml -CimSession s2d-cluster
 
````

**Result**
![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/OS_failure_recovery_result.png)

# All nodes OS failure simulation

This will simulate all OS lost (like all OS disks lost due to some catastrophic failure-like someone incorrectly targeted OS Deployment TS in SCCM, so imagine all your S2D nodes are running Win10 instead of Windows Server).

````PowerShell
#run from hyper-v host
Stop-VM -VMName ws2016lab-s2d* -TurnOff
 
````

Now, because you lost everything, lets replace OS on each S2D node with new one.

````PowerShell
#run from the host
#Remove First OS disks from nodes S2D1-S2D4
$VMNames=1..4 | % {"ws2016lab-S2D$_"}
foreach ($VMName in $VMNames){
    Remove-VMHardDiskDrive -VMName $VMName -ControllerNumber 0 -ControllerLocation 0 -ControllerType SCSI
}

#add new hard disks
$NewVHDs=Get-VMHardDiskDrive -VMName ws2016lab-news2d* | Sort-Object
$i=0
foreach ($VMName in $VMNames){
    Add-VMHardDiskDrive -VMName $VMName -Path $NewVHDs[$i].Path
    $i++
}
 
````

**Result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/NewOS_in_s2d_nodes.png)

Lets make this interesting. Because some Donkey mixed all disks lets reconnect it randomly to VMs :D

````PowerShell
#run from host to mix Disks
$VMNames=1..4 | % {"ws2016lab-S2D$_"}
1..20 | Foreach-Object {
    $VMs=$VMNames | Get-Random -Count 2
    #get some random disks
    $Disk1=Get-VMHardDiskDrive -VMName $VMs[0] | where controllerlocation -ge 1 | get-random
    $Disk2=Get-VMHardDiskDrive -VMName $VMs[1] | where controllerlocation -ge 1 | get-random
    $disk1Path=$disk1.Path
    $disk2Path=$disk2.Path
    Remove-VMHardDiskDrive -VMName $VMs[0] -ControllerLocation $disk1.ControllerLocation -ControllerType SCSI -ControllerNumber 0
    Remove-VMHardDiskDrive -VMName $VMs[1] -ControllerLocation $disk2.ControllerLocation -ControllerType SCSI -ControllerNumber 0
    Add-VMHardDiskDrive -VMName $VMs[0] -Path $Disk2Path
    Add-VMHardDiskDrive -VMName $VMs[1] -Path $Disk1Path
}

#turn on the VMs now
Start-VM -VMName $VMNames
 
````

**Mixed disks result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/mixed_disks_result.png)

Modify following values in LabConfig to create brand new cluster out of brand new OS.

````PowerShell
$ServersNamePrefix="NewS2D"
$ClusterName="S2D-Cluster1"
$CAURoleName="S2D-Clus1-CAU"
 
````

**Modified LabConfig region in Scenario script**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/modified_labconfig_region.png)

Continue with scenario. Run all regions, until enabling S2D (Labconfig->Create Fault Domains)

**Regions to run**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/regions_to_run_allnodes.png)

Now, after cluster is created, all is configured, you can enable-clusters2d. It will recognize drives and bring volumes online. Even I lost 2 disks somewhere when I was writing the scripts (notice only 46 disks were found)

````PowerShell
Enable-ClusterS2D -CimSession S2D-Cluster1 -confirm:0 -Verbose
 
````

**Result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/enable-clusterS2D_newcluster_result.png)
![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/Cluster_disks_in_new_cluster.png)

As you can see, volume paths and names are bit messed up. So let's make this right with following PowerShell script

````PowerShell
$ClusterName="S2D-Cluster1"
$ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name

#remove cluster disk from resources to be able to find correct ID
    Get-ClusterResource -Cluster $ClusterName | Where-Object ResourceType -eq "Physical Disk" | Remove-ClusterResource -Force

#add cluster disks and rename to standard naming, to be able to identify Virtual Disk Name
    $ClusterAvailableDisks=Get-ClusterAvailableDisk -Cluster $ClusterName
    foreach ($ClusterAvailableDisk in $ClusterAvailableDisks){
        $VirtualDisk=Get-VirtualDisk -CimSession $ClusterName | where ObjectID -like "*$($ClusterAvailableDisk.ID)*"
        $ClusterDisk=$ClusterAvailableDisk | Add-ClusterDisk
        $ClusterDisk.Name="Cluster Virtual Disk ($($VirtualDisk.FriendlyName))"
    }

#Add to CSV
    Get-ClusterResource -Cluster $ClusterName | Where-Object ResourceType -eq "Physical Disk" | Add-ClusterSharedVolume

#rename CSV(s) to match name
    Get-ClusterSharedVolume -Cluster $ClusterName | % {
        $volumepath=$_.sharedvolumeinfo.friendlyvolumename
        $newname=$_.name.Substring(22,$_.name.Length-23)
        Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
    }

#wait a bit
Start-Sleep 20

#import all VMs
    Invoke-Command -ComputerName $ClusterNodes[0] -ScriptBlock{
        get-childitem C:\ClusterStorage -Recurse | where {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
               Import-VM -Path $_.FullName -ErrorAction SilentlyContinue
        }
    }

#Add VMs as Highly available
    $VMnames=(Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name).Name
    foreach ($VMName in $VMnames){
        Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName -ErrorAction SilentlyContinue
    }
 
````

**Result**

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/cluster_disks_fixed.png)
![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/VMs_restored.png)

The very last step would be to optimize volumes to regain resiliency (as we mixed all devices)

````PowerShell
Get-StoragePool -CimSession s2d-cluster1 -FriendlyName s2d* | Optimize-StoragePool
 
````

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/rebalance.png)

To check job you can display it with following piece of script

````PowerShell
$ClusterName="S2D-Cluster1"
$jobs=(Get-StorageSubSystem -CimSession $ClusterName -FriendlyName Clus* | Get-StorageJob -CimSession $ClusterName)
if ($jobs){
    do{
        $jobs=(Get-StorageSubSystem -CimSession $ClusterName -FriendlyName Clus* | Get-StorageJob -CimSession $ClusterName)
        $count=($jobs | Measure-Object).count
        $BytesTotal=($jobs | Measure-Object BytesTotal -Sum).Sum
        $BytesProcessed=($jobs | Measure-Object BytesProcessed -Sum).Sum
        [System.Console]::Write("$count Storage Job(s) Running. GBytes Processed: $($BytesProcessed/1GB) GBytes Total: $($BytesTotal/1GB)               `r")
        Start-Sleep 10
    }until($jobs -eq $null)
}
 
````

![](/Scenarios/S2D%20Disaster%20recovery/Screenshots/rebalancejob.png)