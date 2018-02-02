<!-- TOC -->

- [About the scenario](#about-the-scenario)
    - [Description](#description)
    - [Scenario requirements](#scenario-requirements)
- [LabConfig.ps1](#labconfigps1)
- [The lab](#the-lab)
- [The Good](#the-good)
    - [Simulate the failure of primary datacenter](#simulate-the-failure-of-primary-datacenter)
    - [Flip replication and import VMs on second cluster](#flip-replication-and-import-vms-on-second-cluster)
- [The Bad](#the-bad)
    - [Simulate some "nice" Admin who will plug cable back in first datacenter without any isolation](#simulate-some-nice-admin-who-will-plug-cable-back-in-first-datacenter-without-any-isolation)
    - [Possible mitigation - no autostart for VMs](#possible-mitigation---no-autostart-for-vms)
- [The Ugly](#the-ugly)
    - [Set the things right 1 - set replication to rewrite first DC that failed](#set-the-things-right-1---set-replication-to-rewrite-first-dc-that-failed)
    - [Set the things right 2 - shutdown VMs from Site1 on Site2 and flip replication](#set-the-things-right-2---shutdown-vms-from-site1-on-site2-and-flip-replication)
    - [Set the things right 3 - cleanup failed resources and import machines](#set-the-things-right-3---cleanup-failed-resources-and-import-machines)

<!-- /TOC -->

# About the scenario

## Description
* In this scenario will be 2 s2d clusters created
* it is "complex" as it will create 4 volumes (2x Data and 2x Log volumes in each cluster), create VMs on each site and replicate VMs from first to second site and second to first.
* Nanoservers are used as its just smaller and faster
* Labscript takes 30-50 minutes to finish.

## Scenario requirements

* Windows 10 1511 with enabled Hyper-V or Windows 10 1607+ (ne)
* 20+ GB RAM is required for this scenario
* SSD (with HDD it is really slow)


# LabConfig.ps1

in following labconfig you can see, that 4 machines are created. There is also additional network (ReplicaNet1), that will be used as network for Storage Replica.

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$false ; CreateClientParent=$true}

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.2.'; NetVLAN='0'; Subnet='255.255.255.0'}

1..2 | % { $VMNames="Site1-S2D"     ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ;NestedVirt=$True;AdditionalNetworks=$True } } 
1..2 | % { $VMNames="Site2-S2D"     ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ;NestedVirt=$True; AdditionalNetworks=$True } } 
 
````
**Deploy.ps1 result**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/lab.png)

# The lab

The lab begins with setting up two s2d clusters. It's not following all best practices (for all best practices see [S2D Hyperconverged Scenario page](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged) )

Continue with [Scenarip.ps1](/Scenarios/StorageReplica/S2D_to_S2D_Complex/scenario.ps1) script while reading comments.

**Cluster disks**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/clusterdisks.png)

**Cluster networks**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/clusternetworks.png)

**Cluster resources**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/VMs.png)

# The Good

## Simulate the failure of primary datacenter

````PowerShell
#run from Hyper-V host to pause VMs in site1
Suspend-VM -Name *site1*
 
````

**Result**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/pausedVMs.png)

## Flip replication and import VMs on second cluster

````PowerShell
#Variables
    $Cluster1Name="Site1-SR-Clus"
    $Cluster2Name="Site2-SR-Clus"
    $SourceRGName="Data1-Site2"
    $DestinationRGName="Data1-Site1"

#Flip replication
    Set-SRPartnership -NewSourceComputerName $Cluster2Name -SourceRGName $SourceRGName -DestinationComputerName $Cluster1Name -DestinationRGName $DestinationRGName -confirm:$false

#Import all VMs on Site2
    Invoke-Command -ComputerName (get-clusternode -cluster $Cluster2Name).Name[0] -ScriptBlock{
        get-childitem C:\ClusterStorage\Data1 -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
            Import-VM -Path $_.FullName
        }
    }

#Add VMs as Highly available and Start
    $VMnames=(Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name | where path -like *Data1*).Name
    $VMNames | ForEach-Object {Add-ClusterVirtualMachineRole -VMName $_ -Cluster $Cluster2Name}
    Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name | where path -like *Data1* | Start-VM
 
````
**Note:** the set-srpartnership will return warning as cluster1 is offline and cannot be notified about replication flip.

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/flipWarning.png)

**Result**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/flipresultVMs.png)

# The Bad

## Simulate some "nice" Admin who will plug cable back in first datacenter without any isolation

````PowerShell
#run from Hyper-V host
Resume-VM -VMName *site1*
 
````

**Result: Active-Active DC**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/firstDConwithoutisolation.png)

## Possible mitigation - no autostart for VMs

It may not be enough if the outage will be due to network problem as VMs will be always running. Only for power outage the machines will not start.

````PowerShell
Get-VM -CimSession (Get-ClusterNode -Cluster Site2-SR-Clus).Name | Set-VM -AutomaticStartAction Nothing
 
````

# The Ugly

## Set the things right 1 - set replication to rewrite first DC that failed

All changes in primary datacenter will be discarted

````PowerShell
#Variables
    $Cluster1Name="Site1-SR-Clus"
    $Cluster2Name="Site2-SR-Clus"
    $SourceRGName="Data1-Site2"
    $DestinationRGName="Data1-Site1"

#Flip replication
    Set-SRPartnership -NewSourceComputerName $Cluster2Name -SourceRGName $SourceRGName -DestinationComputerName $Cluster1Name -DestinationRGName $DestinationRGName -confirm:$false
 
````

**Result**
![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/allinDC2.png)

VMs lost its storage, so all VMs went to "zombie" state.
![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/theuglythings.png)

Since VMs lost its storage, all actions will timeout.

## Set the things right 2 - shutdown VMs from Site1 on Site2 and flip replication

````PowerShell
#Variables
    $Cluster1Name="Site1-SR-Clus"
    $Cluster2Name="Site2-SR-Clus"
    $SourceRGName="Data1-Site1"
    $DestinationRGName="Data1-Site2"

#cleanup VMs
    #Shut down VMs on Data1 volume
    $VMs=Get-VM -Cimsession (Get-ClusterNode -Cluster $cluster2Name).Name | where path -like *data1*
    $VMs | Stop-VM

#Remove VMs from cluster resources
    Foreach ($VM in $VMs){
        Remove-ClusterGroup -Cluster $Cluster2Name -Name $VM.name -RemoveResources -Force
    }
#remove VMs and keep VM config
    Foreach ($VM in $VMs){
        invoke-command -computername $VM.ComputerName -ArgumentList $VM -scriptblock {
            param($VM);
            Copy-Item -Path "$($VM.Path)\Virtual Machines" -Destination "$($VM.Path)\Virtual Machines Bak" -recurse
            Get-VM -Id $VM.id | Remove-VM -force
            Copy-Item -Path "$($VM.Path)\Virtual Machines Bak\*" -Destination "$($VM.Path)\Virtual Machines" -recurse
            Remove-Item -Path "$($VM.Path)\Virtual Machines Bak" -recurse
        }
    }
#Flip replication
    Set-SRPartnership -NewSourceComputerName $Cluster1Name -SourceRGName $SourceRGName -DestinationComputerName $Cluster2Name -DestinationRGName $DestinationRGName -confirm:$false

````

Meanwhile VMs disappeared (or semi-disappered) but (some) cluster resources are still on Cluster1

````PowerShell
$Cluster1Name="Site1-SR-Clus"

#see that some VMs are gone
Get-VM -Cimsession (Get-ClusterNode -Cluster $Cluster1Name).Name

#see that there are some dead resources
Get-ClusterGroup -Cluster $Cluster1Name | where state -eq failed
 
````
![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/failedresourcesafterfliptoDC1.png)

## Set the things right 3 - cleanup failed resources and import machines

````PowerShell
$Cluster1Name="Site1-SR-Clus"
#Import all VMs on Site1
    Invoke-Command -ComputerName (get-clusternode -cluster $Cluster1Name).Name[0] -ScriptBlock{
        get-childitem C:\ClusterStorage\Data1 -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
            Import-VM -Path $_.FullName -ErrorAction SilentlyContinue
        }
    }

#perform proper cleanup of VMs located on Data1 volume
    $VMs=Get-VM -Cimsession (Get-ClusterNode -Cluster $Cluster1Name).Name | where Path -like *Data1*
    #Find VMs resources and remove
    foreach ($VM in $VMs){
        Get-ClusterGroup -Cluster $Cluster1Name | where Name -eq $VM.Name | Remove-ClusterGroup -RemoveResources -Force
    }
    #Backup VMs config and remove VMs from Hyper-V hosts.
    Foreach ($VM in $VMs){
        invoke-command -computername $VM.ComputerName -ArgumentList $VM -scriptblock {
            param($VM);
            Copy-Item -Path "$($VM.Path)\Virtual Machines" -Destination "$($VM.Path)\Virtual Machines Bak" -recurse
            $vms | Stop-VM -Force -ErrorAction SilentlyContinue #stop VM if its in paused critical state
            Get-VM -Id $VM.id | Remove-VM -force
            Copy-Item -Path "$($VM.Path)\Virtual Machines Bak\*" -Destination "$($VM.Path)\Virtual Machines" -recurse -ErrorAction SilentlyContinue
            Remove-Item -Path "$($VM.Path)\Virtual Machines Bak" -recurse
        }
    }
#Import VMs again
    Invoke-Command -ComputerName (get-clusternode -cluster $Cluster1Name).Name[0] -ScriptBlock{
        get-childitem C:\ClusterStorage\Data1 -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
            Import-VM -Path $_.FullName
        }
    }
#Add VMs as Highly available and Start
    $VMnames=(Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name | where path -like *Data1*).Name
    $VMNames | ForEach-Object {Add-ClusterVirtualMachineRole -VMName $_ -Cluster $Cluster1Name}
    Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name | where path -like *Data1* | Start-VM
 
````

**Result: All good again**

![](/Scenarios/StorageReplica/S2D_to_S2D_Complex/Screenshots/result-allgoodagain.png)
