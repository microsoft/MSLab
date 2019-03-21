# S2D and Metadata deep dive

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

1..2 | % {$VMNames="2node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..3 | % {$VMNames="3node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..4 | % {$VMNames="4node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..5 | % {$VMNames="5node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..6 | % {$VMNames="6node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
 
```

## About the lab

This lab talks about Pool and Virtual Disks (S2D Volumes) metadata. It demonstrates how to display metadata and what different metadata configurations exist.

Run all scripts from DC. Run all code in same PowerShell window to keep variable $Clusters.

VMs will consume ~20GB RAM.

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/ListOfVMs.png)

## Prereq

```PowerShell
# variables
    $Clusters=@()
    $Clusters+=@{Nodes=1..2 | % {"2node$_"} ; Name="2nodeCluster" ; IP="10.0.0.112" }
    $Clusters+=@{Nodes=1..3 | % {"3node$_"} ; Name="3nodeCluster" ; IP="10.0.0.113" }
    $Clusters+=@{Nodes=1..4 | % {"4node$_"} ; Name="4nodeCluster" ; IP="10.0.0.114" }
    $Clusters+=@{Nodes=1..5 | % {"5node$_"} ; Name="5nodeCluster" ; IP="10.0.0.115" }
    $Clusters+=@{Nodes=1..6 | % {"6node$_"} ; Name="6nodeCluster" ; IP="10.0.0.116" }

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

#restart all servers since failover clustering in 2019 requires reboot
    Restart-Computer -ComputerName $Clusters.nodes -Protocol WSMan -Wait -For PowerShell

#create clusters
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
 
```

## Displaying Physical Disks Owners

With following script we can use PhysicalDisk description attribute to host owner node name.

```PowerShell
#Add host owner node name into PhysicalDisk description
foreach ($ClusterName in ($Clusters.Name | select -Unique)){
    #grab StorageNodes
    $StorageNodes=Get-StorageSubSystem -CimSession $clusterName -FriendlyName Clus* | Get-StorageNode

    #add owner node name to description
    foreach ($StorageNode in $StorageNodes){$StorageNode | Get-PhysicalDisk -PhysicallyConnected -CimSession $StorageNode.Name | Set-PhysicalDisk -Description $StorageNode.Name -CimSession $StorageNode.Name}
}
 
```

You can then easily view where are the disks located

```PowerShell
#Display physical disks in 2nodecluster
Get-PhysicalDisk -CimSession 2nodecluster |ft FriendlyName,Size,Description
 
```

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PhysicalDisks.png)

## Exploring Pool Metadata

In following PowerShell example notice -HasMetadata Parameter. This is new in Windows Server 2019. As you can see, number of metadata disks depends on size of the cluster

| Number of Fault domains (Nodes) | Number of Metadata Disks |
|:-------------------------------:| :-----------------------:|
|2                                |6                         |
|3                                |6                         |
|4                                |8                         |
|5                                |5                         |
|6                                |5                         |

```PowerShell
#display pool metadata
foreach ($ClusterName in ($Clusters.Name | select -Unique)){
    Get-StoragePool -CimSession $ClusterName | Get-PhysicalDisk -HasMetadata -CimSession $ClusterName | Sort-Object Description |format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
}
 
```

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolMetadata.png)

In 6 node cluster are metadata located on node 1,3,4,5,6. So in case you loose random half nodes, there is 50% chance going offline. Let's give it a try by turning off nodes 4,5,6 at one moment in Hyper-V manager to simulate failure.

As you can see, Pool is offline with message in EventLog saying, that pool does not have quorum of healthy disk. This is expected, as you lost 3 out of 5 metadata disk in one moment. If those failures did not happen in one moment, Health Service would redistribute metadata to another drives every 5 minutes.

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolDown.png)

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolDownMessage.png)

OK, this was fun, just don't try it in production :)

Turn on nodes 4,5,6 now. You also need to make Pool manually online.

```PowerShell
#make Cluster Pool online
Get-ClusterResource -Cluster 6nodecluster -Name "*pool*" | Start-ClusterResource
 
```
## Exploring Volumes disks metadata

Let's explore virtual disks now with following PowerShell

```PowerShell
#Create Volume on each cluster
Invoke-Command -ComputerName ($Clusters.Name | select -Unique) -ScriptBlock {New-Volume -FriendlyName MyVolume -Size 100GB}

#Display volumes metadata
foreach ($ClusterName in ($Clusters.Name | select -Unique)){
    Get-VirtualDisk -FriendlyName MyVolume -CimSession $ClusterName | Get-PhysicalDisk -HasMetadata -CimSession $ClusterName | Sort-Object Description | Format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
}
 
```

You can see, that same numbers applies to virtual disks too.

| Number of Nodes (Fault domains) | Number of Metadata Disks |
|:-------------------------------:| :-----------------------:|
|2                                |6                         |
|3                                |6                         |
|4                                |8                         |
|5                                |5                         |
|6                                |5                         |


![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/VirtualDisksMetadata.png)

## Exploring Scoped Volumes disks metadata

Let's now create few scoped volumes on 6 node cluster. We will use 2-6 scopes. Only 4 scopes makes sense for production, but we will use it for demonstration only.

```Powershell
$FaultDomains = Get-StorageFaultDomain -Type StorageScaleUnit -CimSession 6nodecluster | Sort FriendlyName
New-Volume -FriendlyName "2Scopes" -Size 100GB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 2) -CimSession 6nodecluster -StoragePoolFriendlyName S2D*  -NumberOfDataCopies 2
New-Volume -FriendlyName "3Scopes" -Size 100GB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 3) -CimSession 6nodecluster -StoragePoolFriendlyName S2D*
New-Volume -FriendlyName "4Scopes" -Size 100GB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 4) -CimSession 6nodecluster -StoragePoolFriendlyName S2D*
New-Volume -FriendlyName "5Scopes" -Size 100GB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 5) -CimSession 6nodecluster -StoragePoolFriendlyName S2D*
New-Volume -FriendlyName "6Scopes" -Size 100GB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 6) -CimSession 6nodecluster -StoragePoolFriendlyName S2D*
 
```

And as you can see, same math applies to scoped volumes (no wonder as it respects fault domains)

```PowerShell
$Friendlynames=2..6 | % {"$($_)Scopes"} #sorry, I was too lazy to type it over and over
foreach ($friendlyName in $FriendlyNames){
    Write-Host -Object "$FriendlyName" -ForeGroundColor Cyan
    Get-VirtualDisk -FriendlyName $FriendlyName -CimSession 6nodecluster | Get-PhysicalDisk -HasMetadata -CimSession 6nodecluster | Sort-Object Description | Format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
}
 
```

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/ScopedVirtualDisksMetadata.png)


## Exploring quorum and metadata rebalance

To illustrate quorun and metadata rebalance let's try to bring down half of 4 scopes metadata disks by turning off node 6node1 and 6node3. Votes are distributed on the same disks where metadata sits. The pictures would be same for 4 node cluster except there would not be a place to rebuild. 

As you can see, Virtual Disks are online while on 4Scopes volume are half of metadata disks lost. In this case, FileShare witness is global witness for both cluster and Pool/Volume quorum therefore quorum was maintained. This is also the reason you should use FileShare witness or Cloud witness every time.

Volume metadata will not be rebuilt since metadata will stick to fault domains (since it's scoped to node 1,3,4,6)

### 4 scopes Volume metadata

```PowerShell
Get-VirtualDisk -FriendlyName 4Scopes -CimSession 6nodecluster | ft FriendlyName,OperationalStatus,HealthStatus
Get-VirtualDisk -FriendlyName 4Scopes -CimSession 6nodecluster | Get-PhysicalDisk -HasMetadata -CimSession 6nodecluster | Sort-Object Description | Format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
 
```
![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/VirtualDiskMetadataFailedNodes.png)

### Pool metadata

Pool metadata will be rebuilt once Health Service will kick in (in approx 5 minutes
)

```PowerShell
#Display pool metadata
Get-StoragePool -CimSession 6nodecluster | Get-PhysicalDisk -HasMetadata -CimSession 6nodecluster | Sort-Object Description |format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
 
```

Right after failure

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolMetadataBefore.png)

After rebuild

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolMetadataAfter.png)