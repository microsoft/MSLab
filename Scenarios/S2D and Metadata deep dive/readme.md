# S2D and Metadata deep dive

## LabConfig

```PowerShell
#Labconfig is almost the same as default. Just with 6 nodes instead of 4
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

1..6 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## About the lab

This lab talks about Pool and Virtual Disks (S2D Volumes) metadata. It demonstrates how to display metadata and what different metadata configurations exist.

Run all scripts from DC

## Prereq

```PowerShell
# LabConfig
    $Servers=1..6 | % {"S2D$_"}
    $ClusterName="S2D-Cluster"
    $ClusterIP="10.0.0.111"

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }

# Install features on servers
    $result=Invoke-Command -computername $Servers -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell"
    }
    $ComputersToRestart=($result | where restartneeded -eq Yes).PSComputerName
    Restart-Computer -ComputerName $ComputersToRestart -Protocol WSMan -Wait -For PowerShell

#create cluster
    New-Cluster -Name $ClusterName -Node $Servers -StaticAddress $ClusterIP
    Start-Sleep 5
    Clear-DNSClientCache

#add file share witness
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

#Enable S2D
    Enable-ClusterS2D -CimSession $ClusterName -Verbose -Confirm:0

#Create some scoped volumes
    $FaultDomains = Get-StorageFaultDomain -Type StorageScaleUnit -CimSession S2D-Cluster| Sort FriendlyName
    #Create 3 scopes volume -should not be used for prod as you want 4 scopes (with 3 scopes, 2 scopes lost = volume offline)
    New-Volume -FriendlyName "3Scopes" -Size 1TB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 3) -CimSession S2D-Cluster -StoragePoolFriendlyName S2D*
    #Create 4 scopes volume
    New-Volume -FriendlyName "4Scopes" -Size 1TB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 4) -CimSession S2D-Cluster -StoragePoolFriendlyName S2D*
    #Create 5 scopes volume (does not make sense for this scenario, just for demoing)
    New-Volume -FriendlyName "5Scopes" -Size 1TB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 5) -CimSession S2D-Cluster -StoragePoolFriendlyName S2D*

#Create Mirror volume
    New-Volume -FriendlyName "Mirror" -Size 1TB -CimSession S2D-Cluster -StoragePoolFriendlyName S2D*
 
```

## Displaying Physical Disks Owners

With following script we can use PhysicalDisk description attribute to host owner node name.

```PowerShell
$ClusterName="S2D-Cluster"

#grab StorageNodes
$StorageNodes=Get-StorageSubSystem -CimSession $clusterName -FriendlyName Clus* | Get-StorageNode

#add owner node name to description
foreach ($StorageNode in $StorageNodes){$StorageNode | Get-PhysicalDisk -PhysicallyConnected -CimSession $StorageNode.Name | Set-PhysicalDisk -Description $StorageNode.Name -CimSession $StorageNode.Name}
 
#display disks
Get-PhysicalDisk -CimSession $ClusterName | format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
 
```

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/DiskOwners.png)

## Exploring Pool Metadata

In following PowerShell example notice -HasMetadata Parameter. This is new in Windows Server 2019. As you can see, pool is using 5 metadata disks.

```PowerShell
$ClusterName="S2D-Cluster"
#display pool metadata
Get-StoragePool -CimSession $ClusterName | Get-PhysicalDisk -HasMetadata -CimSession $ClusterName | Sort-Object Description |format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
 
```

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolMetadata.png)

In this case located on nodes 1,2,3,4,5. So in case you loose random half nodes, there is 50% chance going offline. Let's give it a try by turning off nodes 1,2,3 at one moment in Hyper-V to simulate failure.

As you can see, Pool is offline with message in EventLog saying, that pool does not have quorum of healthy disk. This is expected, as you lost 3 out of 5 metadata disk in one moment. If those failures did not happen in one moment, Health Service would redistribute metadata to another drives every 5 minutes.

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolDown.png)

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolDownMessage.png)

OK, this was fun, just don't try it in prod :)

Turn on nodes 1,2,3 now.

## Exploring Virtual disks metadata

Let's explore virtual disks now with following PowerShell

```PowerShell
$ClusterName="S2D-Cluster"
#display virtual disk metadata
$virtualdisks=Get-VirtualDisk -CimSession $ClusterName | sort FriendlyName
foreach ($virtualdisk in $virtualdisks){
    $virtualdisk.FriendlyName
    $virtualdisk | Get-PhysicalDisk -HasMetadata -CimSession $ClusterName | Sort-Object Description | Format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
}
 
```

You can see following info

| Virtual Disk Type | Number of Metadata Disks |
|:-----------------:| :-----------------------:|
|Mirror             |5                         |
|3 Scopes           |6                         |
|4 Scopes           |8                         |
|5+ Scopes          |5                         |

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/VirtualDisksMetadata.png)

## Exploring quorum

To illustrate resiliency let's try to bring down half of 4 scopes metadata disks by turning off node S2D1 and S2D2

As you can see, Virtual Disks are online while on 4Scopes volume are half of metadata disks lost. In this case, FileShare witness is global witness for both cluster and Pool/Volume quorum therefore quorum was maintained. You can also see, that virtual disks Metadata are already moved on below screenshot (was not on s2d6 on Mirror and PerfHistory volume). Health Service will do rebalance for you in approx 5 minutes

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/VDisksOnline.png)

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/VirtualDisksMetadata2NodesDown.png)

You can also notice that Pool metadata disks are rebalanced. If cluster had more nodes, all metadata disks would be placed on healthy nodes.

Before Rebalance:

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolBeforeRebalance.png)

After Rebalance:

![](/Scenarios/S2D%20and%20Metadata%20deep%20dive/Screenshots/PoolAfterRebalance.png)