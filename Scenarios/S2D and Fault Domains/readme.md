<!-- TOC -->

- [S2D and Fault Domains](#s2d-and-fault-domains)
    - [LabConfig](#labconfig)
    - [About the lab](#about-the-lab)
    - [Prereq](#prereq)
    - [Configure Fault domains](#configure-fault-domains)
    - [Exploring fault domains](#exploring-fault-domains)
        - [Pool](#pool)
        - [Tiers](#tiers)
        - [Volume](#volume)
    - [Resiliency](#resiliency)

<!-- /TOC -->

# S2D and Fault Domains

## LabConfig

````PowerShell
#Labconfig is same as default scenario. Just with 6 nodes instead of 4
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..6 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
 
````

## About the lab

In this lab we will simulate 3 racks with 2 nodes each. We will also demonstrate how cluster survives errors we will introduce (pulled disk, node turned off). You can learn more about fault tolerance [here](https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-fault-tolerance)

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/VMs.png)

## Prereq

Run following script to create cluster. Note: it's way simplified (no networking, no best practices, no CAU, no hyper-v...). Run this code from DC.

````PowerShell
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
    Invoke-Command -computername $Servers -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell"
    }

#create cluster
    New-Cluster -Name $ClusterName -Node $Servers -StaticAddress $ClusterIP
    Start-Sleep 5
    Clear-DNSClientCache

#add file share witnesses
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
 
````

## Configure Fault domains

There are 2 options. To use XML or PowerShell. Unfortunately PowerShell works only in Windows Server 2019 as Enable-ClusterS2D hangs in 2016 (if powershell is used) due to known issue.

**XML**

````PowerShell
#Create Fault domains with XML.
$xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Node Name="S2D1"/>
            <Node Name="S2D2"/>
        </Rack>
        <Rack Name="Rack02" Location="Contoso HQ, Room 4010, Aisle A, Rack 02">
            <Node Name="S2D3"/>
            <Node Name="S2D4"/>
        </Rack>
        <Rack Name="Rack03" Location="Contoso HQ, Room 4010, Aisle A, Rack 03">
            <Node Name="S2D5"/>
            <Node Name="S2D6"/>
        </Rack>
    </Site>
</Topology>
"@

Set-ClusterFaultDomainXML -XML $xml -CimSession S2D-Cluster
 
````

**PowerShell**

````PowerShell
$ClusterName="S2D-Cluster"

#Create Fault domains with PowerShell (note: Enable-ClusterS2D will fail in Windows Server 2016. Fixed in Windows Server 2019)
New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
New-ClusterFaultDomain -Name "Rack02"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 02"           -CimSession $ClusterName
New-ClusterFaultDomain -Name "Rack03"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 03"           -CimSession $ClusterName
New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName

#assign fault domains
    #assign nodes to racks
    1..2 |ForEach-Object {Set-ClusterFaultDomain -Name "S2D$_" -Parent "Rack01"    -CimSession $ClusterName}
    3..4 |ForEach-Object {Set-ClusterFaultDomain -Name "S2D$_" -Parent "Rack02"    -CimSession $ClusterName}
    5..6 |ForEach-Object {Set-ClusterFaultDomain -Name "S2D$_" -Parent "Rack03"    -CimSession $ClusterName}
    #assign racks to site
    1..3 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
 
````

To display FD you can run following PowerShell or you can display it in Cluadmin

````PowerShell
$ClusterName="S2D-Cluster"
Get-ClusterFaultDomain -CimSession $ClusterName
Get-ClusterFaultDomainxml -CimSession $ClusterName
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/FaultDomainsPowerShell.png)

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/FaultDomainsCluadmin.png)

Let's enable S2D now.

````PowerShell
Enable-ClusterS2D -CimSession S2D-Cluster -Verbose
 
````

As you can see, Enable-ClusterS2D will find fault domains and will ask you, if you want to configure Rack FD.

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/Enable-ClusterS2DRack.png)

## Exploring fault domains

### Pool

Notice, that FaultDomainAwarenessDefault is "StorageRack"

````PowerShell
Get-StoragePool -CimSession s2d-cluster -FriendlyName S2D* | fl *
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/Get-StoragePool.png)

### Tiers

Notice, that only one tier was created (same as it would be for 3 node configuration). And also FaultDomanAwareness is "StorageRack"

````PowerShell
Get-StorageTier -CimSession s2d-cluster
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/Get-StorageTier.png)

### Volume

Let's create new volumes. First using predefined tier and then without tier

````PowerShell
#With Tier
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName WithTier  -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes 1TB -CimSession S2D-Cluster
#Without Tier
New-Volume -StoragePoolFriendlyName s2d* -FriendlyName WithoutTier -FileSystem CSVFS_ReFS -Size 1TB -ResiliencySettingName Mirror -CimSession S2D-Cluster
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/VolumesCreated.png)

Let's explore FaultDomain awareness on volumes

````PowerShell
Get-VirtualDisk -CimSession s2d-cluster | ft FriendlyName,FaultDomainAwareness

````

As you can see, only "WithoutTier" volume has FaultDomainAwareness defined in Virtual Disk

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/Get-VirtualDisk.png)

To view FaultDomainAwareness on tiered disk, you need to view tier

````PowerShell
Get-VirtualDisk -CimSession s2d-cluster| Get-StorageTier | ft FriendlyName,FaultDomainAwareness
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/Get-StorageTier2.png)

## Resiliency

Let's take one rack offline by pausing S2D1 and S2D2 VMs and let's see what will happen

````PowerShell
#Run from Hyper-V Host to turn off nodes s2d1 and s2s2
get-vm -Name "wslab-s2d1","wslab-s2d2" | Stop-VM -TurnOff
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/VMsTurnedOff.png)

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/NodesDown.png)

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/NodesDownVirtualDisksUp.png)

As you can see, cluster survives and Virtual Disks (volumes) are online

Let's introduce another failure by removing one capacity disk from S2D3 and one from S2D4

````PowerShell
#Run from Hyper-V Host to remove first capacity disk from nodes in rack 2
get-vm -Name "wslab-s2d3","wslab-s2d4" | Get-VMHardDiskDrive | where controllerlocation -eq 1 | Remove-VMHardDiskDrive
 
````

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/NodesDownDiskRemovedVirtualDisksUp.png)

OK, disks are still online... let's remove all disks from S2D3 and S2D4.

````PowerShell
#Run from Hyper-V Host to remove all capacity disk from nodes in rack 2
get-vm -Name "wslab-s2d3","wslab-s2d4" | Get-VMHardDiskDrive | where controllerlocation -ne 0 | Remove-VMHardDiskDrive
 
````

S2D still survived!

![](/Scenarios/S2D%20and%20Fault%20Domains/Screenshots/NodesDownAllDisksRemovedVirtualDisksUp.png)
