
<!-- TOC -->

- [S2D and Cluster Sets](#s2d-and-cluster-sets)
    - [Sample LabConfig for Windows Server 2019](#sample-labconfig-for-windows-server-2019)
    - [Prerequisites](#prerequisites)
    - [About the lab](#about-the-lab)
    - [Little bit theory](#little-bit-theory)
    - [The Lab](#the-lab)
        - [Create Management Cluster](#create-management-cluster)
        - [Move all VMs to Cluster Set namespace](#move-all-vms-to-cluster-set-namespace)
        - [Enable Live migration with kerberos authentication](#enable-live-migration-with-kerberos-authentication)
        - [add Management cluster computer account to each node local Administrators group](#add-management-cluster-computer-account-to-each-node-local-administrators-group)
        - [Register all existing VMs](#register-all-existing-vms)
        - [Create fault domains](#create-fault-domains)
        - [Create Availability Set](#create-availability-set)
        - [Add Availability Set to existing VMs](#add-availability-set-to-existing-vms)
        - [Identify node to create VM](#identify-node-to-create-vm)
        - [Move VMs around](#move-vms-around)

<!-- /TOC -->

# S2D and Cluster Sets

## Sample LabConfig for Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4'; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

#Management cluster
1..3 | ForEach-Object {$VMNames="Mgmt"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 512MB  }}
#HyperConverged Clusters (member clusters)
1..2 | ForEach-Object {$VMNames="1-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$True}}
1..2 | ForEach-Object {$VMNames="2-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$True}}
1..2 | ForEach-Object {$VMNames="3-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$True}}
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/VMs.png)

## Prerequisites

Run following code to create 3 HyperConverged clusters. Note: it's way simplified (no networking, no best practices, no CAU, ...). Run this code from DC. Cluster will ask for vhd. You can provide nanoserver VHD as it is small.

```PowerShell
#Variables
    #clusterconfig
    $Clusters=@()
    $Clusters+=@{Nodes="1-S2D1","1-S2D2" ; Name="Cluster1" ; IP="10.0.0.211" ; Volumenames="CL1Mirror1","CL1Mirror2" ; VolumeSize=2TB}
    $Clusters+=@{Nodes="2-S2D1","2-S2D2" ; Name="Cluster2" ; IP="10.0.0.212" ; Volumenames="CL2Mirror1","CL2Mirror2" ; VolumeSize=2TB}
    $Clusters+=@{Nodes="3-S2D1","3-S2D2" ; Name="Cluster3" ; IP="10.0.0.213" ; Volumenames="CL3Mirror1","CL3Mirror2" ; VolumeSize=2TB}

    #ask for parent vhdx (choose nanoserver preferably - it's small)
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
        }
        $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx"
        If($openFile.ShowDialog() -eq "OK"){
            Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
        }
        if (!$openFile.FileName){
            Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
        }
        $VHDPath = $openFile.FileName

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica,RSAT-AD-PowerShell
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica,RSAT-AD-PowerShell
    }

# Install features on servers
    Invoke-Command -computername $clusters.nodes -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell","Hyper-V"
    }

#reboot servers to finish Hyper-V install
    Restart-Computer $clusters.nodes -Protocol WSMan -Wait -For PowerShell
    start-sleep 20 #failsafe

#create clusters
    foreach ($Cluster in $clusters){
        New-Cluster -Name $Cluster.Name -Node $Cluster.Nodes -StaticAddress $Cluster.IP
    }

#add file share witnesses
    foreach ($Cluster in $clusters){
        #Create new directory
            $WitnessName=$Cluster.name+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$($Cluster.Name)$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $Cluster.name -FileShareWitness "\\DC\$WitnessName"
    }


#enable s2d
    foreach ($Cluster in $clusters){
        Enable-ClusterS2D -CimSession $Cluster.Name -confirm:0 -Verbose
    }

#create volumes
    Foreach ($Cluster in $clusters){
        New-Volume -StoragePoolFriendlyName "S2D on $($Cluster.Name)" -FriendlyName $Cluster.VolumeNames[0] -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes $Cluster.VolumeSize -CimSession $Cluster.Name
        New-Volume -StoragePoolFriendlyName "S2D on $($Cluster.Name)" -FriendlyName $Cluster.VolumeNames[1]  -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes $Cluster.VolumeSize -CimSession $Cluster.Name
    }

#Create 1 VM on each Volume
    if ($VHDPath){
        Foreach ($Cluster in $clusters){
            $VMName="$($Cluster.Name)_VM1"
            $VolumeName=$Cluster.VolumeNames[0]
            New-Item -Path "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks" -ItemType Directory
            Copy-Item -Path $VHDPath -Destination "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx"
            New-VM -Name $VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\$VolumeName" -VHDPath "c:\ClusterStorage\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx" -ComputerName $Cluster.Nodes[0]
            Start-VM -name $VMName -ComputerName $Cluster.Nodes[0]
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $Cluster.Name

            $VMName="$($Cluster.Name)_VM2"
            $VolumeName=$Cluster.VolumeNames[1]
            New-Item -Path "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks" -ItemType Directory
            Copy-Item -Path $VHDPath -Destination "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx"
            New-VM -Name $VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\$VolumeName" -VHDPath "c:\ClusterStorage\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx" -ComputerName $Cluster.Nodes[1]
            Start-VM -name $VMName -ComputerName $Cluster.Nodes[1]
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $Cluster.Name
        }
    }
 
```

## About the lab

**Cluster Sets** is the new cloud scale-out technology [in Insider Preview release](https://blogs.windows.com/windowsexperience/2018/03/20/announcing-windows-server-vnext-ltsc-build-17623/) that increases cluster node count in a single SDDC (Software-Defined Data Center) cloud by orders of magnitude. A Cluster Set is a loosely-coupled grouping of multiple Failover Clusters: compute, storage or hyper-converged. Cluster Sets technology enables VM fluidity across member clusters within a Cluster Set and a unified storage namespace across the Cluster Set in support of VM fluidity.

In following lab will be 4 clusters. 3 member Clusters contain storage (Storage Spaces Direct) and one Management cluster, that manages Cluster Set Namespace.

For more info visit [this blogpost](https://blogs.msdn.microsoft.com/clustering/2018/05/31/scale-out-file-server-improvements-in-windows-server-2019/)

## Little bit theory

**Management cluster**

Management cluster in a Cluster Set is a Failover Cluster that hosts the highly-available management plane of the entire Cluster Set and the unified storage namespace (CS-Namespace) referral SOFS. A management cluster is logically decoupled from member clusters that run the VM workloads. This makes the Cluster Set management plane resilient to any localized cluster-wide failures, e.g. loss of power of a member cluster. 

**Member cluster**

A member cluster in a Cluster Set is typically a traditional hyper-converged cluster running VM and S2D workloads. Multiple member clusters participate in a single Cluster Set deployment, forming the larger SDDC cloud fabric. Member clusters differ from a management cluster in two key aspects: member clusters participate in fault domain and availability set constructs, and member clusters are also sized to host VM and S2D workloads. Cluster Set VMs that move across cluster boundaries in a Cluster Set must not be hosted on the management cluster for this reason).

**Cluster Set namespace referral SOFS**

A Cluster Set namespace referral (CS-Namespace) SOFS is a Scale-Out File Server wherein each SMB Share on the CS-Namespace SOFS is a referral share – of type ‘SimpleReferral’ newly introduced in this Preview release. This referral allows SMB clients access to the target SMB share hosted on the member cluster SOFS (SOFS-1, SOFS-2 etc. in Figure 1). The Cluster Set namespace referral SOFS is a light-weight referral mechanism and as such, does not participate in the IO path. The SMB referrals are cached perpetually on the each of the client nodes and the Cluster Sets namespace infrastructure dynamically automatically updates these referrals as needed.

**Cluster Set Master**

In a Cluster Set, the communication between the member clusters is loosely coupled, and is coordinated by a new cluster resource called “Cluster Set Master” (CS-Master). Like any other cluster resource, CS-Master is highly available and resilient to individual member cluster failures and/or the management cluster node failures.
Through a new Cluster Set WMI provider, CS-Master provides the management endpoint for all Cluster Set manageability interactions.

**Cluster Set Worker**

In a Cluster Set deployment, the CS-Master interacts with a new cluster resource on the member Clusters called “Cluster Set Worker” (CS-Worker). CS-Worker acts as the only liaison on the cluster to orchestrate the local cluster interactions as requested by the CS-Master. Examples of such interactions include VM placement and cluster-local resource inventorying. There is only one CS-Worker instance for each of the member clusters in a Cluster Set.

**Logical Fault Domain (LFD)**

Compute fault domains (FDs) may be of two types in a Cluster Set: Logical Fault Domains (LFD) or Node Fault Domains (Node-FD). In either case, a Fault Domain is the grouping of software and hardware artifacts that the administrator determines could fail together when a failure does occur. While an administrator could designate one or more clusters together as a LFD, each node could participate as a Node-FD in Availability Set. Cluster Sets by design leaves the decision of FD boundary determination to the administrator who is well-versed with data center topological considerations – e.g. PDU, networking – that member clusters share.

**Availability Set**

An Availability Set helps the administrator configure desired redundancy of clustered workloads across fault domains, by organizing those FDs into an Availability Set and deploying workloads into that Availability Set. Let’s say if you are deploying a two-tier application, we recommend that you configure at least two virtual machines in an Availability Set for each tier which will ensure that when one FD in that Availability Set goes down, your application will at least have one virtual machine in each tier hosted on a different FD of that same Availability Set.

## The Lab

### Create Management Cluster

First we will create Management Cluster "MgmtCluster". This cluster can be anywhere (for example one node on each member cluster - outside cluster set namespace). This makes the resource highly resilient.

```PowerShell
$ClusterName="MgmtCluster"
$ClusterIP="10.0.0.220"
$ClusterNodes=1..3 | % {"Mgmt$_"}
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
    Install-WindowsFeature -Name "Failover-Clustering"
}
#in Windows Server 2019, installing Failover Clustering requires reboot
Restart-Computer -ComputerName $ClusterNodes -Protocol WSMan -Wait -For PowerShell
New-Cluster -Name $ClusterName -Node $ClusterNodes -StaticAddress $ClusterIP
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/MgmtClusterCreated.png)

And now let's create Cluster Set Master on "MgmtCluster"

```PowerShell
New-ClusterSet -name "MyClusterSet" -NamespaceRoot "MC-SOFS" -CimSession "MgmtCluster" -StaticAddress "10.0.0.221"
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ClusterSetCreated.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ScaleoutMaster.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/InfraFS.png)

And let's add member clusters Cluster1,Cluster2 and Cluster3

```PowerShell
Add-ClusterSetMember -ClusterName Cluster1 -CimSession MyClusterSet -InfraSOFSName CL1-SOFS
Add-ClusterSetMember -ClusterName Cluster2 -CimSession MyClusterSet -InfraSOFSName CL2-SOFS
Add-ClusterSetMember -ClusterName Cluster3 -CimSession MyClusterSet -InfraSOFSName CL3-SOFS
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ClusterSetMembersAdded.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/InfraFSCl1.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ScaleoutWorker.png)

As you can see, all shares are visible in \\\MC-SOFS path

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/MC-SOFS.png)

Let's play with PowerShell now

```PowerShell
#List all cluster set nodes
get-clusterset -CimSession MyClusterSet | get-cluster | get-clusternode

#get all cluster set member nodes
Get-ClusterSetNode -CimSession MyClusterSet

#get all cluster members
get-clustersetmember -CimSession MyClusterSet
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ViewingClusterSet.png)

### Move all VMs to Cluster Set namespace

Now we will move all VM's to cluster set namespace. Since Storage Live Migration does not work as files already exist in destination, we can either move files to another volume or unregister and register again with following trick.

```PowerShell
    $ClusterSet="MyClusterSet"
    $ClusterSetSOFS="\\MC-SOFS"
#Grab all VMs from all nodes
    $VMs=Get-VM -CimSession (Get-ClusterSetNode -CimSession $ClusterSet).Name

<# does not work
#perform storage migration to \\MC-SOFS
foreach ($VM in $VMs){
    $NewPath=($vm.path).Replace("c:\ClusterStorage",$ClusterSetSOFS)
    $VM | Move-VMStorage -DestinationStoragePath $NewPath
}
#>

#remove VMs and import again, but from \\MC-SOFS
#Shut down VMs
    $VMs | Stop-VM

#Remove VMs from cluster resources
    Foreach ($VM in $VMs){
        Remove-ClusterGroup -Cluster $VM.ComputerName -Name $VM.name -RemoveResources -Force
    }

#remove VMs and keep VM config
    Foreach ($VM in $VMs){
        invoke-command -computername $VM.ComputerName -scriptblock {
            $path=$using:VM.Path
            Copy-Item -Path "$path\Virtual Machines" -Destination "$path\Virtual Machines Bak" -recurse
            Get-VM -Id $Using:VM.id | Remove-VM -force
            Copy-Item -Path "$path\Virtual Machines Bak\*" -Destination "$path\Virtual Machines" -recurse
            Remove-Item -Path "$path\Virtual Machines Bak" -recurse
        }
    }

#Import again, but replace path to \\MC-SOFS
    Invoke-Command -ComputerName (get-clustersetmember -CimSession $ClusterSet).ClusterName -ScriptBlock{
        get-childitem c:\ClusterStorage -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
            $Path=$_.FullName.Replace("C:\ClusterStorage",$using:ClusterSetSOFS)
            Import-VM -Path $Path
        }
    }

#Add VMs as Highly available and Start
    $ClusterSetNodes=Get-ClusterSetNode -CimSession $ClusterSet
    foreach ($ClusterSetNode in $ClusterSetNodes){
        $VMs=Get-VM -CimSession $ClusterSetNode.Name
        if ($VMs){
            $VMs.Name | ForEach-Object {Add-ClusterVirtualMachineRole -VMName $_ -Cluster $ClusterSetNode.Member}
            $VMs | Start-VM
        }
    }
 
```

Before move

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/VMsBeforeMove.png)

After move

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/VMsAfterMove.png)

### Enable Live migration with kerberos authentication

Let's now configure kerberos constrained delegation between all nodes to be able to LiveMigrate VMs

```PowerShell
    #configure kerberos for shared-nothing live migration between all clusters
    # https://technet.microsoft.com/en-us/windows-server-docs/compute/hyper-v/deploy/set-up-hosts-for-live-migration-without-failover-clustering
    $ClusterSet="MyClusterSet"
    $Clusters=(get-clustersetmember -CimSession $ClusterSet).ClusterName
    $Nodes=Get-ClusterSetNode -CimSession $ClusterSet
    foreach ($Cluster in $Clusters){
        $SourceNodes=($nodes | where member -eq $Cluster).Name
        $DestinationNodes=($nodes | where member -ne $Cluster).Name
        Foreach ($DestinationNode in $DestinationNodes){
            $HostName = $DestinationNode
            $HostFQDN = (Resolve-DnsName $HostName).name | Select-Object -First 1
            Foreach ($SourceNode in $SourceNodes){
                Get-ADComputer $SourceNode | Set-ADObject -Add @{"msDS-AllowedToDelegateTo"="Microsoft Virtual System Migration Service/$HostFQDN", "Microsoft Virtual System Migration Service/$HostName", "cifs/$HostFQDN", "cifs/$HostName"}
            }
        }
    }

    #Switch to any authentication protocol https://blogs.technet.microsoft.com/virtualization/2017/02/01/live-migration-via-constrained-delegation-with-kerberos-in-windows-server-2016/
    Foreach ($Node in $Nodes){
        $GUID=(Get-ADComputer $Node.Name).ObjectGUID
        $comp=Get-ADObject -identity $Guid -Properties "userAccountControl"
        #Flip the ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit using powershell bitwise OR operation (-bor)
        $Comp.userAccountControl = $Comp.userAccountControl -bor 16777216
        Set-ADObject -Instance $Comp
    }

    #Switch to kerberos authentication for live migration
    Set-VMHost -CimSession $Nodes.Name -VirtualMachineMigrationAuthenticationType Kerberos
 
```

Result (on each node)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/DelegationSet.png)

### add Management cluster computer account to each node local Administrators group

And the last step is to add MyClusterSet machine account into local admin group.

```PowerShell
$ClusterSet="MyClusterSet"
$MgmtClusterterName=(Get-ClusterSet -CimSession $ClusterSet).ClusterName
Invoke-Command -ComputerName (Get-ClusterSetNode -CimSession $ClusterSet).Name -ScriptBlock {
    Add-LocalGroupMember -Group Administrators -Member "$using:MgmtClusterterName$"
}
 
```

```PowerShell
#Validate local groups
$ClusterSet="MyClusterSet"
Invoke-Command -ComputerName (Get-ClusterSetNode -CimSession $ClusterSet).Name -ScriptBlock {
    Get-LocalGroupMember -Group Administrators
} | format-table Name,PSComputerName
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/LocalGroups.png)

### Register all existing VMs

```PowerShell
#Register all existing VMs
$ClusterSet="MyClusterSet"
Get-ClusterSetMember -CimSession $ClusterSet | Register-ClusterSetVM -RegisterAll
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/RegisterVMsResult.png)

### Create fault domains

```PowerShell
$ClusterSet="MyClusterSet"
New-ClusterSetFaultDomain -Name FD1 -FdType Logical -CimSession $ClusterSet -MemberCluster CLUSTER1,CLUSTER2 -Description "This is my first fault domain"
New-ClusterSetFaultDomain -Name FD2 -FdType Logical -CimSession $ClusterSet -MemberCluster CLUSTER3 -Description "This is my second fault domain"
#You can add additional member to fault domain with Add-ClusterSetFaultDomainMember
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ClusterSetFDs.png)

### Create Availability Set

```PowerShell
$ClusterSet="MyClusterSet"
$AvailabilitySetName="MyAvailabilitySet"
$FaultDomainNames=(Get-ClusterSetFaultDomain -CimSession $clusterset).FDName
New-ClusterSetAvailabilitySet -Name $AvailabilitySetName -FdType Logical -CimSession $ClusterSet -ParticipantName $FaultDomainNames
#You can add additional fault domain with Add-ClusterSetParticipantToAvailabilitySet
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ClusterSetAS.png)

### Add Availability Set to existing VMs

```PowerShell
$ClusterSet="MyClusterSet"
$AvailabilitySetName="MyAvailabilitySet"
Get-ClusterSetVM -CimSession $clusterset | Set-ClusterSetVm -AvailabilitySetName $AvailabilitySetName
 
#Display VMs
Get-ClusterSetVM -CimSession $clusterset
Get-ClusterSetVM -CimSession $clusterset |ft VMName,AvailabilitySet,FaultDomain,UpdateDomain
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/VMsInAvailabilitySet.png)

### Identify node to create VM

```PowerShell
# Identify the optimal node to create a new virtual machine
$ClusterSet="MyClusterSet"
$memoryinMB=1GB
$vpcount = 1
$AS = Get-ClusterSetAvailabilitySet -CimSession $ClusterSet
Get-ClusterSetOptimalNodeForVM -CimSession $ClusterSet -VMMemory $memoryinMB -VMVirtualCoreCount $vpcount -VMCpuReservation 10 -AvailabilitySet $AS
 
```

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/OptimalNode.png)


### Move VMs around

```PowerShell
$ClusterSet="MyClusterSet"
$VMName="Cluster1_VM1"
#$VMName=(Get-ClusterSetVM -CimSession $ClusterSet | Out-GridView -OutputMode Single).VMName
$DestinationNode="3-S2D1"
#$DestinationNode=(Get-ClusterSetNode -CimSession $clusterset | Out-GridView -OutputMode Single).Name
Move-ClusterSetVM -CimSession $ClusterSet -VMName $VMName -MoveType Live -Node $DestinationNode
 
```

Before move

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/BeforeMove.png)

After move

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/AfterMove.png)
