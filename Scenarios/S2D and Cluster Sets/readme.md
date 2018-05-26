
<!-- TOC -->

- [S2D and Cluster Sets](#s2d-and-cluster-sets)
    - [Sample labconfig for 17666 insider](#sample-labconfig-for-17666-insider)
    - [Prerequisites](#prerequisites)
    - [About the lab](#about-the-lab)
    - [The Lab](#the-lab)

<!-- /TOC -->

!!! WORK IN PROGRESS !!!

# S2D and Cluster Sets

## Sample labconfig for 17666 insider

Note: Nested virtualization is commented (it slows down the environment)

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider17666-'; SwitchName = 'LabSwitch'; DCEdition='4'; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

#Master cluster
1..3 | ForEach-Object {$VMNames="Master"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17666.vhdx'; MemoryStartupBytes= 512MB ; Unattend='DjoinCred' }}
#HyperConverged Clusters
1..2 | ForEach-Object {$VMNames="1-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17666.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; Unattend='DjoinCred'; NestedVirt=$True}}
1..2 | ForEach-Object {$VMNames="2-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17666.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; Unattend='DjoinCred'; NestedVirt=$True}}
1..2 | ForEach-Object {$VMNames="3-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17666.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; Unattend='DjoinCred'; NestedVirt=$True}}

$LabConfig.ServerVHDs += @{
    Edition="4"
    VHDName="Win2019_17666.vhdx"
    Size=60GB
}
$LabConfig.ServerVHDs += @{
    Edition="3"
    VHDName="Win2019Core_17666.vhdx"
    Size=30GB
}
 
````

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/VMs.png)

## Prerequisites

Run following code to create 3 HyperConverged clusters. Note: it's way simplified (no networking, no best practices, no CAU, ...). Run this code from DC.

````PowerShell
#Labconfig
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
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica
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
 
````

## About the lab

**Cluster Sets** is the new cloud scale-out technology in this Preview release that increases cluster node count in a single SDDC (Software-Defined Data Center) cloud by orders of magnitude. A Cluster Set is a loosely-coupled grouping of multiple Failover Clusters: compute, storage or hyper-converged. Cluster Sets technology enables VM fluidity across member clusters within a Cluster Set and a unified storage namespace across the Cluster Set in support of VM fluidit

In following lab will be 3 clusters. 2 Clusters contain storage (Storage Spaces Direct), but one is in Converged mode, where is Scale-Out fileserver, that provides connectivity for another compute cluster.

## The Lab

First we will create Cluster "MasterCluster". This cluster can be anywhere (for example in each fault domain one node). This makes the resource highly resilient.

````PowerShell
$ClusterNodes=1..3 | % {"Master$_"}
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
    Install-WindowsFeature -Name "Failover-Clustering"
}
New-Cluster -Name MasterCluster -Node $ClusterNodes -StaticAddress "10.0.0.220"
 
````

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/MasterClusterCreated.png)

And then we will create Cluster Set master on "MasterCluster"

````PowerShell
New-ClusterSet -name MyClusterSet -NamespaceRoot MC-SOFS -CimSession MasterCluster -StaticAddress "10.0.0.221"
 
````

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ClusterSetCreated.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ScaleoutMaster.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/InfraFS.png)

And let's add Cluster1 and Cluster2

````PowerShell
Add-ClusterSetMember -ClusterName Cluster1 -CimSession MyClusterSet -InfraSOFSName CL1-SOFS
Add-ClusterSetMember -ClusterName Cluster2 -CimSession MyClusterSet -InfraSOFSName CL2-SOFS
Add-ClusterSetMember -ClusterName Cluster3 -CimSession MyClusterSet -InfraSOFSName CL3-SOFS
 
````

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ClusterSetMembersAdded.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/InfraFSCl1.png)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ScaleoutWorker.png)

As you can see, all shares are visible in \\\MC-SOFS path

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/MC-SOFS.png)

Let's play with PowerShell now

````PowerShell
#List all cluster set nodes
get-clusterset -CimSession MyClusterSet | get-cluster | get-clusternode

#get all cluster set member nodes
Get-ClusterSetNode -CimSession MyClusterSet

#get all cluster memmbers
get-clustersetmember -CimSession MyClusterSet
 
````

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/ViewingClusterSet.png)

Now we will move all VM's to cluster set namespace (Live storage migration)

````PowerShell
#Grab all VMs
$VMs=Get-VM -CimSession (Get-ClusterSetNode -CimSession MyClusterSet).Name

#perform storage migration to \\MC-SOFS
foreach ($VM in $VMs){
    $NewPath=($vm.path).Replace("c:\ClusterStorage\","\\MC-SOFS\")
    $VM | Move-VMStorage -DestinationStoragePath $NewPath
}
 
````

Let's now configure kerberos constrained delegation between all nodes.

````PowerShell
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
 
````

Result (on each node)

![](/Scenarios/S2D%20and%20Cluster%20Sets/Screenshots/DelegationSet.png)


