
#stretch cluster using shared storage. More info here https://technet.microsoft.com/en-us/windows-server-docs/storage/storage-replica/stretch-cluster-replication-using-shared-storage

###############
# Run from DC #
###############

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

##### LAB Config #####

$Site1Servers='Replica1','Replica2'
$Site2Servers='Replica3','Replica4'

$ClusterName='Stretch-Cluster'

$ReplicaNetwork="172.16.1.0"

$SourceRGName="RG01"
$DestinationRGName="RG02"
$ReplicationMode="Synchronous" #Synchronous or Asynchronous
$AsyncRPO=300  #Recovery point objective in seconds. Default is 5M

$Scenario="Hyper-V" # Hyper-V or FileServer

$Filesystem="ReFS" #ReFS or NTFS

$HAFSRoleName="HAFS" #HA FS Role name
$VMNames='Test1','Test2' #test VMs that will be created

$Servers=$Site1Servers+$Site2Servers

#Nano server?
$NanoServer=$False

    #exit if nano  and Fileserver
    if (($NanoServer -eq $True) -and ($Scenario -eq "FileServer")){
        Write-Host "Nano does not support HA FS"
        Start-sleep 10
        Exit
    }

#####################

#install features for management
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools

#Install required roles
    if ($NanoServer -eq $True){
        foreach ($server in $servers) {Install-WindowsFeature -Name Storage-Replica,RSAT-Storage-Replica,FS-FileServer -ComputerName $server} 
    }else{
        foreach ($server in $servers) {Install-WindowsFeature -Name "Storage-Replica","RSAT-Storage-Replica","FS-FileServer","Failover-Clustering" -ComputerName $server} 
    }

#install Hyper-V
    if (($scenario -eq "Hyper-V") -and ($NanoServer -eq $false)){
        Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
        foreach ($server in $servers) {Install-WindowsFeature -Name "Hyper-V-PowerShell" -ComputerName $server} 
    }

#restart those servers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
    Start-Sleep 10 #Failsafe

#create cluster
    New-Cluster -Name $ClusterName -Node $servers -NoStorage 
    Start-Sleep 5
    Clear-DnsClientCache

#configure fault domains
    New-ClusterFaultDomain -Name Seattle -Type Site -Description "Primary" -Location "Seattle Datacenter" -CimSession $ClusterName
    New-ClusterFaultDomain -Name Bellevue -Type Site -Description "Secondary" -Location "Bellevue Datacenter" -CimSession $ClusterName

    foreach ($Site1Server in $Site1Servers){
        Set-ClusterFaultDomain -Name $Site1Server -Parent Seattle -CimSession $ClusterName    
    }
    foreach ($Site2Server in $Site2Servers){
        Set-ClusterFaultDomain -Name $Site2Server -Parent Bellevue -CimSession $ClusterName    
    }

    (Get-Cluster -Name $ClusterName).PreferredSite="Seattle"  

#get Cluster Fault domain XML to validate configuration
    Get-ClusterFaultDomainXML -CimSession $ClusterName

##add storage

#format and initialize disks
    new-volume -DiskNumber 1 -FriendlyName Data -FileSystem $Filesystem -AccessPath D: -CimSession $Site1Servers[0] 
    new-volume -DiskNumber 2 -FriendlyName Log -FileSystem $Filesystem -AccessPath E: -CimSession $Site1Servers[0]
    new-volume -DiskNumber 1 -FriendlyName Data -FileSystem $Filesystem -AccessPath D: -CimSession $Site2Servers[0]
    new-volume -DiskNumber 2 -FriendlyName Log -FileSystem $Filesystem -AccessPath E: -CimSession $Site2Servers[0]

#List available disks for replication on Node $Site1Servers[0]
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site1Servers[0]

    $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    $DiskResources | foreach {
        $resource = $_
        $DiskGuidValue = $resource | Get-ClusterParameter DiskIdGuid

        Get-Disk -CimSession $Site1Servers[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume |
            Select @{N="Name"; E={$resource.Name}}, @{N="Status"; E={$resource.State}}, DriveLetter, FileSystemLabel, Size, SizeRemaining
    } | FT -AutoSize


#List available disks for replication on Node $Site2Servers[0]
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site2Servers[0]

    $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    $DiskResources | foreach {
        $resource = $_
        $DiskGuidValue = $resource | Get-ClusterParameter DiskIdGuid

        Get-Disk -CimSession $Site2Servers[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume |
            Select @{N="Name"; E={$resource.Name}}, @{N="Status"; E={$resource.State}}, DriveLetter, FileSystemLabel, Size, SizeRemaining
    } | FT -AutoSize

#move group back
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site1Servers[0]


#find Cluster disk with label Data
        $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
        foreach ($DiskResource in $DiskResources){
            $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
            if (Get-Disk -CimSession $Site1Servers[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume | where filesystemlabel -eq data){
                $ClusterDiskName=$DiskResource.name 
            }
        }

#Hyper-V: add correct volume to CSV (online volume with volume label Data) and setup replication
    if ($Scenario -eq "Hyper-V"){

        Get-ClusterResource -Cluster $ClusterName -name $ClusterDiskName | Add-ClusterSharedVolume

        #Create some VMs
        foreach ($VMName in $VMNames){
            New-VM -Name $VMName -MemoryStartupBytes 32MB -NewVHDPath "C:\ClusterStorage\Volume1\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx" -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\Volume1" -ComputerName $Site1Servers[0]
            Start-VM -name $VMName -ComputerName $Site1Servers[0]
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
        }

        #enable replication
        if ($ReplicationMode -eq "Asynchronous"){
            New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Site1Servers[0] -SourceRGName $SourceRGName -SourceVolumeName "C:\ClusterStorage\Volume1" -SourceLogVolumeName e: -DestinationComputerName $Site2Servers[0] -DestinationRGName $DestinationRGName -DestinationVolumeName d: -DestinationLogVolumeName e:
        }else{
            New-SRPartnership -SourceComputerName $Site1Servers[0] -SourceRGName $SourceRGName -SourceVolumeName "C:\ClusterStorage\Volume1" -SourceLogVolumeName e: -DestinationComputerName $Site2Servers[0] -DestinationRGName $DestinationRGName -DestinationVolumeName d: -DestinationLogVolumeName e:
        }
    }


#FileServer: add $HAFSRoleName role, share and setup replication
    if ($Scenario -eq "FileServer"){
        Add-ClusterFileServerRole -Name $HAFSRoleName -Cluster $ClusterName -Storage $ClusterDiskName
        Clear-DnsClientCache #To find HA FS name
        New-Item -Path "\\$($servers[0])\D$" -Name Share -ItemType Directory
        New-SmbShare -CimSession $($servers[0]) -Path "D:\Share" -ScopeName $HAFSRoleName -Name Share -ContinuouslyAvailable $false
        
        #Enable replication
        if ($ReplicationMode -eq "Asynchronous"){
            New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Site1Servers[0] -SourceRGName $SourceRGName -SourceVolumeName d: -SourceLogVolumeName e: -DestinationComputerName $Site2Servers[0] -DestinationRGName $DestinationRGName -DestinationVolumeName d: -DestinationLogVolumeName e:
        }else{
            New-SRPartnership -SourceComputerName $Site1Servers[0] -SourceRGName $SourceRGName -SourceVolumeName d: -SourceLogVolumeName e: -DestinationComputerName $Site2Servers[0] -DestinationRGName $DestinationRGName -DestinationVolumeName d: -DestinationLogVolumeName e:
        }
    }

#Wait until synced
    do{
        $r=(Get-SRGroup -CimSession $Site2Servers[0] -Name $DestinationRGName).replicas
        [System.Console]::Write("Number of remaining bytes {0}`r", $r.NumOfBytesRemaining)
        Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
    }until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
    Write-Output "Replica Status: "$r.replicationstatus

#configure replication network
    (Get-ClusterNetwork -Cluster $ClusterName | where Address -eq $ReplicaNetwork).Name="ReplicaNetwork"
    Set-SRNetworkConstraint -SourceComputerName $ClusterName -SourceRGName $SourceRGName -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $ClusterName -DestinationRGName $DestinationRGName -DestinationNWInterface "ReplicaNetwork"    
    Get-SRNetworkConstraint -SourceComputerName $ClusterName -SourceRGName $SourceRGName -DestinationComputerName $ClusterName -DestinationRGName $DestinationRGName

#Flip Replication
    if ($scenario -eq "Hyper-V"){
        #Flip withing Redmond Site
        Get-ClusterSharedVolume -Cluster $clustername | fl *  
        Move-ClusterSharedVolume -Name "cluster disk 2" -Node $Site1Servers[1] -Cluster $ClusterName

        #planned flip to antoher site
        Get-ClusterSharedVolume -Cluster $clusterName | fl *
        if ($ReplicationMode -eq "Synchronous"){
            Move-ClusterSharedVolume -Name "cluster disk 2" -Node $Site2Servers[0] -Cluster $ClusterName
        }elseif ($ReplicationMode -eq "Asynchronous"){
            Set-SRPartnership -NewSourceComputerName $ClusterName -SourceRGName $DestinationRGName -DestinationComputerName $ClusterName -DestinationRGName $SourceRGName -confirm:$false
        }
 
        foreach ($VMName in $VMNames){
            Move-ClusterVirtualMachineRole -Name $VMName -Node $Site2Servers[0] -MigrationType Live -Cluster $ClusterName
        }
    }

    if ($scenario -eq "FileServer"){
        #Flip replication
        Set-SRPartnership -NewSourceComputerName $ClusterName -SourceRGName $DestinationRGName -DestinationComputerName $ClusterName -DestinationRGName $SourceRGName -confirm:$false
        #Flip replication again
        Set-SRPartnership -NewSourceComputerName $ClusterName -SourceRGName $SourceRGName -DestinationComputerName $ClusterName -DestinationRGName $DestinationRGName -confirm:$false
    }

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
