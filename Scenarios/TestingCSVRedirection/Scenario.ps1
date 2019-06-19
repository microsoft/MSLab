
#servernames
$SANServers="SAN1","SAN2"
$SharedSSServers="SharedSS1","SharedSS2"
$S2DServers="S2D1","S2D2"
$SRServersSite1="SRSite1_Node1","SRSite1_Node2"
$SRServersSite2="SRSite2_Node1","SRSite2_Node2"
$SRServers=$SRServersSite1+$SRServersSite2

$allservers=$SANServers+$SharedSSServers+$S2DServers+$SRServers

#ClusterNames
$SANClusterName="SAN-Cluster"
$SharedSSClusterName="SSS-Cluster"
$S2DClusterName="S2D-Cluster"
$SRClusterName="SR-Cluster"

#ask for parent vhdx
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

#install features for management on DC
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools

#install failover clustering and Storage Replica
    Invoke-Command -ComputerName $allservers -ScriptBlock {Install-WindowsFeature -Name "Failover-Clustering","Data-Center-Bridging","Hyper-V","Hyper-V-PowerShell"}
    #restart and wait for computers
    Restart-Computer -ComputerName $Allservers -Protocol WSMan -Wait -For PowerShell
    Start-Sleep 20 #Failsafe

#Create clusters
    New-Cluster -Name $SANClusterName -Node $SANServers 
    New-Cluster -Name $SharedSSClusterName -Node $SharedSSServers 
    New-Cluster -Name $S2DClusterName -Node $S2DServers
    New-Cluster -Name $SRClusterName -Node $SRServers

    Start-Sleep 5
    Clear-DnsClientCache
    Enable-ClusterS2D -CimSession $S2DClusterName -Confirm:0 -Verbose

#configure volumes on "SAN" based Hyper-V
    $CSV_disks = get-disk -cimsession $SANClusterName | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB} | sort number

    #NTFS
        $CSV_disk=$CSV_disks[0]
        $volumename="NTFS"
        $CSV_disk | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $SANClusterName -Confirm:$false
        $CSV_disk | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $SANClusterName
        $clusterDisk=Add-ClusterDisk -Cluster $SANClusterName -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $SANClusterName -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $path=$ClusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
        Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ScriptBlock {
            Rename-Item -Path $using:path -NewName $using:volumename -PassThru
        }

    #REFS
        $CSV_disk=$CSV_disks[1]
        $volumename="ReFS"
        $CSV_disk      | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem ReFS -AllocationUnitSize 4kb -NewFileSystemLabel $volumename -CimSession $SANClusterName -Confirm:$false
        $CSV_disk     | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $SANClusterName
        $clusterDisk=Add-ClusterDisk -Cluster $SANClusterName -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $SANClusterName -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $path=$ClusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
        Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ScriptBlock {
            Rename-Item -Path $using:path -NewName $using:volumename -PassThru
        }

#create vDisks on Shared Spaces (just to demo creating volumes using registered storage subsystem)
    Get-StorageProvider | Register-StorageSubsystem -ComputerName $SharedSSClusterName
    $phydisk=Get-PhysicalDisk | where CanPool -eq $True
    $pool=New-StoragePool -FriendlyName  $SharedSSClusterName"Pool" -PhysicalDisks $phydisk -StorageSubSystemFriendlyName *$SharedSSClusterName
    $Pool | Get-PhysicalDisk | where size -lt 900GB | Set-PhysicalDisk -MediaType SSD
    $Pool | Get-PhysicalDisk | where size -gt 900GB | Set-PhysicalDisk -MediaType HDD
    New-StorageTier -StoragePoolFriendlyName $SharedSSClusterName"Pool" -ResiliencySettingName Mirror -FriendlyName SSDTier -NumberOfColumns 1 -PhysicalDiskRedundancy 2 -MediaType SSD
    New-StorageTier -StoragePoolFriendlyName $SharedSSClusterName"Pool" -ResiliencySettingName Mirror -FriendlyName HDDTier -NumberOfColumns 1 -PhysicalDiskRedundancy 2 -MediaType HDD 
    New-Volume -StoragePoolFriendlyName $SharedSSClusterName"Pool" -FriendlyName TieredNTFS -FileSystem CSVFS_NTFS -StorageTierFriendlyNames SSDTier,HDDTier -StorageTierSizes 200GB,1800GB
    New-Volume -StoragePoolFriendlyName $SharedSSClusterName"Pool" -FriendlyName NTFS -FileSystem CSVFS_NTFS -StorageTierFriendlyNames HDDTier -StorageTierSizes 2TB
    New-Volume -StoragePoolFriendlyName $SharedSSClusterName"Pool" -FriendlyName REFS -FileSystem CSVFS_REFS -StorageTierFriendlyNames SSDTier -StorageTierSizes 200GB

    #Rename CSV paths (not needed for 2019)
        $CSVs=Get-ClusterSharedVolume -Cluster $SharedSSClusterName
        foreach ($CSV in $CSVs){
            $volumepath=$CSV.sharedvolumeinfo.friendlyvolumename
            $newname=$csv.name.Replace("Cluster Virtual Disk (","").Replace(")","")
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $SharedSSClusterName -Name $CSV.Name).ownernode -ScriptBlock {Rename-Item -Path $volumepath -NewName $newname} -ErrorAction SilentlyContinue
        }

#Create vDisks on S2D
    New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName ReFS -FileSystem CSVFS_ReFS -StorageTierFriendlyNames MirrorOnHDD -StorageTierSizes 2TB -CimSession $S2DClusterName
    New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName NTFS -FileSystem CSVFS_NTFS -StorageTierFriendlyNames MirrorOnHDD -StorageTierSizes 2TB -CimSession $S2DClusterName
    #Rename CSV paths (not needed for 2019)
        $CSVs=Get-ClusterSharedVolume -Cluster $S2DClusterName
        foreach ($CSV in $CSVs){
            $volumepath=$CSV.sharedvolumeinfo.friendlyvolumename
            $newname=$csv.name.Replace("Cluster Virtual Disk (","").Replace(")","")
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $S2DClusterName -Name $CSV.Name).ownernode -ScriptBlock {Rename-Item -Path $volumepath -NewName $newname} -ErrorAction SilentlyContinue
        }

#Configure SR on SRServers
    #Enable SR Feture
        Foreach ($Server in $SRServers){
            Install-WindowsFeature -Name "Storage-Replica","RSAT-Storage-Replica","FS-FileServer" -ComputerName $Server
        }
        #restart and wait for computers
        Restart-Computer -ComputerName $SRServers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 20 #Failsafe

    #configure fault domains
        New-ClusterFaultDomain -Name Site1 -Type Site -Description "Primary" -Location "Site1 Datacenter" -CimSession $SRClusterName
        New-ClusterFaultDomain -Name Site2 -Type Site -Description "Secondary" -Location "Site2 Datacenter" -CimSession $SRClusterName

        foreach ($Server in $SRServersSite1){
            Set-ClusterFaultDomain -Name $Server -Parent Site1 -CimSession $SRClusterName
        }
        foreach ($Server in $SRServersSite2){
            Set-ClusterFaultDomain -Name $Server -Parent Site2 -CimSession $SRClusterName
        }

        (Get-Cluster -Name $SRClusterName).PreferredSite="Site1"

    #get Cluster Fault domain XML to validate configuration
        Get-ClusterFaultDomainXML -CimSession $SRClusterName

    ## Note: GroupID is not used. It can be used if multiple Data disks are present in each site.
    $diskconfig=@()
    $diskconfig+=@{DiskNumber=1 ; FriendlyName="Log1"  ; FileSystem="NTFS" ; Site="Site1"   ; PrimarySite="Site1"   ; Role="Log"  ; GroupID=1 ; RGName="Data1Source"      }
    $diskconfig+=@{DiskNumber=2 ; FriendlyName="ReFS"  ; FileSystem="REFS" ; Site="Site1"   ; PrimarySite="Site1"   ; Role="Data" ; GroupID=1 ; RGName="Data1Source"      ; CSVFolderName="ReFS"}
    $diskconfig+=@{DiskNumber=3 ; FriendlyName="NTFS"  ; FileSystem="NTFS" ; Site="Site1"   ; PrimarySite="Site1"   ; Role="Data" ; GroupID=1 ; RGName="Data1Source"      ; CSVFolderName="NTFS"}
    $diskconfig+=@{DiskNumber=1 ; FriendlyName="Log1"  ; FileSystem="NTFS" ; Site="Site2"   ; PrimarySite="Site1"   ; Role="Log"  ; GroupID=1 ; RGName="Data1Destination" }
    $diskconfig+=@{DiskNumber=2 ; FriendlyName="ReFS"  ; FileSystem="REFS" ; Site="Site2"   ; PrimarySite="Site1"   ; Role="Data" ; GroupID=1 ; RGName="Data1Destination" }
    $diskconfig+=@{DiskNumber=3 ; FriendlyName="NTFS"  ; FileSystem="NTFS" ; Site="Site2"   ; PrimarySite="Site1"   ; Role="Data" ; GroupID=1 ; RGName="Data1Destination" }


    #region format disks
    foreach ($disk in $diskconfig){
        if ($Disk.site -eq "Site1"){
            New-Volume -DiskNumber $disk.DiskNumber -FriendlyName $disk.FriendlyName -FileSystem $disk.FileSystem -CimSession $SRServersSite1[0] -ErrorAction SilentlyContinue
        }
        if ($Disk.site -eq "Site2") {
            New-Volume -DiskNumber $disk.DiskNumber -FriendlyName $disk.FriendlyName -FileSystem $disk.FileSystem -CimSession $SRServersSite2[0] -ErrorAction SilentlyContinue
        }
    }

    #list storage and add paths to Diskconfig variable
    #List available disks for replication on Node $SRServersSite1[0] and add path to diskconfig
    Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite1[0]

    $DiskResources = Get-ClusterResource -Cluster $SRClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        $disk=Get-Disk -CimSession $SRServersSite1[0] | where Guid -eq $DiskGuidValue.Value
        $volume=$disk | Get-Partition | Get-Volume
        #add path to diskconfig
        ($diskconfig | where Site -eq Site1 | where DiskNumber -eq $disk.Number).Path=$volume.Path
        #list volume
        $volume |Select-Object @{N="Name"; E={$DiskResource.Name}}, @{N="Status"; E={$DiskResource.State}}, DriveLetter, Path, FileSystemLabel, Size, SizeRemaining | FT -AutoSize
    }

    #List available disks for replication on Node $SRServersSite2[0]
        Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite2[0]
        $DiskResources = Get-ClusterResource -Cluster $SRClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
        foreach ($DiskResource in $DiskResources){
            $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
            $disk=Get-Disk -CimSession $SRServersSite2[0] | where Guid -eq $DiskGuidValue.Value
            $volume=$disk | Get-Partition | Get-Volume
            #add path to diskconfig
            ($diskconfig | where Site -eq Site2 | where DiskNumber -eq $disk.Number).Path=$volume.Path
            #list volume
            $volume |Select-Object @{N="Name"; E={$DiskResource.Name}}, @{N="Status"; E={$DiskResource.State}}, DriveLetter, Path, FileSystemLabel, Size, SizeRemaining | FT -AutoSize
        }

    #move group back
    Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite1[0]

    #rename cluster disk resources for easier identification in Site1
    $DiskResources = Get-ClusterResource -Cluster $SRClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        $filesystemlabel=(Get-Disk -CimSession $SRServersSite1[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume).FilesystemLabel
            $DiskResource.name="$($filesystemlabel)_Site1"
    }

    #move available disks group to Site2
    Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite2[0]

    #rename cluster disk resources for easier identification in Site2
    $DiskResources = Get-ClusterResource -Cluster $SRClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        $filesystemlabel=(Get-Disk -CimSession $SRServersSite2[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume).FilesystemLabel
            $DiskResource.name="$($filesystemlabel)_Site2"
    }

    #move available disks group to Site1 again
    Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite1[0]

    #Add Data disks to CSVs
    #add disk from site1
    $CSVConfigs=$diskconfig | where site -eq Site1 | where CSVFoldername #grab CSV name from diskconfig for site1
    Foreach ($CSVConfig in $CSVConfigs){
        $CSV=Get-ClusterResource -Cluster $SRClusterName -name "$($CSVConfig.FriendlyName)_Site1" | Add-ClusterSharedVolume
        #rename csv
        Invoke-Command -ComputerName $CSV.OwnerNode -ScriptBlock {Rename-Item -Path $using:csv.SharedVolumeInfo.friendlyvolumename -NewName $using:CSVConfig.CSVFolderName}
    }

    #move available disks group to Site2
    Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite2[0]

    #add data 2 to CSV
    $CSVConfigs=$diskconfig | where site -eq Site2 | where CSVFoldername #grab CSV name from diskconfig for site1
    Foreach ($CSVConfig in $CSVConfigs){
        $CSV=Get-ClusterResource -Cluster $SRClusterName -name "$($CSVConfig.FriendlyName)_Site2" | Add-ClusterSharedVolume
        #rename csv to Data2
        Invoke-Command -ComputerName $CSV.OwnerNode  -ScriptBlock {Rename-Item -Path $using:csv.SharedVolumeInfo.friendlyvolumename -NewName $using:CSVConfig.CSVFolderName}
    }

    #move group back
    Move-ClusterGroup -Cluster $SRClusterName -Name "available storage" -Node $SRServersSite1[0]

    #enable replication from Site1
    $Sourcelog=        $diskconfig  | where site -eq Site1  | where role -eq log  | where PrimarySite -eq Site1
    $Sourcedata=       $diskconfig  | where site -eq Site1  | where role -eq data | where PrimarySite -eq Site1 | select -First 1
    $Destinationlog =  $diskconfig  | where site -eq Site2  | where role -eq log  | where PrimarySite -eq Site1
    $Destinationdata = $diskconfig  | where site -eq Site2  | where role -eq data | where PrimarySite -eq Site1 | select -First 1
    New-SRPartnership -SourceComputerName $SRServersSite1[0] -SourceRGName $SourceData.RGName -SourceVolumeName "C:\ClusterStorage\$($sourceData.CSVFolderName)" -SourceLogVolumeName $sourcelog.Path -DestinationComputerName $SRServersSite2[0] -DestinationRGName $DestinationData.RGName -DestinationVolumeName $destinationdata.Path -DestinationLogVolumeName $destinationlog.Path
    #add additional CSV to partnership
    $SourceDataDiskToAdd      = $diskconfig  | where site -eq Site1  | where role -eq data | where PrimarySite -eq Site1 | select -Skip 1
    $DestinationDataDiskToAdd = $diskconfig  | where site -eq Site2  | where role -eq data | where PrimarySite -eq Site1 | select -Skip 1
    Set-SRPartnership -SourceComputerName $SRServersSite1[0] -SourceRGName $SourceDataDiskToAdd.RGName -SourceAddVolumePartnership "C:\ClusterStorage\$($SourceDataDiskToAdd.CSVFolderName)" -DestinationComputerName $SRServersSite2[0] -DestinationRGName $DestinationDataDiskToAdd.RGName -DestinationAddVolumePartnership $DestinationDataDiskToAdd.Path

    #Wait until synced
    do{
        $r=(Get-SRGroup -CimSession $SRServersSite2[0] -Name $DestinationData.RGName).replicas
        if ($r.NumOfBytesRemaining -ne 0){ 
            [System.Console]::Write("Number of remaining Gbytes {0}`r", $r.NumOfBytesRemaining/1GB)
            Start-Sleep 5
        }
    }until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
    Write-Output "Replica Status: "$r.replicationstatus

    #move CSVs to node 2 in Site1
    Move-ClusterSharedVolume -Name "ReFS_Site1" -Node $SRServersSite1[1] -Cluster $SRClusterName
    Move-ClusterSharedVolume -Name "NTFS_Site1" -Node $SRServersSite1[1] -Cluster $SRClusterName

#Create VMs
    #Function to create VM
        function Create-CustomVM ($ClusterName,$VolumeName,$VMName,$VHDPath)
            {
                New-Item -Path "\\$ClusterName\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks" -ItemType Directory
                Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks\$VMName.vhdx" 
                New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\$VolumeName\" -VHDPath "c:\ClusterStorage\$VolumeName\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Select -First 1)
                Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
            }

    Create-CustomVM -ClusterName $SANClusterName -VolumeName NTFS -VMName NTFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SANClusterName -VolumeName ReFS -VMName ReFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $S2DClusterName -VolumeName NTFS -VMName NTFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $S2DClusterName -VolumeName ReFS -VMName ReFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SharedSSClusterName -VolumeName NTFS -VMName NTFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SharedSSClusterName -VolumeName ReFS -VMName ReFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SharedSSClusterName -VolumeName TieredNTFS -VMName TieredNTFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SRClusterName -VolumeName ReFS -VMName ReFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SRClusterName -VolumeName NTFS -VMName NTFS -VHDPath $VHDPath

#enable perfmon rule
    Enable-NetFirewallRule -Name "PerfLogsAlerts*" -CimSession $allservers

#Display CSV volume state

Get-ClusterSharedVolumeState -Cluster $SANClusterName      | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason
Get-ClusterSharedVolumeState -Cluster $SharedSSClusterName | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason
Get-ClusterSharedVolumeState -Cluster $S2DClusterName      | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason
Get-ClusterSharedVolumeState -Cluster $SRClusterName       | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason