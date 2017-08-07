
#servernames
$SANServers="SAN1","SAN2"
$SharedSSServers="SharedSS1","SharedSS2"
$S2DServers="S2D1","S2D2"

$allservers=$SANServers+$SharedSSServers+$S2DServers

#ClusterNames
$SANClusterName="SAN-Cluster"
$SharedSSClusterName="SSS-Cluster"
$S2DClusterName="S2D-Cluster"

#Nano server?
$nano=$true

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

#install failover clustering
    if ($Nano -eq $false){
        Invoke-Command -ComputerName $allservers -ScriptBlock {Install-WindowsFeature -Name "Failover-Clustering","Data-Center-Bridging","Hyper-V","Hyper-V-PowerShell"} -
        #restart and wait for computers
        Restart-Computer -ComputerName $Allservers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 20 #Failsafe
    }

#Create clusters
    New-Cluster –Name $SANClusterName –Node $SANServers 
    New-Cluster –Name $SharedSSClusterName –Node $SharedSSServers 
    New-Cluster –Name $S2DClusterName –Node $S2DServers


    Start-Sleep 5
    Clear-DnsClientCache
    Enable-ClusterS2D -CimSession $S2DClusterName -Confirm:0 -Verbose

#configure volumes on "SAN" based Hyper-V
    $CSV_disks    = get-disk -cimsession $SANClusterName | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB} | sort number

    #NTFS
        $CSV_disk=$CSV_disks[0]
        $volumename="NTFS"
        $CSV_disk      | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $SANClusterName -Confirm:$false
        $CSV_disk     | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $SANClusterName
        $clusterDisk=Add-ClusterDisk -Cluster $SANClusterName -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $SANClusterName -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $path=$ClusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
        $path=$path.Substring($path.LastIndexOf("\")+1)
        $FullPath = Join-Path -Path "\\$SANClusterName\ClusterStorage$\" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru

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
        $path=$path.Substring($path.LastIndexOf("\")+1)
        $FullPath = Join-Path -Path "\\$SANClusterName\ClusterStorage$\" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru

#create vDisks on Shared Spaces
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

    #Rename CSV paths
        Get-ClusterSharedVolume -Cluster $SharedSSClusterName | % {
            $volumepath=$_.sharedvolumeinfo.friendlyvolumename
            $newname=$_.name.Substring(22,$_.name.Length-23)
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $SharedSSClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
        }

#Create vDisks on S2D
    New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName ReFS -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes 2TB -CimSession $S2DClusterName
    New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName NTFS -FileSystem CSVFS_NTFS -StorageTierFriendlyNames Capacity -StorageTierSizes 2TB -CimSession $S2DClusterName
    #Rename CSV paths
        Get-ClusterSharedVolume -Cluster $S2DClusterName | % {
            $volumepath=$_.sharedvolumeinfo.friendlyvolumename
            $newname=$_.name.Substring(22,$_.name.Length-23)
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $S2DClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
        }

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
    Create-CustomVM -ClusterName $S2DClusterName -VolumeName ReFS -VMName ReFS -VHDPath $VHDPat
    Create-CustomVM -ClusterName $SharedSSClusterName -VolumeName NTFS -VMName NTFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SharedSSClusterName -VolumeName ReFS -VMName ReFS -VHDPath $VHDPath
    Create-CustomVM -ClusterName $SharedSSClusterName -VolumeName TieredNTFS -VMName TieredNTFS -VHDPath $VHDPath

#enable perf rules
    If ($nano){
        New-NetFirewallRule -CimSession $allservers `
            -Action Allow `
            -Name "PerfLogsAlerts-DCOM-In-TCP" `
            -DisplayName "Performance Logs and Alerts (DCOM-In)" `
            -Description "Inbound rule for Performance Logs and Alerts to allow remote DCOM activation. [TCP-135]" `
            -Enabled True `
            -Direction Inbound `
            -Program "%systemroot%\system32\svchost.exe" `
            -Protocol TCP `
            -LocalPort 135 `
            -Profile Any `
            -Group "Performance Logs and Alerts" `
            -RemoteAddress Any

        New-NetFirewallRule -cimsession $allservers `
            -Action Allow `
            -Name "PerfLogsAlerts-PLASrv-In-TCP" `
            -DisplayName "Performance Logs and Alerts (TCP-In)" `
            -Description "Inbound rule for Performance Logs and Alerts traffic. [TCP-In]" `
            -Enabled True `
            -Direction Inbound `
            -Program "%systemroot%\system32\plasrv.exe" `
            -Profile Any `
            -Group "Performance Logs and Alerts" `
            -Protocol TCP `
            -RemoteAddress Any
    }else{
        Enable-NetFirewallRule -Name "PerfLogsAlerts*" -CimSession $allservers
    }


#Display CSV volume state

Get-ClusterSharedVolumeState -Cluster $SANClusterName      | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason
Get-ClusterSharedVolumeState -Cluster $SharedSSClusterName | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason
Get-ClusterSharedVolumeState -Cluster $S2DClusterName      | sort VolumeFriendlyName,Node | Ft VolumeFriendlyName,Node,StateInfo,BlockRedirectedIOReason,FileSystemRedirectedIOReason