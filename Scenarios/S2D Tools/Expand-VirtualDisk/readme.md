Expanding virtual disk as described in this guide https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/resize-volumes

The only difference is, that it connects to disk owner (I personally preffer it, altrought it's not really needed). This example is only for disks created with default tiers. It also resizes all volumes on all clusters selected.

````PowerShell
#Ask for cluster(s)
$S2DClusters=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -PassThru -Title "Please select your S2D Cluster(s)").Name

#Query for all Virtual Disks
$vdisks=Get-VirtualDisk -CimSession $S2DClusters | Select-Object FriendlyName,@{Name="Size (GB)"; Expression = {$_.Size/1GB}},PSComputerName,UniqueID| Out-GridView -PassThru -Title "Please select disk(s) you want to resize"

#ask for New Capacity Tier Size
[int64]$NewCapacityTierSize=Read-Host -Prompt "Provide New Capacity Tier Size (GB)"
$NewCapacityTierSize=$NewCapacityTierSize*1GB

#ask for New Performance Tier Size
[int64]$NewPerformanceTierSize=Read-Host -Prompt "Provide New Performance Tier Size (GB)"
$NewPerformanceTierSize=$NewPerformanceTierSize*1GB

foreach ($vdisk in $vdisks){
    $ClusterName=$vdisk.PSComputerName
    $owner=((Get-ClusterSharedVolume -Cluster $ClusterName -Name "Cluster Virtual Disk ($($vdisk.friendlyname))").OwnerNode).Name

    # connect to owner (its actually not needed to connect to owner)
    $vdisk = Get-VirtualDisk -CimSession $owner -UniqueId $vdisk.UniqueId
    $tiers=$vdisk | Get-StorageTier
    if ($tiers){
        #resize Performance Tier
        $tiers | Where-Object FriendlyName -like *Performance | Resize-StorageTier -size $NewPerformanceTierSize
        #resize Capacity Tier
        $tiers | Where-Object FriendlyName -like *Capacity | Resize-StorageTier -size $NewCapacityTierSize

        Write-Host "Tiers after Resize: " -ForegroundColor Cyan
        $tiers=$vdisk | Get-StorageTier
        $tiers | Format-Table FriendlyName,@{Label="Size in GB"; Expression={($_.Size)/1GB}}

        #suspend Volume (not needed. It was needed only for NanoServer)
        #Write-Host "Suspending virtual disk" -ForegroundColor Cyan
        #Get-ClusterSharedVolume -Cluster $ClusterName -Name "Cluster Virtual Disk ($($vdisk.friendlyname))" | Suspend-ClusterResource -Force

        #Resize Partition
        $disk=get-disk -CimSession $owner -FriendlyName $vdisk.FriendlyName
        $size=$disk | Get-Partition | Where-Object PartitionNumber -eq 2 | Get-PartitionSupportedSize
        $disk | Get-Partition | Where-Object PartitionNumber -eq 2 | Resize-Partition -Size $size.SizeMax

        #resume Volume (not needed. It was needed only for NanoServer)
        #Write-Host "Resuming virtual disk" -ForegroundColor Cyan
        #Get-ClusterSharedVolume -Cluster $ClusterName -Name "Cluster Virtual Disk ($($vdisk.friendlyname))" | Resume-ClusterResource

        $size=($disk | Get-Partition | Where-Object partitionnumber -eq 2).Size/1GB
        Write-Host "Partition size after Resize operation (GB): $size" -ForegroundColor Green
    }else{
        Write-Host "Virtual disk $($vdisk.friendlyname) does not contain tiers, skipping."
    }
}
 
````