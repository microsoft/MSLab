$URLInfluxDB ="http://InfluxDB:8086"
$DatabaseName="telegraf"
$ClusterName = (get-cluster).name
#Grab volumes owned by current node
$csvs = Get-ClusterSharedVolume | Where-Object {$_.OwnerNode.Name -eq $env:COMPUTERNAME}
foreach ( $csv in $csvs ) {
    $csvinfos = $csv | Select-Object -Property Name -ExpandProperty SharedVolumeInfo
    foreach ( $csvinfo in $csvinfos ) {
        $data = $csv.Name
        $name = ($data.split("(")[1]).split(")")[0]
        $obj = New-Object PSObject -Property @{
            FriendlyName = $name
            Path         = $csvinfo.FriendlyVolumeName
            Size         = $csvinfo.Partition.Size
            FreeSpace    = $csvinfo.Partition.FreeSpace
            UsedSpace    = $csvinfo.Partition.UsedSpace
            PercentFree  = $csvinfo.Partition.PercentFree
        }
    }
    $csvinfo = $obj | Select-Object FriendlyName, Path, @{ Label = "Size" ; Expression = { ($_.Size /1GB) } }, @{ Label = "FreeSpace" ; Expression = { ($_.FreeSpace / 1GB) } }, @{ Label = "UsedSpace" ; Expression = { ($_.UsedSpace /1GB) } }, @{ Label = "PercentFree" ; Expression = { ($_.PercentFree) } } 
    $csvinfo | ConvertTo-Metric -Measure CSVinfo -MetricProperty Size, FreeSpace, UsedSpace, PercentFree -TagProperty FriendlyName, Path -Tags @{ClusterName = $ClusterName} | Write-Influx -Database $DatabaseName -Server $URLInfluxDB
}

#grab all Cluster and non-cluster disks owned by current node and send health stat
$vdisks=@()
$vdisks+=(Get-ClusterResource | Where-Object ResourceType -eq "Physical Disk" | Where-Object {$_.OwnerNode.Name -eq $env:COMPUTERNAME}).Name
$vdisks+=(Get-ClusterSharedVolume | Where-Object {$_.OwnerNode.Name -eq $env:COMPUTERNAME}).Name
$vdisks=ForEach ($vdisk in $vdisks) {if ($vdisk){$vdisk.trim("Cluster Virtual Disk (").trim(")")}}
$vdisks=ForEach ($vdisk in $vdisks) {Get-VirtualDisk -FriendlyName $vdisk}

foreach ( $Vdisk in $VDisks ) {
    If ( $VDisk.HealthStatus -like "Healthy") {
        $HealthNum = 1
    }
    elseif ( $VDisk.HealthStatus -like "Warning") {
        $HealthNum = 2
    }
    else {
        $HealthNum = 3
    }
    $VDiskinfo = Get-VirtualDisk -FriendlyName $Vdisk.FriendlyName | Select-Object FriendlyName, ResiliencySettingName, OperationalStatus, HealthStatus, @{ Label = "HealthNum" ; Expression = { ($HeatlyNum) } }, @{ Label = "Size" ; Expression = { ($_.Size /1GB) } }, @{ Label = "AllocatedSize" ; Expression = { ($_.AllocatedSize /1GB) } }, @{ Label = "StorageEfficiency" ; Expression = { (($_.Size * 100) / $_.FootprintOnPool) } }, @{ Label = "FootprintOnPool" ; Expression = { ($_.FootprintOnPool /1GB) } } 
    $VDiskinfo | ConvertTo-Metric -Measure VDiskinfo -MetricProperty HealthNum, Size, AllocatedSize, StorageEfficiency, FootprintOnPool -TagProperty FriendlyName, ResiliencySettingName, OperationalStatus, HealthStatus -Tags @{ClusterName = $ClusterName} | Write-Influx -Database $DatabaseName -Server $URLInfluxDB
}

#grab storage jobs if node is owner of cluster core resources (to avoid same data in DB)
if ((Get-ClusterGroup -Name "Cluster Group").OwnerNode.Node -eq $env:COMPUTERNAME){
    Get-storagejob | ConvertTo-Metric -Measure StorageJob -TagProperty name, JobState -MetricProperty PercentComplete -Tags @{ClusterName = $ClusterName} | Write-Influx -Database $DatabaseName  -Server $URLInfluxDB
    #Get-clusternode | ConvertTo-Metric -Measure ClusterState -TagProperty name, state -MetricProperty id | Write-Influx -Database $DatabaseName  -Server $URLInfluxDB
    Get-WmiObject -Class MSCluster_Node -namespace "root\mscluster" | ConvertTo-Metric -Measure ClusterState -TagProperty Name, State -MetricProperty ID -Tags @{ClusterName = $ClusterName} | Write-Influx -Database $DatabaseName  -Server $URLInfluxDB
    Get-StorageQoSVolume | Select-Object @{ Label = "Mountpoint" ; Expression = { (($_.Mountpoint.split("\\"))[2]) } }, IOPS, Latency, Bandwidth | ConvertTo-Metric -Measure StorageQoSVolume -TagProperty Mountpoint -MetricProperty IOPS, Latency, Bandwidth | Write-Influx -Database $DatabaseName  -Server $URLInfluxDB
    Get-StorageQosFlow | Select-Object InitiatorName, @{Expression = { $_.InitiatorNodeName.Substring(0, $_.InitiatorNodeName.IndexOf('.')) }; Label = "InitiatorNodeName" }, StorageNodeIOPs | ConvertTo-Metric -Measure StorageQoSVM -TagProperty InitiatorName,InitiatorNodeName -MetricProperty StorageNodeIOPs | Write-Influx -Database $DatabaseName  -Server $URLInfluxDB
}

#Send VM perf metrics
    if (((get-date).second) -in 0..10) {
        $VMtable = get-vm | Get-ClusterPerf | Select-Object ObjectDescription, MetricId, Value
        $i = 1
        $hash = $null
        $hash = @{ }
        foreach ($values in $VMtable) {  
            $vmname = $values.ObjectDescription.split([char]0x0020, 1) | Select-Object -last 1
            $metric = $values.MetricId.split([char]0x002C, 1) | Select-Object -first 1
            $currentvalue = [math]::Round(($values.Value), 0)  
            If ($i -le 18) { $hash.add($metric, $currentvalue) }
            $i++
            If ($i -eq 19) {
                $i = 1
                Write-Influx -Database $DatabaseName -Server $URLInfluxDB -Measure VM -Metrics $hash -Tags @{VMName = $vmname ; clustername = $ClusterName}
                $hash = $null
                $hash = @{ }
            }
        }
    }

#send S2D Metrics if owner of cluster core resources
    ## S2D Metrics
    if ((Get-ClusterGroup -Name "Cluster Group").OwnerNode.Node -eq $env:COMPUTERNAME){
        if (((get-date).second) -in 30..40) {
            $S2DPerfs = Get-ClusterPerf | Select-Object MetricID, value
            $hash = $null
            $hash = @{ }
            $hash.add("host", $env:computername)
            foreach ($S2DPerf in $S2DPerfs) {
                $metric = $S2DPerf.MetricId.split([char]0x002C, 1) | Select-Object -first 1
                $currentvalue = $S2DPerf.Value
                $hash.add($metric, $currentvalue)
            }
            Write-Influx -Database $DatabaseName -Server $URLInfluxDB -Measure S2D -Tags @{clustername = $ClusterName } -Metrics $hash
        }
    }