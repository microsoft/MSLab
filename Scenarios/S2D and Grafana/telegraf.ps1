$URLInfluxDB ="http://127.0.0.1:8086"
$csvs = Get-ClusterSharedVolume

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
    $csvinfo = $obj | Select-Object FriendlyName, Path, @{ Label = "Size" ; Expression = { ($_.Size / 1024 / 1024 / 1024) } }, @{ Label = "FreeSpace" ; Expression = { ($_.FreeSpace / 1024 / 1024 / 1024) } }, @{ Label = "UsedSpace" ; Expression = { ($_.UsedSpace / 1024 / 1024 / 1024) } }, @{ Label = "PercentFree" ; Expression = { ($_.PercentFree) } } 
    $csvinfo | ConvertTo-Metric -Measure CSVinfo -MetricProperty Size, FreeSpace, UsedSpace, PercentFree -TagProperty FriendlyName, Path | Write-Influx -Database HC  -Server $URLInfluxDB
}
 
$VDisks = Get-VirtualDisk 
foreach ( $Vdisk in $VDisks ) {
    If ( $VDisk.HealthStatus -like "Healthy") {
        $HeatlyNum = 1
    }
    elseif ( $VDisk.HealthStatus -like "Warning") {
        $HeatlyNum = 2
    }
    $VDiskinfo = Get-VirtualDisk -FriendlyName $Vdisk.FriendlyName | Select-Object FriendlyName, ResiliencySettingName, OperationalStatus, HealthStatus, @{ Label = "HealthNum" ; Expression = { ($HeatlyNum) } }, @{ Label = "Size" ; Expression = { ($_.Size / 1024 / 1024 / 1024) } }, @{ Label = "AllocatedSize" ; Expression = { ($_.AllocatedSize / 1024 / 1024 / 1024) } }, @{ Label = "StorageEfficiency" ; Expression = { (($_.Size * 100) / $_.FootprintOnPool) } }, @{ Label = "FootprintOnPool" ; Expression = { ($_.FootprintOnPool / 1024 / 1024 / 1024) } } 
    $VDiskinfo | ConvertTo-Metric -Measure VDiskinfo -MetricProperty HealthNum, Size, AllocatedSize, StorageEfficiency, FootprintOnPool -TagProperty FriendlyName, ResiliencySettingName, OperationalStatus, HealthStatus | Write-Influx -Database HC  -Server $URLInfluxDB
}

Get-storagejob | ConvertTo-Metric -Measure StorageJob -TagProperty name, JobState -MetricProperty PercentComplete | Write-Influx -Database HC  -Server $URLInfluxDB
Get-WmiObject -Class MSCluster_Node -namespace "root\mscluster" | ConvertTo-Metric -Measure ClusterState -TagProperty name  -MetricProperty id,state | Write-Influx -Database HC  -Server $URLInfluxDB
Get-StorageQoSVolume | Select-Object @{ Label = "Mountpoint" ; Expression = { (($_.Mountpoint.split("\\"))[2]) } }, IOPS, Latency, Bandwidth | ConvertTo-Metric -Measure StorageQoSVolume -TagProperty Mountpoint -MetricProperty IOPS, Latency, Bandwidth | Write-Influx -Database HC  -Server $URLInfluxDB
Get-StorageQosFlow | Select-Object InitiatorName, @{Expression = { $_.InitiatorNodeName.Substring(0, $_.InitiatorNodeName.IndexOf('.')) }; Label = "InitiatorNodeName" }, StorageNodeIOPs | ConvertTo-Metric -Measure StorageQoSVM -TagProperty InitiatorName,InitiatorNodeName -MetricProperty StorageNodeIOPs | Write-Influx -Database HC  -Server $URLInfluxDB

$FirstNode = (Get-ClusterNode | Where-Object State -Match 'UP').name | Select-Object -First 1

if ($FirstNode -match "$env:computername") {
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
                #Write-InfluxUDP -IP 192.168.132.20 -Port 8889 -Measure VM -Tags @{VMName = $vmname } -Metrics $hash 
                Write-Influx -Database HC  -Server $URLInfluxDB -Measure VM -Metrics $hash -Tags @{VMName = $vmname }
                $hash = $null
                $hash = @{ }
            }
        }
    }
    ## S2D Metrics
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
        Write-Influx -Database HC  -Server $URLInfluxDB -Measure S2D -Metrics $hash -Tags @{host = $env:computername}
    }
}
