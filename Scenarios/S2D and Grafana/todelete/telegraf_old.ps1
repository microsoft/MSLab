Function Send-JsonOverTcp {
    param ( [ValidateNotNullOrEmpty()] 
    [string] $Ip, 
    [int] $Port, 
    $JsonObject) 
    $JsonString = $JsonObject -replace "`n",' ' -replace "`r",' ' -replace ' ',''
    $Socket = New-Object System.Net.Sockets.TCPClient($Ip,$Port) 
    $Stream = $Socket.GetStream() 
    $Writer = New-Object System.IO.StreamWriter($Stream)
    $Writer.WriteLine($JsonString)
    $Writer.Flush()
    $Stream.Close()
    $Socket.Close()
}

$csvs = Get-ClusterSharedVolume

#Get CSV Info
    foreach ($csv in $csvs ){
        $csvinfos = $csv | Select-Object -Property Name -ExpandProperty SharedVolumeInfo
        foreach ( $csvinfo in $csvinfos ){
            $data = $csv.Name
            $name = ($data.split("(")[1]).split(")")[0]
            $obj = New-Object PSObject -Property @{
                FriendlyName        = $name
                Path        = $csvinfo.FriendlyVolumeName
                Size        = $csvinfo.Partition.Size
                FreeSpace   = $csvinfo.Partition.FreeSpace
                UsedSpace   = $csvinfo.Partition.UsedSpace
                PercentFree = $csvinfo.Partition.PercentFree
            }
        }
       $csvinfo = $obj |Select-Object FriendlyName,Path,@{ Label = "Size(GB)" ; Expression = { ($_.Size/1024/1024/1024) } },@{ Label = "FreeSpace(GB)" ; Expression = { ($_.FreeSpace/1024/1024/1024) } },@{ Label = "UsedSpace(GB)" ; Expression = {  ($_.UsedSpace/1024/1024/1024) } },@{ Label = "PercentFree" ; Expression = {  ($_.PercentFree) }} | ConvertTo-Json
       Send-JsonOverTcp 127.0.0.1 8094 "$csvinfo"
    }
 

$VDisks = Get-VirtualDisk 

foreach ( $Vdisk in $VDisks ){
    # Convert HealtStatus To Num
    If ( $VDisk.HealthStatus -like "Healthy"){
        $HeatlyNum = 1
    } elseif ( $VDisk.HealthStatus -like "Warning") {
        $HeatlyNum = 2
    }
    $VDiskinfo = Get-VirtualDisk -FriendlyName $Vdisk.FriendlyName | Select-Object FriendlyName,ResiliencySettingName,OperationalStatus,HealthStatus,@{ Label = "HealthNum" ; Expression = {  ($HeatlyNum) } },@{ Label = "Size(GB)" ; Expression = {  ($_.Size/1024/1024/1024) } },@{ Label = "AllocatedSize(GB)" ; Expression = {  ($_.AllocatedSize/1024/1024/1024) } },@{ Label = "StorageEfficiency" ; Expression = {  (($_.Size*100)/$_.FootprintOnPool) } },@{ Label = "FootprintOnPool (GB)" ; Expression = {  ($_.FootprintOnPool/1024/1024/1024) } } | ConvertTo-Json

    Send-JsonOverTcp 127.0.0.1 8094 "$VDiskinfo"
    #Write-Host $Vdisk
}

$Jobs =  get-storagejob | Select-Object name,JobState,PercentComplete | ConvertTo-Json

Send-JsonOverTcp 127.0.0.1 8095 "$Jobs"

$statusclust = get-clusternode | Select-Object name,state| ConvertTo-Json

Send-JsonOverTcp 127.0.0.1 8096 "$statusclust"

$qos = Get-StorageQoSVolume | Select-Object @{ Label = "Mountpoint" ; Expression = { (($_.Mountpoint.split("\\"))[2])}},IOPS,Latency,Bandwidth | ConvertTo-Json

Send-JsonOverTcp 127.0.0.1 8097 "$qos"

$qosvm = Get-StorageQosFlow |Select-Object InitiatorName, @{Expression={$_.InitiatorNodeName.Substring(0,$_.InitiatorNodeName.IndexOf('.'))};Label="InitiatorNodeName"},StorageNodeIOPs | ConvertTo-Json

Send-JsonOverTcp 127.0.0.1 8098 "$qosvm"