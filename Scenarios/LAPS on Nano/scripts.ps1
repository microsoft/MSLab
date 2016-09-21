#$Labconfig.VMs

1..2 | % {“Nano$_“} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = ‘Simple’; ParentVHD = ‘Win2016Nano_G2.vhdx’; MemoryStartupBytes= 128MB ; DSCMode=‘Pull’; DSCConfig=@(‘LAPS_Nano_Install’,‘LAPSConfig1’)} }
3..4 | % {“Nano$_“} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = ‘Simple’; ParentVHD = ‘Win2016Nano_G2.vhdx’; MemoryStartupBytes= 128MB ; DSCMode=‘Pull’; DSCConfig=@(‘LAPS_Nano_Install’,‘LAPSConfig2’)} }


#starting VMs one by one (bug in LCM DB)

1..4 | % { 
    Start-VM *Nano$_ 
    Start-Sleep 30
} 

#How to validate report

function GetReport{
    param($AgentId, $serviceURL)
    $requestUri = "$serviceURL/Nodes(AgentId= '$AgentId')/Reports"
    $request = Invoke-WebRequest -Uri $requestUri  -ContentType "application/json;odata=minimalmetadata;streaming=true;charset=utf-8" `
               -UseBasicParsing -Headers @{Accept = "application/json";ProtocolVersion = "2.0"} `
               -ErrorAction SilentlyContinue -ErrorVariable ev
    $object = ConvertFrom-Json $request.content
    return $object.value
}

1..4 | ForEach-Object {$servers=$servers+@("Nano$_")}
$Servers | % {GetReport -AgentId (Get-DscLocalConfigurationManager -CimSession $_).AgentId -serviceURL (Get-DscLocalConfigurationManager -CimSession $_).ConfigurationDownloadManagers.serverurl}
