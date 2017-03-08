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