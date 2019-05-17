$AllNodes    = @()
$NonNodeData = @()

$Nodes = 'S2D1','S2D2','S2D3','S2D4'

$Nodes | ForEach-Object {
	$AllNodes   += @{
        NodeName = $_

        VMSwitch = @(
            @{
                Name = 'SETSwitch'
                EmbeddedTeamingEnabled = $true

                RDMAEnabledAdapters = @(
                    @{ Name = 'Ethernet'   ; VMNetworkAdapter = 'SMB01' ; VLANID = '1' ; JumboPacket = 1514 }
                    @{ Name = 'Ethernet 2' ; VMNetworkAdapter = 'SMB02' ; VLANID = '1' ; JumboPacket = 1514 }
                )

                RDMADisabledAdapters = @(
                    @{ VMNetworkAdapter = 'Mgmt' }
                )
            }
        )
    }
}

$NonNodeData = @{
    NetQoS = @(
        @{ Name = 'ClusterHB'; Template = 'Cluster'              ; PriorityValue8021Action = 7 ; BandwidthPercentage = 1  ; Algorithm = 'ETS' }
        @{ Name = 'SMB'      ; NetDirectPortMatchCondition = 445 ; PriorityValue8021Action = 3 ; BandwidthPercentage = 60 ; Algorithm = 'ETS' }
        @{ Name = 'Default'  ; Template = 'Default'              ; PriorityValue8021Action = 0 ; BandwidthPercentage = 39 ; Algorithm = 'ETS' }
    )
}

$Global:configData = @{
    AllNodes    = $AllNodes
    NonNodeData = $NonNodeData
}