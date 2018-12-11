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
                    @{ Name = 'Ethernet'   ; VMNetworkAdapter = 'SMB_1' ; VLANID = '1' ; JumboPacket = 1500 }
                    @{ Name = 'Ethernet 1' ; VMNetworkAdapter = 'SMB_2' ; VLANID = '1' ; JumboPacket = 1500 }
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
        @{ Name = 'ClusterHB'; Template = 'Cluster'              ; PriorityValue8021Action = 5 ; BandwidthPercentage = 1  ; Algorithm = 'ETS' }
        @{ Name = 'SMB'      ; NetDirectPortMatchCondition = 445 ; PriorityValue8021Action = 3 ; BandwidthPercentage = 60 ; Algorithm = 'ETS' }
        @{ Name = 'DEFAULT'  ; Template = 'Default'              ; PriorityValue8021Action = 0 ; BandwidthPercentage = 39 ; Algorithm = 'ETS' }
    )
}

$Global:configData = @{
    AllNodes    = $AllNodes
    NonNodeData = $NonNodeData
}