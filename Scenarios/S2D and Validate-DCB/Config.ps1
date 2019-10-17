$AllNodes = @()
$NonNodeData = @() 

$Nodes = 'S2D1' , 'S2D2' , 'S2D3' , 'S2D4' 

$Nodes | ForEach-Object {
    $AllNodes   += @{
        NodeName = $_

        VMSwitch = @(
            @{
                Name = 'SETSwitch'
                EmbeddedTeamingEnabled = $True
                LoadBalancingAlgorithm = 'HyperVPort'

                RDMAEnabledAdapters = @(
                    @{ Name = 'Ethernet'   ; VMNetworkAdapter = 'SMB01' ; VLANID = 1 ; JumboPacket = 1514 }
                    @{ Name = 'Ethernet 2' ; VMNetworkAdapter = 'SMB02' ; VLANID = 1 ; JumboPacket = 1514 }
                )
            }
        )
    }
}

$NonNodeData = @{
    NetQoS = @(
        @{ Name = 'ClusterHB' ; PriorityValue8021Action = 7 ; Template = 'Cluster'              ; BandwidthPercentage = 1  ; Algorithm = 'ETS' }
        @{ Name = 'SMB'       ; PriorityValue8021Action = 3 ; NetDirectPortMatchCondition = 445 ; BandwidthPercentage = 60 ; Algorithm = 'ETS' }
        @{ Name = 'Default'   ; PriorityValue8021Action = 0 ; Template = 'Default'              ; BandwidthPercentage = 39 ; Algorithm = 'ETS' }
    )
}

$Global:configData = @{
    AllNodes       = $AllNodes
    NonNodeData    = $NonNodeData
}
