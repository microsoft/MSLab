##################
# LabConfig.ps1  #
##################

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'SR-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter';AdditionalNetworksConfig=@();VMs=@()}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

1..2 | % { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016Core_G2.vhdx'   ; ReplicaHDDSize = 200GB ; ReplicaLogSize = 20GB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaCluster1' ; NestedVirt=$True ; AdditionalNetworks = $True} }
3..4 | % { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016Core_G2.vhdx'   ; ReplicaHDDSize = 200GB ; ReplicaLogSize = 20GB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaCluster2' ; NestedVirt=$True ; AdditionalNetworks = $True} }


##################
