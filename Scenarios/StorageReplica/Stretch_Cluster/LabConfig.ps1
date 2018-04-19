##################
# LabConfig.ps1  #
##################

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'SR-'; SwitchName = 'LabSwitch'; DCEdition='4';AdditionalNetworksConfig=@();VMs=@()}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

1..2 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'  ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 2; SSDSize=200GB ; HDDNumber = 2  ; HDDSize= 2TB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSite1' ; NestedVirt=$True ; AdditionalNetworks = $True} }
3..4 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'  ; ParentVHD = 'Win2016Core_G2.vhdx'   ; SSDNumber = 2; SSDSize=200GB ; HDDNumber = 2  ; HDDSize= 2TB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSite2' ; NestedVirt=$True ; AdditionalNetworks = $True} }
