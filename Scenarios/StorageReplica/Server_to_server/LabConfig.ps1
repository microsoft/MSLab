##################
# LabConfig.ps1  #
##################

$LabConfig=@{ DomainAdminName='Ned'; AdminPassword='LS1setup!'; Prefix = 'SR-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter';AdditionalNetworksConfig=@();VMs=@()}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

1..2 | % { $VMNames="Replica"     ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 1; SSDSize=20GB ; HDDNumber = 1; HDDSize= 200GB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; AdditionalNetworks = $True } } 

##################