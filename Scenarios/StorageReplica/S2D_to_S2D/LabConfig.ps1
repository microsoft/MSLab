##################
# LabConfig.ps1  #
##################

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'SR-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter';AdditionalNetworksConfig=@();VMs=@()}

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

1..2 | % { $VMNames="Site1S2D"     ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 2GB ;MemoryMinimumbytes=1GB;NestedVirt=$True;AdditionalNetworks=$True } } 
1..2 | % { $VMNames="Site2S2D"     ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 2GB ;MemoryMinimumbytes=1GB;NestedVirt=$True; AdditionalNetworks=$True } } 

##################