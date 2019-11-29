$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab19522.1000-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

#Notice NestedVirt and aditional networks
1..2 | ForEach-Object {$VMNames="Site1S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_19522.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True}} 
1..2 | ForEach-Object {$VMNames="Site2S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_19522.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True}} 

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.11.'; NetVLAN='0'; Subnet='255.255.255.0'}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet2'; NetAddress='172.16.12.'; NetVLAN='0'; Subnet='255.255.255.0'}
 