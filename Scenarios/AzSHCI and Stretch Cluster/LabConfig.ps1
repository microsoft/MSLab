#sample labconfig with enabled telemetry (Full)

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab19522.1000-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#Management machine
$LABConfig.VMs += @{ VMName = "Management" ; ParentVHD = 'Win2019_G2.vhdx' ; MGMTNICs=1}

#optional WacGW
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx'; MGMTNICs=1}

#AzSHCI Nodes. Notice NestedVirt and aditional networks
1..2 | ForEach-Object {$VMNames="Site1AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True ; ManagementSubnetID=0}} 
1..2 | ForEach-Object {$VMNames="Site2AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4; HDDSize= 8TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true ; AdditionalNetworks=$True ; ManagementSubnetID=1}} 

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.11.'; NetVLAN='0'; Subnet='255.255.255.0'}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet2'; NetAddress='172.16.12.'; NetVLAN='0'; Subnet='255.255.255.0'}
 