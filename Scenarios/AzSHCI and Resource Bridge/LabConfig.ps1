
$LabConfig=@{ManagementSubnetIDs=0..1 ;DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'MSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='JaromiK' ; CustomDnsForwarders="10.8.8.8","10.7.7.7" ; AdditionalNetworksConfig=@(); VMs=@()}

#2 nodes for AzSHCI Cluster
1..2 | ForEach-Object {$VMNames="ASHCIRB" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 20GB; VMProcessorCount="Max" ; NestedVirt=$true ; VirtualTPM=$true}}

#or small just when host is limited
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 1GB; VMProcessorCount="Max" ; vTPM=$true}}

#Optional Windows Admin Center in GW mode
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2022Core_G2.vhdx'; MGMTNICs=1}

#Management machine
$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2022_G2.vhdx' ; MGMTNICs=1 }