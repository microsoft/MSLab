$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#just 2 AzSHCI 21H2 nodes with nested virtualization enabled
1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 8GB; VMProcessorCount="Max" ; vTPM=$true ; NestedVirt=$true}}

#or small footprint just when host is limited - Nested virtualization disabled
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 1GB; VMProcessorCount="Max" ; vTPM=$true}}

#Optional Windows Admin Center in GW mode
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2022Core_G2.vhdx'; MGMTNICs=1}