$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#2 nodes for AzSHCI Cluster
1..2 | ForEach-Object {$VMNames="AzSHCI" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 22GB; VMProcessorCount="Max" ; NestedVirt=$true}}

#Windows 10 management machine (for Windows Admin Center)
$LabConfig.VMs += @{ VMName = 'Win10'; ParentVHD = 'Win1020H1_G2.vhdx' ; AddToolsVHD = $True ; MGMTNICs=1 }

#Windows Admin Center gateway
#$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MGMTNICs=1 }
 