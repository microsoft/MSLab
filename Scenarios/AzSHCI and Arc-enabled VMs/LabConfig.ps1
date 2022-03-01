$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; Prefix = 'MSLab-' ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#2 nodes for AzSHCI Cluster
1..2 | ForEach-Object {$VMNames="ArcVMs" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 14GB; VMProcessorCount="Max" ; NestedVirt=$true ; VirtualTPM=$true}}

#or 2 nodes for Windows Server 2022
#1..2 | ForEach-Object {$VMNames="ArcVMs" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2022Core_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 14GB; VMProcessorCount="Max" ; NestedVirt=$true ; VirtualTPM=$true}}

#optional Windows Admin Center gateway
#$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2022Core_G2.vhdx' ; MGMTNICs=1 }

#optional Windows Management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2022_G2.vhdx' ; MGMTNICs=1 }

