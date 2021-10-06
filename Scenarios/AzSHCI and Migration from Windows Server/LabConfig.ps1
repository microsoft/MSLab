$LabConfig=@{DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#2019 cluster
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "S2D$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 1GB }}
#AzSHCI cluster
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 1GB }}
#VHDs for in-place
1..4 | ForEach-Object {$VMNames="NewAzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; MemoryStartupBytes= 1GB }}

#or with nested virt
<#
#2019 cluster
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "S2D$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True}}
#AzSHCI cluster
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True}}
#VHDs for in-place
1..4 | ForEach-Object {$VMNames="NewAzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; MemoryStartupBytes= 1GB }}
#>
