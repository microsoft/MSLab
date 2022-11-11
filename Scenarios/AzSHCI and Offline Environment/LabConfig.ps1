$LabConfig=@{DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#Azure Stack HCI 21H2
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 2TB ; MemoryStartupBytes= 1GB; VMProcessorCount=4 ; vTPM=$true}}

#Windows Admin Center in GW mode
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2022Core_G2.vhdx'; MGMTNICs=1}

#Management machine
$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2022_G2.vhdx'; MGMTNICs=1}