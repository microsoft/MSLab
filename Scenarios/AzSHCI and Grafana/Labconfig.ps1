$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!';<# Prefix = 'MSLab-';#> SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

#Azure Stack HCI 22H2
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 2TB ; MemoryStartupBytes= 1GB; VMProcessorCount=4 ; vTPM=$true}}
#Or with nested virtualization enabled
#1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 2TB ; MemoryStartupBytes= 4GB; VMProcessorCount=4 ; vTPM=$true ; NestedVirt=$true}}

$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2022_G2.vhdx' ; MGMTNICs=1}
$LabConfig.VMs += @{ VMName = 'CA'         ; ParentVHD = 'Win2022Core_G2.vhdx' ; MGMTNICs=1}
$LabConfig.VMs += @{ VMName = 'Grafana'    ; ParentVHD = 'Win2022Core_G2.vhdx'; MemoryStartupBytes= 1GB ; MGMTNICs=1}
$LabConfig.VMs += @{ VMName = 'InfluxDB'   ; ParentVHD = 'Win2022Core_G2.vhdx'; Configuration = 's2d' ; SSDNumber = 1 ; SSDSize=1GB ; HDDNumber = 0 ; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MGMTNICs=1}
