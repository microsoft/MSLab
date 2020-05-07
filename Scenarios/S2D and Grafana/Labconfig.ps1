$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!';<# Prefix = 'WSLab-';#> SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true}}

# or without nested virt and just 512MB of memory
#1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB}}

$LabConfig.VMs += @{ VMName = 'CA' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 1GB }
$LabConfig.VMs += @{ VMName = 'Grafana' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 1GB }
$LabConfig.VMs += @{ VMName = 'InfluxDB' ; Configuration = 's2d' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 0; HDDSize= 4TB ; MemoryStartupBytes= 1GB }

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 