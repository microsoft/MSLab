#Labconfig is same as default for Windows Server 2019, just with nested virtualization and 4GB for startup memory
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

#S2D Cluster
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true }}

#Certification Authority
$LabConfig.VMs += @{ VMName = 'CA' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; MGMTNICs=1 }

#NC Cluster
1..3 | % {$VMNames="NC0"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MGMTNICs=1}}

#GWs
1..2 | % {$VMNames="GW0"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; ParentVHD = 'Win2019Core_G2.vhdx';MemoryStartupBytes= 1GB ; MGMTNICs=3}}

#GSBLMUXes
1..2 | % {$VMNames="SLBMUX0"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; ParentVHD = 'Win2019Core_G2.vhdx';MemoryStartupBytes= 1GB ; MGMTNICs=3}}

# Optional Management machine
#$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win1019H1_G2.vhdx' ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True ; DisableWCF=$true ; MGMTNICs=1 }

# WAC GW machine
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB; MGMTNICs=1 }
