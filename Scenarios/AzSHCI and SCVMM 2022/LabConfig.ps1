
$LabConfig=@{DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'MSLab-'#> ; DCEdition='4'; Internet=$true ; <#UseHostDnsAsForwarder=$True ;#> InstallSCVMM="yes"; AdditionalNetworksConfig=@(); VMs=@()}

#just 2 nodes with nested virtualization enabled
1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSVMM$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 8GB; VMProcessorCount="Max" ; vTPM=$true ; NestedVirt=$true}}

#or small just when host is limited
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "AzSHCI$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx' ; HDDNumber = 10 ; HDDSize= 10TB ; MemoryStartupBytes= 1GB; VMProcessorCount="Max" ; vTPM=$true}}

#File share for images for SCVMM Library
$LabConfig.VMs += @{ VMName = 'Library' ; Configuration = 'S2D' ; ParentVHD = 'Win2022Core_G2.vhdx' ; SSDNumber = 1; SSDSize=1TB ; MGMTNICs=1 }

#Windows Server Update Services
$LabConfig.VMs += @{ VMName = 'WSUS' ; ParentVHD = 'Win2022Core_G2.vhdx'; MGMTNICs=1}