#################
### Labconfig ###
#################
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..2 | % {"Nano$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'; ParentVHD = 'Win2016NanoHV_G2.vhdx'; MemoryStartupBytes= 128MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig1')} }
3..4 | % {"Nano$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'; ParentVHD = 'Win2016NanoHV_G2.vhdx'; MemoryStartupBytes= 128MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig2')} }
