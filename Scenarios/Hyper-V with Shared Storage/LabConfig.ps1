$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..4 | % {"HVNode$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016Core_G2.vhdx'; ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; VMSet= 'SharedStorage1' } }