$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab1709-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..4 | % {"1709Node$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'WinServer1709_G2.vhdx'; ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; VMSet= 'SSWin1709' } }

$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="WinServer1709_G2.vhdx";
    Size=40GB
}
