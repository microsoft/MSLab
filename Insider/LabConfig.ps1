#With Windows 10 for management and internet connectivity
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016labInsider-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; PullServerDC=$false; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}

$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="Win2016Core_G2.vhdx";
    Size=30GB
}

<#
#Without Windows 10 for management and without Internet connectivity
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016labInsider-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE' ; PullServerDC=$false ; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="Win2016Core_G2.vhdx";
    Size=30GB
}
#>