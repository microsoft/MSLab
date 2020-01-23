$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab17763.973-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

1..3 | % {"FS$_"}    | % { $LABConfig.VMs += @{ VMName = $_ ; ParentVHD = 'Win2019Core_G2.vhdx'  ; Unattend="djoincred"} }
1..3 | % {"FSNEW$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; ParentVHD = 'Win2019Core_G2.vhdx'  ; Unattend="djoincred"} }

$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx' }
$LabConfig.VMs += @{ VMName = 'SMS'   ; ParentVHD = 'Win2019Core_G2.vhdx' }