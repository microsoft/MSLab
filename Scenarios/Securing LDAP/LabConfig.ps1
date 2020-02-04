$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab17763.973-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2019_G2.vhdx'     }
$LabConfig.VMs += @{ VMName = 'CA'         ; ParentVHD = 'Win2019Core_G2.vhdx' }
$LabConfig.VMs += @{ VMName = 'Grafana'    ; ParentVHD = 'Win2019Core_G2.vhdx' }
$LabConfig.VMs += @{ VMName = 'Collector'  ; ParentVHD = 'Win2019Core_G2.vhdx' }