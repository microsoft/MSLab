$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Win10'  ; ParentVHD = 'Win1020H1_G2.vhdx' ; MGMTNICs=1 ; EnableWinRM=$True }
$LabConfig.VMs += @{ VMName = 'Win10_1'; ParentVHD = 'Win1020H1_G2.vhdx' ; MGMTNICs=1 ; EnableWinRM=$True}

$LabConfig.VMs += @{ VMName = 'FileServer' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MGMTNICs=1 }
