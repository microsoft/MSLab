#sample labconfig with enabled telemetry (Full)

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2019_G2.vhdx'; MGMTNICs=1}
$LabConfig.VMs += @{ VMName = 'Win10' ; ParentVHD = 'Win1020H1_G2.vhdx'; MGMTNICs=1 ; EnableWinRM=$true}
$LabConfig.VMs += @{ VMName = 'Win10_1' ; ParentVHD = 'Win1020H1_G2.vhdx'; MGMTNICs=1 ; EnableWinRM=$true}
#$LabConfig.VMs += @{ VMName = 'Win10_2' ; ParentVHD = 'Win1020H1_G2.vhdx'; MGMTNICs=1 ; EnableWinRM=$true}