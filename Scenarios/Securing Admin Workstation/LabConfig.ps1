$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab17763.914-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'AdminStation' ; ParentVHD = 'Win1019H1_G2.vhdx'   ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'UserStation'  ; ParentVHD = 'Win1019H1_G2.vhdx'   ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True ; EnableWinRM=$True ; vTPM=$True}
#$LabConfig.VMs += @{ VMName = 'CA'          ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True}
#$LabConfig.VMs += @{ VMName = 'DHA'         ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'Server01'     ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True}
$LabConfig.VMs += @{ VMName = 'Server02'     ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True}
