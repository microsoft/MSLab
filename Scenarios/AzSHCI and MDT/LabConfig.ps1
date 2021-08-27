$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#MDT machine (GUI is needed as Core does not have WDSUtil)
$LabConfig.VMs += @{ VMName = 'MDT' ; Configuration = 'S2D' ; ParentVHD = 'Win2022_G2.vhdx' ; SSDNumber = 1; SSDSize=1TB }

#optional Windows 11 machine for management
$LabConfig.VMs += @{ VMName = 'Win11' ; ParentVHD = 'Win1121H2_G2.vhdx' }

