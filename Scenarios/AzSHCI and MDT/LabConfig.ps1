$LabConfig=@{<#SwitchNics="NIC1","NIC2";#> DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' <#;Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#MDT machine (GUI is needed as Core does not have WDSUtil)
$LabConfig.VMs += @{ VMName = 'MDT' ; Configuration = 'S2D' ; ParentVHD = 'Win2022_G2.vhdx' ; SSDNumber = 1; SSDSize=1TB ; MGMTNICs=1 }

#optional Windows 11 machine for management
$LabConfig.VMs += @{ VMName = 'Win11' ; ParentVHD = 'Win1121H2_G2.vhdx' ; MGMTNICs=1}

