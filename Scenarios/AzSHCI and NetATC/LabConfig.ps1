$LabConfig=@{AllowedVLANs="1-10,711-719" ; DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; <# Prefix = 'MSLab-';#> SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@()}

#Azure Stack HCI 22h2 (without disks as we dont need it to play with network)
#4VMProcessors are needed for NetATC to work in VMs (intent will fail to apply because of vRSS)
$LabConfig.VMs += @{ VMName = '2NICs1' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 }
$LabConfig.VMs += @{ VMName = '2NICs2' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 }
$LabConfig.VMs += @{ VMName = '4NICs1' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '4NICs2' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '6NICs1' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=6 }
$LabConfig.VMs += @{ VMName = '6NICs2' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=6 }
$LabConfig.VMs += @{ VMName = 'Switchless1' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = 'Switchless2' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = 'Switchless3' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = 'Site1Node1' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = 'Site1Node2' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = 'Site2Node1' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = 'Site2Node2' ; ParentVHD = 'AzSHCI22H2_G2.vhdx' ; VMProcessorCount=4 ; MGMTNICs=4 }

#Management machine
$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2022_G2.vhdx'; MGMTNICs=1}

#Optional Windows Admin Center in GW mode
#$LabConfig.VMs += @{ VMName = 'WacGW' ; ParentVHD = 'Win2022Core_G2.vhdx'; MGMTNICs=1}
