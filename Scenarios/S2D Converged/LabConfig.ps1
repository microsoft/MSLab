$LabConfig=@{
    DomainAdminName='LabAdmin';
    AdminPassword='LS1setup!';
    Prefix = 'S2DConverged-';
    SwitchName = 'LabSwitch';
    DCEdition='ServerDataCenter';
    VMs=@()
}

1..5 | ForEach-Object { $VMNames="Storage" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }
1..5 | ForEach-Object { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'; MemoryStartupBytes= 1GB ; NestedVirt = $True} }

<#or with server core
1..5 | ForEach-Object { $VMNames="Storage" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }
1..5 | ForEach-Object { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes= 1GB ; NestedVirt = $True} }
#>