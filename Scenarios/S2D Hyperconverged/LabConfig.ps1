##### Labconfig.ps1 #####
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@()}
1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; HDDNumber = 12; HDDSize= 4TB }}

#### Or with Nested Virtualization. ####
<#
1..4 | % { 
    $VMNames="S2D";
    $LABConfig.VMs += @{
        VMName = "$VMNames$_" ;
        Configuration = 'S2D' ;
        ParentVHD = 'Win2019Core_G2.vhdx';
        HDDNumber = 12;
        HDDSize= 4TB ;
        MemoryStartupBytes= 4GB;
        NestedVirt=$True
    }
}

#>