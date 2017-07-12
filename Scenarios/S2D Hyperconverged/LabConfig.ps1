##### Labconfig.ps1 #####
$LabConfig=@{
    DomainAdminName='LabAdmin';
    AdminPassword='LS1setup!';
    Prefix = 'S2DHyperConverged-';
    SwitchName = 'LabSwitch';
    DCEdition='ServerDataCenter';
    VMs=@()
}

1..4 | % { 
    $VMNames="S2D";
    $LABConfig.VMs += @{ 
        VMName = "$VMNames$_";
        Configuration = 'S2D';
        ParentVHD = 'Win2016Core_G2.vhdx';
        SSDNumber = 0;
        SSDSize=800GB ;
        HDDNumber = 12;
        HDDSize= 4TB ;
        MemoryStartupBytes= 512MB
    }
} 

#### Or with Nested Virtualization. ####
<#
1..4 | % { 
    $VMNames="S2D";
    $LABConfig.VMs += @{
        VMName = "$VMNames$_" ;
        Configuration = 'S2D' ;
        ParentVHD = 'Win2016Core_G2.vhdx';
        SSDNumber = 0;
        SSDSize=800GB ;
        HDDNumber = 12;
        HDDSize= 4TB ;
        MemoryStartupBytes= 4GB;
        NestedVirt=$True
    }
}

#>