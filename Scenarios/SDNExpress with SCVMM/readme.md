<!-- TOC -->

- [About Scenario](#about-scenario)
    - [Description and requirements](#description-and-requirements)
- [LabConfig](#labconfig)
- [The LAB](#the-lab)

<!-- /TOC -->

# About Scenario 
Author: Andreas Sobczyk / [CloudMechanic.net](https://CloudMechanic.net) / [Twitter](http://twitter.com/Andreas_Sobczyk) / 

## Description and requirements
* In this scenario VMM SDN Express can be created and deployed from scratch using SCVMM nested in one Hyper-V host
* Script is tested only for this specific nested scenario
* Works best with Windows Server 2016, SAC release has smaller success rate for this deployment at the moment

* Works with SCVMM 1801
* Require around 100GB memory and 300GB disk space

* Please hydrate your main lab with SCVMM as demonstrated in this [video](https://youtu.be/NTrncW2omSY?list=PLf9T7wfY_JD2UpjLXoYNcnu4rc1JSPfqE) 
* You can download SCVMM 1801 from [eval center](https://www.microsoft.com/en-us/evalcenter/evaluate-system-center-release)



# LabConfig

````PowerShell
# VMM SDN Express

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'VMMSDNExpress-'; SecureBoot=$false; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; VMs=@();InstallSCVMM='Yes'; PullServerDC=$false; CreateClientParent=$false ; ClientEdition='Enterprise'; Internet=$true;AllowedVLANs="1-400"; AdditionalNetworksInDC=$true; AdditionalNetworksConfig=@(); EnableGuestServiceInterface=$true;}
$LABConfig.AdditionalNetworksConfig += @{ 
        NetName = 'HNV';
        NetAddress='10.103.33.';
        NetVLAN='201';
        Subnet='255.255.255.0'
    }
$LABConfig.AdditionalNetworksConfig += @{ 
        NetName = 'Transit';
        NetAddress='10.103.37.';
        NetVLAN='300';
        Subnet='255.255.255.0'
    }

$LABConfig.ServerVHDs += @{
    Edition="ServerDataCenterCore";
    VHDName="WinServerCore.vhdx";
    Size=40GB
}

1..4 | % { 
    $VMNames="HV";
    $LABConfig.VMs += @{
        VMName = "$VMNames$_" ;
        Configuration = 'S2D' ;
        ParentVHD = 'WinServerCore.vhdx';
        #ParentVHD = 'WinServerCore1709.vhdx';
        SSDNumber = 1;
        SSDSize=150GB ;
        MemoryStartupBytes= 25GB;
        NestedVirt=$True;
        StaticMemory=$True;
        VMProcessorCount = 6
    }
}
````

# The LAB

**Tip:** When prompt for the VHDX used in VMM select the same as you used for the hosts

The script is devided in two parts, first part should be run from the Hyper-V host, second part should be run from the DC

## Part 1
* Select the VHDX to be used for the SDN VMs
* Select the FabricConfig.psd1 file 

## Part 2
Copy the second part of the script to VMM and execute it.

VMMExpress can be abit unstable in deployment
If VMMExpress failes run the code in the catch block to clean the entire SDN deployment and rerun the VMMExpress.ps1 line.

**Notes:** Will continue to figure out how to make this more stable, and working together with the SDN Team