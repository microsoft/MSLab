<!-- TOC -->

- [About Scenario](#about-scenario)
    - [Description and requirements](#description-and-requirements)
- [LabConfig](#labconfig)
- [The LAB](#the-lab)

<!-- /TOC -->

# About Scenario 
Author: Andreas Sobczyk / [CloudMechanic.net](https://CloudMechanic.net) / [Twitter](http://twitter.com/Andreas_Sobczyk) / 

## Description and requirements
* In this scenario SDNv2 without VMM can be created and deployed from scratch nested in one Hyper-V host
* Script is tested only for this specific nested scenario
* Works with Windows Server 2016 and 2019

* Require around 100GB memory and 300GB disk space

# LabConfig

```PowerShell
#SDNExpress

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'SDNExpress2019-'; SecureBoot=$false; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; VMs=@();InstallSCVMM='No'; PullServerDC=$false; CreateClientParent=$false ; ClientEdition='Enterprise'; Internet=$true;AllowedVLANs="1-400"; AdditionalNetworksInDC=$true; AdditionalNetworksConfig=@(); EnableGuestServiceInterface=$true; ServerVHDs=@();}
$LABConfig.AdditionalNetworksConfig += @{ 
        NetName = 'HNV';
        NetAddress='10.103.33.';
        NetVLAN='201';
        Subnet='255.255.255.0'
    }

$LABConfig.ServerVHDs += @{
    Edition="3";
    VHDName="WinServerCore.vhdx";
    Size=150GB
}

$LABConfig.ServerVHDs += @{
    Edition="4";
    VHDName="WinServer.vhdx";
    Size=40GB
}

1..4 | % { 
    $VMNames="HV";
    $LABConfig.VMs += @{
        VMName = "$VMNames$_" ;
        Configuration = 'S2D' ;
        ParentVHD = 'WinServerCore.vhdx';
        SSDNumber = 2;
        SSDSize=800GB ;
        HDDNumber = 4;
        HDDSize=4TB ;
        MemoryStartupBytes= 20GB;
        NestedVirt=$True;
        StaticMemory=$True;
        VMProcessorCount = 6
    }
}

$LABConfig.VMs += @{
        VMName = "Management" ;
        Configuration = 'S2D' ;
        ParentVHD = 'WinServer.vhdx';
        SSDNumber = 1;
        SSDSize=50GB ;
        MemoryStartupBytes= 2GB;
        NestedVirt=$false;
        StaticMemory=$false;
        VMProcessorCount = 2
    }

```

# The LAB

**Tip:** When prompt for the VHDX, select the same as you used for the hosts


The script is devided in two parts, first part should be run from the Hyper-V host, second part should be run from the DC

For detailed guidance go to: https://cloudmechanic.net/2018/08/29/deploying-a-sdnv2-lab-on-a-single-host-using-nested-hyper-v/

## Part 1
* Select the VHDX to be used for the SDN VMs
* Select the MultiNodeConfig.psd1 file 
* Select the Windows Admin Center MSI file (1806+)

## Part 2
Copy the second part of the script to the Management VM and execute it.

### Known Issues
* SDN VMs not join to the domain, especially the gateway VMs seems to have problems, if this happens use the Hyper-V Manager console on the Management VM to connect to HV1 or HV2 or HV3 and domain join the VMs manually with SCONFIG to corp.contoso.com.
* Doing deployment the SLB MUXs is timing out on WinRM, if this happens just rerun the SDNExpress deployment script again and it should continue, the SDNExpress script is made to be rerun if any errors occur.
*  Gateways needs to be rebooted after RemoteAccess is installed, if this happens use the Hyper-V Manager console on the Management VM to connect to HV1 or HV2 and restart the related Contoso-GW VM, then rerun the SDNExpress deployment script.