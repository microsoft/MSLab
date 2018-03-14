<!-- TOC -->

- [About Scenario](#about-scenario)
    - [Description and requirements](#description-and-requirements)
- [LabConfig](#labconfig)
- [The LAB](#the-lab)
    - [region check prerequisites](#region-check-prerequisites)
    - [region Variables](#region-variables)
    - [region basic SCVMM Configuration](#region-basic-scvmm-configuration)
    - [region Configure networks](#region-configure-networks)
    - [region Configure Virtual Switch](#region-configure-virtual-switch)
    - [region Configure Physical Computer Profile](#region-configure-physical-computer-profile)
    - [region Configure WDS](#region-configure-wds)
    - [region Run from Hyper-V Host to create new VMs](#region-run-from-hyper-v-host-to-create-new-vms)
    - [region Deploy hosts (run again from DC or management machine)](#region-deploy-hosts-run-again-from-dc-or-management-machine)
    - [region Apply vSwitch](#region-apply-vswitch)
    - [region Configure Networking (classic approach)](#region-configure-networking-classic-approach)
    - [region Configure Cluster and S2D (classic approach)](#region-configure-cluster-and-s2d-classic-approach)
    - [region Create some Volumes (classic approach)](#region-create-some-volumes-classic-approach)
    - [region Create some dummy VMs (3 per each CSV disk)](#region-create-some-dummy-vms-3-per-each-csv-disk)
    - [region add storage provider to VMM](#region-add-storage-provider-to-vmm)

<!-- /TOC -->

# About Scenario 
Author: Andreas Sobczyk / [CloudMechanic.net](https://CloudMechanic.net) 

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

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'VMMSDNExpress-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; VMs=@();InstallSCVMM='Yes'; PullServerDC=$false; ServerISOFolder="F:\Sources\ISO\GA-LTSC\";  CreateClientParent=$false ; ClientEdition='Enterprise'; Internet=$true;}


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
        SSDNumber = 1;
        SSDSize=150GB ;
        MemoryStartupBytes= 25GB;
        NestedVirt=$True
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