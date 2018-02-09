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

<!-- /TOC -->

# About Scenario 

## Description and requirements
* In this scenario 2-16 node S2D cluster can be created from scratch using SCVMM
* It is just simulation "how it would look like". Performance is not a subject here - it is just to test look and feel
* Script is well tested, on both real and simulated environments. However you should ask your Premier Field Engineer to adapt scenario to your infrastructure
* Nano Servers for bare metal deployment are not the best. It's deployed successfully, but vSwitch fails to apply for some reason.

* Windows 10 1511 with enabled Hyper-V or Windows 10 1607+ (if nested virtualization is enabled)
* 10GB Memory or 20GB if nested virtualization is used (for 4 node configuration)
* SSD is a must

* Please hydrate your main lab with SCVMM as demonstrated in this [video](https://youtu.be/NTrncW2omSY?list=PLf9T7wfY_JD2UpjLXoYNcnu4rc1JSPfqE) 
* you can download SCVMM 1801 from [eval center](https://www.microsoft.com/en-us/evalcenter/evaluate-system-center-release)

# LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016labSCVMM-'; SwitchName = 'LabSwitch'; DCEdition='ServerDataCenter'; VMs=@();InstallSCVMM='Yes';CreateClientParent=$True}

#these 2 VMs are not needed, if you are pasting scripts to DC
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
$LabConfig.VMs += @{ VMName = 'WDS' ; Configuration = 'Simple' ; ParentVHD = 'Win2016_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB  }

````

# The LAB

**Tip:** You can hydrate lab faster, if you already have parent disks created. Just copy ParentDisks to your folder together with scripts, and 2_CreateParentDisks.ps1 will skip parent disks creation, and will even create DC with SCVMM just by reusing parentdisk (if you have GUI version there). Best practice would be to hydrate all with core and use Win10 for management. Both scenarios are valid. I like Win10 more as it's the way it should be in production environment.

**Tip 2:** Copy Server Core VHD into tools.vhd as you will use it for bare metal deploy

**Fun fact** You need GUI version of Windows Server since WDS is in full version only.

Since script is bit long, all regions are described below without code snippets. All code is in scenario.ps1

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/RegionsInISE.png)

## region check prerequisites

This region just checks if VMM console is installed and also if RSAT components are present. It is valid for Server/ServerCore/Client. If VMM console is not installed, it will ask for setup.exe and install it for you. 

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/VMMConsoleResult.png)

## region Variables

Here are all variables, that you can change - like domain name, networks, vSwitch name... 

Script will ask you for credentials. Just provide your LabAdmin creds (it's for run as admin creds.,typically corp\LabAdmin LS1setup!). In real environment you would have dedicated user.

Script will also ask you for VHD. Just provide Core server VHD from your ParentDisks (copy it to tools disk before hydration as instructed in Tip 2)

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/CredRequest.png)

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/VHDRequest.png)

## region basic SCVMM Configuration

For some reason VMM does not start, so its forced to start. Also some basic settings are configured like HostGroup, RunAsAccounts...

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/AutoCreationLogicalNetworks.png)

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/RunAsAccounts.png)

## region Configure networks

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/LogicalNetworks.png)

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/VMNetworks.png)

## region Configure Virtual Switch

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/LogicalSwitchvPorts.png)

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/LogicalSwitchUplinks.png)

## region Configure Physical Computer Profile

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/PhysicalComputerProfile.png)

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/PhysicalComputerProfileDetails.png)

## region Configure WDS

![](/Scenarios/S2D%20Bare%20Metal%20with%20SCVMM/Screenshots/WDS.png)

## region Run from Hyper-V Host to create new VMs

This piece needs to run from Hyper-V host. And also you need to mofify VMPath variable to reflect your lab (in my case E:drive)