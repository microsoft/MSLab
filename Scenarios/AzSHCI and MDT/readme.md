<!-- TOC -->

- [AzSHCI and MDT](#azshci-and-mdt)
    - [About the lab](#about-the-lab)
    - [LabConfig with enabled telemetry Full](#labconfig-with-enabled-telemetry-full)
- [The lab](#the-lab)
    - [Region prereqs](#region-prereqs)
    - [Region configure MDT](#region-configure-mdt)
    - [Region configure MDT run-as account](#region-configure-mdt-run-as-account)
    - [Region configure Bootstrap ini and generate WinPE](#region-configure-bootstrap-ini-and-generate-winpe)
    - [Region Install and configure WDS](#region-install-and-configure-wds)
    - [Region Configure MDT monitoring](#region-configure-mdt-monitoring)
    - [Region replace customsettings.ini ith all DB data to query wizard output](#region-replace-customsettingsini-ith-all-db-data-to-query-wizard-output)
    - [Region configure SQL to be able to access it remotely using MDTUSer account](#region-configure-sql-to-be-able-to-access-it-remotely-using-mdtuser-account)
    - [Region Run from Hyper-V Host to create new, empty VMs](#region-run-from-hyper-v-host-to-create-new-empty-vms)
    - [Create hash table out of machines that attempted to boot last 5 minutes](#create-hash-table-out-of-machines-that-attempted-to-boot-last-5-minutes)
    - [Create DHCP reservation for machines](#create-dhcp-reservation-for-machines)
    - [Region add deploy info to AD Object and MDT Database](#region-add-deploy-info-to-ad-object-and-mdt-database)
    - [Reboot machines](#reboot-machines)

<!-- /TOC -->

# AzSHCI and MDT

## About the lab

In this lab you will learn how to deploy Azure Stack HCI nodes with Microsoft Deployment Toolkit (MDT). Scripts demonstrates unattend installation of all components (ADK, ADKPE, SQL Express, MDT), required configuration, setup of WDS that responds only to known computers, adding servers either by querying local event log for attempted deployments or simply populating with Hash table and many more!

This demonstration is simplified, as in real world scenarios you will need to inject drivers, install software and configure OS. This scenario is great start for designing production deployments! All runs from DC or management machine (Windows 10) demonstrating installation on remote computer.

Same scenario can be used to deploy physical (DELL) servers as lab can connect to physical adapters.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/LabInfo01.png)

Previous iteration of scenario (without dedicated MDT and physical machines) is demonstrated here:

[![MSLab in MVPDays](/Docs/media/Deploying_AzSHCI_with_MDT.png)](https://youtu.be/Vipbhkv9wyM)

## LabConfig with enabled telemetry (Full)

Notice, that following labconfig contains physical switch NIC names (NIC1 and NIC2) that will be added into vSwitch created by MSLab.

Lab also contains Windows 11. To create VHD, you can [use "CreateParentDisk.ps1" script](/Docs/MSLab-Advanced/creating-parent-disk.md).

```powershell
$LabConfig=@{SwitchNics="NIC1","NIC2"; DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='MDT' ; AdditionalNetworksConfig=@(); VMs=@()}

#MDT machine (GUI is needed as Core does not have WDSUtil)
$LabConfig.VMs += @{ VMName = 'MDT' ; Configuration = 'S2D' ; ParentVHD = 'Win2022_G2.vhdx' ; SSDNumber = 1; SSDSize=1TB ; MGMTNICs=1 }

#optional Windows 11 machine for management
$LabConfig.VMs += @{ VMName = 'Win11' ; ParentVHD = 'Win1121H2_G2.vhdx' ; MGMTNICs=1}
 
```

# The lab

Run all code from DC or Management machine. Follow [Scenario.ps1](/Scenarios/AzSHCI%20and%20MDT/Scenario.ps1). Notice one part that needs to be adjusted and ran from hyper-v host (to create empty VMs and boot it).

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/PowerShell_ISE01.png)

## Region prereqs

This region will download following binaries

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer01.png)

and install SQL, ADK and MDT to MDT Server and ADK and MDT to management machine. Note: it will download components from internet as ADK and SQL are just online installers.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer02.png)

## Region configure MDT

This region configures WinPE settings, imports AzSHCI OS, configures SQL to use TCP/IP or named pipes, adds Task Sequence and configures MDT to use database.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT01.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT02.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT03.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT04.png)

## Region configure MDT run-as account

Demonstrates setting up MDT account to be able to access deployment share, and adds permissions to domain join computers into preconfigured OU (source: https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=48)\

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/PowerShell01.png)

## Region configure Bootstrap ini and generate WinPE

Configures bootstrap ini, so when booting WinPE, it uses MDTUser identity and connects to DC to deployment share. Also PowerShell is enabled in Windows PE.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer03.png)

## Region Install and configure WDS

Installs WDS feature, configures WDS to not require F12 for prestaged machines and to refuse unknown. It will also import WDS wim file to WDS.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/PowerShell02.png)

## Region Configure MDT monitoring

Creates MDT monitoring Firewall rule and enables monitoring on deployment share.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/PowerShell03.png)

## Region replace customsettings.ini ith all DB data to query (wizard output)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT08.png)

Same as if you would click on "Configure Database Rules" (with all options selected) as on picture below

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT07.png)

## Region configure SQL to be able to access it remotely using MDTUSer account

Will configure firewall rule to allow named pipes remote access and will enable MDTAccount as db_datareader using sqlserver powershell module

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/PowerShell05.png)

## Region Run from Hyper-V Host to create new, empty VMs

Creates 4 VMs in specified directory (you can adjust memory startup bytes, or number of VMs). By default there are 4 VMs, 4GB RAM each. You can adjust VMs down to 1GB if nested virt is not enabled.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer04.png)

## Create hash table out of machines that attempted to boot last 5 minutes

Since machines booted in order (AzSHCI1 then AzSHCI2 ...) we can simply generate names with static IP Addresses and grab GUIDs and MACs from event log.

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/PowerShell04.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Eventvwr01.png)

## Create DHCP reservation for machines

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/DHCP01.png)

## Region add deploy info to AD Object and MDT Database

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT05.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/MDT06.png)

As you can see, WDS will let machine boot if attribute is present

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer05.png)

It's the same attribute that is displayed in WDS Console. Since WDS management cannot be installed to Win11, screenshot below is from server "MDT".

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer07.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer08.png)

## Reboot machines

(turn off,start) and machines will automatically deploy (as they will boot from pxe

Notice deployment progress in MDT monitoring section

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer09.png)

![](/Scenarios/AzSHCI%20and%20MDT/Screenshots/Explorer10.png)