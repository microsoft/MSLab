#basic, S2D Hyperconverged example. For more see https://github.com/Microsoft/ws2016lab/wiki/LabConfig.ps1-examples or scroll down

$LabConfig=@{
    DomainAdminName='Claus'; 			# Used during 2_CreateParentDisks (no affect if changed after this step)
	AdminPassword='LS1setup!'; 			# Used during 2_CreateParentDisks. If changed after, it will break the functionality of 3_Deploy.ps1
    Prefix = 'S2DHyperConverged-'; 		# All VMs and vSwitch are created with this prefix, so you can identify the lab
    SwitchName = 'LabSwitch';			# Name of vSwitch
    SecureBoot=$true; 					# Useful when testing unsigned builds (Useful for MS developers for daily builds)
    DCEdition='ServerDataCenter';		# ServerDataCenter or ServerDataCenterCore (or if you prefer standard)
    CreateClientParent=$false;			# If True, client OS will be hydrated
    ClientEdition='Enterprise';			# Enterprise/Education/Pro/Home (depends what ISO you use)
	InstallSCVMM='No';					# Yes/Prereqs/SQL/ADK/No
    AdditionalNetworkInDC=$false;		# If Additional networks should be added also to DC
    AdditionalNetworksConfig=@();		# Just empty array for config below
    VMs=@()								# Just empty array for config below
} 

# Specifying LabVMs
1..4 | % { 
	$VMNames="S2D"; 							# Here you can bulk edit name of 4 VMs created. In this case will be s2d1,s2d2,s2d3,s2d4 created
	$LABConfig.VMs += @{ 
		VMName = "$VMNames$_" ; 
		Configuration = 'S2D' ; 				# Simple/S2D/Shared/Replica
		ParentVHD = 'Win2016NanoHV_G2.vhdx';	# VHD Name from .\ParentDisks folder
		SSDNumber = 4; 							# Number of "SSDs" (its just simulation of SSD-like sized HDD, just bunch of smaller disks)
		SSDSize=800GB ; 						# Size of "SSDs"
		HDDNumber = 12; 						# Number of "HDDs"
		HDDSize= 4TB ; 							# Size of "HDDs"
		MemoryStartupBytes= 512MB 				# Startup memory size
	} 
} 

#optional: (only if AdditionalNetworks are configured in $LabConfig.VMs) this is just an example. In this configuration its not needed.
$LABConfig.AdditionalNetworksConfig += @{ 
	NetName = 'Storage1'; 						# Network Name
	NetAddress='172.16.1.'; 					# Network Addresses prefix. (starts with 1), therefore first VM with Additional network config will have IP 172.16.1.1
	NetVLAN='1'; 								# VLAN tagging
	Subnet='255.255.255.0'						# Subnet Mask
}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage2'; NetAddress='172.16.2.'; NetVLAN='2'; Subnet='255.255.255.0'}
$LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage3'; NetAddress='172.16.3.'; NetVLAN='3'; Subnet='255.255.255.0'}

<#
# More complex labconfig example for Microsoft Premier Software Defined Storage Workshop (work-in-progress)
$LabConfig=@{
    DomainAdminName='Ned'; 				
	AdminPassword='LS1setup!'; 		
    Prefix = 'S2DHyperConverged-'; 		
    SwitchName = 'LabSwitch';			
    SecureBoot=$true; 					
    DCEdition='ServerDataCenterCore';		
    CreateClientParent=$false;			
    ClientEdition='Enterprise';			
	InstallSCVMM='No';					
    AdditionalNetworkInDC=$false;		
    AdditionalNetworksConfig=@();		
    VMs=@();							
} 

$LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

$LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True }
1..2 | % { $VMNames="Shared"  ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared'   ; ParentVHD = 'Win2016Core_G2.vhdx'     ; SSDNumber = 3; SSDSize=800GB ; HDDNumber = 9  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1' } }
1..4 | % { $VMNames="Direct"  ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } } 
1..4 | % { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 256MB } }
1..2 | % { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
3..4 | % { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; AdditionalNetworks = $True} }

#>

### HELP ###
<# If you need more help or different configuration options, ping me at jaromirk@microsoft.com

### Parameters ###

##$Labconfig##
Password
	Specifies password for your lab. This password is used for domain admin, vmm account, sqlservice account and additional DomainAdmin... Define before running 2_CreateParentImages

Prefix
	Prefix for your lab. Each VM and switch will have this prefix.

Secureboot
	$True/$False
	This enables or disables secure boot. In Microsoft we can test unsigned test builds with Secureboot off.

CreateClientParent
	$True/$False
	If Yes, Client Parent image will be created, so you can create Windows 10 management machine.

DCEdition
	'ServerDataCenter'/'ServerDataCenterCore'
	If you dont like GUI and you have management VM, you can select Core edition.

ClientEdition
	Enterprise/Education/Pro/Home
	Depends what ISO you use. Edition name matches the one you get from DISM.

InstallSCVMM *
	'Yes' 		- installs ADK, SQL and VMM
	'ADK' 		- installs just ADK
	'SQL' 		- installs just SQL
	'Prereqs' 	- installs ADK and SQL
	'No' 		- No, or anything else, nothing is installed.
		
		*requires install files in toolsVHD\SCVMM\, or it will fail. You can download all tools here:
			SQL: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2014
			SCVMM: http://www.microsoft.com/en-us/evalcenter/evaluate-system-center-technical-preview
			ADK: https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx (you need to run setup and download the content. 2Meg file is not enough)

AdditionalNetworkInDC
	If $True, networks specified in $LABConfig.AdditionalNetworksConfig will be added.

MGMTNICsInDC
	If nothing specified, then just 1 NIC is added in DC.
	Can be 1-8
			
##$LabConfig.VMs##
 Example: 
 	Single:
	 $LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True }
 	Multiple:
	 1..2 | % { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
 
 VMName
    Can be whatever. This name will be used as name to djoin VM.

Configuration
    'Simple' - No local storage. Just VM
    'S2D' - locally attached SSDS and HDDs. For Storage Spaces Direct. You can specify 0 for SSDnumber or HDD number if you want only one tier.
    'Shared' - Shared VHDS attached to all nodes. Simulates traditional approach with shared space/shared storage. Requires Shared VHD->Requires Clustering Components
    'Replica' - 2 Shared disks, first for Data, second for Log. Simulates traditional storage. Requires Shared VHD->Requires Clustering Components

VMSet
	This is unique name for your set of VMs. You need to specify it for Spaces and Replica scenario, so script will connect shared disks to the same VMSet.

ParentVHD
	'Win2016Core_G2.vhdx'     - Windows Server 2016 Core
	'Win2016Nano_G2.vhdx'    - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM
	'Win2016NanoHV_G2.vhdx'   - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM, Compute, SCVMM Compute
	'Win10_G2.vhdx'		- Windows 10 if you selected to hydrate it with create client parent.

AdditionalNetworks
	$True - Additional networks (configured in AdditonalNetworkConfig) are added 

DSCMode
	If 'Pull', VMs will be configured to Pull config from DC.

Config
	You can specify random Config names to identify configuration that should be pulled from pull server

NestedVirt
	If $True, nested virt is enabled
	Enables -ExposeVirtualizationExtensions $true

MemoryStartupBytes
	Example: 512MB
	Startup memory bytes

MemoryMinimumBytes
	Example: 1GB
	Minimum memory bytes, must be less or equal to MemoryStartupBytes
	If not set, default is used.	

AddToolsVHD
	If $True, then ToolsVHD will be added

SkipDjoin
	If $True, VM will not be djoined.
    
Win2012Djoin
    If $True, older way to domain join will be used (Username and Password in Answer File instead of blob) as Djoin Blob works only in Win 2016

vTPM
	if $true, vTPM will be enabled for virtual machine.

MGMTNICs
	Number of management NIC.
	Default is 2, maximum 8.

##$LabConfig.AdditionalNetworksConfig##
	Example: $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage1'; NetAddress='172.16.1.'; NetVLAN='1'; Subnet='255.255.255.0'}

NetName
	Name of network adapter (visible from host)

NetAddress
	Network prefix of IP address thats injected into the VM. IP Starts with 1.

NetVLAN
	Will tag VLAN. If 0, vlan tagging will be skipped.

Subnet
	Subnet of network.

#>

### $LabConfig.VMs Examples ###
<#

Just some VMs
$LabConfig.VMs = @(
    @{ VMName = 'Simple1'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
    @{ VMName = 'Simple2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
    @{ VMName = 'Simple3'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
    @{ VMName = 'Simple4'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }
)

or you can use this to deploy 100 simple VMs
1..100 | % {"Simple$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB } }

or you can use this to deploy 100 simple VMs with 1 management Client OS
1..100 | % {"Simple$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 512MB ; AddToolsVHD=$True }

or Several different servers 
* you need to provide your GPT VHD for win 2012 (like created with convertwindowsimage script)
$LabConfig.VMs += @{ VMName = 'Win2016'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2.vhdx'          ; MemoryStartupBytes= 512MB ; SkipDjoin=$True }
$LabConfig.VMs += @{ VMName = 'Win2016_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'      ; MemoryStartupBytes= 512MB }
$LabConfig.VMs += @{ VMName = 'Win2016_Nano' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'      ; MemoryStartupBytes= 128MB }
$LabConfig.VMs += @{ VMName = 'Win2012'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2.vhdx'        ; MemoryStartupBytes= 512MB ; Win2012Djoin=$True }
$LabConfig.VMs += @{ VMName = 'Win2012_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Win2012Djoin=$True }

Example with 2 sets of different DSC Configs
1..6 | % {"DSC$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig=@('Config1','Config2')} }
7..12| % {"DSC$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig='Config3'} }

Hyperconverged S2D with nano and nested virtualization (see https://msdn.microsoft.com/en-us/virtualization/hyperv_on_windows/user_guide/nesting for more info)
1..4 | % {"S2D$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True} }

HyperConverged Storage Spaces Direct with Nano Server
1..4 | % {"S2D$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

Disaggregated Storage Spaces Direct with Nano Server
1..4 | % {"Compute$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
1..4 | % {"SOFS$_"}     | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 12; SSDSize=800GB ; HDDNumber = 0 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

"traditional" stretch cluster (like with traditional SAN)
1..2 | % {"Replica$_"} | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
3..4 | % {"Replica$_"} | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; AdditionalNetworks = $True} }

HyperConverged Storage Spaces with Shared Storage
1..4 | % {"Compute$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
1..4 | % {"SOFS$_"}     | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 6; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 1TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1'} }

ShieldedVMs lab
$LABConfig.VMs += @{ VMName = 'HGS' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; SkipDjoin=$True }
1..2 | % { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 2GB ; NestedVirt=$True ; vTPM=$True  } }

#>