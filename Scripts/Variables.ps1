#basic, S2D Hyperconverged example. For more see https://github.com/Microsoft/ws2016lab/wiki/variables.ps1-examples or scroll down

$LabConfig=@{AdminPassword='LS1setup!'; DomainAdminName='Claus'; Prefix = 'S2DHyperConverged-'; SecureBoot='On'; CreateClientParent='No';DCEdition='ServerDataCenter';ClientEdition='Enterprise';InstallSCVMM='No'}

$NetworkConfig=@{SwitchName = 'LabSwitch' ; StorageNet1='172.16.1.'; StorageNet2='172.16.2.'}

$LAbVMs = @()
1..4 | % {"S2D$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } } 

<#
The configuration below is an example config thats being used in Microsoft Premier Workshop for SDS. 
#>

<# 

$LabConfig=@{AdminPassword='LS1setup!'; DomainAdminName='Ned'; Prefix = 'SDSWS-'; SecureBoot='On'; CreateClientParent='Yes';DCEdition='ServerDataCenterCore';ClientEdition='Enterprise';InstallSCVMM='Yes'}

$NetworkConfig=@{SwitchName = 'LabSwitch' ; StorageNet1='172.16.1.'; StorageNet2='172.16.2.'}

$LAbVMs = @()
$LAbVMs += @{ VMName = 'Management'        ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 1GB }
1..4 | % {"Direct$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } } 
1..4 | % {"Shared$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016Core_G2.vhdx'     ; SSDNumber = 6; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 1TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1' ; StorageNetwork = 'Yes'} }
1..4 | % {"Compute$_"} | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 128MB } }
1..2 | % {"Replica$_"} | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; StorageNetwork = 'Yes'} }
3..4 | % {"Replica$_"} | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; StorageNetwork = 'Yes'} }
#>


### HELP ###
<# If you need more help or different configuration options, ping me at jaromirk@microsoft.com

### Parameters ###

##Labconfig##
Password
	Specifies password for your lab. This password is used for domain admin, vmm account, sqlservice account and additional DomainAdmin... Define before running 2_CreateParentImages

Prefix
	Prefix for your lab. Each VM and switch will have this prefix.

Secureboot
	'On'/'Off'
	This enables or disables secure boot. In Microsoft we can test unsigned test builds with Secureboot off.

CreateClientParent
	'Yes'/'No'
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
		*requires install files in toolsVHD\SCVMM\, or it will fail. You can download all tools here:
			
			SQL: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2014
			SCVMM: http://www.microsoft.com/en-us/evalcenter/evaluate-system-center-technical-preview
			ADK: https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx (you need to run setup and download the content. 2Meg file is not enough)
			

##LABVMs##

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

StorageNetwork
	'Yes' - Additional 2 network adapters with IP from StorageNet1 and StorageNet2 

DSCMode
	If 'Pull', VMs will be configured to Pull config from DC.

GUID
	You can specify random GUID such as 'bcb6821b-dbfa-47a7-8c4d-923aaceb7479'
	You can create guid if you run this [guid]::NewGuid()
	If you dont specify this, random guid will be used

NestedVirt
	If 'Yes', nested virt is enabled
	Enables -ExposeVirtualizationExtensions $true and sets static memory	

AddToolsVHD
	If 'Yes', then ToolsVHD will be added

SkipDjoin
	If 'Yes', VM will not be djoined.
    
Win2012Djoin
    If 'Yes', older way to domain join will be used (Username and Password in Answer File instead of blob) as Djoin Blob works only in Win 2016

#>

### LABVMs Examples ###
<#

Just some VMs
$LAbVMs = @(
    @{ VMName = 'Simple1'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
    @{ VMName = 'Simple2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
    @{ VMName = 'Simple3'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
    @{ VMName = 'Simple4'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'     ; MemoryStartupBytes= 512MB }
)

or you can use this to deploy 100 simple VMs
$LAbVMs = @()
1..100 | % {"Simple$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB } }

or you can use this to deploy 100 simple VMs with 1 management Client OS
$LAbVMs = @()
1..100 | % {"Simple$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
$LAbVMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 512MB ; AddToolsVHD='Yes' }

or Several different servers 
* you need to provide your GPT VHD for win 2012 (like created with convertwindowsimage script)
$LAbVMs = @()
$LAbVMs += @{ VMName = 'Win2016'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2'          ; MemoryStartupBytes= 512MB ; SkipDjoin='Yes' }
$LAbVMs += @{ VMName = 'Win2016_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2'      ; MemoryStartupBytes= 512MB }
$LAbVMs += @{ VMName = 'Win2016_Nano' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2'      ; MemoryStartupBytes= 128MB }
$LAbVMs += @{ VMName = 'Win2012'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2'        ; MemoryStartupBytes= 512MB ; Win2012Djoin='Yes' }
$LAbVMs += @{ VMName = 'Win2012_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2'    ; MemoryStartupBytes= 512MB ; Win2012Djoin='Yes' }

Example with 2 sets of different DSC GUIDs
$LAbVMs = @()
1..6 | % {"DSC$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; GUID= 'bcb6821b-dbfa-47a7-8c4d-923aaceb7479'} }
7..12| % {"DSC$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'    ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; GUID= 'bcb6821b-dbfa-47a7-8c4d-923aaceb7480'} }

Hyperconverged S2D with nano and nested virtualization (see https://msdn.microsoft.com/en-us/virtualization/hyperv_on_windows/user_guide/nesting for more info)
$LAbVMs = @()
1..4 | % {"S2D$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt='Yes'} }

HyperConverged Storage Spaces Direct with Nano Server
$LAbVMs = @()
1..4 | % {"S2D$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

Disaggregated Storage Spaces Direct with Nano Server
$LAbVMs = @()
1..4 | % {"Compute$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
1..4 | % {"SOFS$_"}     | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 12; SSDSize=800GB ; HDDNumber = 0 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

"traditional" stretch cluster (like with traditional SAN)
$LAbVMs = @()
1..2 | % {"Replica$_"} | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; StorageNetwork = 'Yes'} }
3..4 | % {"Replica$_"} | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; StorageNetwork = 'Yes'} }

HyperConverged Storage Spaces with Shared Storage
$LAbVMs = @()
1..4 | % {"Compute$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
1..4 | % {"SOFS$_"}     | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 6; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 1TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1'} }

#>