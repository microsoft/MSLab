#basic config, that creates VMs for S2D Hyperconverged scenario https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 

### HELP ###

#If you need more help or different configuration options, ping me at jaromirk@microsoft.com

#region Same as above, but with more explanation
    <#
    $LabConfig=@{
        DomainAdminName='LabAdmin';            # Used during 2_CreateParentDisks (no affect if changed after this step)
        AdminPassword='LS1setup!';             # Used during 2_CreateParentDisks. If changed after, it will break the functionality of 3_Deploy.ps1
        Prefix = 'ws2016lab-';                 # All VMs and vSwitch are created with this prefix, so you can identify the lab
        SwitchName = 'LabSwitch';              # Name of vSwitch
        SecureBoot=$true;                      # (Optional) Useful when testing unsigned builds (Useful for MS developers for daily builds)
        DCEdition='DataCenter';                # DataCenter or DataCenterCore (or if you prefer standard)
        CreateClientParent=$false;             # (Optional) If True, client OS will be hydrated
        ClientEdition='Enterprise';            # (Mandatory when CreateClientParent=$True) Enterprise/Education/Pro/Home (depends what ISO you use)
        InstallSCVMM='No';                     # (Optional) Yes/Prereqs/SQL/ADK/No
        AdditionalNetworksInDC=$false;         # (Optional) If Additional networks should be added also to DC
        DomainNetbiosName="Corp";              # (Optional) If set, custom domain NetBios name will be used. if not specified, Default "corp" will be used
        DomainName="Corp.contoso.com";         # (Optional) If set, custom DomainName will be used. If not specified, Default "Corp.contoso.com" will be used
        DefaultOUName="Workshop";              # (Optional) If set, custom OU for all machines and account will be used. If not specified, default "Workshop" is created
        AllowedVLANs="1-10";                   # (Optional) Sets the list of VLANs that can be used on Management vNICs. If not specified, default "1-10" is set.
        Internet=$false                        # (Optional) If $true, it will add external vSwitch and configure NAT in DC to provide internet (Logic explained below)
        PullServerDC=$true                     # (Optional) If $false, then DSC Pull Server will not be configured on DC
        ClientISOFolder=""                     # (Optional) If configured, script will use ISO located in this folder for Windows Client hydration (if more ISOs are present, then out-grid view is called)
        ClientMSUsFolder=""                    # (Optional) If configured, script will inject all MSU files found into client OS
        ServerISOFolder=""                     # (Optional) If configured, script will use ISO located in this folder for Windows Server hydration (if more ISOs are present, then out-grid view is called)
        ServerMSUsFolder=""                    # (Optional) If configured, script will inject all MSU files found into server OS
        AdditionalNetworksConfig=@();          # Just empty array for config below
        VMs=@();                               # Just empty array for config below
        ServerVHDs=@()                         # Just empty array for config below
    }

    # Specifying LabVMs
    1..4 | % { 
        $VMNames="S2D";                                # Here you can bulk edit name of 4 VMs created. In this case will be s2d1,s2d2,s2d3,s2d4 created
        $LABConfig.VMs += @{
            VMName = "$VMNames$_" ;
            Configuration = 'S2D' ;                    # Simple/S2D/Shared/Replica
            ParentVHD = 'Win2016Core_G2.vhdx';         # VHD Name from .\ParentDisks folder
            SSDNumber = 0;                             # Number of "SSDs" (its just simulation of SSD-like sized HDD, just bunch of smaller disks)
            SSDSize=800GB ;                            # Size of "SSDs"
            HDDNumber = 12;                            # Number of "HDDs"
            HDDSize= 4TB ;                             # Size of "HDDs"
            MemoryStartupBytes= 512MB                  # Startup memory size
        }
    }

    #optional: (only if AdditionalNetworks are configured in $LabConfig.VMs) this is just an example. In this configuration its not needed.
    $LABConfig.AdditionalNetworksConfig += @{ 
        NetName = 'Storage1';                        # Network Name
        NetAddress='172.16.1.';                      # Network Addresses prefix. (starts with 1), therefore first VM with Additional network config will have IP 172.16.1.1
        NetVLAN='1';                                 # VLAN tagging
        Subnet='255.255.255.0'                       # Subnet Mask
    }
    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage2'; NetAddress='172.16.2.'; NetVLAN='2'; Subnet='255.255.255.0'}
    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage3'; NetAddress='172.16.3.'; NetVLAN='3'; Subnet='255.255.255.0'}

    #optional: (these are defaults images that will be created during 2_CreateParentDisks.ps1. If nothing is specified, the below config is automatically used)
    $LABConfig.ServerVHDs += @{
        Edition="DataCenterCore";
        VHDName="Win2016Core_G2.vhdx";
        Size=30GB
    }
    $LABConfig.ServerVHDs += @{
        Edition="DataCenterNano";
        VHDName="Win2016NanoHV_G2.vhdx";
        NanoPackages="Microsoft-NanoServer-DSC-Package","Microsoft-NanoServer-FailoverCluster-Package","Microsoft-NanoServer-Guest-Package","Microsoft-NanoServer-Storage-Package","Microsoft-NanoServer-SCVMM-Package","Microsoft-NanoServer-Compute-Package","Microsoft-NanoServer-SCVMM-Compute-Package","Microsoft-NanoServer-SecureStartup-Package","Microsoft-NanoServer-DCB-Package","Microsoft-NanoServer-ShieldedVM-Package";
        Size=30GB
    }

    #>
#endregion

#region More complex labconfig example for Microsoft Premier Software Defined Storage Workshop
    <#
    $LabConfig=@{
        DomainAdminName='LabAdmin';
        AdminPassword='LS1setup!';
        Prefix = 'SDSWS-';
        SwitchName = 'LabSwitch';
        SecureBoot=$true;
        DCEdition='ServerDataCenterCore';
        CreateClientParent=$true;
        ClientEdition='Enterprise';
        InstallSCVMM='No';
        AdditionalNetworksInDC=$false;
        AdditionalNetworksConfig=@();
        VMs=@()
    }

    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'ReplicaNet1'; NetAddress='172.16.1.'; NetVLAN='0'; Subnet='255.255.255.0'}

    $LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'    ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
    1..2 | % { $VMNames="Shared"    ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Shared' ; ParentVHD = 'Win2016Core_G2.vhdx'      ; SSDNumber = 3; SSDSize=800GB ; HDDNumber = 9  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1' } }
    1..2 | % { $VMNames="2Node"     ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; NestedVirt = $True } } 
    1..4 | % { $VMNames="S2D"       ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }
    1..4 | % { $VMNames="Compute"   ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB ; NestedVirt = $True} }
    1..2 | % { $VMNames="Replica"   ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; ReplicaHDDSize = 200GB ; ReplicaLogSize = 20GB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSet1' ; NestedVirt=$True ; AdditionalNetworks = $True} }
    3..4 | % { $VMNames="Replica"   ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; ReplicaHDDSize = 200GB ; ReplicaLogSize = 20GB ; MemoryStartupBytes= 2GB ; MemoryMinimumBytes= 1GB ; VMSet= 'ReplicaSet2' ; NestedVirt=$True ; AdditionalNetworks = $True} }

    #>
#endregion

#region $Labconfig
    <#
    DomainAdminName (Mandatory)
        Additional Domain Admin.

    Password (Mandatory)
        Specifies password for your lab. This password is used for domain admin, vmm account, sqlservice account and additional DomainAdmin... Define before running 2_CreateParentImages

    Prefix (Mandatory)
        Prefix for your lab. Each VM and switch will have this prefix.

    Secureboot (Optional)
        $True/$False
        This enables or disables secure boot. In Microsoft we can test unsigned test builds with Secureboot off.

    CreateClientParent (Optional)
        $True/$False
        If Yes, Client Parent image will be created, so you can create Windows 10 management machine.

    DCEdition (Mandatory)
        'ServerDataCenter'/'ServerDataCenterCore'
        If you dont like GUI and you have management VM, you can select Core edition.

    ClientEdition (Optional)
        Enterprise/Education/Pro/Home
        Depends what ISO you use. Edition name matches the one you get from DISM.

    InstallSCVMM * (Optional)
        'Yes'         - installs ADK, SQL and VMM
        'ADK'         - installs just ADK
        'SQL'         - installs just SQL
        'Prereqs'     - installs ADK and SQL
        'No'          - No, or anything else, nothing is installed.
            
            *requires install files in toolsVHD\SCVMM\, or it will fail. You can download all tools here:
                SQL: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016
                SCVMM: http://www.microsoft.com/en-us/evalcenter/evaluate-system-center-technical-preview
                ADK: https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx (you need to run setup and download the content. 2Meg file is not enough)

    AdditionalNetworksInDC (optional)
        If $True, networks specified in $LABConfig.AdditionalNetworksConfig will be added.

    MGMTNICsInDC (Optional)
        If nothing specified, then just 1 NIC is added in DC.
        Can be 1-8

    DomainNetbiosName (Optional)
        Domain NetBios Name. If nothing is specified, default "Corp" will be used

    DomainName (Optional)
        Domain Name. If nothing is specified, default "Corp.contoso.com" will be used

    DefaultOUName (Optional)
        Default Organization Unit Name for all computers and accounts. If nothing is specified, default "Workshop" will be used

    AllowedVLANs (Optional)
        Allowed VLANs configured on all management adapters. Accepts "1-10" or "1,2,3,4,5,6,7,8,9,10"

    Internet (Optional)
        If $True, it will configure vSwitch based on following Logic (designed to not ask you anything most of the times):
            If no vSwitch exists:
                If only one connected adapter exists, then it will create vSwitch from it.
                If more connected adapters exists, it will ask for only one
            If vSwitch named "$($labconfig.Prefix)$($labconfig.Switchname)-External" exists, it will be used (in case lab already exists)
            If only one vSwitch exists, then it will be used
            If more vSwitches exists, you will be prompted for what to use.
        It will add vNIC to DC and configure NAT with some Open DNS servers in DNS forwarder

    PullServerDC (optional)
        If $False, Pull Server will not be setup.

    ServerISOFolder,ClientISOFolder
        Example: ServerISOFolder="d:\ISO\Server2016"
        Script will try to find ISO in this folder and subfolders. If more ISOs are present, then out-grid view is called and you will be promted to select only one

    ServerMSUsFolder,ClientMSUsFolder
        Example: ServerMSUsFolder="d:\Updates\Server2016"
        If ServerISOFolder/ClientISOFolder is specified, then updates are being grabbed from ServerMSUsFolder/ClientMSUsFolder.
        If ServerMSUsFolder/ClientMSUsFolder is not specified, or empty, you are not asked for providing MSU files and no MSUs are applied.
    #>
#endregion

#region $LabConfig.VMs
    <#
    Example
        Single:
        $LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True }
        Multiple:
        1..2 | % { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
    
    VMName (Mandatory)
        Can be whatever. This name will be used as name to djoin VM.

    Configuration (Mandatory)
        'Simple' - No local storage. Just VM
        'S2D' - locally attached SSDS and HDDs. For Storage Spaces Direct. You can specify 0 for SSDnumber or HDD number if you want only one tier.
        'Shared' - Shared VHDS attached to all nodes. Simulates traditional approach with shared space/shared storage. Requires Shared VHD->Requires Clustering Components
        'Replica' - 2 Shared disks, first for Data, second for Log. Simulates traditional storage. Requires Shared VHD->Requires Clustering Components

    VMSet (Mandatory for Shared and Replica configuration)
        This is unique name for your set of VMs. You need to specify it for Spaces and Replica scenario, so script will connect shared disks to the same VMSet.

    ParentVHD (Mandatory)
        'Win2016Core_G2.vhdx'     - Windows Server 2016 Core
        'Win2016NanoHV_G2.vhdx'    - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM
        'Win2016NanoHV_G2.vhdx'   - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM, Compute, SCVMM Compute
        'Win10_G2.vhdx'        - Windows 10 if you selected to hydrate it with create client parent.

    AdditionalNetworks (Optional)
        $True - Additional networks (configured in AdditonalNetworkConfig) are added 

    DSCMode (Optional)
        If 'Pull', VMs will be configured to Pull config from DC.

    Config
        You can specify random Config names to identify configuration that should be pulled from pull server

    NestedVirt (Optional)
        If $True, nested virt is enabled
        Enables -ExposeVirtualizationExtensions $true

    MemoryStartupBytes (Mandatory)
        Example: 512MB
        Startup memory bytes

    MemoryMinimumBytes (Optional)
        Example: 1GB
        Minimum memory bytes, must be less or equal to MemoryStartupBytes
        If not set, default is used.    

    StaticMemory (Optional)
        if $True, then static memory is configured

    AddToolsVHD (Optional)
        If $True, then ToolsVHD will be added

    SkipDjoin (Optional)
        If $True, VM will not be djoined.
        Note: you might want to use AdditionalLocalAdmin variable with Windows 10 as local administrator account is by default disabled there.
        
    Win2012Djoin (Optional)
        If $True, older way to domain join will be used (Username and Password in Answer File instead of blob) as Djoin Blob works only in Win 2016

    vTPM (Optional)
        if $true, vTPM will be enabled for virtual machine.

    MGMTNICs (Optional)
        Number of management NIC.
        Default is 2, maximum 8.

    DisableWCF (Optional)
        If $True, then Disable Windows Consumer Features registry is added= no consumer apps in start menu.

    AdditionalLocalAdmin (Optional, depends on SkipDjoin)
        Example AdditionalLocalAdmin='Ned'
        Works only with SkipDjoin as you usually don't need additional local account
        When you skipDjoin on Windows10 and local administrator is disabled. Then AdditionalLocalAdmin is useful
    #>
#endregion

#region $LabConfig.AdditionalNetworksConfig
    <#
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
#endregion

#region $LabConfig.ServerVHDs
    <#
    Example:
        $LABConfig.ServerVHDs += @{
            Edition="DataCenterNano" 
            VHDName="Win2016NanoHV_G2.vhdx"
            NanoPackages="Microsoft-NanoServer-DSC-Package","Microsoft-NanoServer-FailoverCluster-Package","Microsoft-NanoServer-Guest-Package","Microsoft-NanoServer-Storage-Package","Microsoft-NanoServer-SCVMM-Package"
            Size=30GB
        }

    Edition
        Edition of VHD, consumed by convert-windowsimage
        possible values: DatacenterNano, DatacenterCore, Datacenter, StandardNano, StandardCore, Standard

    VHDName
        Name of VHD that will be created

    NanoPackages
        Names of packages (it will automatically grab all files starting with the name provided, so all cabs with language cabs)

    Size
        Size in bytes
    #>

#endregion

#region $LabConfig.VMs Examples
    <#
    Just some VMs
        $LabConfig.VMs = @(
            @{ VMName = 'Simple1'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
            @{ VMName = 'Simple2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
            @{ VMName = 'Simple3'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
            @{ VMName = 'Simple4'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }
        )

    or you can use this to deploy 100 simple VMs with name NanoServer1, NanoServer2...
        1..100 | % {"NanoServer$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }

    or you can use this to deploy 100 server VMs with 1 Client OS with name Windows10
        1..100 | % {"NanoServer$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        $LabConfig.VMs += @{ VMName = 'Windows10' ; Configuration = 'Simple'  ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 512MB ; AddToolsVHD=$True ; DisableWCF=$True}

    or you can use this to deploy 100 nanoservers and 100 Windows 10 machines named Windows10_..
        1..100 | % {"NanoServer$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        1..100 | % {"Windows10_$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'          ; MemoryStartupBytes= 512MB ;   AddToolsVHD=$True ; DisableWCF=$True } }

    or Several different servers 
        * you need to provide your GPT VHD for win 2012 (like created with convertwindowsimage script)
        $LabConfig.VMs += @{ VMName = 'Win2016'        ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2.vhdx'          ; MemoryStartupBytes= 512MB ; SkipDjoin=$True }
        $LabConfig.VMs += @{ VMName = 'Win2016_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'      ; MemoryStartupBytes= 512MB }
        $LabConfig.VMs += @{ VMName = 'Win2016_Nano'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB }
        $LabConfig.VMs += @{ VMName = 'Win2012R2'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2.vhdx'        ; MemoryStartupBytes= 512MB ; Win2012Djoin=$True }
        $LabConfig.VMs += @{ VMName = 'Win2012R2_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Win2012Djoin=$True }

    Example with sets of different DSC Configs
        1..2 | % {"Nano$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = ‘Simple’    ; ParentVHD = ‘Win2016NanoHV_G2.vhdx’    ; MemoryStartupBytes= 256MB ; DSCMode=‘Pull’; DSCConfig=@(‘LAPS_Nano_Install’,‘LAPSConfig1’)} }
        3..4 | % {"Nano$_"} | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = ‘Simple’    ; ParentVHD = ‘Win2016NanoHV_G2.vhdx’    ; MemoryStartupBytes= 256MB ; DSCMode=‘Pull’; DSCConfig=@(‘LAPS_Nano_Install’,‘LAPSConfig2’)} }
        1..6 | % {"DSC$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig=@('Config1','Config2')} }
        7..12| % {"DSC$_"}  | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig='Config3'} }

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
        1..4 | % {"SOFS$_"}     | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1'} }

    ShieldedVMs lab
        $LABConfig.VMs += @{ VMName = 'HGS' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; SkipDjoin=$True }
        1..2 | % { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 2GB ; NestedVirt=$True ; vTPM=$True  } }

    Windows Server 2012R2 Hyper-V (8x4TB CSV + 1 1G Witness)
        1..8 | % {"Node$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'HyperV2012R2Lab' ;Win2012Djoin=$True } }

    Windows Server 2012R2 Storage Spaces
        1..2 | % {"2012r2Spaces$_"}     | % { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= '2012R2SpacesLab';Win2012Djoin=$True } }

    #>
#endregion