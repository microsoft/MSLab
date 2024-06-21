#basic config for Windows Server 2022, that creates VMs for S2D Hyperconverged scenario https://github.com/Microsoft/MSLab/tree/master/Scenarios/S2D%20Hyperconverged

$LabConfig=@{AllowedVLANs="1-10,711-719" ; DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'MSLab-' ; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}
# Windows Server 2022
1..4 | ForEach-Object {$LABConfig.VMs += @{ VMName = "$S2D$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2022Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
# Or Azure Stack HCI 23H2 (non-domain joined) https://github.com/DellGEOS/AzureStackHOLs/tree/main/lab-guides/01a-DeployAzureStackHCICluster-CloudBasedDeployment
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName = "ASNode$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI23H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 2TB ; MemoryStartupBytes= 20GB; VMProcessorCount=16 ; vTPM=$true ; Unattend="NoDjoin" ; NestedVirt=$true }}
# Or Windows Server 2025 https://github.com/DellGEOS/AzureStackHOLs/tree/main/lab-guides/03-TestingWindowsServerInsider
#1..2 | ForEach-Object {$LABConfig.VMs += @{ VMName="S2D$_" ; Configuration='S2D' ; ParentVHD='WinSrvInsiderCore_26063.vhdx' ; HDDNumber=4 ; HDDSize=2TB ; MemoryStartupBytes=1GB; VMProcessorCount=4 ; vTPM=$true}}

### HELP ###

#If you need more help or different configuration options, ping us at jaromir.kaspar@dell.com or vlmach@microsoft.com

#region Same as above, but with more explanation
    <#
    $LabConfig=@{
        DomainAdminName="LabAdmin";                  # Used during 2_CreateParentDisks (no affect if changed after this step)
        AdminPassword="LS1setup!";                   # Used during 2_CreateParentDisks. If changed after, it will break the functionality of 3_Deploy.ps1
        Prefix = "MSLab-";                           # (Optional) All VMs and vSwitch are created with this prefix, so you can identify the lab. If not specified, Lab folder name is used
        SwitchName = "LabSwitch";                    # (Optional) Name of vSwitch
        SwitchNICs = "";                             # (Optional) Adds these NICs to vSwitch (without connecting hostOS). (example "NIC1","NIC2")
        SecureBoot=$true;                            # (Optional) Useful when testing unsigned builds (Useful for MS developers for daily builds)
        DCEdition="4";                               # 4 for DataCenter or 3 for DataCenterCore
        InstallSCVMM="No";                           # (Optional) Yes/Prereqs/SQL/ADK/No
        AdditionalNetworksInDC=$false;               # (Optional) If Additional networks should be added also to DC
        DomainNetbiosName="Corp";                    # (Optional) If set, custom domain NetBios name will be used. if not specified, Default "corp" will be used
        DomainName="Corp.contoso.com";               # (Optional) If set, custom DomainName will be used. If not specified, Default "Corp.contoso.com" will be used
        DefaultOUName="Workshop";                    # (Optional) If set, custom OU for all machines and account will be used. If not specified, default "Workshop" is created
        AllowedVLANs="1-10";                         # (Optional) Sets the list of VLANs that can be used on Management vNICs. If not specified, default "1-10" is set.
        Internet=$false;                             # (Optional) If $true, it will add external vSwitch and configure NAT in DC to provide internet (Logic explained below)
        UseHostDnsAsForwarder=$false;                # (Optional) If $true, local DNS servers will be used as DNS forwarders in DC
        CustomDnsForwarders=@("8.8.8.8","1.1.1.1");  # (Optional) If configured, script will use those servers as DNS fordwarders in DC (Defaults to 8.8.8.8 and 1.1.1.1)
        PullServerDC=$true;                          # (Optional) If $false, then DSC Pull Server will not be configured on DC
        ServerISOFolder="";                          # (Optional) If configured, script will use ISO located in this folder for Windows Server hydration (if more ISOs are present, then out-grid view is called)
        ServerMSUsFolder="";                         # (Optional) If configured, script will inject all MSU files found into server OS
        EnableGuestServiceInterface=$false;          # (Optional) If True, then Guest Services integration component will be enabled on all VMs.
        DCVMProcessorCount=2;                        # (Optional) 2 is default. If specified more/less, processorcount will be modified.
        DHCPscope="10.0.0.0";                        # (Optional) 10.0.0.0 is configured if nothing is specified. Scope has to end with .0 (like 10.10.10.0). It's always /24
        DCVMVersion="9.0";                           # (Optional) Latest is used if nothing is specified. Make sure you use values like "8.0","8.3","9.0"
        TelemetryLevel="";                           # (Optional) If configured, script will stop prompting you for telemetry. Values are "None","Basic","Full"
        TelemetryNickname="";                        # (Optional) If configured, telemetry will be sent with NickName to correlate data to specified NickName. So when leaderboards will be published, MSLab users will be able to see their own stats
        AutoStartAfterDeploy=$false;                 # (Optional) If $false, no VM will be started; if $true or 'All' all lab VMs will be started after Deploy script; if 'DeployedOnly' only newly created VMs will be started.
        InternetVLAN="";                             # (Optional) If set, it will apply VLAN on Interent adapter connected to DC
        Linux=$false;                                # (Optional) If set to $true, required prerequisities for building Linux images with Packer will be configured.
        LinuxAdminName="linuxadmin";                 # (Optional) If set, local user account with that name will be created in Linux image. If not, DomainAdminName will be used as a local account.
        SshKeyPath="$($env:USERPROFILE)\.ssh\id_rsa" # (Optional) If set, specified SSH key will be used to build and access Linux images.
        AutoClosePSWindows=$false;                   # (Optional) If set, the PowerShell console windows will automatically close once the script has completed successfully. Best suited for use in automated deployments.
        AutoCleanUp=$false;                          # (Optional) If set, after creating initial parent disks, files that are no longer necessary will be cleaned up. Best suited for use in automated deployments.
        NoDehydrateDC=$false;                        # (Optional) If set, do not attempt to create a dehydrated DC.
        AdditionalNetworksConfig=@();                # Just empty array for config below
        VMs=@();                                     # Just empty array for config below
    }

    # Specifying LabVMs
    1..4 | ForEach-Object {
        $VMNames="S2D";                                # Here you can bulk edit name of 4 VMs created. In this case will be s2d1,s2d2,s2d3,s2d4 created
        $LABConfig.VMs += @{
            VMName = "$VMNames$_" ;
            Configuration = 'S2D' ;                    # Simple/S2D/Shared/Replica
            ParentVHD = 'Win2022Core_G2.vhdx';         # VHD Name from .\ParentDisks folder
            SSDNumber = 0;                             # Number of "SSDs" (its just simulation of SSD-like sized HDD, just bunch of smaller disks)
            SSDSize=800GB ;                            # Size of "SSDs"
            HDDNumber = 12;                            # Number of "HDDs"
            HDDSize= 4TB ;                             # Size of "HDDs"
            MemoryStartupBytes= 512MB;                 # Startup memory size
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

    #>
#endregion

#region $Labconfig
    <#
    DomainAdminName (Mandatory)
        Additional Domain Admin.

    Password (Mandatory)
        Specifies password for your lab. This password is used for domain admin, vmm account, sqlservice account and additional DomainAdmin... Define before running 2_CreateParentImages

    Prefix (Optional)
        Prefix for your lab. Each VM and switch will have this prefix.
        If not specified, labfolder name will be used

    SwitchName (Optional)
        If not specified, LabSwitch will be used as switch name

    Secureboot (Optional)
        $True/$False
        This enables or disables secure boot. In Microsoft we can test unsigned test builds with Secureboot off.

    DCEdition (Mandatory)
        'ServerDataCenter'/'ServerDataCenterCore'
        If you dont like GUI and you have management VM, you can select Core edition.

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

    UseHostDnsAsForwarder (Optional)
        If $true, local DNS servers will be used as DNS forwarders in DC when Internet is enabled.
        By default local host's DNS servers will be used as forwarders.

    CustomDnsForwarders (Optional)
        If configured, DNS servers listed will be appended to DNS forwaders list on DC's DNS server.
        If not defined at all, commonly known DNS servers will be used as a fallback:
             - Google DNS: 8.8.8.8
             - Cloudfare: 1.1.1.1

    DHCPscope (Optional)
        If configured, a custom DHCP scope will be used. Will always use a '/24'.
        Specify input like '10.1.0.0' or '192.168.0.0'
        If not defined at all, DHCP scope 10.0.0.0 will be used.

    PullServerDC (optional)
        If $False, Pull Server will not be setup.

    ServerISOFolder
        Example: ServerISOFolder="d:\ISO\Server2016"
        Script will try to find ISO in this folder and subfolders. If more ISOs are present, then out-grid view is called and you will be promted to select only one

    ServerMSUsFolder
        Example: ServerMSUsFolder="d:\Updates\Server2016"
        If ServerISOFolder is specified, then updates are being grabbed from ServerMSUsFolder.
        If ServerMSUsFolder is not specified, or empty, you are not asked for providing MSU files and no MSUs are applied.

    DCVMProcessorCount (optional)
        Example: DCVMProcessorCount=4
        Number of CPUs in DC.
        If not specified, 2 vCPUs will be set. If specified more/less, processorcount will be modified. If more vCPUs specified than available in host, the maximum possible number will be configured.

    EnableGuestServiceInterface (optional)
        Example: EnableGuestServiceInterface=$true
        If True, then Guest Services integration component will be enabled on all VMs. This allows simple file copy from host to guests.

    DCVMVersion
        Example: DCVMVersion="8.0" (optional)
        If set, version for DC will be used. It is useful if you want to keep DC older to be able to use it on previous versions of OS.

    TelemetryLevel (optional)
        Example: TelemetryLevel="Full"
        If set, scripts will not prompt for telemetry. Can be "None","Basic","Full"
        For more info see https://aka.ms/mslab/telemetry

    TelemetryNickname (optional)
        Example: TelemetryNickname="Jaromirk"
        If configured, telemetry will be sent with NickName to correlate data to specified NickName. So when leaderboards will be published, MSLab users will be able to see their own stats

    Linux (optional)
        Example: Linux=$true
        If set to $true, additional prerequisities (SSH Client, SSH Key, Packer, Packer templates) required for building Linux images will be downloaded and configured.

    LinuxAdminName (optional)
        Example: LinuxAdminName="linuxadmin"
        If set, local user account with that name will be created in Linux image. If not, DomainAdminName will be used as a local account.

    SshKeyPath (optional)
        Example: SshKeyPath="$($env:USERPROFILE)\.ssh\id_rsa"
        If configured, existing SSH key will be used for building and connecting to Linux images. If not, 0_Prereq.ps1 will generate a new SSH key pair and store it locally in LAB folder.

    AutoStartAfterDeploy (optional)
        Example: AutoClosePSWindows=$true
        If set to true, the PowerShell console windows will automatically close once the script has completed successfully. Best suited for use in automated deployments.

    AutoCleanup (optional)
        Example: AutoCleanUp=$true
        If set to true, after creating initial parent disks, files that are no longer necessary will be cleaned up. Best suited for use in automated deployments.

    #>
#endregion

#region $LabConfig.VMs
    <#
    Example
        Single:
        $LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True }
        Multiple:
        1..2 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }

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

    AdditionalNetworkAdapters (Optional) - Hashtable or array if multiple network adapters should be connected to this virtual machine
        @{
            VirtualSwitchName  (Mandatory) - Name of the Hyper-V Switch to witch the adapter will be connected
            Mac                (Optional)  - Static MAC address of the interface otherwise default will be generated
            VlanId             (Optional)  - VLAN ID for this adapter
            IpConfiguration    (Optional)  - DHCP or hastable with specific IP configuration
            @{
                IpAddress      (Mandatory) - Static IP Address that would be injected to the OS
                Subnet         (Mandatory)
            }
        }

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

    Unattend
        Example: Unattend="DjoinCred"
        Possible values: "DjoinBlob", "DjoinCred", "NoDjoin", "None"
        Default "DjoinBlob"
        "DjoinBlob" uses blob, can be consumed only by Windows Server 2016+
        "DjoinCred" uses credentials. Can be used in 2008+
        "NoDjoin" inserts just local admin. For win10 use also AdditionalLocalAdmin
        "None" does not inject any unattend.

    LinuxDomainJoin
        Example: LinuxDomainJoin="No"
        Possible values: "No", "SSSD"
        Default: SSSD
          "No" VM will be just renamed, but not joined to Active Directory
          "SSSD" VM will be joined to domain online using SSSD tool

    SkipDjoin (Optional,Deprecated)
        If $True, VM will not be djoined. Default unattend used.
        Note: you might want to use AdditionalLocalAdmin variable with Windows 10 as local administrator account is by default disabled there.

    Win2012Djoin (Optional,Deprecated)
        If $True, older way to domain join will be used (Username and Password in Answer File instead of blob) as Djoin Blob works only in Win 2016

    vTPM (Optional)
        if $true, vTPM will be enabled for virtual machine. Gen2 only.

    MGMTNICs (Optional)
        Number of management NIC.
        Default is 2, maximum 8.

    DisableWCF (Optional)
        If $True, then Disable Windows Consumer Features registry is added= no consumer apps in start menu.

    AdditionalLocalAdmin (Optional, only applies if Unattend="NoDjoin")
        Example AdditionalLocalAdmin='Ned'
        Works only with SkipDjoin as you usually don't need additional local account
        When you skipDjoin on Windows10 and local administrator is disabled. Then AdditionalLocalAdmin is useful

    VMProcessorCount (Optional)
        Example VMProcessorCount=8
        Number of Processors in VM. If specified more than available in host, maximum possible number will be used.
        If "Max" is specified, maximum number of VCPUs will be used (determined from host where mslab is running)

    Generation (Optional)
        Example Generation=1
        If not specified, then it's 2. If 1, then its 1. Easy.

    EnableWinRM (Optional)
        Example EnableWinRM=$True
        If $true, then synchronous command winrm quickconfig -force -q will be run
        Only useful for 2008 and Win10

    CustomPowerShellCommands (Optional)
        Example (single command) CustomPowerShellCommands="New-Item -Name Temp -Path c:\ -ItemType Directory"
        Example (multiple commands) CustomPowerShellCommands="New-Item -Name Temp -Path c:\ -ItemType Directory","New-Item -Name Temp1 -Path c:\ -ItemType Directory"

    #DisableTimeIC (Optional)
        Example DisableTimeIC=$true
        if $true, time Hyper-V Time Synchronization Integration Service (VMICTimeProvider) will be disabled
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
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }

    or you can use this to deploy 100 server VMs with 1 Client OS with name Windows10
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        $LabConfig.VMs += @{ VMName = 'Windows10' ; Configuration = 'Simple'  ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 512MB ; AddToolsVHD=$True ; DisableWCF=$True}

    or you can use this to deploy 100 nanoservers and 100 Windows 10 machines named Windows10_..
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        1..100 | ForEach-Object {"Windows10_$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'          ; MemoryStartupBytes= 512MB ;   AddToolsVHD=$True ; DisableWCF=$True } }

    or Several different VMs
        * you need to provide your GPT VHD for win 2012 (like created with convertwindowsimage script)
        $LabConfig.VMs += @{ VMName = 'Win10'            ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; EnableWinRM=$True }
        $LabConfig.VMs += @{ VMName = 'Win10_OOBE'       ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; Unattend="None" }
        $LabConfig.VMs += @{ VMName = 'Win10_NotInDomain'; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; Unattend="NoDjoin" ; AdditionalLocalAdmin="Ned" }
        $LabConfig.VMs += @{ VMName = 'Win2016'          ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2.vhdx'          ; MemoryStartupBytes= 512MB ; Unattend="NoDjoin" }
        $LabConfig.VMs += @{ VMName = 'Win2016_Core'     ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'      ; MemoryStartupBytes= 512MB }
        $LabConfig.VMs += @{ VMName = 'Win2016_Nano'     ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB }
        $LabConfig.VMs += @{ VMName = 'Win2012R2'        ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2.vhdx'        ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" }
        $LabConfig.VMs += @{ VMName = 'Win2012R2_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" }
        $LabConfig.VMs += @{ VMName = 'Win2008R2_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2008R2.vhdx'           ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" ; Generation = 1}

    Example with sets of different DSC Configs
        1..2 | ForEach-Object {"Nano$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig1')} }
        3..4 | ForEach-Object {"Nano$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig2')} }
        1..6 | ForEach-Object {"DSC$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig=@('Config1','Config2')} }
        7..12| ForEach-Object {"DSC$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig='Config3'} }

    Hyperconverged S2D with nano and nested virtualization (see https://msdn.microsoft.com/en-us/virtualization/hyperv_on_windows/user_guide/nesting for more info)
        1..4 | ForEach-Object {"S2D$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True} }

    HyperConverged Storage Spaces Direct with Nano Server
        1..4 | ForEach-Object {"S2D$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

    Disaggregated Storage Spaces Direct with Nano Server
        1..4 | ForEach-Object {"Compute$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
        1..4 | ForEach-Object {"SOFS$_"}     | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 12; SSDSize=800GB ; HDDNumber = 0 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

    "traditional" stretch cluster (like with traditional SAN)
        1..2 | ForEach-Object {"Replica$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
        3..4 | ForEach-Object {"Replica$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; AdditionalNetworks = $True} }

    HyperConverged Storage Spaces with Shared Storage
        1..4 | ForEach-Object {"Compute$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
        1..4 | ForEach-Object {"SOFS$_"}     | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1'} }

    ShieldedVMs lab
        $LABConfig.VMs += @{ VMName = 'HGS' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Unattend="NoDjoin" }
        1..2 | ForEach-Object { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 2GB ; NestedVirt=$True ; vTPM=$True  } }

    Windows Server 2012R2 Hyper-V (8x4TB CSV + 1 1G Witness)
        1..8 | ForEach-Object {"Node$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'HyperV2012R2Lab' ;Unattend="DjoinCred" } }

    Windows Server 2012R2 Storage Spaces
        1..2 | ForEach-Object {"2012r2Spaces$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= '2012R2SpacesLab';Unattend="DjoinCred" } }

    #>
#endregion
