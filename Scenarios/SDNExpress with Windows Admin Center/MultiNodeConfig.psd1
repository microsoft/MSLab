@{
    ScriptVersion      = "2.0"

     VHDPath           = "\\management.corp.contoso.com\Library"
     VHDFile           = "WScore_Master.vhdx"

     VMLocation        = "C:\VM"
     JoinDomain        = "Corp.contoso.com"

     SDNMacPoolStart     = "00-11-22-00-01-00"
     SDNMacPoolEnd       = "00-11-22-00-ff-FF"

     ManagementSubnet  = "10.0.0.0/24"
     ManagementGateway = "10.0.0.1"
     ManagementDNS     = @("10.0.0.1")
     ManagementVLANID  = 0

    DomainJoinUsername  = "corp\svcNCManagement"

     LocalAdminDomainUser = "corp\svcNCManagement"

     RestName = "nccluster.$env:USERDNSDOMAIN"

     NCs = @(
                    @{ComputerName='Contoso-NC01'; HostName='HV1'; ManagementIP='10.0.0.5'; MACAddress='001DD8220000'},
                    @{ComputerName='Contoso-NC02'; HostName='HV2'; ManagementIP='10.0.0.6'; MACAddress='001DD8220001'}
                    @{ComputerName='Contoso-NC03'; HostName='HV3'; ManagementIP='10.0.0.7'; MACAddress='001DD8220002'}
    )
     Muxes = @(
                    @{ComputerName='Contoso-Mux01'; HostName='HV1'; ManagementIP='10.0.0.8'; MACAddress='001DD8220003'; PAIPAddress='10.103.33.2'; PAMACAddress='001DD8220004'},
                    @{ComputerName='Contoso-Mux02'; HostName='HV2'; ManagementIP='10.0.0.9'; MACAddress='001DD8220005'; PAIPAddress='10.103.33.3'; PAMACAddress='001DD8220006'}
    )
     Gateways = @(
                    @{ComputerName='Contoso-GW01'; HostName='HV1'; ManagementIP='10.0.0.10'; MACAddress='001DD8220007'; FrontEndIp='10.103.33.51'; FrontEndMac="001DD8220008"; BackEndMac="001DD8220009"},
                    @{ComputerName='Contoso-GW02'; HostName='HV2'; ManagementIP='10.0.0.11'; MACAddress='001DD822000A'; FrontEndIp='10.103.33.52'; FrontEndMac="001DD822000B"; BackEndMac="001DD822000C"}
    )

     HyperVHosts = @(
                    "HV1", 
                    "HV2", 
                    "HV3", 
                    "HV4"
    )

    NCUsername   = "corp\svcNCManagement"

    PASubnet         = '10.103.33.0/24'
    PAVLANID         = '201'
    PAGateway        = '10.103.33.1'
    PAPoolStart      = '10.103.33.51'
    PAPoolEnd        = '10.103.33.100'  

    SDNASN =           "65530"
    Routers = @(
                    @{ RouterASN='65000'; RouterIPAddress='10.103.33.1'}
    )

    PrivateVIPSubnet = "10.20.0.0/24"
    PublicVIPSubnet  = "10.10.0.0/24"

    PoolName         = "DefaultAll"
    GRESubnet        = "10.30.0.0/24"
    Capacity         = 10000


    # Optional fields.  Uncomment items if you need to override the defaults.

    # Specify ProductKey if you have a product key to use for newly created VMs.  If this is not specified you may need 
    # to connect to the VM console to proceed with eval mode.
    #ProductKey       = ''

    # Switch name is only required if more than one virtual switch exists on the Hyper-V hosts.
    SwitchName='sdnSwitch'

    # Amount of Memory and number of Processors to assign to VMs that are created.
    # If not specified a default of 8 procs and 8GB RAM are used.
    VMMemory = 4GB
    VMProcessorCount = 4

    # If Locale and Timezone are not specified the local time zone of the deployment machine is used.
    # Locale           = ''
    # TimeZone         = ''

    # Passowrds can be optionally included if stored encrypted as text encoded secure strings.  Passwords will only be used
    # if SDN Express is run on the same machine where they were encrypted, otherwise it will prompt for passwords.
    DomainJoinSecurePassword  = '##PASSWORD##'
    LocalAdminSecurePassword   = '##PASSWORD##'
    NCSecurePassword   = '##PASSWORD##'

}