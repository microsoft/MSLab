<!-- TOC -->

- [S2D and SCVMM 2019](#s2d-and-scvmm-2019)
    - [LabConfig Windows Server 2019](#labconfig-windows-server-2019)
    - [About the lab](#about-the-lab)
    - [Lab prerequisites](#lab-prerequisites)
    - [Do some neccessarities](#do-some-neccessarities)
        - [Check some prereq](#check-some-prereq)
        - [Add run as account to connect to infrastructure machines](#add-run-as-account-to-connect-to-infrastructure-machines)
    - [Transition networkring](#transition-networkring)
        - [Create Host Group and configure networking](#create-host-group-and-configure-networking)
        - [Add S2D Cluster](#add-s2d-cluster)
        - [Convert External switch to Logical Switch](#convert-external-switch-to-logical-switch)
        - [Configure vNICs IP Pool and Classification](#configure-vnics-ip-pool-and-classification)
    - [Transition to SCVMM based updates](#transition-to-scvmm-based-updates)
        - [Setup WSUS server](#setup-wsus-server)
        - [Add WSUS to SCVMM](#add-wsus-to-scvmm)
        - [Add Update Baseline](#add-update-baseline)
        - [Scan for compliance](#scan-for-compliance)
        - [Disable CAU](#disable-cau)
        - [Remediate](#remediate)

<!-- /TOC -->

# S2D and SCVMM 2019

## LabConfig Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019_SCVMM-'; SwitchName = 'LabSwitch'; DCEdition='4' ; InstallSCVMM='Yes'; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}

$LabConfig.VMs += @{ VMName = 'WSUS' ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 512MB; MGMTNICs=1}
 
```

## About the lab

The intention of this lab is to demonstrate transitioning from standalone S2D cluster to S2D cluster managed by SCVMM. It will demonstrate how to transition to Logical Switch and how to transition from Cluster-Aware Updating to updating with SCVMM.

## Lab prerequisites

* Please hydrate your main lab with SCVMM as demonstrated in this [video](https://youtu.be/NTrncW2omSY?list=PLf9T7wfY_JD2UpjLXoYNcnu4rc1JSPfqE) 

* you can download SCVMM 2019 from [eval center](https://www.microsoft.com/en-us/evalcenter/evaluate-system-center-release)

* you need to deploy [S2D Hyperconverged Scenario](/Scenarios/S2D%20Hyperconverged/) as prerequisite.

* The lab is inspired (and shares some code) with [S2D and Bare Metal with SCVMM](/Scenarios/S2D%20and%20Bare%20Metal%20with%20SCVMM/)]

Run all code from DC. Run all code in one PowerShell windows to keep variables.

## Do some neccessarities

### Check some prereq

```PowerShell
#Make sure SQL and VMM services are started
Start-service -Name MSSQLSERVER
Start-service -Name SCVMMService

#Make sure RSAT features are installed
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica,UpdateServices-RSAT,UpdateServices-UI

#Import VMM Module
Import-Module VirtualMachineManager

#connect to server
Get-VMMServer "DC"
 
```

### Add run as account to connect to infrastructure machines

```PowerShell
$RunAsAccountName="VMM RAA"
$UserName="CORP\LabAdmin"
$Password="LS1setup!"
$Credentials = New-Object System.Management.Automation.PSCredential ($UserName, (ConvertTo-SecureString $Password -AsPlainText -Force))
New-SCRunAsAccount -Credential $Credentials -Name $RunAsAccountName -Description "Run As Account for managing Hyper-V hosts"
 
```

## Transition networkring

### Create Host Group and configure networking

```PowerShell
#region variables
    $vSwitchName="SETSwitch"
    $HostGroupName="SeattleDC"
    $SRIOV=$false

    #vSwitch vNICs and vmNICs classifications
        $Classifications=@()
        $Classifications+=@{PortClassificationName="vNIC mgmt" ; NativePortProfileName="vNIC mgmt" ; Description="Classification for mgmt vNIC"                   ; EnableIov=$false ; EnableVrss=$true  ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
        $Classifications+=@{PortClassificationName="vNIC RDMA" ; NativePortProfileName="vNIC RDMA" ; Description="Classification for RDMA enabled vNICs (Mode 2)" ; EnableIov=$false ; EnableVrss=$true  ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$true }
        $Classifications+=@{PortClassificationName="vmNIC VMQ" ; NativePortProfileName="vmNIC VMQ" ; Description="Classification for VMQ enabled vmNICs"          ; EnableIov=$false ; EnableVrss=$false ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
        
        if ($SRIOV) {
            $Classifications+=@{PortClassificationName="vmNIC SR-IOV" ; NativePortProfileName="vmNIC SR-IOV" ; Description="Classification for SR-IOV enabled vmNICs" ; EnableIov=$true  ; EnableVrss=$false ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
        }

    #logical networks definition
        $Networks=@()
        $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupNames=$HostGroupName ; Name="Management"  ; Description="Management VLAN" ; VMNetworkName= "Management" ; VMNetworkDescription= ""  ; Subnet="10.0.0.0/24"      ; VLAN=0 ; IPAddressRangeStart="10.0.0.1"   ;IPAddressRangeEnd="10.0.0.254"           ; DNSSuffix="Corp.contoso.com" ;DNSServers="10.0.0.1"  ;Gateways="10.0.0.1"}
        $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupNames=$HostGroupName ; Name="Storage"     ; Description="SMB"             ; VMNetworkName= "Storage"    ; VMNetworkDescription= ""  ; Subnet="172.16.1.0/24"    ; VLAN=1 ; IPAddressRangeStart="172.16.1.1" ;IPAddressRangeEnd="172.16.1.254"         ; DNSSuffix="Corp.contoso.com" ;DNSServers=""          ;Gateways=""}
        #some fake networks just for demonstration
        $Networks+=@{LogicalNetworkName="VMs Network"       ; HostGroupNames=$HostGroupName ; Name="Production"  ; Description="Production VLAN" ; VMNetworkName= "Production" ; VMNetworkDescription= ""  ; Subnet="192.168.1.0/24"   ; VLAN=2 ; IPAddressRangeStart="192.168.1.1"   ;IPAddressRangeEnd="192.168.1.254"     ; DNSSuffix="Corp.contoso.com" ;DNSServers=("10.0.0.11","10.0.0.10")  ;Gateways="192.168.1.1"}
        $Networks+=@{LogicalNetworkName="VMs Network"       ; HostGroupNames=$HostGroupName ; Name="DMZ"         ; Description="DMZ VLAN"        ; VMNetworkName= "DMZ"        ; VMNetworkDescription= ""  ; Subnet="192.168.2.0/24"   ; VLAN=3 ; IPAddressRangeStart="192.168.2.1"   ;IPAddressRangeEnd="192.168.2.254"     ; DNSSuffix="Corp.contoso.com" ;DNSServers=("10.0.0.11","10.0.0.10")  ;Gateways="192.168.2.1"}

        $vNICDefinitions=@()
        $vNICDefinitions+=@{NetAdapterName="SMB01"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="Storage"    ; VMSubnetName="Storage"        ;PortClassificationName="vNIC RDMA"                  ;IPAddressPoolName="Storage_IPPool"}
        $vNICDefinitions+=@{NetAdapterName="SMB02"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="Storage"    ; VMSubnetName="Storage"        ;PortClassificationName="vNIC RDMA"                  ;IPAddressPoolName="Storage_IPPool"}
        $vNICDefinitions+=@{NetAdapterName="Mgmt"       ; Management=$true  ; InheritSettings=$true  ; IPv4AddressType="Dynamic"; VMNetworkName="Management" ; VMSubnetName="Management"     ;PortClassificationName="vNIC mgmt" ;IPAddressPoolName="Management_IPPool"}

    #Uplink Port Profile
        $UplinkPPName="Seattle_PP" 
        $UplinkPPSiteNames='Storage','Management','Production','DMZ'
#endregion

#region do the job
    #Create Host Group
        New-SCVMHostGroup -Name $HostGroupName

    #Disable automatic logical network creation
        Set-SCVMMServer -AutomaticLogicalNetworkCreationEnabled $false -LogicalNetworkMatch "FirstDNSSuffixLabel" -BackupLogicalNetworkMatch "VirtualNetworkSwitchName"

    #create logical networks
        foreach ($NetworkName in ($Networks.LogicalNetworkName | Select-Object -Unique)){
            if (-not (Get-SCLogicalNetwork -Name $NetworkName)){
                New-SCLogicalNetwork -Name $NetworkName -LogicalNetworkDefinitionIsolation $true -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
            }
        }

    #Create network sites
        foreach ($Network in $Networks){
            if (-not (Get-SCLogicalNetworkDefinition -Name $Network.Name)){
                $logicalNetwork=Get-SCLogicalNetwork -Name $Network.LogicalNetworkName
                $allHostGroups = @()
                foreach ($HostGroupName in $network.HostGroupNames){
                    $allHostGroups+=Get-SCVMHostGroup -Name $HostGroupName
                }
                $allSubnetVlan = @()
                $allSubnetVlan += New-SCSubnetVLan -Subnet $network.Subnet -VLanID $network.VLAN
                New-SCLogicalNetworkDefinition -Name $network.Name -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously
            }
        }

    #create IP Pools
        foreach ($Network in $Networks){
            if ($network.IPAddressRangeStart){
                if (-not (Get-SCStaticIPAddressPool -Name "$($network.name)_IPPool")){
                    $logicalNetwork = Get-SCLogicalNetwork -Name $network.LogicalNetworkName
                    $logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name $network.Name
                    # Gateways
                    $allGateways = @()
                                    if ($Network.Gateways){
                    foreach ($gateway in $Network.Gateways){
                        $allGateways += New-SCDefaultGateway -IPAddress $gateway -Automatic
                    }
                }

                    # DNS servers
                            if ($Network.DNSServers){
                    $allDnsServer = $Network.DNSServers
                        }else{
                    $allDnsServer=@()
                }

                    # DNS suffixes
                    $allDnsSuffixes = @()
            
                    # WINS servers
                    $allWinsServers = @()

                    New-SCStaticIPAddressPool -Name "$($network.Name)_IPPool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet $Network.Subnet -IPAddressRangeStart $network.IPAddressRangeStart -IPAddressRangeEnd $network.IPAddressRangeEnd -DNSServer $allDnsServer -DNSSuffix $network.DNSSuffix -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -DefaultGateway $allGateways -RunAsynchronously
                }
            }
        }


    #Create VM Networks
    foreach ($Network in $Networks){
        if (-not (Get-SCVMNetwork -Name $network.VMNetworkName)){
            $logicalNetwork = Get-SCLogicalNetwork -Name $network.LogicalNetworkName
            $vmNetwork = New-SCVMNetwork -Name $network.VMNetworkName -LogicalNetwork $logicalNetwork -IsolationType "VLANNetwork"
            $logicalNetworkDefinition = Get-SCLogicalNetworkDefinition -Name $Network.Name
            $subnetVLANs = @()
            $subnetVLANv4 = New-SCSubnetVLan -Subnet $Network.Subnet -VLanID $network.VLAN
            $subnetVLANs += $subnetVLANv4
            $vmSubnet = New-SCVMSubnet -Name $network.VMNetworkName -Description $network.VMNetworkDescription -LogicalNetworkDefinition $logicalNetworkDefinition -SubnetVLan $subnetVLANs -VMNetwork $vmNetwork
        }
    }

    <#Cleanup networking if needed
        Get-SCVMNetwork | Remove-SCVMNetwork
        Get-SCIPAddress | Revoke-SCIPAddress
        Get-SCStaticIPAddressPool | Remove-SCStaticIPAddressPool
        get-sclogicalnetworkdefinition |Remove-SCLogicalNetworkDefinition
        Get-SCLogicalNetwork | remove-sclogicalnetwork
    #>
#endregion

#region configure vSwitch
    #create uplink pp. Use all Logical networks
        $definition = @()
        foreach ($UplinkPPSiteName in $UplinkPPSiteNames){
            $definition += Get-SCLogicalNetworkDefinition -Name $uplinkppsitename
        }
        if (-not (Get-SCNativeUplinkPortProfile -Name $UplinkPPName)){
            New-SCNativeUplinkPortProfile -Name $UplinkPPName -Description "" -LogicalNetworkDefinition $definition -EnableNetworkVirtualization $false -LBFOLoadBalancingAlgorithm "HyperVPort" -LBFOTeamMode "SwitchIndependent" -RunAsynchronously
        }

    #create port classifications and port profiles
        foreach ($Classification in $Classifications){
            If (-not (Get-SCVirtualNetworkAdapterNativePortProfile -Name $Classification.NativePortProfileName)){
                New-SCVirtualNetworkAdapterNativePortProfile -Name $Classification.NativePortProfileName -Description $Classification.Description -AllowIeeePriorityTagging $false -AllowMacAddressSpoofing $false -AllowTeaming $false -EnableDhcpGuard $false -EnableGuestIPNetworkVirtualizationUpdates $false -EnableIov $Classification.EnableIOV -EnableVrss $Classification.EnableVrss -EnableIPsecOffload $Classification.EnableIPsecOffload -EnableRouterGuard $false -EnableVmq $Classification.EnableVmq -EnableRdma $Classification.EnableRdma -MinimumBandwidthWeight "0" -RunAsynchronously
            }
            If (-not (Get-SCPortClassification -Name $Classification.PortClassificationName)){
                New-SCPortClassification -Name $Classification.PortClassificationName -Description $Classification.Description
            }
        }

    #Create Logical Switch
        $virtualSwitchExtensions = @()
        if ($SRIOV){
            $logicalSwitch = New-SCLogicalSwitch -Name $vSwitchName -Description "" -EnableSriov $true -SwitchUplinkMode "EmbeddedTeam" -MinimumBandwidthMode "None" -VirtualSwitchExtensions $virtualSwitchExtensions
        }else{
            $logicalSwitch = New-SCLogicalSwitch -Name $vSwitchName -Description "" -EnableSriov $false -SwitchUplinkMode "EmbeddedTeam" -MinimumBandwidthMode "Absolute" -VirtualSwitchExtensions $virtualSwitchExtensions
        }

    #Add virtual port classifications
        foreach ($Classification in $Classifications){
            # Get Network Port Classification
            $portClassification = Get-SCPortClassification -Name  $Classification.PortClassificationName
            # Get Hyper-V Switch Port Profile
            $nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name $Classification.NativePortProfileName
            New-SCVirtualNetworkAdapterPortProfileSet -Name $Classification.PortClassificationName -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
        }

    #Set Uplink Port Profile
        $nativeUppVar = Get-SCNativeUplinkPortProfile -Name $UplinkPPName
        $uppSetVar = New-SCUplinkPortProfileSet -Name $UplinkPPName -LogicalSwitch $logicalSwitch -NativeUplinkPortProfile $nativeUppVar -RunAsynchronously

    #Add virtual network adapters to switch.
        foreach ($vNICDefinition in $vNICDefinitions){
            # Get VM Network
            $vmNetwork = Get-SCVMNetwork -Name $vNICDefinition.VMNetworkName
            # Get VMSubnet'
            $vmSubnet = Get-SCVMSubnet -Name $vNICDefinition.VMSubnetName
        #Get Classification
            $vNICPortClassification = Get-SCPortClassification  -Name $vNICDefinition.PortClassificationName
            New-SCLogicalSwitchVirtualNetworkAdapter -Name $vNICDefinition.NetAdapterName -PortClassification $vNICPortClassification -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VMSubnet $vmSubnet -IsUsedForHostManagement $vNICDefinition.Management -InheritsAddressFromPhysicalNetworkAdapter $vNICDefinition.InheritSettings -IPv4AddressType $vNICDefinition.IPv4AddressType -IPv6AddressType "Dynamic"
        }
#endregion
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/LogicalNetworks.png)

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/NetworkSites.png)

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/LogicalSwitch.png)

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/VMNetworks.png)


### Add S2D Cluster

```PowerShell
$HostGroupName="SeattleDC"
$RunAsAccountName="VMM RAA"
$ClusterName="S2D-Cluster"

$runAsAccount = Get-SCRunAsAccount -Name $RunAsAccountName
$hostGroup = Get-SCVMHostGroup -Name $HostGroupName
Add-SCVMHostCluster -Name $ClusterName -VMHostGroup $hostGroup -Reassociate $true -Credential $runAsAccount -RemoteConnectEnabled $true
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/ClusterAdded.png)

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/ClusterAddedStorage.png)

### Convert External switch to Logical Switch

Since Switch is not logical as you can see on screenshot below, let's convert it.

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/ExternalSwitch.png)

```PowerShell
$vmHostNames="S2D1","S2D2","S2D3","S2D4"
$vSwitchName="SETSwitch"
$UplinkPPName="Seattle_PP"
Foreach($vmHostName in $vmHostNames){
    # Get Host Network Adapter
    $networkAdapter = Get-SCVMHostNetworkAdapter -VMHost $vmHostName | Select -first 1
    # Get Logical Switch
    $logicalSwitch = Get-SCLogicalSwitch -Name $vSwitchName
    # Get Virtual Network
    $standardSwitch = Get-SCVirtualNetwork -Name $vSwitchName -VMHost $VMHostName
    # Get Uplink Port Profile Set
    $uplinkPortProfileSet = Get-SCUplinkPortProfileSet -Name $UplinkPPName
    # Get Host
    $vmHost = Get-SCVMHost -ComputerName $vmHostName
    Set-SCVMHostNetworkAdapter -VMHostNetworkAdapter $networkAdapter -UplinkPortProfileSet $uplinkPortProfileSet
    Set-SCVirtualNetwork -ConvertToLogicalSwitch -LogicalSwitch $logicalSwitch -VirtualNetwork $standardSwitch
    Set-SCVMHost -VMHost $vmHost
}
 
```

As you can see on screenshot below, Logical Switch was mapped, however IP Pools and Classifications are missing. Let's fix it.

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/LogicalSwitchMissingPieces.png)

### Configure vNICs IP Pool and Classification

```PowerShell
    $vmHostNames="S2D1","S2D2","S2D3","S2D4"
    $vSwitchName="SETSwitch"
    $vNICDefinitions=@()
    $vNICDefinitions+=@{NetAdapterName="SMB01"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="Storage"    ; VMSubnetName="Storage"        ;PortClassificationName="vNIC RDMA"                  ;IPAddressPoolName="Storage_IPPool"}
    $vNICDefinitions+=@{NetAdapterName="SMB02"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="Storage"    ; VMSubnetName="Storage"        ;PortClassificationName="vNIC RDMA"                  ;IPAddressPoolName="Storage_IPPool"}
    $vNICDefinitions+=@{NetAdapterName="Mgmt" ; Management=$true  ; InheritSettings=$true  ; IPv4AddressType="Dynamic"; VMNetworkName="Management" ; VMSubnetName="Management"     ;PortClassificationName="vNIC mgmt" ;IPAddressPoolName="Management_IPPool"}

foreach ($vmHostName in $vmHostNames){
    $vmHost = Get-SCVMHost -ComputerName $vmHostName
    foreach ($vNICDefinition in $vNICDefinitions){
        # Get VM Network
        $vmNetwork = Get-SCVMNetwork -Name $vNICDefinition.VMNetworkName
        # Get VMSubnet
        $vmSubnet = Get-SCVMSubnet -Name $vNICDefinition.VMSubnetName
        #Get Classification
        $vNICPortClassification = Get-SCPortClassification  -Name $vNICDefinition.PortClassificationName
        # Get vNIC
        $vNic = Get-SCVirtualNetworkAdapter -VMHost $vmhost | where Name -eq $vNICDefinition.NetAdapterName
        # Get IPPool
        $ipV4Pool = Get-SCStaticIPAddressPool -Name $vNICDefinition.IPAddressPoolName
        # Get Subnet
        $vmSubnet = Get-SCVMSubnet -Name $vNICDefinition.VMSubnetName
        #apply config
        if ($vNICDefinition.IPv4AddressType -eq "Dynamic"){
            Set-SCVirtualNetworkAdapter -VirtualNetworkAdapter $vNic -PortClassification $vNICPortClassification -VMNetwork $vmNetwork -VMSubnet $vmSubnet -IPv4AddressType $vNICDefinition.IPv4AddressType -IPv6AddressType "Dynamic"
        }else{
            Set-SCVirtualNetworkAdapter -VirtualNetworkAdapter $vNic -PortClassification $vNICPortClassification -VMNetwork $vmNetwork -VMSubnet $vmSubnet -IPv4AddressType $vNICDefinition.IPv4AddressType -IPv4AddressPools $ipV4Pool  -IPv6AddressType "Dynamic"
        }
    }
}
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/LogicalSwitchFixeds.png)

## Transition to SCVMM based updates

### Setup WSUS server

Following scripts are inspired by this blog https://smsagent.blog/2014/02/07/installing-and-configuring-wsus-with-powershell/

```PowerShell
$WSUSServerName="WSUS"
$WSUSDir="C:\WSUS_Updates"
#Install feature
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools -ComputerName $WSUSServerName

#Configure WSUS Server
Invoke-Command -ComputerName $WSUSServerName -ScriptBlock {
    Start-Process -Wait -FilePath "C:\Program Files\Update Services\Tools\wsusutil.exe" -ArgumentList "postinstall CONTENT_DIR=$Using:WSUSDir"
}

# Get WSUS Server Object
$wsus = Get-WsusServer -Name $WSUSServerName -PortNumber 8530
 
# Connect to WSUS server configuration
$wsusConfig = $wsus.GetConfiguration()
 
# Set to download updates from Microsoft Updates
$wsus | Set-WsusServerSynchronization -SyncFromMU
 
# Set Update Languages to English and save configuration settings
$wsusConfig.AllUpdateLanguagesEnabled = $false
$wsusConfig.SetEnabledUpdateLanguages("en")
$wsusConfig.Save()

# Get WSUS Subscription and perform initial synchronization to get latest categories
$subscription = $wsus.GetSubscription()
$subscription.StartSynchronizationForCategoryOnly()
write-host 'Beginning first WSUS Sync to get available Products etc' -ForegroundColor Magenta
write-host 'Will take some time to complete'
While ($subscription.GetSynchronizationStatus() -ne 'NotProcessing') {
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 5
}
write-host ' '
Write-Host "Sync is done." -ForegroundColor Green

# Configure the Platforms that we want WSUS to receive updates
#First disable all products
$wsus | Get-WsusProduct | Set-WsusProduct -Disable
#then set just 2019 server
$wsus | Get-WsusProduct | where-Object {
    $_.Product.Title -in (
    #'Windows Server 2016',
    'Windows Server 2019')
} | Set-WsusProduct

# Configure the Classifications
$wsus | Get-WsusClassification |Set-WsusClassification -Disable
$wsus | Get-WsusClassification | Where-Object {
    $_.Classification.Title -in (
    #'Critical Updates',
    #'Definition Updates',
    #'Feature Packs',
    #'Service Packs',
    #'Update Rollups',
    'Updates',
    'Security Updates')
} | Set-WsusClassification
 
```

### Add WSUS to SCVMM

```PowerShell
$WSUSServerName="WSUS"
$RunAsAccountName="VMM RAA"

$credential = Get-SCRunAsAccount -Name $RunAsAccountName
Add-SCUpdateServer -ComputerName $WSUSServerName -Credential $credential -TCPPort 8530 -StartUpdateServerSync
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/WSUSinSCVMM.png)

### Add Update Baseline 

Add Update baseline and assign it to SeattleDC host group. The powershell code will select only Windows Server 2019 LTSC updates.

```PowerShell
$VMHostGroupName="SeattleDC"

$Date=Get-Date
$2digitsDay  ="{0:D2}" -f $date.Day
$2digitsMonth="{0:D2}" -f $date.Month
$BaselineName="$($Date.Year)-$2DigitsMonth-$2DigitsDay Windows Server 2019 Updates+Security updates"

if (-not (Get-SCBaseline -Name $BaselineName -ErrorAction SilentlyContinue)){
    $baseline = New-SCBaseline -Name $BaselineName -Description ""
    $addedUpdateList = Get-SCUpdate | Where IsSuperseded -eq $False | Where Name -Like "*Windows Server 2019 for*"
    $scope = Get-SCVMHostGroup -Name $VMHostGroupName
    Set-SCBaseline -Baseline $baseline -AddAssignmentScope $scope
    Set-SCBaseline -Baseline $baseline -AddUpdates $addedUpdateList -StartNow
}
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/UpdateBaseline.png)

### Scan for compliance

```PowerShell
$vmHostNames="S2D1","S2D2","S2D3","S2D4"
foreach ($vmHostName in $vmHostNames){
    $VMHost = Get-SCVMHost -ComputerName $vmHostName
    $Compliance = Get-SCComplianceStatus -VMMManagedComputer $VMHost.ManagedComputer
    foreach($Bsc in $Compliance.BaselineLevelComplianceStatus){
        Start-SCComplianceScan -VMMManagedComputer $VMHost.ManagedComputer -Baseline $Bsc.Baseline
    }
}
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/Compliance-NonCompliant1.png)

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/Compliance-NonCompliant2.png)

### Disable CAU

Since we will use SCVMM, it's no longer needed.

```PowerShell
$ClusterName="S2D-Cluster"

Disable-CauClusterRole -ClusterName $ClusterName -Force
 
```

### Remediate

```PowerShell
$ClusterName="S2D-Cluster"
$JobGUID=[guid]::NewGuid()
$vmHostNames="S2D1","S2D2","S2D3","S2D4"

$cluster = Get-SCVMHostCluster -Name $ClusterName
foreach ($vmHostName in $vmHostNames){
	$vmHost = Get-SCVMHost -ComputerName $vmHostName -VMHostCluster $cluster
	Start-SCUpdateRemediation -JobGroup $JobGUID -VMHost $vmHost -VMHostCluster $cluster
}
Start-SCUpdateRemediation -JobGroup $JobGUID -StartNow -UseLiveMigration -VMHostCluster $cluster
 
```

![](/Scenarios/S2D%20and%20SCVMM%202019/Screenshots/RemediationInProgress.png)
