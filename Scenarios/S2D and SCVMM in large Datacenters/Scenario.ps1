#start services
Start-Service -Name "MSSQLSERVER","SCVMMService"

#Import VMM Module
Import-Module VirtualMachineManager

#connect to server
Get-VMMServer "DC"

#Disable automatic logical network creation
Set-SCVMMServer -AutomaticLogicalNetworkCreationEnabled $false -LogicalNetworkMatch "FirstDNSSuffixLabel" -BackupLogicalNetworkMatch "VirtualNetworkSwitchName"

#Datacenter definition
$Datacenters=@()
$Datacenters+=@{
    DCName="Redmond"
    ManagementIPBlockStart="10.0.0" # 1C per aisle
    StorageIPBlockStart="10.1.0"    # 1C per rack
    NumberOfRoomsperDC=2
    NumberOfAislesPerRoom=2
    NumberOfRacksPerAisle=4
}
$Datacenters+=@{
    DCName="Seattle"
    ManagementIPBlockStart="10.2.0" # 1C per aisle
    StorageIPBlockStart="10.3.0"    # 1C per rack
    NumberOfRoomsperDC=2
    NumberOfAislesPerRoom=2
    NumberOfRacksPerAisle=4
}
$Datacenters+=@{
    DCName="London"
    ManagementIPBlockStart="10.4.0" # 1C per aisle
    StorageIPBlockStart="10.5.0"    # 1C per rack
    NumberOfRoomsperDC=2
    NumberOfAislesPerRoom=2
    NumberOfRacksPerAisle=4
}
$DNSServers="10.0.0.1","10.0.0.2" #Just an example
$InfrastructureNetworkName="InfrastructureNetwork"
$vSwitchName="SETSwitch"

#Create Host Groups
Foreach ($Datacenter in $Datacenters){
    $Name=$Datacenter.DCName
    if (-not (Get-SCVMHostGroup -Name $Name)){
        $DCParentHostGroup=New-SCVMHostGroup -Name $Name
    }

    #Create Room
    1..$Datacenter.NumberOfRoomsPerDC | ForEach-Object {
        if (-not (Get-SCVMHostGroup -Name "Room$_" -ParentHostGroup $DCParentHostGroup)){
            $RoomParentHostGroup=New-SCVMHostGroup -Name "Room$_" -ParentHostGroup $DCParentHostGroup
        }
        #Create Aisles
        1..$Datacenter.NumberOfAislesPerRoom | ForEach-Object {
            if (-not (Get-SCVMHostGroup -Name "Aisle$_" -ParentHostGroup $RoomParentHostGroup)){
                $AisleParentHostGroup=New-SCVMHostGroup -Name "Aisle$_" -ParentHostGroup $RoomParentHostGroup
            }
            1..$Datacenter.NumberOfRacksPerAisle | ForEach-Object {
                if (-not (Get-SCVMHostGroup -Name "Rack$_" -ParentHostGroup $AisleParentHostGroup)){
                    New-SCVMHostGroup -Name "Rack$_" -ParentHostGroup $AisleParentHostGroup
                }
            }
        }
    }
}

#Cleanup Host Groups
#Get-SCVMHostGroup -ParentHostGroup (Get-SCVMHostGroup "All Hosts") | Remove-SCVMHostGroup

#Create Management Logical Network
if (-not (Get-SCLogicalNetwork -Name $InfrastructureNetworkName)){
    New-SCLogicalNetwork -Name $InfrastructureNetworkName -LogicalNetworkDefinitionIsolation $true -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
}

#Add sites,Pools and VM Networks
    #Create Storage Networks for each Rack
    Foreach ($Datacenter in $Datacenters){
        #Create Site in each Rack
        $HostGroups=Get-SCVMHostGroup | Where-Object Path -match $Datacenter.DCName | Where-Object Path -match Rack | Sort-Object Path
        $logicalNetwork = Get-SCLogicalNetwork -Name $InfrastructureNetworkName
        #Start C range for StorageIPs
        [int]$i=$Datacenter.StorageIPBlockStart.split(".") | Select-Object -Last 1
        #Grab prefix for StorageIPs
        $Prefix=($Datacenter.StorageIPBlockStart.split(".") | Select-Object -First 2) -join "."
        foreach ($HostGroup in $HostGroups){
            $subnet="$Prefix.$i.0/24"
            $allSubnetVlan = @()
            $allSubnetVlan += New-SCSubnetVLan -Subnet $Subnet -VLanID 1
            $i++
            #Generate SiteName (eg NetworkSite_Seattle_Room1_Aisle1_Rack1)
            $SiteName="NetworkSite_"+(($HostGroup.Path.Split("\") | Select-Object -Last 4) -Join("_"))
            #Create Site
            $LogicalNetworkDefinition=$null
            $LogicalNetworkDefinition=Get-SCLogicalNetworkDefinition -Name $SiteName -LogicalNetwork $logicalNetwork
            if ($LogicalNetworkDefinition){
                Set-SCLogicalNetworkDefinition -LogicalNetworkDefinition $logicalNetworkDefinition -name $SiteName -SubnetVLan $AllSubnetVlan -RunAsynchronously
            }else{
                $LogicalNetworkDefinition=New-SCLogicalNetworkDefinition -Name $SiteName -LogicalNetwork $logicalNetwork -VMHostGroup $HostGroup -SubnetVLan $AllSubnetVlan -RunAsynchronously
            }
            #Create IP Pool
            $IPPoolName=$SiteName.Replace("NetworkSite_","IPPool_Storage_")
            $IPAddressRangeStart=$Subnet.Replace("0/24","1")
            $IPAddressRangeEnd=$Subnet.Replace("0/24","254")
            if (-not (Get-SCStaticIPAddressPool -Name IPPoolName)) {
                New-SCStaticIPAddressPool -Name $IPPoolName -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet $Subnet -IPAddressRangeStart $IPAddressRangeStart -IPAddressRangeEnd $IPAddressRangeEnd -RunAsynchronously
            }
            #Create VM Network
            $vmNetwork = New-SCVMNetwork -Name Storage -Description $SiteName.Replace("NetworkSite_","") -LogicalNetwork $logicalNetwork -IsolationType "VLANNetwork"
            $subnetVLAN = New-SCSubnetVLan -Subnet $Subnet -VLanID 1
            New-SCVMSubnet -Name Storage -LogicalNetworkDefinition $logicalNetworkDefinition -SubnetVLan $subnetVLAN -VMNetwork $vmNetwork -Description $SiteName.Replace("NetworkSite_","")
        }
    }
    Foreach ($Datacenter in $Datacenters){
        #Create Site in each Aisle
        $HostGroups=Get-SCVMHostGroup | Where-Object Path -match $Datacenter.DCName | Where-Object Path -match Aisle | Where-Object Path -NotMatch Rack | Sort-Object Path
        $logicalNetwork = Get-SCLogicalNetwork -Name $InfrastructureNetworkName
        #Start C range for ManagementIPs
        [int]$i=$Datacenter.ManagementIPBlockStart.split(".") | Select-Object -Last 1
        #Grab prefix for ManagementIPs
        $Prefix=($Datacenter.ManagementIPBlockStart.split(".") | Select-Object -First 2) -join "."
        foreach ($HostGroup in $HostGroups){
            $subnet="$Prefix.$i.0/24"
            $allSubnetVlan = @()
            $allSubnetVlan += New-SCSubnetVLan -Subnet $Subnet -VLanID 0
            $i++
            #Generate SiteName (eg NetworkSite_Seattle_Room1_Aisle1)
            $SiteName="NetworkSite_"+(($HostGroup.Path.Split("\") | Select-Object -Last 3) -Join("_"))
            #Create Site
            $LogicalNetworkDefinition=$null
            $LogicalNetworkDefinition=Get-SCLogicalNetworkDefinition -Name $SiteName -LogicalNetwork $logicalNetwork
            if ($LogicalNetworkDefinition){
                Set-SCLogicalNetworkDefinition -LogicalNetworkDefinition $logicalNetworkDefinition -name $SiteName -SubnetVLan $AllSubnetVlan -RunAsynchronously
            }else{
                $LogicalNetworkDefinition=New-SCLogicalNetworkDefinition -Name $SiteName -LogicalNetwork $logicalNetwork -VMHostGroup $HostGroup -SubnetVLan $AllSubnetVlan -RunAsynchronously
            }
            #Create IP Pool
            $IPPoolName=$SiteName.Replace("NetworkSite_","IPPool_Management_")
            $IPAddressRangeStart=$Subnet.Replace("0/24","1")
            $IPAddressRangeEnd=$Subnet.Replace("0/24","254")
            $Gateway=New-SCDefaultGateway -IPAddress $Subnet.Replace("0/24","254") -Automatic
            if (-not (Get-SCStaticIPAddressPool -Name IPPoolName)) {
                New-SCStaticIPAddressPool -Name $IPPoolName -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet $Subnet -IPAddressRangeStart $IPAddressRangeStart -IPAddressRangeEnd $IPAddressRangeEnd -DefaultGateway $Gateway -DNSServer $DNSServers -RunAsynchronously
            }
            #Create VM Network
            $vmNetwork = New-SCVMNetwork -Name Management -Description $SiteName.Replace("NetworkSite_","") -LogicalNetwork $logicalNetwork -IsolationType "VLANNetwork"
            $subnetVLAN = New-SCSubnetVLan -Subnet $Subnet -VLanID 0
            New-SCVMSubnet -Name Management -LogicalNetworkDefinition $logicalNetworkDefinition -SubnetVLan $subnetVLAN -VMNetwork $vmNetwork  -Description $SiteName.Replace("NetworkSite_","")
        }
    }

#Create Uplink port profile for each Rack that has both Management and Storage network.
$RackHostGroups=Get-SCVMHostGroup | Where-Object Path -match Rack
$logicalNetwork = Get-SCLogicalNetwork -Name $InfrastructureNetworkName
foreach ($HostGroup in $RackHostGroups){
    $RackSiteName="NetworkSite_"+(($HostGroup.Path.Split("\") | Select-Object -Last 4) -Join("_"))
    $AisleSiteName="NetworkSite_"+(($HostGroup.ParentHostGroup.Path.Split("\") | Select-Object -Last 3) -Join("_"))
    $UplinkPPName=$RackSiteName.replace("NetworkSite_","UplinkPP_")
    If (-not (Get-SCNativeUplinkPortProfile -Name $UplinkPPName)){
        $definition  = @()
        $definition  += Get-SCLogicalNetworkDefinition -Name $RackSiteName -LogicalNetwork $logicalNetwork
        $definition  += Get-SCLogicalNetworkDefinition -Name $AisleSiteName -LogicalNetwork $logicalNetwork
        New-SCNativeUplinkPortProfile -Name $UplinkPPName -Description "" -LogicalNetworkDefinition $definition -EnableNetworkVirtualization $false -LBFOLoadBalancingAlgorithm "HyperVPort" -LBFOTeamMode "SwitchIndependent" -RunAsynchronously
    }
}

#Cleanup Sites, IP Pools and VMNetworks
<#
Get-SCNativeUplinkPortProfile | Remove-SCNativeUplinkPortProfile
Get-SCVMNetwork | Remove-SCVMNetwork
Get-SCStaticIPAddressPool | Remove-SCStaticIPAddressPool
Get-SCLogicalNetworkDefinition | Remove-SCLogicalNetworkDefinition
#>

#Create Port Profiles for RDMA, VMQ
    #vSwitch vNICs classifications
    $Classifications=@()
    $Classifications+=@{PortClassificationName="Host Management absolute" ; NativePortProfileName="Host management absolute" ; Description="Classification for Mgmt vNICs with absolute reservation (Windows Server 2016 or later)" ; EnableIov=$false ; EnableVrss=$true  ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
    $Classifications+=@{PortClassificationName="vNIC RDMA"                ; NativePortProfileName="vNIC RDMA"                ; Description="Classification for RDMA enabled vNICs (Mode 2)"                                         ; EnableIov=$false ; EnableVrss=$true  ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$true }
    $Classifications+=@{PortClassificationName="vmNIC VMQ"                ; NativePortProfileName="vmNIC VMQ"                ; Description="Classification for VMQ enabled vmNICs"                                                  ; EnableIov=$false ; EnableVrss=$false ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
    $Classifications+=@{PortClassificationName="vmNIC SR-IOV"             ; NativePortProfileName="vmNIC SR-IOV"             ; Description="Classification for SR-IOV enabled vmNICs"                                               ; EnableIov=$true  ; EnableVrss=$false ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}

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
$logicalSwitch = New-SCLogicalSwitch -Name $vSwitchName -Description "SR-IOV Enabled vSwitch" -EnableSriov $true -SwitchUplinkMode "EmbeddedTeam" -MinimumBandwidthMode "None" -VirtualSwitchExtensions $virtualSwitchExtensions

#Add virtual port classifications
foreach ($Classification in $Classifications){
    # Get Network Port Classification
    $portClassification = Get-SCPortClassification -Name  $Classification.PortClassificationName
    # Get Hyper-V Switch Port Profile
    $nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name $Classification.NativePortProfileName
    New-SCVirtualNetworkAdapterPortProfileSet -Name $Classification.PortClassificationName -PortClassification $portClassification -LogicalSwitch $logicalSwitch -RunAsynchronously -VirtualNetworkAdapterNativePortProfile $nativeProfile
}

#Management vNIC Classification
foreach ($UplinkPP in (Get-SCNativeUplinkPortProfile | Sort-Object -Property Name)){
    $uppSetVar = New-SCUplinkPortProfileSet -Name $UplinkPP.Name -LogicalSwitch $logicalSwitch -NativeUplinkPortProfile $UplinkPP -RunAsynchronously

    #Add Management vNIC
    $vmNetwork=Get-SCVMNetwork -Name Management | Where-Object Description -eq (($uppSetVar.name.replace("UplinkPP_","").split("_") | Select-Object -SkipLast 1) -join "_")
    $vmSubnet= Get-SCVMSubnet  -Name Management | Where-Object Description -eq (($uppSetVar.name.replace("UplinkPP_","").split("_") | Select-Object -SkipLast 1) -join "_")
    $vNICPortClassification = Get-SCPortClassification  -Name "Host Management absolute"
    New-SCLogicalSwitchVirtualNetworkAdapter -Name Mgmt -PortClassification $vNICPortClassification -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VMSubnet $vmSubnet -IsUsedForHostManagement $true -InheritsAddressFromPhysicalNetworkAdapter $True -IPv4AddressType "Dynamic" -IPv6AddressType "Dynamic"
    #Add SMB vNICs
    $vmNetwork=Get-SCVMNetwork -Name Storage | Where-Object Description -eq ($uppSetVar.name.replace("UplinkPP_",""))
    $vmSubnet= Get-SCVMSubnet  -Name Storage | Where-Object Description -eq ($uppSetVar.name.replace("UplinkPP_",""))
    $vNICPortClassification = Get-SCPortClassification  -Name "vNIC RDMA"

    New-SCLogicalSwitchVirtualNetworkAdapter -Name SMB01 -PortClassification $vNICPortClassification -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VMSubnet $vmSubnet -IsUsedForHostManagement $false -InheritsAddressFromPhysicalNetworkAdapter $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic"
    New-SCLogicalSwitchVirtualNetworkAdapter -Name SMB02 -PortClassification $vNICPortClassification -UplinkPortProfileSet $uppSetVar -RunAsynchronously -VMNetwork $vmNetwork -VMSubnet $vmSubnet -IsUsedForHostManagement $false -InheritsAddressFromPhysicalNetworkAdapter $false -IPv4AddressType "Static" -IPv6AddressType "Dynamic"
}