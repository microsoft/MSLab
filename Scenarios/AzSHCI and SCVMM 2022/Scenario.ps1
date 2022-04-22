#this lab will demonstrate how to add existing cluster into System Center Virtual Machine Manager

#region Create 2 node cluster (just simple. Not for prod - follow azure stack hci scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20Deployment)
    # LabConfig
    $Servers="AzSVMM1","AzSVMM2"
    $ClusterName="AzSVMM-Cluster"
    $vSwitchName="vSwitch"
    $StorNet1="172.16.1."
    $StorNet2="172.16.2."
    $StorVLAN1=1
    $StorVLAN2=2
    $IP=1

    # Install features for management on server
    Install-WindowsFeature -Name RSAT-DHCP,RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

    # Update servers
    <#
    Invoke-Command -ComputerName $servers -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
    }
    #remove temporary PSsession config
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }
    #>

    # Install features on servers
    Invoke-Command -computername $Servers -ScriptBlock {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell"
    }

    # restart servers
    Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
    #failsafe - sometimes it evaluates, that servers completed restart after first restart (hyper-v needs 2)
    Start-sleep 20

    # create vSwitch
    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableIov $True -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

    #region configure networks
        #add vNICs
        foreach ($Server in $Servers){
            #rename Management vNIC first
                Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Management -ComputerName $Server
            #add SMB vNICs (number depends on how many NICs are connected to vSwitch)
                $SMBvNICsCount=(Get-VMSwitch -CimSession $Server -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count
                foreach ($number in (1..$SMBvNICsCount)){
                    $TwoDigitNumber="{0:D2}" -f $Number
                    Add-VMNetworkAdapter -ManagementOS -Name "SMB$TwoDigitNumber" -SwitchName $vSwitchName -CimSession $Server
                }
            #configure IP Addresses
                foreach ($number in (1..$SMBvNICsCount)){
                    $TwoDigitNumber="{0:D2}" -f $Number
                    if ($number % 2 -eq 1){
                        New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB$TwoDigitNumber)" -CimSession $Server -PrefixLength 24
                    }else{
                        New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB$TwoDigitNumber)" -CimSession $Server -PrefixLength 24
                        $IP++
                    }
                }
        }
        Start-Sleep 5
        Clear-DnsClientCache

        #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
            #configure Odds and Evens for VLAN1 and VLAN2
            foreach ($Server in $Servers){
                $NetAdapters=Get-VMNetworkAdapter -CimSession $server -ManagementOS -Name *SMB* | Sort-Object Name
                $i=1
                foreach ($NetAdapter in $NetAdapters){
                    if (($i % 2) -eq 1){
                        Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $Server
                        $i++
                    }else{
                        Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $Server
                        $i++
                    }
                }
            }

        #Restart each host vNIC adapter so that the Vlan is active.
            Get-NetAdapter -CimSession $Servers -Name "vEthernet (SMB*)" | Restart-NetAdapter

        #Enable RDMA on the host vNIC adapters
            Enable-NetAdapterRDMA -Name "vEthernet (SMB*)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
            Invoke-Command -ComputerName $servers -ScriptBlock {
                #grab adapter names
                $physicaladapternames=(get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions
                #map pNIC and vNICs
                $vmNetAdapters=Get-VMNetworkAdapter -Name "SMB*" -ManagementOS
                $i=0
                foreach ($vmNetAdapter in $vmNetAdapters){
                    $TwoDigitNumber="{0:D2}" -f ($i+1)
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB$TwoDigitNumber" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapternames[$i]).name
                    $i++
                }
            }
    #endregion

    #create cluster
        New-Cluster -Name $ClusterName -Node $Servers
        Start-Sleep 5
        Clear-DNSClientCache

    #Configure Cluster Networks
        #rename networks
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB01"
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB02"

        #Rename Management Network
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Role -eq "ClusterAndClient").Name="Management"

        #configure Live Migration 
            Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Role -ne "Cluster"}).ID))
            Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers

    #add file share witness on "DC"
        #Create new directory
            $WitnessName=$ClusterName+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$($ClusterName)$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

    #Enable S2D
        Enable-ClusterS2D -CimSession $ClusterName -Verbose -Confirm:0

    #configure thin provisioning (if available)
        $OSInfo=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        }
        if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuildNumber -ge 20348){
            Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
        }

    #create some 1TB volumes (same name as node)
        foreach ($Server in $Servers){
            New-Volume -CimSession $Server -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 1TB -FriendlyName "$Server"
        }
    #region Register Azure Stack HCI to Azure - if not registered, VMs are not added as cluster resources = AKS script will fail
        #download Azure module
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
            Install-Module -Name Az.StackHCI -Force
        }

        #login to azure
        #download Azure module
        if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
            Install-Module -Name Az.Accounts -Force
        }
        Connect-AzAccount -UseDeviceAuthentication
        <# or download edge and do it without device authentication
        #download
        Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
        #start install
        Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
        #start Edge
        start-sleep 5
        & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        Connect-AzAccount
        #>
        <#or use IE for autentication
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2
        Connect-AzAccount
        #>
        #select subscription if more available
        $subscription=Get-AzSubscription
        if (($subscription).count -gt 1){
            $subscription | Out-GridView -OutputMode Single | Set-AzContext
        }

        #grab subscription ID
        $subscriptionID=(Get-AzContext).Subscription.id

        <# Register AZSHCi without prompting for creds, 
        Notes: As Dec. 2021, in Azure Stack HCI 21H2,  if you Register-AzStackHCI the cluster multiple times in same ResourceGroup (e.g. default
        resource group name is AzSHCI-Cluster-rg) without run UnRegister-AzStackHCI first, although you may succeed in cluster registration, but
        sever node Arc integration will fail, even if you have deleted the ResourceGroup in Azure Portal before running Register-AzStackHCI #>

        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id


        #Install Azure Stack HCI RSAT Tools to all nodes
        $Servers=(Get-ClusterNode -Cluster $ClusterName).Name
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name RSAT-Azure-Stack-HCI
        }

        #Validate registration (query on just one node is needed)
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            Get-AzureStackHCI
        }
    #endregion

    #create three "fake" VMs on each CSV
        $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
        foreach ($CSV in $CSVs){
            $CSV=($CSV -split '\((.*?)\)')[1]
            1..3 | ForEach-Object {
                $VMName="$($CSV)_TestVM$_"
                Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random) -ScriptBlock {
                    #create some fake VMs
                    New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\$($using:CSV)\$($using:VMName)\Virtual Hard Disks\$($using:VMName).vhdx" -NewVHDSizeBytes 32GB -SwitchName $using:vSwitchName -Generation 2 -Path "c:\ClusterStorage\$($using:CSV)\" -MemoryStartupBytes 32MB
                }
                Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
            }
        }
#endregion

#region Configure System Center Virtual Machine Manager to describe environment
    #region variables
        $VMMServerName="DC"
        
        $RunAsAccountName="VMM RAA"
        $RunAsAccountUserName="CORP\LabAdmin"
        $RunAsAccountPassword="LS1setup!"

        $vSwitchName="vSwitch"
        $HostGroupName="SeattleDC"
        $SRIOV=$true

        #vSwitch vNICs and vmNICs classifications
            $Classifications=@()
            $Classifications+=@{PortClassificationName="vNIC mgmt" ; NativePortProfileName="vNIC mgmt" ; Description="Classification for Management vNIC"             ; EnableIov=$false ; EnableVrss=$true  ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
            $Classifications+=@{PortClassificationName="vNIC RDMA" ; NativePortProfileName="vNIC RDMA" ; Description="Classification for RDMA enabled vNICs (Mode 2)" ; EnableIov=$false ; EnableVrss=$true  ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$true }
            $Classifications+=@{PortClassificationName="vmNIC VMQ" ; NativePortProfileName="vmNIC VMQ" ; Description="Classification for VMQ enabled vmNICs"          ; EnableIov=$false ; EnableVrss=$false ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
            
            if ($SRIOV) {
                $Classifications+=@{PortClassificationName="vmNIC SR-IOV" ; NativePortProfileName="vmNIC SR-IOV" ; Description="Classification for SR-IOV enabled vmNICs" ; EnableIov=$true  ; EnableVrss=$false ; EnableIPsecOffload=$true  ; EnableVmq=$true  ; EnableRdma=$false}
            }

        #logical networks definition
            $Networks=@()
            $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupNames=$HostGroupName ; Name="Management"  ; Description="Management VLAN" ; VMNetworkName= "Management" ; VMNetworkDescription= ""  ; Subnet="10.0.0.0/24"      ; VLAN=0 ; IPAddressRangeStart="10.0.0.1"   ;IPAddressRangeEnd="10.0.0.254"           ; DNSSuffix="Corp.contoso.com" ;DNSServers="10.0.0.1"  ;Gateways="10.0.0.1"}
            $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupNames=$HostGroupName ; Name="SMB01"     ; Description="SMB01"             ; VMNetworkName= "SMB01"    ; VMNetworkDescription= ""  ; Subnet="172.16.1.0/24"    ; VLAN=1 ; IPAddressRangeStart="172.16.1.1" ;IPAddressRangeEnd="172.16.1.254"         ; DNSSuffix="Corp.contoso.com" ;DNSServers=""          ;Gateways=""}
            $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupNames=$HostGroupName ; Name="SMB02"     ; Description="SMB02"             ; VMNetworkName= "SMB02"    ; VMNetworkDescription= ""  ; Subnet="172.16.2.0/24"    ; VLAN=2 ; IPAddressRangeStart="172.16.2.1" ;IPAddressRangeEnd="172.16.2.254"         ; DNSSuffix="Corp.contoso.com" ;DNSServers=""          ;Gateways=""}

            #some fake networks just for demonstration
            $Networks+=@{LogicalNetworkName="VMs Network"       ; HostGroupNames=$HostGroupName ; Name="Production"  ; Description="Production VLAN" ; VMNetworkName= "Production" ; VMNetworkDescription= ""  ; Subnet="192.168.1.0/24"   ; VLAN=3 ; IPAddressRangeStart="192.168.1.1"   ;IPAddressRangeEnd="192.168.1.254"     ; DNSSuffix="Corp.contoso.com" ;DNSServers=("10.0.0.11","10.0.0.10")  ;Gateways="192.168.1.1"}
            $Networks+=@{LogicalNetworkName="VMs Network"       ; HostGroupNames=$HostGroupName ; Name="DMZ"         ; Description="DMZ VLAN"        ; VMNetworkName= "DMZ"        ; VMNetworkDescription= ""  ; Subnet="192.168.2.0/24"   ; VLAN=4 ; IPAddressRangeStart="192.168.2.1"   ;IPAddressRangeEnd="192.168.2.254"     ; DNSSuffix="Corp.contoso.com" ;DNSServers=("10.0.0.11","10.0.0.10")  ;Gateways="192.168.2.1"}

            $vNICDefinitions=@()
            $vNICDefinitions+=@{NetAdapterName="SMB01"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="SMB01"    ; VMSubnetName="SMB01"        ;PortClassificationName="vNIC RDMA"                  ;IPAddressPoolName="SMB01_IPPool"}
            $vNICDefinitions+=@{NetAdapterName="SMB02"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="SMB02"    ; VMSubnetName="SMB02"        ;PortClassificationName="vNIC RDMA"                  ;IPAddressPoolName="SMB02_IPPool"}
            $vNICDefinitions+=@{NetAdapterName="Management" ; Management=$true  ; InheritSettings=$true  ; IPv4AddressType="Dynamic"; VMNetworkName="Management" ; VMSubnetName="Management"     ;PortClassificationName="vNIC mgmt" ;IPAddressPoolName="Management_IPPool"}

        #Uplink Port Profile
            $UplinkPPName="Seattle_PP" 
            $UplinkPPSiteNames='SMB01','SMB02','Management','Production','DMZ'
    #endregion

    #region do the job
        #Make sure RSAT features are installed to be able to manage clusters
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica,UpdateServices-RSAT,UpdateServices-UI

        #Import VMM Module
        Import-Module VirtualMachineManager

        #connect to server
        Get-VMMServer $VMMServerName

        #Create Run As Account
        $Credentials = New-Object System.Management.Automation.PSCredential ($RunAsAccountUserName, (ConvertTo-SecureString $RunAsAccountPassword -AsPlainText -Force))
        New-SCRunAsAccount -Credential $Credentials -Name $RunAsAccountName -Description "Run As Account for managing Hyper-V hosts"

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

        #region create Logical Switch
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
    #endregion

#endregion

#region add Azure Stack HCI Cluster

    #variables
        $HostGroupName="SeattleDC"
        $RunAsAccountName="VMM RAA"
        $ClusterName="AzSVMM-Cluster"
        $vmHostNames="AzSVMM1","AzSVMM2"
        $vSwitchName="vSwitch"
        $UplinkPPName="Seattle_PP"

    #add cluster
        $runAsAccount = Get-SCRunAsAccount -Name $RunAsAccountName
        $hostGroup = Get-SCVMHostGroup -Name $HostGroupName
        Add-SCVMHostCluster -Name $ClusterName -VMHostGroup $hostGroup -Reassociate $true -Credential $runAsAccount -RemoteConnectEnabled $true

    #convert external switch to Logical Switch
        Foreach($vmHostName in $vmHostNames){
            # Get Host Network Adapter
            $networkAdapter = (Get-SCVirtualNetwork -VMHost $VMHostName).VMHostNetworkAdapters[0]
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

    #finish configuration
        #little bit more variables
        $vNICDefinitions=@()
        $vNICDefinitions+=@{NetAdapterName="SMB01"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="SMB01"      ; VMSubnetName="SMB01"      ;PortClassificationName="vNIC RDMA" ;IPAddressPoolName="SMB01_IPPool"}
        $vNICDefinitions+=@{NetAdapterName="SMB02"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="SMB02"      ; VMSubnetName="SMB02"      ;PortClassificationName="vNIC RDMA" ;IPAddressPoolName="SMB02_IPPool"}
        $vNICDefinitions+=@{NetAdapterName="Management" ; Management=$true  ; InheritSettings=$true  ; IPv4AddressType="Dynamic"; VMNetworkName="Management" ; VMSubnetName="Management" ;PortClassificationName="vNIC mgmt" ;IPAddressPoolName="Management_IPPool"}
    
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
                $vNic = Get-SCVirtualNetworkAdapter -VMHost $vmhost | Where-Object Name -eq $vNICDefinition.NetAdapterName
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


#endregion

#region cleanup
    <#
    #remove cluster
    $credential = Get-SCRunAsAccount -Name $RunAsAccountName
    $hostCluster = Get-SCVMHostCluster -Name $ClusterName
    Remove-SCVMHostCluster -VMHostCluster $hostCluster -Credential $credential
    #remove Logical Switch
    Get-SCLogicalSwitch -Name $vSwitchName | remove-sclogicalswitch
    #remove virtual networks
    Get-scvmnetwork | Remove-SCVMNetwork
    #remove pools
    Get-SCStaticIPAddressPool | Remove-SCStaticIPAddressPool
    #remove uplink port profiles
    Get-SCNativeUplinkPortProfile | Remove-SCNativeUplinkPortProfile
    #remove logical networks
    get-sclogicalnetworkdefinition |Remove-SCLogicalNetworkDefinition
    #remove host group
    Get-SCVMHostGroup | Where-Object Name -NE "All Hosts" | Remove-SCVMHostGroup
    #remove Run-As account
    Get-SCRunAsAccount -Name $RunAsAccountName | Remove-SCRunAsAccount
    #>
#endregion

#region Add WSUS server
    #variables
    $WSUSServerName="WSUS"
    $WSUSDir="C:\WSUS_Updates"
    $RunAsAccountName="VMM RAA"
    $HostGroupName="SeattleDC"
    $ClusterName="AzSVMM-Cluster"
    $vmHostNames="AzSVMM1","AzSVMM2"

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
    #then set just Azure Stack HCI (And Windows Server 2022). "Azure Stack HCI" refers to 20H2
    $wsus | Get-WsusProduct | where-Object {
        $_.Product.Title -in (
        #'Windows Server 2016',
        #'Windows Server 2019',
        #'Azure Stack HCI',
        'Microsoft Server operating system-21H2')
    } | Set-WsusProduct

    # Configure the Classifications https://docs.microsoft.com/en-US/troubleshoot/windows-client/deployment/standard-terminology-software-updates
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

    #Add WSUS to SCVMM
    $credential = Get-SCRunAsAccount -Name $RunAsAccountName
    Add-SCUpdateServer -ComputerName $WSUSServerName -Credential $credential -TCPPort 8530 -StartUpdateServerSync
    #start sync if needed
    $UpdateServer=Get-SCUpdateServer
    $UpdateServer | Start-SCUpdateServerSynchronization
 
    #add Update Baseline to SCVMM
    $Date=Get-Date
    $2digitsDay  ="{0:D2}" -f $date.Day
    $2digitsMonth="{0:D2}" -f $date.Month
    $BaselineName="$($Date.Year)-$2DigitsMonth-$2DigitsDay Azure Stack HCI 21H2 Updates+Security updates"

    if (-not (Get-SCBaseline -Name $BaselineName -ErrorAction SilentlyContinue)){
        $baseline = New-SCBaseline -Name $BaselineName -Description ""
        $addedUpdateList = Get-SCUpdate | Where-Object IsSuperseded -eq $False | Where-Object Name -Like "*21H2 for x64*"
        $scope = Get-SCVMHostGroup -Name $HostGroupName
        Set-SCBaseline -Baseline $baseline -AddAssignmentScope $scope
        Set-SCBaseline -Baseline $baseline -AddUpdates $addedUpdateList -StartNow
    }
 
    #Start Compliance Scan
    Get-SCVMMManagedComputer | Where-Object RoleString -eq "Host"| Start-SCComplianceScan
    #view compliance status
    Get-SCComplianceStatus | Select-Object Name,OverallComplianceState

    #remediate
    $JobGUID=[guid]::NewGuid()
    $cluster = Get-SCVMHostCluster -Name $ClusterName
    foreach ($vmHostName in $vmHostNames){
        $vmHost = Get-SCVMHost -ComputerName $vmHostName -VMHostCluster $cluster
        Start-SCUpdateRemediation -JobGroup $JobGUID -VMHost $vmHost -VMHostCluster $cluster
    }
    Start-SCUpdateRemediation -JobGroup $JobGUID -StartNow -UseLiveMigration -VMHostCluster $cluster

#endregion

#region add Library server and add some images from Azure
    #variables
    $LibraryServerName = "Library"
    $LibraryShareLocation = "D:\VMMLibrary"
    $LibraryShareName="VMMLibrary"
    $RunAsAccountName="VMM RAA"
    $AzureImages=@()
    $AzureImages+=@{PublisherName = "microsoftwindowsserver";Offer="windowsserver";SKU="2022-datacenter-azure-edition-smalldisk"}
    $AzureImages+=@{PublisherName = "microsoftwindowsserver";Offer="windowsserver";SKU="2022-datacenter-azure-edition-core-smalldisk"}
    $ResourceGroupName="AzureImagesTemp"

    #Prepare fileshare first
        #format and prepare "D" drive
        Get-Disk -CimSession $LibraryServerName | Where-Object PartitionStyle -eq RAW | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -Filesystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel "Storage"

    #Create Library Share
    Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
        New-Item -Path $using:LibraryShareLocation -ItemType Directory -ErrorAction Ignore
        New-SmbShare -Name $using:LibraryShareName -Path "$using:LibraryShareLocation" -FullAccess Administrators
    }

    #Add Library Server to SCVMM
    $credential = Get-SCRunAsAccount -Name $RunAsAccountName
    $JobGUID=[guid]::NewGuid()
    Add-SCLibraryShare -Description "" -JobGroup $JobGUID -SharePath "\\$LibraryServerName\$LibraryShareName" -UseAlternateDataStream $true #-AddDefaultResources
    Add-SCLibraryServer -ComputerName $LibraryServerName -Description "" -JobGroup $JobGUID -Credential $credential

    #region add VHDx from Azure Marketplace
        #Install or update Azure packages
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        $ModuleNames="Az.Accounts","Az.Compute","Az.Resources","Az.StackHCI"
        foreach ($ModuleName in $ModuleNames){
            $Module=Get-InstalledModule -Name $ModuleName -ErrorAction Ignore
            if ($Module){$LatestVersion=(Find-Module -Name $ModuleName).Version}
            if (-not($Module) -or ($Module.Version -lt $LatestVersion)){
                Install-Module -Name $ModuleName -Force
            }
        }

        #login to Azure
        if (-not (Get-AzContext)){
            Login-AzAccount -UseDeviceAuthentication
        }

        #select context
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context=$context | Out-GridView -OutputMode Single
            $context | Set-AzContext
        }

        #grab region
        $region = (Get-AzLocation | Where-Object Providers -Contains "Microsoft.Compute" | Out-GridView -OutputMode Single -Title "Please select your Azure Region").Location

        #Create Resource Group 
        If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
            New-AzResourceGroup -Name $ResourceGroupName -Location $region
        }

           #Create managed disks with azure images
           foreach ($AzureImage in $AzureImages){
            $image=Get-AzVMImage -Location $region -PublisherName $AzureImage.PublisherName -Offer $AzureImage.Offer -SKU $AzureImage.SKU | Sort-Object Version -Descending |Select-Object -First 1
            $ImageVersionID = $image.id
            # Export the OS disk
            $imageOSDisk = @{Id = $ImageVersionID}
            $OSDiskConfig = New-AzDiskConfig -Location $region -CreateOption "FromImage" -ImageReference $imageOSDisk
            New-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $AzureImage.SKU -Disk $OSDiskConfig
        }

        #Download AZCopy
            # Download the package 
            Start-BitsTransfer -Source "https://aka.ms/downloadazcopy-v10-windows" -Destination "$env:UserProfile\Downloads\AzCopy.zip"
            Expand-Archive -Path "$env:UserProfile\Downloads\AzCopy.zip" -DestinationPath "$env:UserProfile\Downloads\AZCopy" -Force
            $item=Get-ChildItem -Name azcopy.exe -Recurse -Path "$env:UserProfile\Downloads\AZCopy" 
            Move-Item -Path "$env:UserProfile\Downloads\AZCopy\$item" -Destination "$env:UserProfile\Downloads\" -Force
            Remove-Item -Path "$env:UserProfile\Downloads\AZCopy\" -Recurse
            Remove-Item -Path "$env:UserProfile\Downloads\AzCopy.zip"

        #Create Folder on Library Share for VHDs
            Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
                New-Item -Path $using:LibraryShareLocation -ItemType Directory -Name VHDs
            }

        #Install Hyper-V PowerShell and Hyper-V feature on Library machine to be able to work with VHDs (mounting and such)
            Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart
                Install-WindowsFeature -Name Hyper-V-PowerShell
            }
            Restart-Computer -ComputerName $LibraryServerName -Protocol WSMan -Wait -For PowerShell -Force

        #Download Images
            foreach ($AzureImage in $AzureImages){
                #Grant Access https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview
                $output=Grant-AzDiskAccess -ResourceGroupName $ResourceGroupName -DiskName $AzureImage.SKU -Access 'Read' -DurationInSecond 36000 #10 hours
                #Grab shared access signature
                $SAS=$output.accesssas
                #Download
                & $env:UserProfile\Downloads\azcopy.exe copy $sas "\\$LibraryServerName\$LibraryShareName\VHDs\$($AzureImage.SKU).vhd" --check-md5 NoCheck --cap-mbps 500
                #once disk is downloaded, disk access can be revoked
                Revoke-AzDiskAccess -ResourceGroupName  $ResourceGroupName -Name $AzureImage.SKU
                #and disk itself can be removed
                Remove-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $AzureImage.SKU -Force
                #and disk itself can be converted to VHDx and compacted
                Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
                    Convert-VHD -Path "$($using:LibraryShareLocation)\VHDs\$($using:AzureImage.sku).vhd" -DestinationPath "$($using:LibraryShareLocation)\VHDs\$($using:AzureImage.sku).vhdx" -VHDType Dynamic -DeleteSource
                    Optimize-VHD -Path "$($using:LibraryShareLocation)\VHDs\$($using:AzureImage.sku).vhdx" -Mode Full
                }
                if ($AzureImage.SKU -like "*-smalldisk*"){
                    #and it can be also expanded from default 32GB (since image is small to safe some space)
                    Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
                        Resize-VHD -Path "$($using:LibraryShareLocation)\VHDs\$($using:AzureImage.sku).vhdx" -SizeBytes 127GB
                        #mount VHD
                        $VHDMount=Mount-VHD "$($using:LibraryShareLocation)\VHDs\$($using:AzureImage.sku).vhdx" -Passthru
                        $partition = $vhdmount | Get-Disk | Get-Partition | Where-Object PartitionNumber -Eq 4
                        $partition | Resize-Partition -Size ($Partition | Get-PartitionSupportedSize).SizeMax
                        $VHDMount| Dismount-VHD 
                    }
                    #and since it's no longer smalldisk, it can be renamed
                    Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
                        $NewName=($using:AzureImage.SKU).replace("-smalldisk","")
                        Rename-Item -Path "$($using:LibraryShareLocation)\VHDs\$($using:AzureImage.sku).vhdx" -NewName "$NewName.vhdx"
                    }
                }
            }
        #remove resource group
        Remove-AzResourceGroup -Name $ResourceGroupName -Force

        #Describe Images
            #refresh library share
            Get-SCLibraryShare | Where-Object LibraryServer -like $LibraryServerName* | Read-SCLibraryShare

            #add operating system version and virtualization platform to image
            foreach ($AzureImage in $AzureImages){
                $ImageName="$($AzureImage.SKU.replace('-smalldisk','')).vhdx"
                $libraryObject = Get-SCVirtualHardDisk -Name $ImageName
                $os = Get-SCOperatingSystem | Where-Object Name -eq "Windows Server 2022 Datacenter"
                Set-SCVirtualHardDisk -VirtualHardDisk $libraryObject -OperatingSystem $os -VirtualizationPlatform "HyperV" -Name $ImageName -Description "" -Release "" -FamilyName ""
            }
    #endregion
#endregion

#region add Dell EMC OpenManage Integration for SCVMM https://www.dell.com/support/kbdoc/en-us/000147399/openmanage-integration-suite-for-microsoft-system-center#OMIMSSC-Download
    #you can explore integration here https://www.dell.com/en-us/dt/product-demos/openmanage-integrations/index.htm?ref=DemoCenter

    $LibraryServerName="Library"
    $LibraryShareName="VMMLibrary"
    $LibraryShareLocation = "D:\VMMLibrary"
    $VMHostName="AzSVMM1"
    $VMLocation="C:\ClusterStorage\AzSVMM1"

    #download VHD
    Start-BitsTransfer -Source https://dl.dell.com/FOLDER07473193M/1/OMIMSSC_v7.3.0.2948_for_VMM_and_ConfigMgr_A00.vhd.zip -Destination $env:USERPROFILE\Downloads\
    #extract
    Expand-Archive -Path $env:USERPROFILE\Downloads\OMIMSSC_v7.3.0.2948_for_VMM_and_ConfigMgr_A00.vhd.zip -DestinationPath $env:USERPROFILE\Downloads\OMIMSSC

    #copy VHDx to Library server
    Copy-Item -Path "$env:USERPROFILE\Downloads\OMIMSSC\OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhd" -Destination \\$LibraryServerName\$LibraryShareName\VHDs\
    #convert VHD to VHDx
    Invoke-Command -ComputerName $LibraryServerName -ScriptBlock {
        Convert-VHD -Path "$using:LibraryShareLocation\VHDs\OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhd" -DestinationPath "$using:LibraryShareLocation\VHDs\OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhdx" -VHDType Dynamic -DeleteSource
        Optimize-VHD -Path "$using:LibraryShareLocation\VHDs\OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhdx" -Mode Full
    }
    #refresh library
    Get-SCLibraryShare | Where-Object LibraryServer -like $LibraryServerName* | Read-SCLibraryShare

    #add description to VHD
    $libraryObject = Get-SCVirtualHardDisk -Name "OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhdx"
    $os = Get-SCOperatingSystem | Where-Object { $_.Name -eq "CentOS Linux 7 (64 bit)" }
    Set-SCVirtualHardDisk -VirtualHardDisk $libraryObject -OperatingSystem $os -VirtualizationPlatform "HyperV" -Name "OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhdx" -Description "" -Release "" -FamilyName ""

    #Create a VM (more or less copied from script generated by click-next-next)
    $JobGUID=[guid]::NewGuid()
    New-SCVirtualScsiAdapter -JobGroup $JobGUID -AdapterID 7 -ShareVirtualScsiAdapter $false -ScsiControllerType DefaultTypeNoType 
    New-SCVirtualDVDDrive -JobGroup $JobGUID -Bus 1 -LUN 0 
    $VMNetwork = Get-SCVMNetwork -Name "Management"
    New-SCVirtualNetworkAdapter -JobGroup $JobGUID -MACAddressType Dynamic -Synthetic -EnableVMNetworkOptimization $false -EnableMACAddressSpoofing $false -EnableGuestIPNetworkVirtualizationUpdates $false -IPv4AddressType Dynamic -IPv6AddressType Dynamic -VMNetwork $VMNetwork 
    Set-SCVirtualCOMPort -NoAttach -GuestPort 1 -JobGroup $JobGUID
    Set-SCVirtualCOMPort -NoAttach -GuestPort 2 -JobGroup $JobGUID 
    Set-SCVirtualFloppyDrive -RunAsynchronously -NoMedia -JobGroup $JobGUID
    $CPUType = Get-SCCPUType | Where-Object {$_.Name -eq "3.60 GHz Xeon (2 MB L2 cache)"}
    New-SCHardwareProfile -CPUType $CPUType -Name "TemporaryProfile" -Description "Profile used to create a VM/Template" -CPUCount 2 -MemoryMB 2048 -DynamicMemoryEnabled $true -DynamicMemoryMinimumMB 2048 -DynamicMemoryMaximumMB 1048576 -DynamicMemoryBufferPercentage 20 -MemoryWeight 5000 -VirtualVideoAdapterEnabled $false -CPUExpectedUtilizationPercent 20 -DiskIops 0 -CPUMaximumPercent 100 -CPUReserve 0 -NumaIsolationRequired $false -NetworkUtilizationMbps 0 -CPURelativeWeight 100 -HighlyAvailable $true -HAVMPriority 2000 -DRProtectionRequired $false -CPULimitFunctionality $false -CPULimitForMigration $false -CheckpointType Production -Generation 1 -JobGroup $JobGUID
    $VirtualHardDisk = Get-SCVirtualHardDisk | where-object {$_.Location -eq "\\library.corp.contoso.com\VMMLibrary\VHDs\OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhdx"}
    New-SCVirtualDiskDrive -IDE -Bus 0 -LUN 0 -JobGroup $JobGUID -CreateDiffDisk $false -VirtualHardDisk $VirtualHardDisk -FileName "OMIMSSC_OMIMSSC_v7.3.0_for_VMM_and_ConfigMgr.vhdx" -VolumeType BootAndSystem 
    $HardwareProfile = Get-SCHardwareProfile | Where-Object {$_.Name -eq "TemporaryProfile"}
    New-SCVMTemplate -Name "TemporaryTemplate" -EnableNestedVirtualization $false -Generation 1 -HardwareProfile $HardwareProfile -JobGroup $JobGUID -NoCustomization 
    $template = Get-SCVMTemplate -All | Where-Object { $_.Name -eq "TemporaryTemplate" }
    $virtualMachineConfiguration = New-SCVMConfiguration -VMTemplate $template -Name "OMIMSSC"
    Write-Output $virtualMachineConfiguration
    $vmHost = Get-SCVMHost -ComputerName $VMHostName
    Set-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration -VMHost $vmHost
    Update-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration
    Set-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration -VMLocation $VMLocation -PinVMLocation $true
    #$AllNICConfigurations = Get-SCVirtualNetworkAdapterConfiguration -VMConfiguration $virtualMachineConfiguration
    $VHDConfiguration = Get-SCVirtualHardDiskConfiguration -VMConfiguration $virtualMachineConfiguration
    Set-SCVirtualHardDiskConfiguration -VHDConfiguration $VHDConfiguration -PinSourceLocation $false -PinDestinationLocation $false -PinFileName $false -StorageQoSPolicy $null -DeploymentOption "UseNetwork"
    Update-SCVMConfiguration -VMConfiguration $virtualMachineConfiguration
    $operatingSystem = Get-SCOperatingSystem | Where-Object { $_.Name -eq "CentOS Linux 7 (64 bit)" }
    New-SCVirtualMachine -StartVM -Name "OMIMSSC" -VMConfiguration $virtualMachineConfiguration -Description "" -BlockDynamicOptimization $false -JobGroup $JobGUID -StartAction "NeverAutoTurnOnVM" -StopAction "SaveVM" -OperatingSystem $operatingSystem #-ReturnImmediately

    #remove temporary config, template and profile
    $virtualMachineConfiguration | Remove-SCVMConfiguration
    $template | Remove-SCVMTemplate
    $HardwareProfile | Remove-SCHardwareProfile
#endregion

#region Configure OMIMSSC (MANUAL Operation)
    #1) start OMIMSSC VM and open console
    #2) login, and change password. Once done, services will be started. Notice the IP Address
    #3) navigate to https://IPAddress/ and validate if OMIMSC is running
    #4) navigate to https://IPAddress/ and go to SETTINGS -> CONSOLE ENROLLMENT and enroll SCVMM. It requires creating credentials. Create Windows Credential profile and LabAdmin and corp.contoso.com domain
    #5) download and install extension - in OMIMSSC navigate to downloads and download OMIMSSC console extension for SCVMM. Install it.
    #6) after extension is installed, import extension in SCVMM console (Settings -> Import Console Add-in) from C:\Program Files\OMIMSSC\VMM Console Extension
    #7) check if console extension registration profile contains OMIMMSC IP Address, not localhost.

        #$IPAddress="10.0.0.20"
        $mac=(hyper-v\get-vm -CimSession azsvmm1,azsvmm2 -VMName OMIMSSC | Get-VMNetworkAdapter).macaddress
        $IPAddress=(Get-DhcpServerv4Lease -ScopeID 10.0.0.0 -ClientId $mac -computername DC).IPAddress.IPAddressToString
        $profile=Get-SCApplicationProfile -Name "OMIMSSC SCVMM Console Extension Registration Profile"
        $command = Get-SCScriptCommand -ApplicationProfile $profile | Where-Object { $_.ScriptType -eq "PreInstall" -and $_.DeploymentOrder -eq "1" }
        if ($command.Parameters -eq "Localhost"){
            $scriptSetting = Get-SCScriptCommandSetting -ScriptCommand $command
            Set-SCScriptCommandSetting -ScriptCommandSetting $scriptSetting -WorkingDirectory "" -PersistStandardOutputPath "" -PersistStandardErrorPath "" -MatchStandardOutput "" -MatchStandardError ".+" -MatchExitCode "[1-9][0-9]*" -FailOnMatch -RestartOnRetry $false -MatchRebootExitCode "{1641}|{3010}|{3011}" -RestartScriptOnExitCodeReboot $false -AlwaysReboot $false
            Set-SCScriptCommand -ScriptCommand $command -ScriptCommandSetting $scriptSetting -CommandParameters $IPAddress -Executable "cmd /c echo" -ScriptType "PreInstall" -TimeoutSeconds 120 -DeploymentOrder "1"
        }

    #8) disable IE Enhanced Security Configuration for admins
    #9) navigate to All Hosts in VMs and Services and open IMIMSSC from Ribbon
#endregion