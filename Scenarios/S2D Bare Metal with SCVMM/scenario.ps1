####################################
# Run from DC or mangement machine #
####################################

#region check prerequisites
    #test if VMM console is installed
    if (!(get-module -ListAvailable | Where-Object Name -eq virtualmachinemanager)){
        #ask for VMM setup.exe
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select setup.exe from Virtual Machine Manager to install VMM console" 
        }
        $openFile.Filter = "exe files (*.exe)|*.exe" 
        If($openFile.ShowDialog() -eq "OK"){
            Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
        }
        if (!$openFile.FileName){
            Write-Host "No exe was selected... Press enter to exit" -ForegroundColor Red
            $exit=Read-Host
            exit
        }
        $SetupExePath = $openFile.FileName
        $SetupExeName = $openfile.SafeFileName
        $SetupRoot=$SetupExePath.Substring(0,$SetupExePath.Length-$setupexename.Length)

        #Create Answer file
        New-Item "$SetupRoot\VMConsole.ini" -type File -Force
        "[OPTIONS]" >> "$SetupRoot\VMConsole.ini"
        "VmmServerName=DC" >> "$SetupRoot\VMConsole.ini"
        "IndigoTcpPort=8100" >> "$SetupRoot\VMConsole.ini"
        "MUOptIn = 1"  >> "$SetupRoot\VMConsole.ini"

        Write-Host "VMM console is being installed..." -ForegroundColor Cyan
        & $SetupExePath /client /i /f "$SetupRoot\VMConsole.ini" /IACCEPTSCEULA
        do{
            Start-Sleep 2
        }until ((Get-Process | Where-Object {$_.Description -eq "Virtual Machine Manager Setup"} -ErrorAction SilentlyContinue) -eq $null)
        Write-Host "VMM Console is Installed" -ForegroundColor Green
        Remove-Item "$SetupRoot\VMConsole.ini" -ErrorAction Ignore
        Write-Host "Please hit enter to exit. Please run the script again in new window to load PowerShell module"
        $exit=Read-Host
        exit
    }else{
        Write-Host "SCVMM Console is installed"
    }
    
    #install features for management (Client needs RSAT, Server/Server Core have different features)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica
    }elseif ($WindowsInstallationType -eq "Client"){
        #Validate RSAT Installed
            if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                Write-Host "Please install RSAT, Exitting in 5s"
                Start-Sleep 5
                Exit
            }
        #Install Hyper-V Management features
            if ((Get-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -ne "Enabled"){
                #Install all features and then remove all except Management (fails when installing just management)
                Enable-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-All -NoRestart
                Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart
                $Q=Read-Host -Prompt "Restart is needed. Do you want to restart now? Y/N"
                If ($Q -eq "Y"){
                    Write-Host "Restarting Computer"
                    Start-Sleep 3
                    Restart-Computer
                }else{
                    Write-Host "You did not type Y, please restart Computer. Exitting"
                    Start-Sleep 3
                    Exit
                }
            }elseif((get-command -Module Hyper-V) -eq $null){
                $Q=Read-Host -Prompt "Restart is needed to load Hyper-V Management. Do you want to restart now? Y/N"
                If ($Q -eq "Y"){
                    Write-Host "Restarting Computer"
                    Start-Sleep 3
                    Restart-Computer
                }else{
                    Write-Host "You did not type Y, please restart Computer. Exitting"
                    Start-Sleep 3
                    Exit
                }
            }
    }

#endregion

#region Variables

    $VMMServerName="DC"
    $WDSServerName="WDS" #can be also DC if you paste all scripts into DC
    $HostGroupName="SeattleDC"
    $PhysicalComputerProfileName="HVHost"

    $domain="corp.contoso.com"

    $vSwitchName="SETSwitch"

    #DHCP and reservations configuration
        $DHCPServer="DC"
        $ScopeID="10.0.0.0"
        $IpaddressScope="10.0.0."
        $IPAddressStart=101 #starting this number IPs will be asigned

    #Servers Name Prefix 
        $ServersNamePrefix="S2D" #Names will be S2D1, S2D2,...

    #Cluster
        $ClusterName="S2D-Cluster"
        $ClusterIP="10.0.0.111"
        $ManagementNetwork="10.0.0.0"
        $StorageNetwork="172.16.1.0"

    #Credentials
        #Note: All account share the same credentials in this case. In real world deployments you want to use different accounts.
        Function ValidateCred ($cred) {
            $username = $cred.username
            $password = $cred.GetNetworkCredential().password
            # Get current domain using logged-on user's credentials
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$UserName,$Password)
            if ($domain.name -eq $null){
                return $false 
            }else{
                return $true
            }
        }
        
        #grab and validate Run As Account
        $RunAsAccountName="VMM RAA"
        do{
            $RunAsAccountCred=Get-Credential -Message "Please provide Run as Admin Cred"
        }until (ValidateCred $RunAsAccountCred)

        #grab and validate Run Djoin Account
        $DomainJoinAccountName="VMM Djoin"
        <#
        do{
            $DomainJoinAccountCred=Get-Credential -Message "Please provide Domain Join Cred"
        }until (ValidateCred $DomainJoinAccountCred)
        #>
        $DomainJoinAccountCred=$RunAsAccountCred

        #$LocalAdminCredentials=Get-Credential -Message "Please provide Local Admin Cred for physical computer profile"
        $LocalAdminCredentials=$RunAsAccountCred

    #Networking
        $SRIOV=$false
        $DCB=$False
        $iWARP=$False

    #vSwitch vNICs classifications
        $Classifications=@()
        $Classifications+=@{PortClassificationName="Host Management static"    ; NativePortProfileName="Host management static" ; Description=""                                  ; EnableIov=$false ; EnableVrss=$false ;EnableIPsecOffload=$true  ;EnableVmq=$true  ;EnableRdma=$false}
        $Classifications+=@{PortClassificationName="vRDMA"                     ; NativePortProfileName="vRDMA"                  ; Description="Classification for vRDMA adapters" ; EnableIov=$false ; EnableVrss=$false ;EnableIPsecOffload=$false ;EnableVmq=$false ;EnableRdma=$true}
        $Classifications+=@{PortClassificationName="vNIC VMQ"                  ; NativePortProfileName="vNIC VMQ"               ; Description=""                                  ; EnableIov=$false ; EnableVrss=$false ;EnableIPsecOffload=$true  ;EnableVmq=$true  ;EnableRdma=$false}
        $Classifications+=@{PortClassificationName="vNIC vRSS"                 ; NativePortProfileName="vNIC vRSS"              ; Description=""                                  ; EnableIov=$false ; EnableVrss=$true  ;EnableIPsecOffload=$true  ;EnableVmq=$true  ;EnableRdma=$false}
        if ($SRIOV) {
            $Classifications+=@{PortClassificationName="SR-IOV"   ; NativePortProfileName="SR-IOV Profile"                      ; Description=""                                  ; EnableIov=$true  ; EnableVrss=$false ;EnableIPsecOffload=$false ;EnableVmq=$false ;EnableRdma=$false}
        }

    #logical networks definition
        $Networks=@()
        $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupName=$HostGroupName ; Name="Management"  ; Description="Management VLAN" ; Subnet="10.0.0.0/24"      ; VLAN=0 ; IPAddressRangeStart="10.0.0.1"   ;IPAddressRangeEnd="10.0.0.254"           ;DNSServers="10.0.0.1"  ;Gateways="10.0.0.1"}
        $Networks+=@{LogicalNetworkName="DatacenterNetwork" ; HostGroupName=$HostGroupName ; Name="Storage"     ; Description="SMB"             ; Subnet="172.16.1.0/24"    ; VLAN=3 ; IPAddressRangeStart="172.16.1.1" ;IPAddressRangeEnd="172.16.1.254"         ;DNSServers=""       ;Gateways=""}
        #some fake networks just for demonstration
        $Networks+=@{LogicalNetworkName="VMs Network"       ; HostGroupName=$HostGroupName ; Name="Production"  ; Description="Production VLAN" ; Subnet="192.168.1.0/24"   ; VLAN=1 ; IPAddressRangeStart="192.168.1.1"   ;IPAddressRangeEnd="192.168.1.254"     ;DNSServers=("10.0.0.11","10.0.0.10")  ;Gateways="192.168.1.1"}
        $Networks+=@{LogicalNetworkName="VMs Network"       ; HostGroupName=$HostGroupName ; Name="DMZ"         ; Description="DMZ VLAN"        ; Subnet="192.168.2.0/24"   ; VLAN=2 ; IPAddressRangeStart="192.168.2.1"   ;IPAddressRangeEnd="192.168.2.254"     ;DNSServers=("10.0.0.11","10.0.0.10")  ;Gateways="192.168.2.1"}

        $vNICDefinitions=@()
        $vNICDefinitions+=@{NetAdapterName="SMB_1"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="Storage"    ; VMSubnetName="Storage"        ;PortClassificationName="vRDMA"                  ;IPAddressPoolName="Storage IP Pool"}
        $vNICDefinitions+=@{NetAdapterName="SMB_2"      ; Management=$false ; InheritSettings=$false ; IPv4AddressType="Static" ; VMNetworkName="Storage"    ; VMSubnetName="Storage"        ;PortClassificationName="vRDMA"                  ;IPAddressPoolName="Storage IP Pool"}
        $vNICDefinitions+=@{NetAdapterName="Management" ; Management=$true  ; InheritSettings=$true  ; IPv4AddressType="Dynamic"; VMNetworkName="Management" ; VMSubnetName="Management"     ;PortClassificationName="Host management static" ;IPAddressPoolName="Management IP Pool"}

    #ask for parent vhdx for Hyper-V Hosts and VMs
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select parent VHDx for Hyper-V Hosts and VMs." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
        }
        $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
        If($openFile.ShowDialog() -eq "OK"){
            Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
        } 
        if (!$openFile.FileName){
            Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
        }
        $VHDPath = $openFile.FileName
        $VHDName = $openfile.SafeFileName
#endregion

#region basic SCVMM Configuration
    #Start services if not started
    if ((Get-Service -ComputerName $VMMServerName -Name MSSQLSERVER).status -ne "Running"){
        Invoke-Command -ComputerName $VMMServerName -ScriptBlock {Start-service -Name MSSQLSERVER}
    }

    if ((Get-Service -ComputerName $VMMServerName -Name SCVMMService).status -ne "Running"){
        Invoke-Command -ComputerName $VMMServerName -ScriptBlock {Start-service -Name SCVMMService}
    }

    
    #Connect to VMM Server
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
    Import-Module VirtualMachineManager
    Get-VMMServer $VMMServerName

    #Create Host Group
        New-SCVMHostGroup -Name $HostGroupName

    #Disable automatic logical network creation
        Set-SCVMMServer -AutomaticLogicalNetworkCreationEnabled $false -LogicalNetworkMatch "FirstDNSSuffixLabel" -BackupLogicalNetworkMatch "VirtualNetworkSwitchName"

    #Create Run As Account 
        $runAsAccount = New-SCRunAsAccount -Credential $RunAsAccountCred -Name $RunAsAccountName -Description ""
        Write-Output $runAsAccount


    #Create Djoin Account
        
        $runAsAccount = New-SCRunAsAccount -Credential $DomainJoinAccountCred -Name $DomainJoinAccountName -Description "" 
        Write-Output $runAsAccount
#endregion

#region Configure networks
    foreach ($NetworkName in ($Networks.LogicalNetworkName | Select-Object -Unique)){
        
        ## Create Logical Networks
            $logicalNetwork = New-SCLogicalNetwork -Name $NetworkName -LogicalNetworkDefinitionIsolation $true -EnableNetworkVirtualization $false -UseGRE $false -IsPVLAN $false
            $allHostGroups = @()
            $allSubnetVlan = @()
        
            #add Subnets
            foreach ($network in ($networks | Where-Object -Property LogicalNetworkName -EQ $NetworkName)){
                $allSubnetVlan +=New-SCSubnetVLan -Subnet $network.Subnet -VLanID $network.VLAN
            }

            #add HostGroups
            $HostGroupNames=@()
            foreach ($network in ($networks | Where-Object -Property LogicalNetworkName -EQ $NetworkName)){
                $HostGroupNames+=$network.HostGroupName
            }

            $allHostGroups += Get-SCVMHostGroup -Name ($HostGroupNames | Select-Object -Unique)
            $logicalNetworkDefinition=New-SCLogicalNetworkDefinition -Name "$NetworkName" -LogicalNetwork $logicalNetwork -VMHostGroup $allHostGroups -SubnetVLan $allSubnetVlan -RunAsynchronously

        ##Create IP Pools
            foreach ($network in ($networks | Where-Object -Property LogicalNetworkName -EQ $NetworkName)){
                if ($network.IPAddressRangeStart){
                    $allNetworkRoutes = @()
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
                    New-SCStaticIPAddressPool -Name "$($network.Name) IP Pool" -LogicalNetworkDefinition $logicalNetworkDefinition -Subnet $Network.Subnet -IPAddressRangeStart $network.IPAddressRangeStart -IPAddressRangeEnd $network.IPAddressRangeEnd -DNSServer $allDnsServer -DNSSuffix "" -DNSSearchSuffix $allDnsSuffixes -NetworkRoute $allNetworkRoutes -DefaultGateway $allGateways -RunAsynchronously
                }
            }


        #Create Virtual Networks
            foreach ($network in ($networks | Where-Object -Property LogicalNetworkName -EQ $NetworkName)){
                $vmNetwork = New-SCVMNetwork -Name $network.Name -Description $network.Description -LogicalNetwork $logicalNetwork -IsolationType "VLANNetwork"
                Write-Output $vmNetwork
                $subnetVLANs = New-SCSubnetVLan -Subnet $network.Subnet -VLanID $network.VLAN
                $vmSubnet = New-SCVMSubnet -Name $network.Name -LogicalNetworkDefinition $logicalNetworkDefinition -SubnetVLan $subnetVLANs -VMNetwork $vmNetwork
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

#region Cofigure virtual Switch
    #create uplink pp. Use all Logical networks
        $definition = @()
        $definition += Get-SCLogicalNetworkDefinition
        New-SCNativeUplinkPortProfile -Name "UplinkPP" -Description "" -LogicalNetworkDefinition $definition -EnableNetworkVirtualization $false -LBFOLoadBalancingAlgorithm "HyperVPort" -LBFOTeamMode "SwitchIndependent" -RunAsynchronously

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
            $virtualSwitchExtensions += Get-SCVirtualSwitchExtension -Name "Microsoft Windows Filtering Platform"
            $logicalSwitch = New-SCLogicalSwitch -Name $vSwitchName -Description "" -EnableSriov $false -SwitchUplinkMode "EmbeddedTeam" -MinimumBandwidthMode "None" -VirtualSwitchExtensions $virtualSwitchExtensions
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
        $nativeUppVar = Get-SCNativeUplinkPortProfile -Name "UplinkPP"
        $uppSetVar = New-SCUplinkPortProfileSet -Name "UplinkPP" -LogicalSwitch $logicalSwitch -NativeUplinkPortProfile $nativeUppVar -RunAsynchronously

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

#region Configure Physical Computer Profile
    #Add drivers (real environment only)
        <#
        Can be done by copying inf into some folder. Like Proliant DL380G9 and then mathcing it like this
        get-scdriverpackage | where sharepath -like *DL380G9* |  set-scdriverpackage -tag "HP Proliant DL380G9"          
        #>

    #Copy Host VHD to library
        Copy-Item -Path $VHDPath -Destination "$((Get-SCLibraryShare).Path)\VHDs"
    #Refresh Library
        Get-SCLibraryShare | Read-SCLibraryShare
    #Set that VHD as Server 2016 Datacenter
        $libraryobject=Get-SCVirtualHardDisk -Name $VHDName
        $os=Get-SCOperatingSystem | Where-Object Name -eq "Windows Server 2016 Datacenter"
        Set-SCVirtualHardDisk -VirtualHardDisk $libraryObject -OperatingSystem $os -VirtualizationPlatform "HyperV" -Name $VHDName -Description "" -Release "" -FamilyName ""
    #Configure Profile (In real environment you would also configure PNP matching for drivers)
        $VHD = Get-SCVirtualHardDisk -Name $VHDName
        # Get RunAs Account for Domain Join (Best practice is use some account that has only rights to write to one OU)
        $DomainJoinRunAsAccount = Get-SCRunAsAccount | Where-Object Name -eq $DomainJoinAccountName
        # Get RunAs Account for Computer Access (Best practice is use some account that has privileges to Hyper-V hosts, but not Domain Admin as we are showing here)
        $ComputerAccessRunAsAccount = Get-SCRunAsAccount | Where-Object Name -eq $RunAsAccountName
    
        $NicProfilesArray = @()
        $NicProfile1 = New-SCPhysicalComputerNetworkAdapterProfile -SetAsManagementNIC -SetAsPhysicalNetworkAdapter -UseDhcpForIPConfiguration
        $NicProfilesArray += $NicProfile1
        #$Tags = @("HP Proliant")
        New-SCPhysicalComputerProfile -Name $PhysicalComputerProfileName -Description "" -DiskConfiguration "GPT=1:PRIMARY:QUICK:4:FALSE:OS::0:BOOTPARTITION;" -Domain $domain -TimeZone 4 -RunAsynchronously -FullName "" -OrganizationName "" -ProductKey "" -IsGuarded $false -VMPaths "" -UseAsVMHost -VirtualHardDisk $VHD -BypassVHDConversion $true -DomainJoinRunAsAccount $DomainJoinRunAsAccount -ComputerAccessRunAsAccount $ComputerAccessRunAsAccount -LocalAdministratorCredential $LocalAdminCredentials -PhysicalComputerNetworkAdapterProfile $NicProfilesArray #-DriverMatchingTag $Tags

#endregion

#region Configure WDS
    # Configure WDS
    Install-WindowsFeature WDS -IncludeManagementTools -IncludeAllSubFeature -ComputerName $WDSServerName
    if ($env:COMPUTERNAME -eq "DC"){
        Invoke-Command -ComputerName $WDSServerName -ScriptBlock {
            wdsutil /initialize-server /reminst:"C:\RemoteInstall"
            wdsutil /start-server
        }
    }else{ #need to do credssp delegation to be able to send creds to server. Make sure the remote server is not DC.
        winrm quickconfig -force #on client is winrm not configured
        Enable-WSManCredSSP -DelegateComputer "$WDSServerName"  -Role Client -Force
        Invoke-Command -ComputerName $WDSServerName -ScriptBlock {Enable-WSManCredSSP Server -Force}
        Invoke-Command -ComputerName $WDSServerName -Credential $RunAsAccountCred -Authentication Credssp -ScriptBlock {
            wdsutil /initialize-server /reminst:"C:\RemoteInstall"
            wdsutil /start-server
        }
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $WDSServerName -ScriptBlock {Disable-WSManCredSSP Server}
    }

    #Add WDS to SCVMM
        $credential = Get-SCRunAsAccount -Name $RunAsAccountName
        Add-SCPXEServer -ComputerName $WDSServerName -Credential $credential 
    #not needed
        #Publish-SCWindowsPE -UseDefaultImage
#endregion

#########################
# Run from Hyper-V Host #
#########################

#region Run from Hyper-V Host to create new VMs
    #some variables
    $LabPrefix="ws2016labSCVMM-"
    $vSwitchName="$($LabPrefix)LabSwitch"
    $VMsPath="E:\ws2016lab_14393.2007_SCVMM\LAB\VMs"
    $VMNames="S2D1","S2D2","S2D3","S2D4"
    $NumberOfHDDs=12
    $SizeOfHDD=4TB
    $MemoryStartupBytes=2GB
    #create some blank VMs
    foreach ($VMName in $VMNames){
            $VMName="$LabPrefix$VMName"
            New-VM -Name $VMName -NewVHDPath "$VMsPath\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 128GB -SwitchName $vSwitchName -Generation 2 -Path "$VMsPath" -MemoryStartupBytes $MemoryStartupBytes
            1..$NumberOfHDDs | ForEach-Object {
                $VHD=New-VHD -Path "$VMsPath\$VMName\Virtual Hard Disks\HDD$_.vhdx" -SizeBytes $SizeOfHDD
                Add-VMHardDiskDrive -VMName $VMName -Path "$VMsPath\$VMName\Virtual Hard Disks\HDD$_.vhdx"
            }
            #Add Adapter
            Add-VMNetworkAdapter -VMName $VMName -SwitchName $vSwitchName
            #configure Nested Virt and 2 cores
            Set-VMProcessor -ExposeVirtualizationExtensions $true -VMName $VMName -Count 2
            #configure Memory
            Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false
            #configure network adapters
            Set-VMNetworkAdapter -VMName $VMName -AllowTeaming On -MacAddressSpoofing On
            Set-VMNetworkAdapterVlan -VMName $VMName -Trunk -NativeVlanId 0 -AllowedVlanIdList "1-10"
            #disable automatic checkpoints
            if ((get-vm -VMName $VMName).AutomaticCheckpointsEnabled -eq $True){
                Set-VM -Name $VMName -AutomaticCheckpointsEnabled $False
            }
            #Start VM
            Start-VM -Name $VMName
    }

#endregion

###################################
# Continue on DC or Management VM #
###################################

#region deploy hosts
    <#Example of manual host definition if you do real deployments

        $HVHosts=@()
        $HVHosts+=@{ComputerName="xxx01HV1"  ;IPAddress="10.0.0.31" ; MACAddress="AA:BB:CC:8F:BD:E8" ; BMCAddress="10.0.1.31" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C428"}
        $HVHosts+=@{ComputerName="xxx02HV1"  ;IPAddress="10.0.0.32" ; MACAddress="AA:BB:CC:8F:BC:E8" ; BMCAddress="10.0.1.32" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C433"}
        $HVHosts+=@{ComputerName="xxx03HV1"  ;IPAddress="10.0.0.33" ; MACAddress="AA:BB:CC:8F:BE:20" ; BMCAddress="10.0.1.33" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C43E"}
        $HVHosts+=@{ComputerName="xxx04HV1"  ;IPAddress="10.0.0.34" ; MACAddress="AA:BB:CC:8F:BB:48" ; BMCAddress="10.0.1.34" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C442"}
        $HVHosts+=@{ComputerName="xxx05HV1"  ;IPAddress="10.0.0.35" ; MACAddress="AA:BB:CC:8F:BC:F8" ; BMCAddress="10.0.1.35" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C443"}
        $HVHosts+=@{ComputerName="xxx09HV1"  ;IPAddress="10.0.0.39" ; MACAddress="AA:BB:CC:8F:BD:F8" ; BMCAddress="10.0.1.39" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C447"}
        $HVHosts+=@{ComputerName="xxx10HV1"  ;IPAddress="10.0.0.40" ; MACAddress="AA:BB:CC:7E:8E:78" ; BMCAddress="10.0.1.40" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C429"}
        $HVHosts+=@{ComputerName="xxx11HV1"  ;IPAddress="10.0.0.41" ; MACAddress="AA:BB:CC:8F:BD:90" ; BMCAddress="10.0.1.41" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C42A"}
        $HVHosts+=@{ComputerName="xxx12HV1"  ;IPAddress="10.0.0.42" ; MACAddress="AA:BB:CC:8F:BD:E0" ; BMCAddress="10.0.1.42" ; SMBiosGuid="20170518-0000-0000-0001-1ABB4983C42B"}
    #>

    #Grab Machine GUIDs from Event log, sort oldest->newest, select unique and add it to hash table with server names. Grab only unique GUIDs
    #If you do this in real environment, think twice. You grab all servers that attemted PXE boot (!!!you can wipe production with this!!!)

        <#sample HVHosts output
        PS C:\Users\Administrator> $HVHosts

        Name                           Value
        ----                           -----
        SMBiosGuid                     27ED1EF6-8ACD-49E7-9AFB-26CF7E639AA1
        ComputerName                   S2D1
        IPAddress                      10.0.0.100
        MACAddress                     00:15:5D:89:E9:6F
        SMBiosGuid                     DE3F75DF-0DCC-4BA1-89FF-AE692734A277
        ComputerName                   S2D2
        IPAddress                      10.0.0.101
        MACAddress                     00:15:5D:89:E9:71
        SMBiosGuid                     6E8B1544-844B-4D8A-BDF2-217033230069
        ComputerName                   S2D3
        IPAddress                      10.0.0.102
        MACAddress                     00:15:5D:89:E9:73
        SMBiosGuid                     8618D3F3-09E6-4E9A-878F-7A4D3A032BA5
        ComputerName                   S2D4
        IPAddress                      10.0.0.103
        MACAddress                     00:15:5D:89:E9:75
        #>
        $messages=Invoke-Command -ComputerName $VMMServerName -ScriptBlock {(Get-WinEvent -LogName Microsoft-VirtualMachineManager-Server/Admin | Where-Object message -Like "*will not deploy*" | Sort-Object timecreated).message | Select-Object -Unique}
        $HVHosts = @()
        $GUIDS=@()
        $i=1
        foreach ($message in $Messages){
            if (!($guids).Contains($message.Substring(76,37))){
                $HVHosts+= @{ ComputerName="$ServersNamePrefix$i";SMBiosGuid = $message.Substring(76,37) ; MACAddress = $message.Substring(118,17);IPAddress="$IpaddressScope$($IPAddressStart.tostring())"}
                $i++
                $IPAddressStart++
                $GUIDS+=$message.Substring(76,37)
            }
        }

    #Create DHCP reservations for Hyper-V hosts
        #install RSAT for DHCP
        if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType) -ne "Client"){
            Install-WindowsFeature -Name RSAT-DHCP 
        }

        #Add DHCP Reservations
        foreach ($HVHost in $HVHosts){
            if (!(Get-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $DHCPServer -ScopeId $ScopeID -ClientId ($HVHost.MACAddress).Replace(":","") | Where-Object IPAddress -eq $HVHost.IPAddress)){
                Add-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $ScopeID -IPAddress $HVHost.IPAddress -ClientId ($HVHost.MACAddress).Replace(":","")
            }
        }

    #configure NTP server in DHCP (might be useful if Servers have issues with time)
        if (!(get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -ErrorAction SilentlyContinue)){
            Set-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -Value "10.0.0.1"
        }

    #deploy hosts
    $PhysicalComputerProfile=Get-SCPhysicalComputerProfile -Name $PhysicalComputerProfileName
    $HostGroup=Get-SCVMHostGroup -Name $HostGroupName
    foreach ($HVHost in $HVHosts){
        $NetworkAdapters = @()
        $NetworkAdapters += New-SCPhysicalComputerNetworkAdapterConfig -UseDhcpForIPConfiguration -SetAsManagementNIC -SetAsPhysicalNetworkAdapter -MACAddress $HVHost.MACAddress
        <#Example of real deployment
        $PhysicalComputerConfig = New-SCPhysicalComputerConfig -BypassADMachineAccountCheck -BMCAddress $HVHost.BMCAddress -BMCPort 623 -BMCProtocol "IPMI" -BMCRunAsAccount $RunAsAccount -ComputerName $HVHost.ComputerName -Description "" -SMBiosGuid $HVHost.SMBiosGuid -PhysicalComputerProfile $PhysicalComputerProfile -VMHostGroup $HostGroup -BootDiskVolume "\\.\PHYSICALDRIVE0" -PhysicalComputerNetworkAdapterConfig $NetworkAdapters
        #>
        #Deployment in virtual environment
        $PhysicalComputerConfig = New-SCPhysicalComputerConfig  -SkipBmcPowerControl -BypassADMachineAccountCheck -ComputerName $HVHost.ComputerName -Description "" -SMBiosGuid $HVHost.SMBiosGuid -PhysicalComputerProfile $PhysicalComputerProfile -VMHostGroup $HostGroup -BootDiskVolume "\\.\PHYSICALDRIVE0" -PhysicalComputerNetworkAdapterConfig $NetworkAdapters
        New-SCVMHost -VMHostConfig $PhysicalComputerConfig -RunAsynchronously
    }

    #verify status of deployment jobs.
        $jobs=Get-SCJob | Where-Object Name -like "Create a new host from physical machine*" | Sort-Object Name

        foreach ($Job in $jobs){
            If ($job.status -eq "Running"){
                Write-Output "Waiting for $($job.Name.Substring(41,($job.Name.Length-41))) to Finish"
                do {
                    [System.Console]::Write("Progress {0}`r", $job.Progress)
                    Start-Sleep 1
                } until (($job.status -eq "Completed") -or ($job.status -eq "Failed"))
            }
            if ($job.status -eq "Completed"){
                    Write-Output "Deployment of Host $($job.Name.Substring(41,($job.Name.Length-41))) Finished"
                }
            if ($job.status -eq "failed"){
                    Write-Output "Deployment of Host $($job.Name.Substring(41,($job.Name.Length-41))) Failed"
                }
        }

#endregion

#########################
# Action on Hyper-V Host#
#########################
#Restart (turn off and start) the S2D machines on Host manualy to initiate deployment (othervise deployment progress will stick at 29% and fails)
#This step mimics BMC, that will send reboot to hosts.

###################################
# Continue on DC or Management VM #
###################################

#region Apply vSwitch
    #refresh hosts
        Get-SCVMHost | Read-SCVMHost

    #apply vSwitch Note: this takes forever, so be patient
    foreach ($HVHost in $HVHosts){
        $vmHost = Get-SCVMHost | Where-Object computername -eq $HVHost.ComputerName
        #Make management adapter only the one defined in $HVHosts
        $ManagementAdapter=(Get-SCVMHostNetworkAdapter -VMHost $VMHost.Name) | Where-Object {$_.IPAddresses.IPAddressToString -eq $HVHost.IPAddress}
        $VMHost | Get-SCVMHostNetworkAdapter | Where-Object Name -ne $ManagementAdapter.Name | Set-SCVMHostNetworkAdapter -UsedForManagement $false
        $networkAdapter = @()
        # Set uplink port profile to all adapters
        $vmhost | Get-SCVMHostNetworkAdapter | ForEach-Object {
            Set-SCVMHostNetworkAdapter -VMHostNetworkAdapter $_ -UplinkPortProfileSet (Get-SCUplinkPortProfileSet -Name "UplinkPP")
            $networkAdapter += $_
        }
        $logicalSwitch = Get-SCLogicalSwitch -Name $vSwitchName
        New-SCVirtualNetwork -VMHost $vmHost -VMHostNetworkAdapters $networkAdapter -LogicalSwitch $logicalSwitch -DeployVirtualNetworkAdapters
        Set-SCVMHost -VMHost $vmHost -RunAsynchronously
    }

    $servers=$HVHosts.ComputerName

    #Verify that the VlanID is set
        Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | Format-Table ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName
    #verify RDMA
        Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | Format-Table systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
    #verify ip config 
        Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | Format-Table pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername

#endregion


#region set static IP Does not work ?? BUG ??   
    <#    foreach ($HVHost in $HVHosts){
            $vmHost = Get-SCVMHost | where computername -eq $HVHost.ComputerName
            $vNic = $VMHost | Get-SCVirtualNetworkAdapter | where IsUsedForHostManagement -eq $True
            $vmNetwork = Get-SCVMNetwork -Name $vNIC.VMNetwork
            $vmSubnet = Get-SCVMSubnet -Name $vNIC.VMSubnet
            $vNICPortClassification = Get-SCPortClassification -Name $vNIC.PortClassification
            $vNicLogicalSwitch = Get-SCLogicalSwitch -Name $vNic.LogicalSwitch
            $ipV4Pool =  Get-SCStaticIPAddressPool | where Subnet -eq $Vnic.IPv4Subnets
            $ipv4List=$vnic.IPv4Addresses
            Set-SCVirtualNetworkAdapter -VirtualNetworkAdapter $vNic -VMNetwork $vmNetwork -VMSubnet $vmSubnet -PortClassification $vNICPortClassification -IPv4AddressType "Static" -IPv4AddressPools $ipV4Pool -IPv4Addresses $ipv4List -IPv6AddressType "Dynamic"
            Set-SCVMHost -VMHost $vmHost -RunAsynchronously
        }
    #>
#endregion

#region Configure Networking (classic approach)
    #set static IP address (need to test more, not sure if this is OK)    
            Foreach ($Server in $servers){
                Invoke-Command -ComputerName $server -ArgumentList $vSwitchName -ScriptBlock {
                    param ($vSwitchname);
                    $IPConf=Get-NetIPConfiguration | Where-Object InterfaceAlias -like "*$vSwitchName*"
                    $IPAddress=Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like "*$vSwitchName*"
                    $IP=$IPAddress.IPAddress
                    $Index=$IPAddress.InterfaceIndex
                    $GW=$IPConf.IPv4DefaultGateway.NextHop
                    $Prefix=$IPAddress.PrefixLength
                    $DNSServers=@()
                    $ipconf.dnsserver | ForEach-Object {if ($_.addressfamily -eq 2){$DNSServers+=$_.ServerAddresses}}
                    Set-NetIPInterface -InterfaceIndex $Index -Dhcp Disabled
                    New-NetIPAddress -InterfaceIndex $Index -AddressFamily IPv4 -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $GW -ErrorAction SilentlyContinue
                    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $DNSServers
                }
            }
    #Refresh VM Hosts
        Get-SCVMHost | Read-SCVMHost

    #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each vRDMA NIC is mapped to separate pRDMA NIC)
        #install features
            foreach ($server in $servers) {Install-WindowsFeature -Name "Hyper-V-PowerShell" -ComputerName $server} 

        #Associate vNICs
        Invoke-Command -ComputerName $servers -ArgumentList $vSwitchName -ScriptBlock {
            param($vSwitchName);
            $physicaladapters=(get-vmswitch $vSwitchName).NetAdapterInterfaceDescriptions | Sort-Object
            1..$physicaladapters.Count | ForEach-Object {
                Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_$_" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters | Select-Object -Index ($_-1)).name
            }
        }


        #verify mapping
            Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | Format-Table ComputerName,NetAdapterName,ParentAdapter 
        

    if ($DCB -eq $True){

        #install features
        foreach ($server in $servers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 

        ##Configure QoS
            New-NetQosPolicy "SMB" -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers

        #Turn on Flow Control for SMB
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

        #Disable flow control for other traffic
            Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

        #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

        #validate flow control setting
            Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | Format-Table PSComputerName,Priority,Enabled -GroupBy PSComputerNa

        #Validate DCBX setting
            Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName

        #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

        #validate policy
            Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName

        #Create a Traffic class and give SMB Direct 30% of the bandwidth minimum.  The name of the class will be "SMB"
            Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB" -Priority 3 -BandwidthPercentage 30 -Algorithm ETS}
    }

    #enable iWARP firewall rule
    if ($iWARP -eq $True){
        Enable-NetFirewallRule -Name "FPSSMBD-iWARP-In-TCP" -CimSession $servers
    }

#endregion 

#region Configure Cluster and S2D (classic approach)
    <#Create Cluster with SCVMM - Validate cluster takes forever... skipping
        #get hosts
            $VMHosts = @()
            foreach ($server in $servers){
                $VMHosts += Get-SCVMHost | where computername -eq $server
            }
        #Grab run as account
            $credential = Get-SCRunAsAccount -Name $RunAsAccountName
        #create cluster
            Install-SCVMHostCluster -ClusterName $ClusterName -EnableS2D -Credential $credential -VMHost $VMHosts -ClusterIPAddress $ClusterIP -SkipValidation
    #>

    #Classic approach to enable cluster and S2D
        #install features
            foreach ($server in $servers) {Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering","RSAT-Clustering-PowerShell" -ComputerName $server} 
        #create cluster
            Test-Cluster -Node $servers -Include "Storage Spaces Direct",Inventory,Network,"System Configuration"
            New-Cluster -Name $ClusterName -node $servers -StaticAddress $ClusterIP
            Start-Sleep 5
            Clear-DnsClientCache

        #Enable-ClusterS2D with invoke command, as RSAT1709 is not compatible with 1607, so it might fail without invoke-command
            Invoke-Command -ComputerName $clustername -ScriptBlock {Enable-ClusterS2D -confirm:0 -Verbose}

    #rename networks
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorageNetwork).Name="SMB"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ManagementNetwork).Name="Management"

    #Configure LM to use RDMA
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -ne "SMB"}).ID))
        #Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers
        foreach ($Server in $servers){
        Get-VMHost -ComputerName $Server | Set-VMHost -MigrationPerformanceOption UseSmbTransport
        }

    #set CSV Cache
        #(Get-Cluster $ClusterName).BlockCacheSize = 10240 

    #configure witness
        #Create new directory
        $WitnessName=$Clustername+"Witness"
        Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);new-item -Path c:\Shares -Name $WitnessName -ItemType Directory} -ArgumentList $WitnessName
        $accounts=@()
        $accounts+="corp\$ClusterName$"
        $accounts+="corp\Domain Admins"
        New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        # Set NTFS permissions 
        Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);(Get-SmbShare "$WitnessName").PresetPathAcl | Set-Acl} -ArgumentList $WitnessName
        #Set Quorum
        Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

#endregion


#region Create some Volumes (classic approach)
    #Create volumes
        1..(get-clusternode -Cluster $clustername).count | ForEach-Object {
            New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName MirrorDisk$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes 2TB -CimSession $ClusterName   
            New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName MirrorAcceleratedParity$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance,capacity -StorageTierSizes 2TB,8TB -CimSession $ClusterName
        }
    #Fix volume names
        Get-ClusterSharedVolume -Cluster $ClusterName | ForEach-Object {
            $volumepath=$_.sharedvolumeinfo.friendlyvolumename
            $newname=$_.name.Substring(22,$_.name.Length-23)
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
        } 

#endregion

#region Create some dummy VMs (3 per each CSV disk)
    Start-Sleep -Seconds 60 #just to a bit wait as I saw sometimes that first VMs fails to create
    $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
    foreach ($CSV in $CSVs){
            $CSV=$CSV.Substring(22)
            $CSV=$CSV.TrimEnd(")")
            1..3 | ForEach-Object {
                $VMName="TestVM$($CSV)_$_"
                Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random) -ArgumentList $CSV,$VMName -ScriptBlock {
                    param($CSV,$VMName);
                    New-VM -Name $VMName -NewVHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 32GB -SwitchName SETSwitch -Generation 2 -Path "c:\ClusterStorage\$CSV\"
                }
                Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
            }
        }
#endregion

#region add storage provider to VMM
    $ClassS2D=New-SCStorageClassification -Name "S2D" -Description "" -RunAsynchronously
    $ClassMirror=New-SCStorageClassification -Name "Mirror" -Description "" -RunAsynchronously
    $ClassMAP=New-SCStorageClassification -Name "MirrorAcceleratedParity" -Description "" -RunAsynchronously
    $runAsAccount = Get-SCRunAsAccount -Name $RunAsAccountName
    Add-SCStorageProvider -ComputerName $ClusterName -AddWindowsNativeWmiProvider -Name $Clustername -RunAsAccount $runAsAccount -RunAsynchronously
    $provider = Get-SCStorageProvider -Name "s2d-cluster" 
    Set-SCStorageProvider -StorageProvider $provider -RunAsynchronously
    $pool = Get-SCStoragePool -Name "S2D on $Clustername"
    $ClassS2D = Get-SCStorageClassification -Name "S2D"
    $Pool | Set-SCStoragePool -StorageClassification $ClassS2D
    Get-SCStorageDisk | Where-Object StorageLogicalUnit -like MirrorDisk* | Set-SCStorageDisk -StorageClassification $ClassMirror
    Get-SCStorageDisk | Where-Object StorageLogicalUnit -like MirrorAcceleratedParity* | Set-SCStorageDisk -StorageClassification $ClassMAP
    #refresh provider
    Read-SCStorageProvider $provider

#endregion