#region single-node cluster
    #region setup single-node cluster
        #assuming one NIC is connected to physical switch (more or less because of demonstration adding another NIC to embedded team when adding second cluster node)

        #Config
        $Server="Exp1"
        $ClusterName="Exp-Cluster"
        $vSwitchName="vSwitch"

        # Install features for management on server
        Install-WindowsFeature -Name RSAT-DHCP,RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

        # Install features on server
        Invoke-Command -computername $Server -ScriptBlock {
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell"
        }

        # restart server
        Restart-Computer -ComputerName $server -Protocol WSMan -Wait -For PowerShell
        #failsafe - sometimes it evaluates, that servers completed restart after first restart (hyper-v needs 2)
        Start-sleep 20
        #make sure computers are restarted
            #Foreach ($Server in $Servers){
                do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
            #}
        # create vSwitch from first connected NIC
        $NetAdapterName=(Get-NetAdapter -Cimsession $Server | Where-Object HardwareInterface -eq $True | Where-Object Status -eq UP | Sort-Object InterfaceAlias | Select-Object -First 1).InterfaceAlias
        New-VMSwitch -Cimsession $Server -Name $vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName $NetAdapterName -EnableIov $true

        #rename vNIC
        Rename-VMNetworkAdapter -Cimsession $Server -ManagementOS -Name $vSwitchName -NewName Management

        #create cluster with Distributed Network Name (to not consume extra IP, because why not)
        New-Cluster -Name $ClusterName -Node $Server -ManagementPointNetworkType "Distributed"
        Start-Sleep 5
        Clear-DNSClientCache

        #Rename Cluster Management Network
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Role -eq "ClusterAndClient").Name="Management"

        #Enable-ClusterS2D
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

        #region register Azure Stack HCI
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
            Login-AzAccount -UseDeviceAuthentication
        
            #select context if more available
            $context=Get-AzContext -ListAvailable
            if (($context).count -gt 1){
                $context | Out-GridView -OutputMode Single | Set-AzContext
            }
        
            #select subscription if more available
            $subscriptions=Get-AzSubscription
            if (($subscriptions).count -gt 1){
                $SubscriptionID=($subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription).Subscription.Id
            }else{
                $SubscriptionID=$subscriptions.id
            }
            if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
                Install-Module -Name Az.Resources -Force
            }
            #choose location for cluster (and RG)
            $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata").Location

            #Register AZSHCi without prompting for creds again
            $armTokenItemResource = "https://management.core.windows.net/"
            $graphTokenItemResource = "https://graph.windows.net/"
            $azContext = Get-AzContext
            $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
            $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
            $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
            $id = $azContext.Account.Id
            Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName  $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -ResourceName $ClusterName
        #endregion
    #endregion

    #region explore pool settings
        #Config
        $ClusterName="Exp-Cluster"

        #notice that there is FaultDomainAwarenessDefault "PhysicalDisk". With mode nodes it is "StorageScaleUnit" (like a server with it's enclosures). Default resiliency setting is mirror
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | Select-Object ResiliencySettingNameDefault,FaultDomainAwarenessDefault
        #you can notice that mirror resiliency setting is configured to create 2 copies (2-way mirror)
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | get-resiliencysetting
    #endregion

    #region create volume and a VM
        #config
        $ClusterName="Exp-Cluster"
        $VolumeFriendlyName="OneNodeMirror"
        $VMName="TestVM"

        #ask for VHD (you can hit cancel to create dummy VM)
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
            }
            $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
            If($openFile.ShowDialog() -eq "OK"){
                Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
            } 
            if (!$openFile.FileName){
                Write-Host "No VHD was selected... Dummy VM will be created" -ForegroundColor Red
            }
            $VHDPath = $openFile.FileName

        #create Cluster Shared Volume (thin provisioned)
        New-Volume -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $VolumeFriendlyName -Size 1TB -ProvisioningType Thin

        #Create VM
            if ($VHDPath){
                New-Item -Path "\\$ClusterName\ClusterStorage$\$VolumeFriendlyName\$VMName\Virtual Hard Disks" -ItemType Directory
                Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$VolumeFriendlyName\$VMName\Virtual Hard Disks\$VMName.vhdx" 
                $VM=New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\$VolumeFriendlyName\" -VHDPath "c:\ClusterStorage\$VolumeFriendlyName\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random)

            }else{
                Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random) -ScriptBlock {
                    #create some fake VMs
                    $VM=New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\$($using:VolumeFriendlyName)\$($using:VMName)\Virtual Hard Disks\$($using:VMName).vhdx" -NewVHDSizeBytes 32GB -SwitchName $using:vSwitchName -Generation 2 -Path "c:\ClusterStorage\$($using:VolumeFriendlyName)\" -MemoryStartupBytes 32MB
                }
            }
            #make it HA
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
            #start VM
            $VM | Start-VM
    #endregion
#endregion

#region expand cluster (1node->2node)
    #region install roles and features on second node
        #Config
        $SecondNodeName="Exp2"
        # Install features on server
        Invoke-Command -computername $SecondNodeName -ScriptBlock {
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell"
        }

        # restart server
        Restart-Computer -ComputerName $SecondNodeName -Protocol WSMan -Wait -For PowerShell
        #failsafe - sometimes it evaluates, that servers completed restart after first restart (hyper-v needs 2)
        Start-sleep 20
        #make sure computers are restarted
            #Foreach ($Server in $Servers){
                do{$Test= Test-NetConnection -ComputerName $SecondNodeName -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
            #}
    #endregion

    #region configure networking (assuming scalable, converged networking).
    #Direct connectivity would be bit different, but since we will add 3rd node and simulating direct connectivity in MSLab would add another layer of complexity, I decided to demonstrate converged
        #Config
        $FirstNodeName="Exp1"
        $SecondNodeName="Exp2"
        $ClusterName="Exp-Cluster"
        $vSwitchName="vSwitch"
        $IP=1 #start IP
        $StorNet1="172.16.1."
        $StorNet2="172.16.2."
        $StorVLAN1=1
        $StorVLAN2=2

        #add second NIC to vSwitch on First Node (assuming there was only one connected before)
            #grab second adapter (select all hardware interfaces that are up and skip fist as it's in vSwitch already)
            $NetAdapterName=(Get-NetAdapter -CimSession $FirstNodeName | Where-Object HardwareInterface -eq $True | Where-Object Status -eq UP | Sort-Object InterfaceAlias | Select-Object -Skip 1).InterfaceAlias
            Add-VMSwitchTeamMember -CimSession $FirstNodeName -VMSwitchName $vSwitchName -NetAdapterName $NetAdapterName 

        #create vSwitch on second node
            #create vSwitch
            $NetAdapterNames=(Get-NetAdapter -CimSession $SecondNodeName | Where-Object HardwareInterface -eq $True | Where-Object Status -eq UP | Sort-Object InterfaceAlias).InterfaceAlias
            New-VMSwitch -Cimsession $SecondNodeName -Name $vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName $NetAdapterNames -EnableIov $true
            #rename vNIC
            Rename-VMNetworkAdapter -Cimsession $SecondNodeName -ManagementOS -Name $vSwitchName -NewName Management

        #add SMB vNICs and configure IP
            foreach ($Server in ($FirstNodeName,$SecondNodeName)){
                #grab number of physical nics connected to vswitch
                $SMBvNICsCount=(Get-VMSwitch -CimSession $Server -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count

                #create SMB vNICs
                foreach ($number in (1..$SMBvNICsCount)){
                    $TwoDigitNumber="{0:D2}" -f $Number
                    Add-VMNetworkAdapter -ManagementOS -Name "SMB$TwoDigitNumber" -SwitchName $vSwitchName -CimSession $Server
                }

                #assign IP Adresses
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

        #configure VLANs
            #configure Odds and Evens for VLAN1 and VLAN2
            foreach ($Server in ($FirstNodeName,$SecondNodeName)){
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
            #restart adapters so VLAN is active
            Get-NetAdapter -CimSession ($FirstNodeName,$SecondNodeName) -Name "vEthernet (SMB*)" | Restart-NetAdapter

        #configure RDMA and DCB
            $Servers=$FirstNodeName,$SecondNodeName
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

            #Install DCB
                foreach ($server in $servers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 

            #Configure QoS
                New-NetQosPolicy "SMB"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers
                New-NetQosPolicy "ClusterHB" -Cluster                         -PriorityValue8021Action 7 -CimSession $servers
                New-NetQosPolicy "Default"   -Default                         -PriorityValue8021Action 0 -CimSession $servers

            #Turn on Flow Control for SMB
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

            #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
                Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

            #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

            #Configure IeeePriorityTag
                #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}

            #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

            #Create a Traffic class and give SMB Direct 50% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB"       -Priority 3 -BandwidthPercentage 50 -Algorithm ETS}
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "ClusterHB" -Priority 7 -BandwidthPercentage 1 -Algorithm ETS}

        #rename smb cluster networks
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB01"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB02"

    #endregion

    #region add witness
        #Config
        $ClusterName="Exp-Cluster"
        $WitnessType="FileShare" #or Cloud
            #config for cloud witness
            $ResourceGroupName="MSLabCloudWitness"
            $StorageAccountName="mslabcloudwitness$(Get-Random -Minimum 100000 -Maximum 999999)"
            #config for fileshare witness
            $FileServerName="DC"
            $DomainName=$env:UserDomain

        #region add file share witness
            if ($WitnessType -eq "FileShare"){
                #Create new directory
                    $WitnessName=$Clustername+"Witness"
                    Invoke-Command -ComputerName $FileServerName -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
                    $accounts=@()
                    $accounts+="$DomainName\$ClusterName$"
                    New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession $FileServerName
                #Set NTFS permissions 
                    Invoke-Command -ComputerName $FileServerName -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
                #Set Quorum
                    Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\$FileServerName\$WitnessName"
            }
        #endregion

        #region or add cloud witness
            if ($WitnessType -eq "Cloud"){
                #download Azure modules
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
                Install-Module -Name Az.Accounts -Force
                Install-Module -Name Az.Resources -Force
                Install-Module -Name Az.Storage -Force

                #login to Azure
                if (-not (Get-AzContext)){
                    Connect-AzAccount -UseDeviceAuthentication
                }
                #select context if more available
                $context=Get-AzContext -ListAvailable
                if (($context).count -gt 1){
                    $context | Out-GridView -OutputMode Single | Set-AzContext
                }
                #Create resource group
                $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.Storage" | Out-GridView -OutputMode Single
                #create resource group first
                if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
                    New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
                }
                #create Storage Account
                If (-not(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction Ignore)){
                    New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -SkuName Standard_LRS -Location $location.location -Kind StorageV2 -AccessTier Cool 
                }
                $StorageAccountAccessKey=(Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroupName | Select-Object -First 1).Value
                Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $StorageAccountName -AccessKey $StorageAccountAccessKey -Endpoint "core.windows.net"
            }
        #endregion

    #endregion

    #region add cluster member
        #Config
        $ClusterName="Exp-Cluster"
        $SecondNodeName="Exp2"
        #add node
        Add-ClusterNode -Name $SecondNodeName -Cluster $ClusterName
    #endregion

    #region configure pool fault domain to be Storage Scale Unit and create new volume
        #config
        $ClusterName="Exp-Cluster"
        $VolumeFriendlyName="TwoNodesMirror"

        #configure storage pool
        Set-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" -FaultDomainAwarenessDefault StorageScaleUnit

        #create new volume
        New-Volume -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $VolumeFriendlyName -Size 1TB -ProvisioningType Thin

        #validate volume fault domain awareness
        Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName,FaultDomainAwareness
    #endregion

    #region recreate cluster performance history volume
        #config
        $ClusterName="Exp-Cluster"

        #delete performance history including volume (without invoking it returned error "get-srpartnership : The WS-Management service cannot process the request. The CIM namespace")
        Invoke-Command -ComputerName $CLusterName -ScriptBlock {Stop-ClusterPerformanceHistory -DeleteHistory}
        #recreate performance history
        Start-ClusterPerformanceHistory -cimsession $ClusterName

        #validate volume fault domain awareness again (takes some time to recreate volume)
        Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName,FaultDomainAwareness

    #endregion

    #region move VM(s) to new volume
        #config
        $ClusterName="Exp-Cluster"
        $VolumeFriendlyName="TwoNodesMirror"
        $DestinationStoragePath="c:\ClusterStorage\$VolumeFriendlyName"

        $VMs=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name
        foreach ($VM in $VMs){
            $VM | Move-VMStorage -DestinationStoragePath "$DestinationStoragePath\$($VM.Name)"
        }
    #endregion
#endregion

#region expand cluster (2node->3node, or more)
    #region install roles and features on third node
        #Config
        $Servers="Exp3"
        # Install features on server(s)
        Invoke-Command -computername $Servers -ScriptBlock {
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell"
        }

        # restart server(s)
        Restart-Computer -ComputerName $Servers -Protocol WSMan -Wait -For PowerShell
        #failsafe - sometimes it evaluates, that servers completed restart after first restart (hyper-v needs 2)
        Start-sleep 20
        #make sure computers are restarted
            Foreach ($Server in $Servers){
                do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
            }
    #endregion

    #region configure networking (assuming scalable, converged networking).
    #Direct connectivity would be bit different, but since we will add 3rd node and simulating direct connectivity in MSLab would add another layer of complexity, I decided to demonstrate converged
        #Config
        $Servers="Exp3"
        $ClusterName="Exp-Cluster"
        $vSwitchName="vSwitch"
        $IP=3 #start IP
        $StorNet1="172.16.1."
        $StorNet2="172.16.2."
        $StorVLAN1=1
        $StorVLAN2=2

        #create vSwitch on third node
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            #create vSwitch
            $NetAdapterNames=(Get-NetAdapter | Where-Object HardwareInterface -eq $True | Where-Object Status -eq UP | Sort-Object InterfaceAlias).InterfaceAlias
            New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName $NetAdapterNames -EnableIov $true
            #rename vNIC
            Rename-VMNetworkAdapter -ManagementOS -Name $using:vSwitchName -NewName Management
        }

        #add SMB vNICs and configure IP
        Foreach ($Server in $Servers){
            #grab number of physical nics connected to vswitch
            $SMBvNICsCount=(Get-VMSwitch -CimSession $Server -Name $vSwitchName).NetAdapterInterfaceDescriptions.Count

            #create SMB vNICs
            foreach ($number in (1..$SMBvNICsCount)){
                $TwoDigitNumber="{0:D2}" -f $Number
                Add-VMNetworkAdapter -ManagementOS -Name "SMB$TwoDigitNumber" -SwitchName $vSwitchName -CimSession $Server
            }

            #assign IP Adresses
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

        #configure VLANs
            #configure Odds and Evens for VLAN1 and VLAN2
            Invoke-Command -ComputerName $Servers -ScriptBlock {
                $NetAdapters=Get-VMNetworkAdapter -ManagementOS -Name *SMB* | Sort-Object Name
                $i=1
                foreach ($NetAdapter in $NetAdapters){
                    if (($i % 2) -eq 1){
                        Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name -VlanId $using:StorVLAN1 -Access -ManagementOS
                        $i++
                    }else{
                        Set-VMNetworkAdapterVlan -VMNetworkAdapterName $NetAdapter.Name -VlanId $using:StorVLAN2 -Access -ManagementOS
                        $i++
                    }
                }
            }
            #restart adapters so VLAN is active
            Get-NetAdapter -CimSession $Servers -Name "vEthernet (SMB*)" | Restart-NetAdapter

        #configure RDMA and DCB
            #Enable RDMA on the host vNIC adapters
                Enable-NetAdapterRDMA -Name "vEthernet (SMB*)" -CimSession $Servers

            #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
                Invoke-Command -ComputerName $Servers -ScriptBlock {
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

            #Install DCB
                Invoke-Command -ComputerName $Servers -ScriptBlock {
                    Install-WindowsFeature -Name "Data-Center-Bridging"
                }

            #Configure QoS
                New-NetQosPolicy "SMB"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers
                New-NetQosPolicy "ClusterHB" -Cluster                         -PriorityValue8021Action 7 -CimSession $servers
                New-NetQosPolicy "Default"   -Default                         -PriorityValue8021Action 0 -CimSession $servers

            #Turn on Flow Control for SMB
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

            #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
                Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

            #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

            #Configure IeeePriorityTag
                #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}

            #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

            #Create a Traffic class and give SMB Direct 50% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB"       -Priority 3 -BandwidthPercentage 50 -Algorithm ETS}
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "ClusterHB" -Priority 7 -BandwidthPercentage 1 -Algorithm ETS}

    #endregion

    #region add cluster member(s)
        #Config
        $ClusterName="Exp-Cluster"
        $ClusterNodeNames="Exp3"
        #add node
        Add-ClusterNode -Name $ClusterNodeNames -Cluster $ClusterName
    #endregion

    #region configure ResiliencySettingNameDefault to have 3 data copies and create 3 way mirror volume
        #config
        $ClusterName="Exp-Cluster"
        $VolumeFriendlyName="Three+NodesMirror"

        #check configuration of mirror resiliency setting (notice 2 data copies)
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | get-resiliencysetting

        #configure Mirror ResiliencySetting
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | get-resiliencysetting -Name Mirror | Set-ResiliencySetting -NumberOfDataCopiesDefault 3
        
        #once configured, you will see that NumberOfDatacopies will be 3 with FaultDomainRedundancy2 (2 faults possible)
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | get-resiliencysetting -Name Mirror

        #create new volume
        New-Volume -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $VolumeFriendlyName -Size 1TB -ProvisioningType Thin

        #validate volume resiliency
        Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName,NumberOfDataCopies
    #endregion

    #region recreate cluster performance history volume
        #config
        $ClusterName="Exp-Cluster"

        #delete performance history including volume (without invoking it returned error "get-srpartnership : The WS-Management service cannot process the request. The CIM namespace")
        Invoke-Command -ComputerName $CLusterName -ScriptBlock {Stop-ClusterPerformanceHistory -DeleteHistory}
        #recreate performance history
        Start-ClusterPerformanceHistory -cimsession $ClusterName

        #validate volume resiliency again (takes some time to recreate volume)
        Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName,NumberOfDataCopies
    #endregion

    #region move VM(s) to new volume
        #config
        $ClusterName="Exp-Cluster"
        $VolumeFriendlyName="Three+NodesMirror"
        $DestinationStoragePath="c:\ClusterStorage\$VolumeFriendlyName"

        $VMs=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name
        foreach ($VM in $VMs){
            $VM | Move-VMStorage -DestinationStoragePath "$DestinationStoragePath\$($VM.Name)"
        }
    #endregion
#endregion