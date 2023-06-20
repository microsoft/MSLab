#source: 
#https://learn.microsoft.com/en-us/azure-stack/hci/deploy/network-atc?tabs=22H2
#https://techcommunity.microsoft.com/t5/networking-blog/network-atc-common-preview-questions/ba-p/2780086

#region variables
    $Clusters=@()
    $Clusters+=@{Nodes="2NICs1","2NICs2" ; Name="2NICsCluster" ; IP="10.0.0.111" }
    $Clusters+=@{Nodes="4NICs1","4NICs2" ; Name="4NICsCluster" ; IP="10.0.0.112" }
    $Clusters+=@{Nodes="6NICs1","6NICs2" ; Name="6NICsCluster" ; IP="10.0.0.113" }
    $Clusters+=@{Nodes="Switchless1","Switchless2","Switchless3" ; Name="SLCluster" ; IP="10.0.0.114" }
    $Clusters+=@{Nodes="Site1Node1","Site1Node2","Site2Node1","Site2Node2" ; Name="StretchCluster" ; IP="10.0.0.115" }

    $StretchClusterName="StretchCluster"
    $CredSSPUserName="corp\LabAdmin"
    $CredSSPPassword="LS1setup!"

#endregion

#region update all servers (there have been multiple fixes for NetATC. Updating servers is crucial)
    # Update servers with all updates (including preview)
        $Servers=$Clusters.Nodes
        Invoke-Command -ComputerName $servers -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore
        #sleep a bit
        Start-Sleep 2
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            if ($SearchResult.Count -gt 0){
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Downloader = $Session.CreateUpdateDownloader()
                $Downloader.Updates = $SearchResult
                $Downloader.Download()
                $Installer = New-Object -ComObject Microsoft.Update.Installer
                $Installer.Updates = $SearchResult
                $Result = $Installer.Install()
                $Result
            }
        }
        #remove temporary PSsession config
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }
#endregion

#region Install features (Same as Azure Stack HCI 22H2 Scenario)
    #install features for management (assuming you are running these commands on Windows Server with GUI)
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica

    #install roles and features on servers
    $Servers=$Clusters.Nodes
    #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
        if ($result.ExitCode -eq "failed"){
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        }
    }
    #define and install other features
    $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","NetworkATC","NetworkHUD","Data-Center-Bridging","RSAT-DataCenterBridging-LLDP-Tools","FS-SMBBW","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
    Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features}

    #restart all servers
    Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell

    #check windows version
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    $ComputersInfo  = Invoke-Command -ComputerName $servers -ScriptBlock {
        Get-ItemProperty -Path $using:RegistryPath
    }
    $ComputersInfo | Select-Object PSComputerName,ProductName,DisplayVersion,CurrentBuildNumber,UBR | Format-Table -AutoSize

#endregion

#region Explore NetATC commands
        $Servers=$Clusters.Nodes
        #make sure NetATC,FS-SMBBW and other required features are installed on servers
        #FS-SMBBW feature is used to configure SMB limits on Live Migration traffic using NetATC.  
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
        }

        #since ATC is not available on management machine, copy PowerShell module over to management machine from cluster. However global intents will not be automatically added as in C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC\NetWorkATC.psm1 is being checked if NetATC feature is installed [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled()
        $session=New-PSSession -ComputerName $Servers[0]
        $items="C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC","C:\Windows\System32\NetworkAtc.Driver.dll","C:\Windows\System32\Newtonsoft.Json.dll","C:\Windows\System32\NetworkAtcFeatureStaging.dll"
        foreach ($item in $items){
            Copy-Item -FromSession $session -Path $item -Destination $item -Recurse -Force
        }

        #Explore Commands available locally
        $Commands1=Get-Command -Module NetworkATC
        $Commands1

        #Explore commands avalable on Servers
        $Commands2=Invoke-Command -ComputerName $Servers[0] -ScriptBlock {
            Get-Command -Module NetworkATC
        }
        $Commands2

        #you will most likely see, that there are some commands present only on Servers
        Compare-Object $Commands1.Name $Commands2.Name
        <#
        InputObject                         SideIndicator
        -----------                         -------------
        New-NetIntentGlobalClusterOverrides =>
        New-NetIntentGlobalProxyOverrides   =>
        New-NetIntentSiteOverrides          =>
        New-NetIntentStorageOverrides       =>
        #>
        #The reason is, that PowerShell module is wrongly (I guess design decision) detecting, if NetATC 22H2 is running locally. 
#endregion

#region Working with Network intent with server scope
    $Servers=$Clusters.Nodes
    #region apply intent and troubleshoot
        #You can configure Network intent on one server, or on entire cluster.
        #it might be useful to configure intent first on servers before cluster is created, as flapping network will make node isolated during intent application

        #let's configure converged intent on first server (will fail - what???)
        Add-NetIntent -ComputerName $Servers[0] -Name compute_management_storage -Management -Compute -Storage -AdapterName "Ethernet","Ethernet 2"

        #anyway, let's invoke it
        Invoke-Command -ComputerName $Servers[0] -ScriptBlock {
            Add-NetIntent -Name compute_management_storage -Management -Compute -Storage -AdapterName "Ethernet","Ethernet 2"
        }

        #Converged intent will be submitted. Let's check status
        Get-NetIntentStatus -ComputerName $Servers[0]

        #we can also wait until intent is finished (will take quite some time)
        Start-Sleep 20 #let intent propagate a bit
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $Servers[0] -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #Intent will fail to apply, since we are in VMs. Let's troubleshoot
        Get-NetIntentStatus -ComputerName $Servers[0]

        #check event logs
        $events=Invoke-Command -ComputerName $Servers[0] -ScriptBlock {
            Get-WinEvent -FilterHashtable @{"ProviderName"="Microsoft-Windows-Networking-NetworkATC"}
        }
        $events | Format-Table -AutoSize

        #the problem is, that in VM you cannot configure DCB (because of hyper-v adapters), so let's create an override (Error:AdvancedPropertyNotSupported)
        #note: Name of the intent is case sensitive!!!

        #let's remove intent first (it's faster than adjusting failing intent)
        Remove-NetIntent -ComputerName $Servers[0] -Name compute_management_storage

        #and let's try to create intent again, but now with override
        Invoke-Command -ComputerName $Servers[0] -ScriptBlock {
            $AdapterOverride = New-NetIntentAdapterPropertyOverrides
            $AdapterOverride.NetworkDirect = 0
            Add-NetIntent -Name compute_management_storage -Management -Compute -Storage -AdapterName "Ethernet","Ethernet 2" -AdapterPropertyOverrides $AdapterOverride -Verbose
        }
        #wait for intent to be applied
        #wait a bit first
        Start-Sleep 20
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $Servers[0] -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #Check intent status
        Get-NetIntentStatus -ComputerName $Servers[0]
    #endregion

    #region explore what was configured
        #explore intent
        $Intent=Get-NetIntent -ComputerName $Servers[0]
        $Intent
        $Intent.AdapterAdvancedParametersOverride
        $Intent.RssConfigOverride
        $Intent.QosPolicyOverride
        $Intent.SwitchConfigOverride
        $Intent.IPOverride

        #VMSwitch (notice IOVEnabled,BandwidthReservationMode,)
        Get-VMSwitch -CimSession $Servers[0] | Select-Object *

        #validate vNICs to pNICs mapping
        Get-VMNetworkAdapterTeamMapping -CimSession $servers[0] -ManagementOS | Select-Object ComputerName,NetAdapterName,ParentAdapter
        #grab vNICs
        Get-VMNetworkAdapter -CimSession $Servers[0] -ManagementOS
        #grab IPAddresses
        Get-NetIPAddress -InterfaceAlias v* -AddressFamily IPv4 -CimSession $Servers[0]
        #validate JumboFrames setting (is default - disabled)
        Get-NetAdapterAdvancedProperty -CimSession $servers[0] -DisplayName "Jumbo Packet"
        #verify RDMA settings (disabled in VMs)
        Get-NetAdapterRdma -CimSession $servers[0] | Sort-Object -Property PSComputerName,Name
        #validate if VLANs were set
        Get-VMNetworkAdapterVlan -CimSession $Servers[0] -ManagementOS
        #VLANs in NetATC are set with VMNetworkAdapterIsolation
        Get-VMNetworkAdapterIsolation -CimSession $Servers[0] -ManagementOS
        #validate policy (no result since it's not available in VM)
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName
        #Validate QOS Policies
        Get-NetQosPolicy -CimSession $servers[0] | Sort-Object PSComputerName,Name | Select-Object PSComputerName,NetDirectPort,PriorityValue
        #validate flow control setting
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {Get-NetQosFlowControl} | Sort-Object  -Property PSComputername,Priority | Select-Object PSComputerName,Priority,Enabled
        #validate QoS Traffic Classes (2 percent for cluster since in VMs are 10Gbps NICs)
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {Get-NetQosTrafficClass} |Sort-Object PSComputerName,Name |Select-Object PSComputerName,Name,PriorityFriendly,Bandwidth
    #endregion

    #region remove netintent from first server
        Remove-NetIntent -ComputerName $Servers[0] -Name compute_management_storage
        #remove VMSwitch
        Get-VMSwitch -CimSession $Servers[0] | Remove-VMSwitch -Force
    #endregion
#endregion

#region working with network intents in clusters
    #region create clusters
        foreach ($Cluster in $Clusters){
            New-Cluster -Name $cluster.Name -Node $Cluster.Nodes -StaticAddress $cluster.IP
            Start-Sleep 5
            Clear-DNSClientCache
        }
    #endregion

    #region create fully converged cluster intent on 2NICsCluster
        $ClusterName=$Clusters[0].Name
        $Servers=$Clusters[0].Nodes
        
        #make sure NetATC,FS-SMBBW and other required features are installed on servers
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
        }

        Import-Module NetworkATC
        $AdapterNames="Ethernet","Ethernet 2"
        Add-NetIntent -ClusterName $ClusterName -Name compute_management_storage -Management -Compute -Storage -AdapterName $AdapterNames -AdapterPropertyOverrides $AdapterOverride -Verbose #-StorageVlans 1,2

        #in virtual environment it's needed to add override for RDMA config (you should skip this for physical servers)
            #virtual environment (skipping RDMA config)
            $AdapterOverride = New-NetIntentAdapterPropertyOverrides
            $AdapterOverride.NetworkDirect = 0
            Set-NetIntent -ClusterName $ClusterName -Name management -AdapterPropertyOverrides $AdapterOverride

        #Add default global intent
        #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Import-Module NetworkATC
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }

        #check
        Start-Sleep 20 #let intent propagate a bit
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #remove if necessary
            <#
            Invoke-Command -ComputerName $servers[0] -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>

            #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
                #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
    #endregion

    #region create Network Intent for cluster where are 2 NICs used for compute and management, and another 2 NICs for storage
        $ClusterName=$Clusters[1].Name
        $Servers=$Clusters[1].Nodes
        
        #make sure NetATC,FS-SMBBW and other required features are installed on servers
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
        }

        Import-Module NetworkATC
        #add compute+management intent
        $AdapterNames="Ethernet","Ethernet 2"
        Add-NetIntent -ClusterName $ClusterName -Name compute_management -Management -Compute -AdapterName $AdapterNames -Verbose

        #add storage intent
        $AdapterNames="Ethernet 3","Ethernet 4"
        Add-NetIntent -ClusterName $ClusterName -Name storage -Storage -AdapterName $AdapterNames -Verbose #-StorageVlans 1,2

        #in virtual environment it's needed to add override for RDMA config (you should skip this for physical servers)
            #virtual environment (skipping RDMA config)
            $AdapterOverride = New-NetIntentAdapterPropertyOverrides
            $AdapterOverride.NetworkDirect = 0
            Set-NetIntent -ClusterName $ClusterName -Name compute_management -AdapterPropertyOverrides $AdapterOverride
            Set-NetIntent -ClusterName $ClusterName -Name storage -AdapterPropertyOverrides $AdapterOverride

        #Add default global intent
        #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Import-Module NetworkATC
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }

        #check
        Start-Sleep 20 #let intent propagate a bit
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #remove if necessary
            <#
            Invoke-Command -ComputerName $servers[0] -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>

            #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
            #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
    #endregion

    #region create Network Intent for cluster where are 2 NICs used for Management, 2NICs for VMs, and 2NICs for Storage
        $ClusterName=$Clusters[2].Name
        $Servers=$Clusters[2].Nodes

        #make sure NetATC,FS-SMBBW and other required features are installed on servers
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
        }

        Import-Module NetworkATC
        #add Management intent
        $AdapterNames="Ethernet","Ethernet 2"
        Add-NetIntent -ClusterName $ClusterName -Name management -Management -AdapterName $AdapterNames -Verbose

        #add Compute intent
        $AdapterNames="Ethernet 3","Ethernet 4"
        Add-NetIntent -ClusterName $ClusterName -Name compute -Compute -AdapterName $AdapterNames -Verbose

        #add storage intent
        $AdapterNames="Ethernet 5","Ethernet 6"
        Add-NetIntent -ClusterName $ClusterName -Name storage -Storage -AdapterName $AdapterNames -Verbose #-StorageVlans 1,2

        #in virtual environment it's needed to add override for RDMA config (you should skip this for physical servers)
            #virtual environment (skipping RDMA config)
            $AdapterOverride = New-NetIntentAdapterPropertyOverrides
            $AdapterOverride.NetworkDirect = 0
            Set-NetIntent -ClusterName $ClusterName -Name management -AdapterPropertyOverrides $AdapterOverride
            Set-NetIntent -ClusterName $ClusterName -Name compute -AdapterPropertyOverrides $AdapterOverride
            Set-NetIntent -ClusterName $ClusterName -Name storage -AdapterPropertyOverrides $AdapterOverride

        #Add default global intent
        #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Import-Module NetworkATC
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }

        #check
        Start-Sleep 20 #let intent propagate a bit
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #remove if necessary
            <#
            Invoke-Command -ComputerName $servers[0] -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>

            #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
            #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
    #endregion

    #region create Network Intent for switchless 3 node cluster
        $ClusterName=$Clusters[3].Name
        $Servers=$Clusters[3].Nodes

        #make sure NetATC,FS-SMBBW and other required features are installed on servers
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
        }

        Import-Module NetworkATC
        #add Management intent
        $AdapterNames="Ethernet","Ethernet 2"
        Add-NetIntent -ClusterName $ClusterName -Name compute_management -Management -Compute -AdapterName $AdapterNames -Verbose

        #add storage intent (notice just one VLAN for Storage - as per https://techcommunity.microsoft.com/t5/networking-blog/network-atc-common-preview-questions/ba-p/2780086)
        $AdapterNames="Ethernet 3","Ethernet 4"
        Add-NetIntent -ClusterName $ClusterName -Name storage -Storage -AdapterName $AdapterNames -Verbose -StorageVlans 711

        #in virtual environment it's needed to add override for RDMA config (you should skip this for physical servers)
            #virtual environment (skipping RDMA config)
            $AdapterOverride = New-NetIntentAdapterPropertyOverrides
            $AdapterOverride.NetworkDirect = 0
            Set-NetIntent -ClusterName $ClusterName -Name compute_management -AdapterPropertyOverrides $AdapterOverride
            Set-NetIntent -ClusterName $ClusterName -Name storage -AdapterPropertyOverrides $AdapterOverride

        #Add default global intent
        #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Import-Module NetworkATC
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }

        #check
        Start-Sleep 20 #let intent propagate a bit
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #make sure automatic IP Generation is disabled, as in 3+ node configuration in 22h2 NetATC cannot determine individual connections
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            Import-Module networkatc
            $overrides=New-NetIntentStorageOverrides
            $overrides.EnableAutomaticIPGeneration=$false
            Set-NetIntent -Name storage -StorageOverrides $overrides
        }

        #configure static IP Addresses
        $Pairs=@()
        $Pairs+=@{Node1="Switchless1" ; Node2="Switchless2" ; Node1NICName="Ethernet 3" ; Node2NICName="Ethernet 3"; Node1NICIP="172.16.1.1"; Node2NICIP="172.16.1.2" ; PrefixLength=24}
        $Pairs+=@{Node1="Switchless1" ; Node2="Switchless3" ; Node1NICName="Ethernet 4" ; Node2NICName="Ethernet 4"; Node1NICIP="172.16.2.1"; Node2NICIP="172.16.2.2" ; PrefixLength=24}
        $Pairs+=@{Node1="Switchless2" ; Node2="Switchless3" ; Node1NICName="Ethernet 4" ; Node2NICName="Ethernet 3"; Node1NICIP="172.16.3.1"; Node2NICIP="172.16.3.2" ; PrefixLength=24}

        foreach ($pair in $pairs){
            New-NetIPAddress -CimSession $pair.Node1 -IPAddress $pair.Node1NICIP -InterfaceAlias $pair.Node1NicName -PrefixLength $pair.PrefixLength
            New-NetIPAddress -CimSession $pair.Node2 -IPAddress $pair.Node2NICIP -InterfaceAlias $pair.Node2NicName -PrefixLength $pair.PrefixLength
        }

        #remove if necessary
            <#
            Invoke-Command -ComputerName $servers[0] -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>

            #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
            #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
    #endregion

    #region (WORK IN PROGRESS!!!) create Network Intent for stretch cluster https://learn.microsoft.com/en-us/azure-stack/hci/deploy/create-cluster-powershell#step-54-set-up-stretch-clustering-with-network-atc
        #configure sites in Stretch cluster first
        New-ClusterFaultDomain -Name "SEA-Rack01" -FaultDomainType Rack -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"        -CimSession $StretchClusterName
        New-ClusterFaultDomain -Name "RED-Rack01" -FaultDomainType Rack -Location "Contoso HQ, Room 1040, Aisle A, Rack 01"        -CimSession $StretchClusterName
        New-ClusterFaultDomain -Name "SEA"        -FaultDomainType Site -Location "Contoso HQ, 123 Example St, Room 4010, Seattle" -CimSession $StretchClusterName
        New-ClusterFaultDomain -Name "RED"        -FaultDomainType Site -Location "Contoso HQ, 321 Example St, Room 1040, Redmond" -CimSession $StretchClusterName

        Set-ClusterFaultDomain -Name "Site1Node1" -Parent "SEA-Rack01" -CimSession $StretchClusterName
        Set-ClusterFaultDomain -Name "Site1Node2" -Parent "SEA-Rack01" -CimSession $StretchClusterName
        Set-ClusterFaultDomain -Name "Site2Node1" -Parent "RED-Rack01" -CimSession $StretchClusterName
        Set-ClusterFaultDomain -Name "Site2Node2" -Parent "RED-Rack01" -CimSession $StretchClusterName

        Set-ClusterFaultDomain -Name "SEA-Rack01" -Parent "SEA"    -CimSession $StretchClusterName
        Set-ClusterFaultDomain -Name "RED-Rack01" -Parent "RED"    -CimSession $StretchClusterName

        #validate
        Get-ClusterFaultDomainXML -CimSession $StretchClusterName

        $Servers=(Get-ClusterNode -Cluster $StretchClusterName).Name
        $ClusterName=$StretchClusterName

        #make sure NetATC,FS-SMBBW and other required features are installed on servers
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,FS-SMBBW
        }

        Import-Module NetworkATC
        #add stretch intent
        $AdapterNames="Ethernet","Ethernet 2"
        #it needs to be invoked with CredSSP as it contains check for netatc enabled - obviously not available in management machine that is WS2022

            #Enable CredSSP
            # Temporarily enable CredSSP delegation to avoid double-hop issue
            foreach ($Server in $servers){
                Enable-WSManCredSSP -Role "Client" -DelegateComputer $Server -Force
            }
            Invoke-Command -ComputerName $servers -ScriptBlock { Enable-WSManCredSSP Server -Force }
            $password = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
            $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $password)

            Invoke-Command -ComputerName $servers -Credential $Credentials -Authentication Credssp -ScriptBlock {
                Add-NetIntent -Name compute_management_storage_stretch -Compute -Management -Storage -Stretch -AdapterName $using:AdapterNames -Verbose
            }

        # Disable CredSSP
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $servers -ScriptBlock { Disable-WSManCredSSP Server }

        #in virtual environment it's needed to add override for RDMA config (you should skip this for physical servers)
            #virtual environment (skipping RDMA config)
            $AdapterOverride = New-NetIntentAdapterPropertyOverrides
            $AdapterOverride.NetworkDirect = 0
            Set-NetIntent -ClusterName $ClusterName -Name compute_management_storage_stretch -AdapterPropertyOverrides $AdapterOverride

        #Add default global intent
        #since when configuring from Management machine there is a test [FabricManager.FeatureStaging]::Feature_NetworkATC_IsEnabled() to make global intents available, it will not be configured, so it has to be configured manually with invoke command
        Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Import-Module NetworkATC
            $overrides=New-NetIntentGlobalClusterOverrides
            #add empty intent
            Add-NetIntent -GlobalClusterOverrides $overrides
        }

        #check
        Start-Sleep 20 #let intent propagate a bit
        Write-Output "applying intent"
        do {
            $status=Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-NetIntentStatus}
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")

        #remove if necessary
            <#
            Invoke-Command -ComputerName $servers[0] -ScriptBlock {
                $intents = Get-NetIntent
                foreach ($intent in $intents){
                    Remove-NetIntent -Name $intent.IntentName
                }
            }
            #>

            #if deploying in VMs, some nodes might fail (quarantined state) and even CNO can go to offline ... go to cluadmin and fix
            #Get-ClusterNode -Cluster $ClusterName | Where-Object State -eq down | Start-ClusterNode -ClearQuarantine
    #endregion

#endregion

#region install network HUD (NetATC)
    $Servers=$Clusters.Nodes
    #make sure NetworkHUD features are installed and network HUD is started on servers
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-WindowsFeature -Name "NetworkHUD","Hyper-V","Hyper-V-PowerShell","Data-Center-Bridging", "RSAT-DataCenterBridging-LLDP-Tools","NetworkATC","Failover-Clustering"
        #make sure service is started and running (it is)
        #Set-Service -Name NetworkHUD -StartupType Automatic 
        #Start-Service -Name NetworkHUD
    }
    #install Network HUD modules (Test-NetStack and az.stackhci.networkhud) on nodes
        $Modules="Test-NetStack","az.stackhci.networkhud"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        foreach ($Module in $Modules){
            #download module to management node
            Save-Module -Name $Module -Path $env:Userprofile\downloads\
            #copy it to servers
            foreach ($Server in $Servers){
                Copy-Item -Path "$env:Userprofile\downloads\$module" -Destination "\\$Server\C$\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
            }
        }
    #restart NetworkHUD service to activate
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Restart-Service NetworkHUD
    }
    #wait a bit
    Start-Sleep 10

    #check event logs (no successfull events found as there is some error in PCIE.ps1)
    $events=Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-WinEvent -FilterHashtable @{"ProviderName"="Microsoft-Windows-Networking-NetworkHUD";Id=105}
    }
    $events | Format-Table -AutoSize
#endregion




