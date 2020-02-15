################################
# Run from DC or Management VM #
################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region LAB Config

    # 2-16 nodes
        $S2DNodesCount=4
        $S2DNames="Storage"
    # 1-64 nodes
        $ComputeNodesCount=4
        $ComputeNames="Compute"

    #generate servernames (based number of nodes and serversnameprefix)
        $S2DNodes=@()
        $ComputeNodes=@()
        1..$S2DNodesCount | ForEach-Object {$S2DNodes+=@("$($S2DNames)$_")}
        1..$ComputeNodesCount | ForEach-Object {$ComputeNodes+=@("$($ComputeNames)$_")}
        $AllServers=$ComputeNodes+$S2DNodes

    #Cluster Names
        $S2DClusterName="Storage-Clus"
        $ComputeClusterName="Compute-Clus"

    #Cluster-Aware Updating role Names
        $S2DClusterCAUName="Storage-CAU"
        $ComputeClusterCAUName="Compute-CAU"

    #Number of MirrorAccelerated Parity Volumes Created
        $MAPCount=0
        $MAPVolumeName="MirrorAcceleratedParity"

    #generateMAP Volume names (Same as $MAPVolumeNames="MirrorAcceleratedParity1","MirrorAcceleratedParity2",....)
        $MAPVolumeNames=@()
        If($MAPCount -ge 1){
            1..$MAPCount | ForEach-Object {$MAPVolumeNames+=@("$MAPVolumeName$_")}
        }

        #Number of Mirror Volumes Created
        $MVCount=$S2DNodesCount
        $MirrorVolumeName="Mirror"

    #generateMirror Volume names 
        $MirrorVolumeNames=@()
        If($MVCount -ge 1){
            1..$MVCount | ForEach-Object {$MirrorVolumeNames+=@("$MirrorVolumeName$_")}
        }

    #SOFS Name
        $SOFSHAName="S2D-SOFS"

    #Cluster IPs
        $StorageClusterIP="10.0.0.112" #If blank (you can write just $ClusterIP="", DHCP will be used)
        $ComputeClusterIP="10.0.0.113" #If blank (you can write just $ClusterIP="", DHCP will be used)

    #Storage networks
        $NumberOfStorageNets=1 #1 or 2

        #IF Stornet is 1
        $StorNet="172.16.1."
        $StorVLAN=1

        #IF Stornets are 2
        $StorNet1="172.16.1."
        $StorNet2="172.16.2."
        $StorVLAN1=1
        $StorVLAN2=2

    #start IP
        $IP=11

    #Real hardware?
        $RealHW=$False #will configure VMQ not to use CPU 0 if $True
        $DellHW=$False #include Dell recommendations

    #PFC?
        $DCB=$False #$true for ROCE, $false for iWARP

    #iWARP?
        $iWARP=$False

    #SR-IOV?
        $SRIOV=$False

    #Nano server? its just faster with Nano. Nano will be soon out of support
        $NanoServer=$False

    #SMB Bandwith Limits for Live Migration? https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
        $SMBBandwidthLimits=$true

    #Jumbo Frames? Might be necessary to increase for iWARP. If not default, make sure all switches are configured end-to-end and (for example 9216). Also if non-default is set, you might run into various issues such as https://blog.workinghardinit.work/2019/09/05/fixing-slow-roce-rdma-performance-with-winof-2-to-winof/.
    #if 1514 is set, setting JumboFrames is skipped. All NICs are configured (vNICs + pNICs)
    $JumboSize=1514 #9014, 4088 or 1514 (default)

    #Additional Features in S2D Cluster
        $Bitlocker=$false #Install "Bitlocker" and "RSAT-Feature-Tools-BitLocker" on nodes?
        $StorageReplica=$false #Install "Storage-Replica" and "RSAT-Storage-Replica" on nodes?
        $Deduplication=$false #install "FS-Data-Deduplication" on nodes?

    #Enable Meltdown mitigation? https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
    #CVE-2017-5754 cannot be used to attack across a hardware virtualized boundary. It can only be used to read memory in kernel mode from user mode. It is not a strict requirement to set this registry value on the host if no untrusted code is running and no untrusted users are able to logon to the host.
        $MeltdownMitigationEnable=$false

    #Enable speculative store bypass mitigation? https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in , https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180012
        $SpeculativeStoreBypassMitigation=$false

    #Configure PCID to expose to VMS prior version 8.0 https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
        $ConfigurePCIDMinVersion=$true

    #Configure Core scheduler on Windows Server 2016? https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types#configuring-the-hypervisor-scheduler-type-on-windows-server-2016-hyper-v
        $CoreScheduler=$True

    #Memory dump type (Active or Kernel) https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
        $MemoryDump="Active"

    #S2D Node Name To Scale
        $S2DNodesToScale="Storage5"

    #Compute Node Name to Scale
        $ComputeNodesToScale="Compute5"

    #Mirror Volume to Scale
        $NewMirrorVolumeName="Mirror5"

#endregion

#region install features for management (Client needs RSAT, Server/Server Core have different features)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    $CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
        #Validate RSAT Installed
            if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                Write-Host "Please install RSAT, Exitting in 5s"
                Start-Sleep 5
                Exit
            }
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
        #Install RSAT tools
            $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            foreach ($Capability in $Capabilities){
                Add-WindowsCapability -Name $Capability -Online
            }
    }
    if ($WindowsInstallationType -eq "Client"){
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

#region Configure basic settings on servers
    #Tune HW timeout to 10 minutes (6minutes is default) for Dell servers
        if ($DellHW){
            Invoke-Command -ComputerName $S2DNodes -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
        }

    #configure memory dump
        if ($MemoryDump -eq "Kernel"){
            #Configure Kernel memory dump
            Invoke-Command -ComputerName $AllServers -ScriptBlock {
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 2
            }
        }
        if ($MemoryDump -eq "Active"){
            #Configure Active memory dump
            Invoke-Command -ComputerName $AllServers -ScriptBlock {
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
            }
        }

    #enable meltdown mitigation
        if ($MeltdownMitigationEnable){
            Invoke-Command -ComputerName $AllServers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #enable Speculative Store Bypass mitigation
        if ($SpeculativeStoreBypassMitigation){
            Invoke-Command -ComputerName $AllServers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #Configure MinVmVersionForCpuBasedMitigations
        if ($ConfigurePCIDMinVersion){
            Invoke-Command -ComputerName $AllServers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -value "1.0"
            }
        }

    #Enable core scheduler
    if ($CoreScheduler){
        $RevisionNumber=Invoke-Command -ComputerName $ComputeNodes[0] -ScriptBlock {
            Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name UBR
        }
        $CurrentBuildNumber=Invoke-Command -ComputerName $ComputeNodes[0] -ScriptBlock {
            Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
        }
        if ($CurrentBuildNumber -eq 14393 -and $RevisionNumber -ge 2395){
            Invoke-Command -ComputerName $ComputeNodes {
                bcdedit /set hypervisorschedulertype Core
            }
        }
    }

    #install roles and features
        if (!$NanoServer){
            #install Hyper-V using DISM (if nested virtualization is not enabled install-windowsfeature would fail)
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
            
            #define features for S2D Cluster
                $features="Failover-Clustering","Hyper-V-PowerShell"
                if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
                if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
                if ($Deduplication){$features+="FS-Data-Deduplication"}
            
            #install features on S2D Cluster
                foreach ($S2DNode in $S2DNodes) {Install-WindowsFeature -Name $features -ComputerName $S2DNode}

            #install features on Compute Cluster
                foreach ($ComputeNode in $ComputeNodes) {Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell" -ComputerName $ComputeNode}

            #restart and wait for computers
                Restart-Computer $AllServers -Protocol WSMan -Wait -For PowerShell
                Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

        }

#endregion

#region Configure Networking

    if ($SRIOV){
        Invoke-Command -ComputerName $AllServers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    }else{
        Invoke-Command -ComputerName $AllServers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    }

    #Configure Hyper-V Port Load Balancing algorithm (in 1709 its already Hyper-V, therefore setting only for Windows Server 2016)
        Invoke-Command -ComputerName $AllServers -scriptblock {
            if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
                Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
            }
        }


    $AllServers | ForEach-Object {
        #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName SETSwitch -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName SETSwitch -Cimsession $_

        #configure IP Addresses
            If ($NumberOfStorageNets -eq 1){
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                $IP++
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }

            If($NumberOfStorageNets -eq 2){
                New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }
    }

    Start-Sleep 5
    #its good to clean DNSClientCache (same as ipconfig /flushdns) as management IP might change (there were 2 IPs for each server, now is only 1)
    Clear-DnsClientCache

    #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans
        If ($NumberOfStorageNets -eq 1){
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN -Access -ManagementOS -CimSession $AllServers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN -Access -ManagementOS -CimSession $AllServers
        }else{
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $AllServers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $AllServers
        }
    #Restart each host vNIC adapter so that the Vlan is active.
        Restart-NetAdapter "vEthernet (SMB01)" -CimSession $AllServers
        Restart-NetAdapter "vEthernet (SMB02)" -CimSession $AllServers

    #Enable RDMA on the host vNIC adapters
        Enable-NetAdapterRDMA "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $AllServers

    #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
        Invoke-Command -ComputerName $allservers -ScriptBlock {
            $physicaladapters=(get-vmswitch SETSwitch).NetAdapterInterfaceDescriptions | Sort-Object
            Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
            Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
        }

    #Configure Jumbo Frames
    if ($JumboSize -ne 1514){
        Set-NetAdapterAdvancedProperty -CimSession $AllServers  -DisplayName "Jumbo Packet" -RegistryValue $JumboSize
    }

    #verify mapping
        Get-VMNetworkAdapterTeamMapping -CimSession $AllServers -ManagementOS | ft ComputerName,NetAdapterName,ParentAdapter 
    #Verify that the VlanID is set
        Get-VMNetworkAdapterVlan -ManagementOS -CimSession $AllServers |Sort-Object -Property Computername | ft ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName
    #verify RDMA
        Get-NetAdapterRdma -CimSession $AllServers | Sort-Object -Property Systemname | ft systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
    #verify ip config 
        Get-NetIPAddress -CimSession $AllServers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
    #verify JumboFrames
        Get-NetAdapterAdvancedProperty -CimSession $AllServers -DisplayName "Jumbo Packet"


        if ($DCB -eq $True){
            #Install DCB
                if (!$NanoServer){
                    foreach ($server in $AllServers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 
                }
            ##Configure QoS
                New-NetQosPolicy "SMB"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $AllServers
                New-NetQosPolicy "ClusterHB" -Cluster                         -PriorityValue8021Action 7 -CimSession $AllServers
                New-NetQosPolicy "Default"   -Default                         -PriorityValue8021Action 0 -CimSession $AllServers

            #Turn on Flow Control for SMB
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

            #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

            #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

            #Configure IeeePriorityTag
                #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}

            #validate flow control setting
                Invoke-Command -ComputerName $AllServers -ScriptBlock { Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | ft PSComputerName,Priority,Enabled -GroupBy PSComputerName

            #Validate DCBX setting
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName

            #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

            #validate policy
                Invoke-Command -ComputerName $AllServers -ScriptBlock {Get-NetAdapterQos | where enabled -eq true} | Sort-Object PSComputerName

            #Create a Traffic class and give SMB Direct 60% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $AllServers -ScriptBlock {New-NetQosTrafficClass "SMB"     -Priority 3 -BandwidthPercentage 60 -Algorithm ETS}
                Invoke-Command -ComputerName $AllServers -ScriptBlock {New-NetQosTrafficClass "Cluster" -Priority 5 -BandwidthPercentage 1 -Algorithm ETS}
        }

    #enable iWARP firewall rule if requested
        if ($iWARP -eq $True){
            Enable-NetFirewallRule -Name "FPSSMBD-iWARP-In-TCP" -CimSession $AllServers
        }
#endregion

#region Create Storage and Compute Cluster and configure basic settings
    #Test S2D Nodes
        Test-Cluster -Node $S2DNodes -Include "Storage Spaces Direct",Inventory,Network,"System Configuration"
    #Create Storage Cluster
        if ($StorageClusterIP){
            New-Cluster -Name $S2DClusterName -Node $S2DNodes -StaticAddress $StorageClusterIP
        }else{
            New-Cluster -Name $S2DClusterName -Node $S2DNodes
        }

    #test compute nodes
        Test-Cluster -Node $ComputeNodes
    #create compute cluster
        if ($ComputeClusterIP){
            New-Cluster -Name $ComputeClusterName -Node $ComputeNodes -StaticAddress $ComputeClusterIP
        }else{
            New-Cluster -Name $ComputeClusterName -Node $ComputeNodes
        }

    #clear dns client cache to resolve new CNOs
        Start-Sleep 5
        Clear-DnsClientCache

    #Configure CSV Cache on storage cluster
        if ($RealHW){
            #10GB might be a good starting point. Needs tuning depending on workload
            (Get-Cluster $S2DClusterName).BlockCacheSize = 10240
        }else{
            #Starting 1709 is block cache 512. For virtual environments it does not make sense
            (Get-Cluster $S2DClusterName).BlockCacheSize = 0
        }

    #configure File Share Witness for both clusters
        foreach ($ClusterName in ($ComputeClusterName,$S2DClusterName)){
            $WitnessName=$ClusterName+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$ClusterName$"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
            # Set NTFS permissions 
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
            #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
        }
#endregion

#region Configure Cluster networks
    #rename networks
    foreach ($ClusterName in ($ComputeClusterName,$S2DClusterName)){

        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name="Management"

        if ($NumberOfStorageNets -eq 1){
            #if 1 network
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet"0").Name="SMB"
        }

        if ($NumberOfStorageNets -eq 2){
            #if 2 networks
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB1"
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB2"
        }
    }

    #Configure SMB Networks as public on Storage Cluster
        if ($NumberOfStorageNets -eq 1){
                #if 1 network
                (Get-ClusterNetwork -Cluster $S2DClustername | Where-Object Address -eq $StorNet"0").role="ClusterAndClient"
        }

        if ($NumberOfStorageNets -eq 2){
                #if 2 networks
                (Get-ClusterNetwork -Cluster $S2DClustername | Where-Object Address -eq $StorNet1"0").role="ClusterAndClient"
                (Get-ClusterNetwork -Cluster $S2DClustername | Where-Object Address -eq $StorNet2"0").role="ClusterAndClient"
        }

    #configure Live Migration on Compute Cluster
        #configure LM to use SMB networks
            if ($NumberOfStorageNets -eq 1){
                Get-ClusterResourceType -Cluster $ComputeClustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $ComputeClustername | Where-Object {$_.Name -ne "SMB"}).ID))
            }
            if ($NumberOfStorageNets -eq 2){
                Get-ClusterResourceType -Cluster $ComputeClustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $ComputeClustername | Where-Object {($_.Name -ne "SMB1") -or ($_.Name -ne "SMB1")}).ID))
            }
        #set Live Migration to SMB on compute nodes
            Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $ComputeNodes
        #Configure SMB Bandwidth Limits for Live Migration https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
            if ($SMBBandwidthLimits){
                #install feature
                Invoke-Command -ComputerName $S2DNodes -ScriptBlock {Install-WindowsFeature -Name "FS-SMBBW"} 
                #Calculate 40% of capacity of NICs in vSwitch (considering 2 NICs, if 1 fails, it will not consume all bandwith, therefore 40%)
                $Adapters=(Get-VMSwitch -CimSession $S2DNodes[0]).NetAdapterInterfaceDescriptions
                $BytesPerSecond=((Get-NetAdapter -CimSession $S2DNodes[0] -InterfaceDescription $adapters).TransmitLinkSpeed | Measure-Object -Sum).Sum/8
                Set-SmbBandwidthLimit -Category LiveMigration -BytesPerSecond ($BytesPerSecond*0.4) -CimSession $S2DNodes
            }

#endregion

#region configure Cluster-Aware-Updating
    if (!$NanoServer){
        #Install required features on nodes.
        foreach ($Server in $AllServers){
            Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $Server
        }
        #add role
        Add-CauClusterRole -ClusterName $S2DClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $S2DClusterCAUName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
        Add-CauClusterRole -ClusterName $ComputeClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $ComputeClusterCAUName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    }

#endregion

#region Enable Cluster S2D and check Pool and Tiers

    #Enable-ClusterS2D
    Enable-ClusterS2D -CimSession $S2DClusterName -confirm:0 -Verbose

    #display pool
        Get-StoragePool "S2D on $S2DClusterName" -CimSession $S2DClusterName

    #Display disks
        Get-StoragePool "S2D on $S2DClusterName" -CimSession $S2DClusterName | Get-PhysicalDisk -CimSession $S2DClusterName

    #Get Storage Tiers
        Get-StorageTier -CimSession $S2DClusterName

   
    <#alternate way
        #register storage provider 
            Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName

        #display pool
            Get-StoragePool "S2D on $ClusterName"

        #Display disks
            Get-StoragePool "S2D on $ClusterName" | Get-PhysicalDisk

        #display tiers
            Get-StorageTier

        #unregister StorageSubsystem
            $ss=Get-StorageSubSystem -FriendlyName *$ClusterName
            Unregister-StorageSubsystem -ProviderName "Windows Storage Management Provider" -StorageSubSystemUniqueId $ss.UniqueId
    #>
#endregion

#region Create Volumes (it also depends what mix of devices you have. This example is valid for One or two tiers)

    if ($S2DNodesCount -ge 4){
        #Create Mirror Accelerated Parity Volumes
            Foreach ($MAPVolumeName in $MAPVolumeNames) {
                New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName $MAPVolumeName -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance,capacity -StorageTierSizes 2TB,8TB -CimSession $S2DClusterName
            }
        #Create Mirror Volumes
            Foreach ($MirrorVolumeName in $MirrorVolumeNames) {
                New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName $MirrorVolumeName -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance -StorageTierSizes 2TB -CimSession $S2DClusterName
            }
    }else{
        #Create Mirror Volumes
            Foreach ($MirrorVolumeName in $MirrorVolumeNames) {
                New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName $MirrorVolumeName -FileSystem CSVFS_ReFS -StorageTierFriendlyNames capacity -StorageTierSizes 2TB -CimSession $S2DClusterName
            }
    }
    start-sleep 10

    #rename CSV(s) to match name on Windows Server 2016 (in 2019 it is not needed as it's already renamed)
    $CurrentBuildNumber=Invoke-Command -ComputerName $S2DClusterName -scriptblock {Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber}
    if ($CurrentBuildNumber -eq 14393) {
        $CSVs=Get-ClusterSharedVolume -Cluster $S2DClusterName
        foreach ($CSV in $CSVs){
            $volumepath=$CSV.sharedvolumeinfo.friendlyvolumename
            $newname=$CSV.name.Substring(22,$CSV.name.Length-23)
            $CSV_Owner=(Get-ClusterSharedVolume -Cluster $S2DClusterName -Name $CSV.Name).ownernode
            Invoke-Command -ComputerName $CSV_Owner -ScriptBlock {Rename-Item -Path $using:volumepath -NewName $using:newname} -ErrorAction SilentlyContinue
        }
    }

#endregion

#region Configure Scale-Out File Server, create HA File Shares

    #Configure SOFS
    #Install File Server role on S2D-Cluster nodes
        $SOFSNodes=(Get-ClusterNode -Cluster $S2DClusterName).Name
        foreach ($SOFSNode in $SOFSNodes ) {Install-WindowsFeature -Name FS-FileServer -ComputerName $SOFSNode}

    #create HA SOFS Roles on Shared and S2D Cluster
        Add-ClusterScaleOutFileServerRole -Name $SOFSHAName -Cluster $S2DClusterName

    #Create File Shares
        #Create account list (note the domain admin. This is just an example. Account (admin) that will create VMs, should have write access.)
        $accounts=@()
        (Get-ClusterNode -Cluster $ComputeClusterName).Name | Foreach-Object {$accounts+="corp\$_$"}
        $accounts+="corp\$ComputeClusterName$"
        $accounts+="corp\Domain Admins"

        #create folders and share it
        foreach ($VolumeName in ($MAPVolumeNames+$MirrorVolumeNames)){
            New-Item -Path "\\$S2DClusterName\ClusterStorage$\$VolumeName" -Name Share -ItemType Directory
            New-SmbShare -CimSession $S2DClusterName -Path "C:\ClusterStorage\$VolumeName\Share" -ScopeName $SOFSHAName -Name $VolumeName -FullAccess $accounts
            Invoke-Command -ComputerName $S2DClusterName -ArgumentList $SOFSHAName,$VolumeName -ScriptBlock {
                param($SOFSHAName,$VolumeName);
                Set-SmbPathAcl -ScopeName $SOFSHAName -ShareName $VolumeName
            }
        }

#endregion

#region configure kerberos constrained delegation https://technet.microsoft.com/en-us/library/jj134187.aspx
    #configure delegation
        foreach ($ComputeNode in (Get-ClusterNode -Cluster $ComputeClusterName).Name) {
                Enable-SmbDelegation -SmbServer $SOFSHAName -SmbClient $ComputeNode
        }
    #Validate Delegation
        Get-SmbDelegation -SmbServer $SOFSHAName
#endregion

#region move VMQ out of CPU 0 and set correct BaseProcessorNumber based on NUMA for every pNIC in external vSwitch.
#more info: https://techcommunity.microsoft.com/t5/Networking-Blog/Synthetic-Accelerations-in-a-Nutshell-Windows-Server-2012/ba-p/447792
    if ($RealHW){
        $Switches=Get-VMSwitch -CimSession $AllServers -SwitchType External

        foreach ($switch in $switches){
            if ($switch.DefaultQueueVmmqEnabled -eq $false){ #only if VMMQ does not work, let's make sure VMQ will not assign CPU 0
                $processor=Get-WmiObject win32_processor -ComputerName $switch.ComputerName | Select-Object -First 1
                if ($processor.NumberOfCores -eq $processor.NumberOfLogicalProcessors/2){
                    $HT=$True
                }
                $adapters=@()
                $switch.NetAdapterInterfaceDescriptions | ForEach-Object {$adapters+=Get-NetAdapterHardwareInfo -InterfaceDescription $_ -CimSession $switch.computername}
                foreach ($adapter in $adapters){
                    $BaseProcessorNumber=$adapter.NumaNode*$processor.NumberOfLogicalProcessors
                    if ($adapter.NumaNode -eq 0){
                        if($HT){
                            $BaseProcessorNumber=$BaseProcessorNumber+2
                        }else{
                            $BaseProcessorNumber=$adapter.NumaNode*$processor.NumberOfLogicalProcessors+1
                        }
                    }
                    $adapter=Get-NetAdapter -InterfaceDescription $adapter.InterfaceDescription -CimSession $adapter.PSComputerName
                    $adapter | Set-NetAdapterVmq -BaseProcessorNumber $BaseProcessorNumber
                }
            }
        }
    }
#endregion

#region activate High Performance Power plan
    if ($RealHW){
        <#Cim method
        #show enabled power plan
            Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession $AllServers | where isactive -eq $true | ft PSComputerName,ElementName
        #Grab instances of power plans
            $instances=Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession $AllServers | where Elementname -eq "High performance"
        #activate plan
            foreach ($instance in $instances) {Invoke-CimMethod -InputObject $instance -MethodName Activate}
        #show enabled power plan
            Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession $AllServers | where isactive -eq $true | ft PSComputerName,ElementName
        #>
        #set high performance
            Invoke-Command -ComputerName $AllServers -ScriptBlock {powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}
        #check settings
            Invoke-Command -ComputerName $AllServers -ScriptBlock {powercfg /list}
    }

#endregion

#region Create some dummy VMs (3 per each CSV disk)
    Start-Sleep 30 #Sleeep to settle things down
    $Number=1
    foreach ($VolumeName in ($MAPVolumeNames+$MirrorVolumeNames)){
        1..3 | ForEach-Object {
            $VMName="TestVM$Number"
            Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ComputeClusterName).name | Get-Random) -ArgumentList $VolumeName,$VMName,$SOFSHAName -ScriptBlock {
                param($VolumeName,$VMName,$SOFSHAName);
                New-VM -Name $VMName -NewVHDPath "\\$SOFSHAName\$VolumeName\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 32GB -SwitchName SETSwitch -Generation 2 -Path "\\$SOFSHAName\$VolumeName\"
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ComputeClusterName
            $number++
        }
    }

    #configure some small amount of RAM if just demoing running VMs
    Get-VM -CimSession (Get-ClusterNode -Cluster $ComputeClusterName).Name | Set-VM -MemoryStartupBytes 32MB
    #start VMs
    Get-VM -CimSession (Get-ClusterNode -Cluster $ComputeClusterName).Name | Start-VM


#endregion

#### Scale out S2D Cluster ####

#region Configure basic settings on servers
    #Tune HW timeout to 10 minutes (6minutes is default) for Dell servers
    if ($DellHW){
        Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
    }

#Configure Active memory dump
    Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {
        Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
        Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
    }

#enable meltdown mitigation
    if ($MeltdownMitigationEnable){
        Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
        }
    }

#enable Speculative Store Bypass mitigation
    if ($SpeculativeStoreBypassMitigation){
        Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
        }
    }

#Configure MinVmVersionForCpuBasedMitigations
    if ($ConfigurePCIDMinVersion){
        Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -value "1.0"
        }
    }


#install roles and features
    if (!$NanoServer){
        #install Hyper-V using DISM (if nested virtualization is not enabled install-windowsfeature would fail)
            Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
        
        #define features for S2D Cluster
            $features="Failover-Clustering","Hyper-V-PowerShell","FS-FileServer","RSAT-Clustering-PowerShell"
            if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
            if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
            if ($Deduplication){$features+="FS-Data-Deduplication"}
        
        #install features on S2D Cluster
            foreach ($S2DNode in $S2DNodesToScale) {Install-WindowsFeature -Name $features -ComputerName $S2DNode}

        #restart and wait for computers
            Restart-Computer $S2DNodesToScale -Protocol WSMan -Wait -For PowerShell
            Start-Sleep 10 #Failsafe
    }

#endregion

#region Configure networking
    if ($SRIOV){
        Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    }else{
        Invoke-Command -ComputerName $S2DNodesToScale -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    }

    #Configure Hyper-V Port Load Balancing algorithm (in 1709 its already Hyper-V, therefore setting only for Windows Server 2016)
        Invoke-Command -ComputerName $S2DNodesToScale -scriptblock {
            if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
                Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
            }
        }


    $S2DNodesToScale | ForEach-Object {
        #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName SETSwitch -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName SETSwitch -Cimsession $_

        #configure IP Addresses
            If ($NumberOfStorageNets -eq 1){
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                $IP++
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }

            If($NumberOfStorageNets -eq 2){
                New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }
    }

    #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans
    If ($NumberOfStorageNets -eq 1){
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN -Access -ManagementOS -CimSession $S2DNodesToScale
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN -Access -ManagementOS -CimSession $S2DNodesToScale
    }else{
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $S2DNodesToScale
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $S2DNodesToScale
    }
    #Restart each host vNIC adapter so that the Vlan is active.
    Restart-NetAdapter "vEthernet (SMB01)" -CimSession $S2DNodesToScale
    Restart-NetAdapter "vEthernet (SMB02)" -CimSession $S2DNodesToScale

#endregion

# + you need to configure all other hardware related stuff (mapping adapters, QoS, VMQ, Performance plan ... )

#Add as S2D node
    Add-ClusterNode -Name $S2DNodesToScale -Cluster $S2DClusterName

#### Scale out Compute Cluster ####

#region Configure basic settings on servers
    #Tune HW timeout to 10 minutes (6minutes is default) for Dell servers
    if ($DellHW){
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
    }

    #Configure Active memory dump
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
        }

    #enable meltdown mitigation
    if ($MeltdownMitigationEnable){
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
        }
    }

    #enable Speculative Store Bypass mitigation
    if ($SpeculativeStoreBypassMitigation){
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
        }
    }

    #Configure MinVmVersionForCpuBasedMitigations
    if ($ConfigurePCIDMinVersion){
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -value "1.0"
        }
    }


    #install roles and features
        if (!$NanoServer){
            #install Hyper-V using DISM (if nested virtualization is not enabled install-windowsfeature would fail)
                Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
            #Install Hyper-V PowerShell and Failover Clustering 
                foreach ($ComputeNodeToScale in $ComputeNodesToScale) {Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell" -ComputerName $ComputeNodeToScale}
            #restart and wait for computers
                Restart-Computer $ComputeNodesToScale -Protocol WSMan -Wait -For PowerShell
                Start-Sleep 10 #Failsafe
        }

#endregion

#region Configure networking
    if ($SRIOV){
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    }else{
        Invoke-Command -ComputerName $ComputeNodesToScale -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    }

    #Configure Hyper-V Port Load Balancing algorithm (in 1709 its already Hyper-V, therefore setting only for Windows Server 2016)
        Invoke-Command -ComputerName $ComputeNodesToScale -scriptblock {
            if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
                Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
            }
        }

    $ComputeNodesToScale | ForEach-Object {
        #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName SETSwitch -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName SETSwitch -Cimsession $_

        #configure IP Addresses
            If ($NumberOfStorageNets -eq 1){
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                $IP++
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }

            If($NumberOfStorageNets -eq 2){
                New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }
    }

    #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans
    If ($NumberOfStorageNets -eq 1){
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN -Access -ManagementOS -CimSession $ComputeNodesToScale
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN -Access -ManagementOS -CimSession $ComputeNodesToScale
    }else{
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $ComputeNodesToScale
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $ComputeNodesToScale
    }
    #Restart each host vNIC adapter so that the Vlan is active.
    Restart-NetAdapter "vEthernet (SMB01)" -CimSession $ComputeNodesToScale
    Restart-NetAdapter "vEthernet (SMB02)" -CimSession $ComputeNodesToScale
    
    #set Live Migration to SMB on compute nodes
        Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $ComputeNodesToScale
#endregion

# + you need to configure all other hardware related stuff (mapping adapters, QoS, VMQ, Performance plan ... )

#Add Cluster node
    Add-ClusterNode -Name $ComputeNodesToScale -Cluster $ComputeClusterName

#region Configure permissions on Shares
    #Create account list
    $accounts=@()
    (Get-ClusterNode -Cluster $ComputeClusterName).Name | Foreach-Object {$Accounts+="corp\$_$"}
    $accounts+="corp\$ComputeClusterName$"
    $accounts+="corp\Domain Admins"

    foreach ($VolumeName in ($MAPVolumeNames+$MirrorVolumeNames)){
        Get-SmbShare -CimSession $S2DClusterName -Name $VolumeName -ScopeName $SOFSHAName | Grant-SmbShareAccess -AccessRight Full -AccountName $accounts -Confirm:0 
        Invoke-Command -ComputerName $S2DClusterName -ArgumentList $SOFSHAName,$VolumeName -ScriptBlock {
            param($SOFSHAName,$VolumeName);
            Set-SmbPathAcl -ScopeName $SOFSHAName -ShareName $VolumeName
        }
    }
#endregion

#region configure kerberos constrained delegation https://technet.microsoft.com/en-us/library/jj134187.aspx
    #configure delegation
    foreach ($ComputeNode in (Get-ClusterNode -Cluster $ComputeClusterName).Name) {
            Enable-SmbDelegation -SmbServer $SOFSHAName -SmbClient $ComputeNode
    }

    #Validate Delegation
        Get-SmbDelegation -SmbServer $SOFSHAName

#endregion

#region Add Volumes

    if ($S2DNodesCount -ge 4){
        #Create Mirror Volume
            New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName $NewMirrorVolumeName -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance -StorageTierSizes 2TB -CimSession $S2DClusterName
    }else{
        #Create Mirror Volume
            New-Volume -StoragePoolFriendlyName "S2D on $S2DClusterName" -FriendlyName $NewMirrorVolumeName -FileSystem CSVFS_ReFS -StorageTierFriendlyNames capacity -StorageTierSizes 2TB -CimSession $S2DClusterName

    }
    start-sleep 10


    #rename CSV(s)
        Get-ClusterSharedVolume -Cluster $S2DClusterName | Foreach-Object {
            $volumepath=$_.sharedvolumeinfo.friendlyvolumename
            $newname=$_.name.Substring(22,$_.name.Length-23)
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $S2DClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
        }

    #Create account list
        $accounts=@()
        (Get-ClusterNode -Cluster $ComputeClusterName).Name | Foreach-Object {$Accounts+="corp\$_$"}
        $accounts+="corp\$ComputeClusterName$"
        $accounts+="corp\Domain Admins"

    #Create New FileShare
            New-Item -Path "\\$S2DClusterName\ClusterStorage$\$NewMirrorVolumeName" -Name Share -ItemType Directory
            New-SmbShare -CimSession $S2DClusterName -Path "C:\ClusterStorage\$NewMirrorVolumeName\Share" -ScopeName $SOFSHAName -Name $NewMirrorVolumeName -FullAccess $accounts
            Invoke-Command -ComputerName $S2DClusterName -ArgumentList $SOFSHAName,$NewMirrorVolumeName -ScriptBlock {
                param($SOFSHAName,$NewMirrorVolumeName);
                Set-SmbPathAcl -ScopeName $SOFSHAName -ShareName $NewMirrorVolumeName
            }

#endregion

#region Create some VMs
    Start-Sleep 60 #Sleeep to settle things down
    1..3 | ForEach-Object {
        $VMName="NewTestVM$_"
        Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ComputeClusterName).name | Get-Random) -ArgumentList $NewMirrorVolumeName,$VMName,$SOFSHAName -ScriptBlock {
            param($NewMirrorVolumeName,$VMName,$SOFSHAName);
            New-VM -Name $VMName -NewVHDPath "\\$SOFSHAName\$NewMirrorVolumeName\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 32GB -SwitchName SETSwitch -Generation 2 -Path "\\$SOFSHAName\$NewMirrorVolumeName\"
        }
        Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ComputeClusterName
        $number++
    }

    #configure some small amount of RAM if just demoing running VMs
        Get-VM -CimSession (Get-ClusterNode -Cluster $ComputeClusterName).Name | Where-Object name -like "New*" | Set-VM -MemoryStartupBytes 32MB
    #start VMs
        Get-VM -CimSession (Get-ClusterNode -Cluster $ComputeClusterName).Name | Where-Object name -like "New*" | Start-VM

#endregion

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
