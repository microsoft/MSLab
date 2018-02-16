################################
# Run from DC or Management VM #
################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region LAB Config

    # 2,3,4,8, or 16 nodes
        $numberofnodes=4
        $ServersNamePrefix="S2D"
    #generate servernames (based number of nodes and serversnameprefix)
        $Servers=@()
        1..$numberofnodes | ForEach-Object {$Servers+="$($ServersNamePrefix)$_"}
    #Cluster Name
        $ClusterName="S2D-Cluster"

    #Cluster-Aware-Updating role name
        $CAURoleName="S2D-Clus-CAU"

    ## Networking ##
        $ClusterIP="10.0.0.111" #If blank (you can write just $ClusterIP="", DHCP will be used)
        $StorNet="172.16.1."
        $StorVLAN=1
        $SRIOV=$false #Deploy SR-IOV enabled switch
    #start IP
        $IP=1

    #Real hardware?
        $RealHW=$False #will configure VMQ not to use CPU 0 if $True, configures power plan
        $DellHW=$False #include Dell recommendations

    #PFC?
        $DCB=$False #$true for ROCE, $false for iWARP

    #iWARP?
        $iWARP=$False

    #Number of Disks Created. If >4 nodes, then x Mirror-Accelerated Parity and x Mirror disks are created
        $NumberOfDisks=$numberofnodes

    #Nano server?
        $NanoServer=$False

    #Additional Features
        $Bitlocker=$false #Install "Bitlocker" and "RSAT-Feature-Tools-BitLocker" on nodes?
        $StorageReplica=$false #Install "Storage-Replica" and "RSAT-Storage-Replica" on nodes?
        $Deduplication=$false #install "FS-Data-Deduplication" on nodes?

    #Enable Meltdown mitigation? https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
    #CVE-2017-5754 cannot be used to attack across a hardware virtualized boundary. It can only be used to read memory in kernel mode from user mode. It is not a strict requirement to set this registry value on the host if no untrusted code is running and no untrusted users are able to logon to the host.
        $MeltdownMitigationEnable=$false

    #Configure PCID to expose to VMS prior version 8.0 https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
        $ConfigurePCIDMinVersion=$true

#endregion

#region install features for management (Client needs RSAT, Server/Server Core have different features)
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

#region Configure basic settings on servers
    #Tune HW timeout to 10 minutes (6minutes is default) for Dell servers
        if ($DellHW){
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
        }
    
    #Configure Active memory dump
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
        }

    #enable meltdown mitigation
        if ($MeltdownMitigationEnable){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #Configure MinVmVersionForCpuBasedMitigations (only needed if you are running VM versions prior 8.0)
        if ($ConfigurePCIDMinVersion){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization")){
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name Virtualization -Force
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -value "1.0"
            }
        }

    #install roles and features
        if (!$NanoServer){
            #install Hyper-V using DISM (if nested virtualization is not enabled install-windowsfeature would fail)
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
            
            #define features
            $features="Failover-Clustering","Hyper-V-PowerShell"
            if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
            if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
            if ($Deduplication){$features+="FS-Data-Deduplication"}
            
            #install features
            foreach ($server in $servers) {Install-WindowsFeature -Name $features -ComputerName $server} 
            #restart and wait for computers
            Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
            Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
        }

#endregion

#region configure Networking
    #Create Virtual Switches and Virtual Adapters
        if ($SRIOV){
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        }else{
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        }

        #Configure Hyper-V Port Load Balancing algorithm (in 1709 its already Hyper-V, therefore setting only for Windows Server 2016)
            Invoke-Command -ComputerName $servers -scriptblock {
                if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
                    Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
                }
            }

        $Servers | ForEach-Object {
            #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB_1 -SwitchName SETSwitch -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB_2 -SwitchName SETSwitch -Cimsession $_

            #configure IP Addresses
            New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB_1)" -CimSession $_ -PrefixLength 24
            $IP++
            New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB_2)" -CimSession $_ -PrefixLength 24
            $IP++
        }

        Start-Sleep 5
        Clear-DnsClientCache

        #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_1 -VlanId $StorVLAN -Access -ManagementOS -CimSession $Servers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_2 -VlanId $StorVLAN -Access -ManagementOS -CimSession $Servers

        #Restart each host vNIC adapter so that the Vlan is active.
            Restart-NetAdapter "vEthernet (SMB_1)" -CimSession $Servers 
            Restart-NetAdapter "vEthernet (SMB_2)" -CimSession $Servers

        #Enable RDMA on the host vNIC adapters
            Enable-NetAdapterRDMA "vEthernet (SMB_1)","vEthernet (SMB_2)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each vRDMA NIC is mapped to separate pRDMA NIC)
            Invoke-Command -ComputerName $servers -ScriptBlock {
                    $physicaladapters=(get-vmswitch SETSwitch).NetAdapterInterfaceDescriptions | Sort-Object
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_1" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_2" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
                }
    
    #Verify Networking
        #verify mapping
            Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | ft ComputerName,NetAdapterName,ParentAdapter 
        #Verify that the VlanID is set
            Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | ft ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName
        #verify RDMA
            Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | ft systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
        #verify ip config 
            Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername

    #configure DCB if requested
        if ($DCB -eq $True){
            #Install DCB
                if (!$NanoServer){
                    foreach ($server in $servers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 
                }
            ##Configure QoS
                New-NetQosPolicy "SMB" -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers

            #Turn on Flow Control for SMB
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

            #Disable flow control for other traffic
                Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

            #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

            #validate flow control setting
                Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | ft PSComputerName,Priority,Enabled -GroupBy PSComputerNa

            #Validate DCBX setting
                Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName

            #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

            #validate policy
                Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | where enabled -eq true} | Sort-Object PSComputerName

            #Create a Traffic class and give SMB Direct 30% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB" -Priority 3 -BandwidthPercentage 30 -Algorithm ETS}
        }

    #enable iWARP firewall rule if requested
        if ($iWARP -eq $True){
            Enable-NetFirewallRule -Name "FPSSMBD-iWARP-In-TCP" -CimSession $servers
        }

#endregion

#region Create HyperConverged cluster and configure basic settings
    Test-Cluster -Node $servers -Include "Storage Spaces Direct",Inventory,Network,"System Configuration"
    if ($ClusterIP){
        New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
    }else{
        New-Cluster -Name $ClusterName -Node $servers
    }
    Start-Sleep 5
    Clear-DnsClientCache

    #Configure CSV Cache
    if ($RealHW){
        #10GB might be a good starting point. Needs tuning depending on workload
        (Get-Cluster $ClusterName).BlockCacheSize = 10240
    }else{
        #Starting 1709 is block cache 512. For virtual environments it does not make sense
        (Get-Cluster $ClusterName).BlockCacheSize = 0
    }

    #ConfigureWitness on DC
        #Create new directory
            $WitnessName=$Clustername+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);new-item -Path c:\Shares -Name $WitnessName -ItemType Directory} -ArgumentList $WitnessName
            $accounts=@()
            $accounts+="corp\$ClusterName$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions 
            Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);(Get-SmbShare "$WitnessName").PresetPathAcl | Set-Acl} -ArgumentList $WitnessName
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

#endregion

#region Configure Cluster Networks
    #rename networks
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet"0").Name="SMB"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name="Management"

    #configure Live Migration 
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -ne "SMB"}).ID))
        Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers
#endregion

#region configure Cluster-Aware-Updating
    if (!$NanoServer){
        #Install required features on nodes.
            $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
            foreach ($ClusterNode in $ClusterNodes){
                Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
            }
        #add role
            Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    }
#endregion

#region Create Fault Domains https://technet.microsoft.com/en-us/library/mt703153.aspx

#just some examples for Rack/Chassis fault domains.
    if ($numberofnodes -eq 4){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
                <Node Name="$($ServersNamePrefix)1"/>
                <Node Name="$($ServersNamePrefix)2"/>
                <Node Name="$($ServersNamePrefix)3"/>
                <Node Name="$($ServersNamePrefix)4"/>
        </Rack>
    </Site>
</Topology>
"@
    
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }
    
    if ($numberofnodes -eq 8){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Node Name="$($ServersNamePrefix)1"/>
            <Node Name="$($ServersNamePrefix)2"/>
        </Rack>
        <Rack Name="Rack02" Location="Contoso HQ, Room 4010, Aisle A, Rack 02">
            <Node Name="$($ServersNamePrefix)3"/>
            <Node Name="$($ServersNamePrefix)4"/>
        </Rack>
        <Rack Name="Rack03" Location="Contoso HQ, Room 4010, Aisle A, Rack 03">
            <Node Name="$($ServersNamePrefix)5"/>
            <Node Name="$($ServersNamePrefix)6"/>
        </Rack>
        <Rack Name="Rack04" Location="Contoso HQ, Room 4010, Aisle A, Rack 04">
            <Node Name="$($ServersNamePrefix)7"/>
            <Node Name="$($ServersNamePrefix)8"/>
        </Rack>
    </Site>
</Topology>
"@
    
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }

    if ($numberofnodes -eq 16){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Chassis Name="Chassis01" Location="Rack Unit 1 (Upper)" >
                <Node Name="$($ServersNamePrefix)1"/>
                <Node Name="$($ServersNamePrefix)2"/>
                <Node Name="$($ServersNamePrefix)3"/>
                <Node Name="$($ServersNamePrefix)4"/>
            </Chassis>
            <Chassis Name="Chassis02" Location="Rack Unit 1 (Upper)" >
                <Node Name="$($ServersNamePrefix)5"/>
                <Node Name="$($ServersNamePrefix)6"/>
                <Node Name="$($ServersNamePrefix)7"/>
                <Node Name="$($ServersNamePrefix)8"/>
            </Chassis>
            <Chassis Name="Chassis03" Location="Rack Unit 1 (Lower)" >
                <Node Name="$($ServersNamePrefix)9"/>
                <Node Name="$($ServersNamePrefix)10"/>
                <Node Name="$($ServersNamePrefix)11"/>
                <Node Name="$($ServersNamePrefix)12"/>
            </Chassis>
            <Chassis Name="Chassis04" Location="Rack Unit 1 (Lower)" >
                <Node Name="$($ServersNamePrefix)13"/>
                <Node Name="$($ServersNamePrefix)14"/>
                <Node Name="$($ServersNamePrefix)15"/>
                <Node Name="$($ServersNamePrefix)16"/>
            </Chassis>
        </Rack>
    </Site>
</Topology>
"@
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }
    
    #show fault domain configuration
        Get-ClusterFaultDomainxml -CimSession $ClusterName
    
    <#Alternate way
    if ($numberofnodes -eq 4){
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..4 | ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_"  -Parent "Rack01" -CimSession $ClusterName}
        Set-ClusterFaultDomain -Name "Rack01" -Parent "SEA"    -CimSession $ClusterName
    
    }
    
    if ($numberofnodes -eq 8){
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack02"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 02"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack03"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 03"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack04"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 04"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..2 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack01"    -CimSession $ClusterName}
        3..4 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack02"    -CimSession $ClusterName}
        5..6 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack03"    -CimSession $ClusterName}
        7..8 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack04"    -CimSession $ClusterName}
        1..4 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
    }
    
    if ($numberofnodes -eq 16){
        New-ClusterFaultDomain -Name "Chassis01" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Chassis02" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Chassis03" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName 
        New-ClusterFaultDomain -Name "Chassis04" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis01" -CimSession $ClusterName}
        5..8   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis02" -CimSession $ClusterName}
        9..12  |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis03" -CimSession $ClusterName}
        13..16 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis04" -CimSession $ClusterName}
    
        1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "Chassis0$_" -Parent "Rack01"    -CimSession $ClusterName}
        
        1..1 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
    
    }
    #>

#endregion

#region Enable Cluster S2D and check Pool and Tiers

    #Enable-ClusterS2D
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #display pool
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName

    #Display disks
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

    #Get Storage Tiers
        Get-StorageTier -CimSession $ClusterName
    
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
 
    if ($numberofnodes -le 3){
        1..$NumberOfDisks | ForEach-Object {
                New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName Mirror$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes 2TB -CimSession $ClusterName
            }
    }else{
        1..$NumberOfDisks | ForEach-Object {
                New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName MirrorAcceleratedParity$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance,capacity -StorageTierSizes 2TB,8TB -CimSession $ClusterName
                New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName Mirror$_                  -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance          -StorageTierSizes 2TB     -CimSession $ClusterName
            }
    }

    start-sleep 10

    #rename CSV(s) to match name
        Get-ClusterSharedVolume -Cluster $ClusterName | % {
            $volumepath=$_.sharedvolumeinfo.friendlyvolumename
            $newname=$_.name.Substring(22,$_.name.Length-23)
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
        } 

#endregion

#region move NICs out of CPU 0 (not tested)
    if ($RealHW){
        $Switches=Get-VMSwitch -CimSession $servers -SwitchType External

        foreach ($switch in $switches){
            $processor=Get-WmiObject win32_processor -ComputerName $switch.ComputerName | Select -First 1
            if ($processor.NumberOfCores -eq $processor.NumberOfLogicalProcessors/2){
                $HT=$True
            }
            $adapters=@()
            $switch.NetAdapterInterfaceDescriptions | ForEach-Object {$adapters+=Get-NetAdapterHardwareInfo -InterfaceDescription $_ -CimSession $switch.computername}

            foreach ($adapter in $adapters){
                if($HT){
                    $BaseProcessorNumber=$adapter.NumaNode*$processor.NumberOfLogicalProcessors+2
                }else{
                    $BaseProcessorNumber=$adapter.NumaNode*$processor.NumberOfLogicalProcessors+1
                }
                $adapter=Get-NetAdapter -InterfaceDescription $adapter.InterfaceDescription -CimSession $adapter.PSComputerName  
                $adapter | Set-NetAdapterVmq -BaseProcessorNumber $BaseProcessorNumber -MaxProcessors ($processor.NumberOfCores-1)
                $adapter | Set-NetAdapterRss -Profile Closest
            }
        }
    }
#endregion

#region activate High Performance Power plan
    if ($RealHW){
        #show enabled power plan
            Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | where isactive -eq $true | ft PSComputerName,ElementName
        #Grab instances of power plans
            $instances=Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | where Elementname -eq "High performance"
        #activate plan
            foreach ($instance in $instances) {Invoke-CimMethod -InputObject $instance -MethodName Activate}
        #show enabled power plan
            Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | where isactive -eq $true | ft PSComputerName,ElementName
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

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
 