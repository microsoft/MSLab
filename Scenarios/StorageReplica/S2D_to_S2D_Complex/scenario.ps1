################################
# Run from DC or Management VM #
################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region labconfig
    $Clusters=@()
    $Clusters+=[pscustomobject]@{
        Name= "Site1-SR-Clus"
        IP = ""
        Servers = 'Site1-S2D1','Site1-S2D2'
        CAURoleName = "Site1SRClusCAU"
    }

    $Clusters+=[pscustomobject]@{
        Name= "Site2-SR-Clus"
        IP = ""
        Servers = 'Site2-S2D1','Site2-S2D2'
        CAURoleName = "Site2SRClusCAU"
    }
    #generate some friendly variables
        $Servers=$clusters.servers
        $Cluster1Name=$Clusters[0].Name
        $Cluster2Name=$Clusters[1].Name
        $Cluster1FirstNode=$Clusters[0].Servers[0]
        $Cluster2FirstNode=$Clusters[1].Servers[0]

    #Site1->Site2 Replication Group
    $SourceRGName1="Data1-Site1"
    $DestinationRGName1="Data1-Site2"

    #Site2->Site1 Replication Group
    $SourceRGName2="Data2-Site2"
    $DestinationRGName2="Data2_Site1"

    #Replication mode
    $ReplicationMode="Synchronous" #Synchronous or Asynchronous
    $AsyncRPO=30  #Recovery point objective in seconds. Default is 5M, minimum is 30s

    #Networks
        $StorNet="172.16.1."
        $StorVLAN=1
        $IP=1   #start IP
        $SRIOV=$false #Deploy SR-IOV enabled switch
        $ReplicaNetwork="172.16.2.0"

    #Virtual Machines to be created
        $Site1VMNames="TestVM1_Site1","TestVM2_Site1"
        $Site2VMNames="TestVM1_Site2","TestVM2_Site2"

    #ask for parent vhdx for VMs
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
        }
        $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
        If($openFile.ShowDialog() -eq "OK"){
            Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
        } 
        if (!$openFile.FileName){
            Write-Host "No VHD was selected... Will skip VM Creation" -ForegroundColor Red
        }
        $VHDPath = $openFile.FileName

    #Real hardware?
        $RealHW=$False #will configure VMQ not to use CPU 0 if $True, configures power plan
        $DellHW=$False #include Dell recommendations

    #PFC?
        $DCB=$False #$true for ROCE, $false for iWARP

    #iWARP?
        $iWARP=$False

    #Nano server?
        $NanoServer=$True

    #Additional Features
        $Bitlocker=$false #Install "Bitlocker" and "RSAT-Feature-Tools-BitLocker" on nodes?
        $StorageReplica=$true #Install "Storage-Replica" and "RSAT-Storage-Replica" on nodes?
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
    }else{
        if ($Deduplication) {
            #install Dedup Feature
            foreach ($server in $servers) {Install-WindowsFeature -Name "FS-Data-Deduplication" -ComputerName $server}
        }
        if ($StorageReplica){
            #install SR Feature
            foreach ($server in $servers) {Install-WindowsFeature -Name "Storage-Replica","RSAT-Storage-Replica" -ComputerName $server}
            #restart and wait for computers
            Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
            Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
        }
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
            Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName

        #Create a Traffic class and give SMB Direct 30% of the bandwidth minimum. The name of the class will be "SMB".
        #This value needs to match physical switch configuration. Value might vary based on your needs.
            Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB" -Priority 3 -BandwidthPercentage 30 -Algorithm ETS}
    }

#enable iWARP firewall rule if requested
    if ($iWARP -eq $True){
        Enable-NetFirewallRule -Name "FPSSMBD-iWARP-In-TCP" -CimSession $servers
    }

#endregion

#region Create HyperConverged clusters and configure basic setting

    foreach ($Cluster in $Clusters){
        Test-Cluster -Node $Cluster.Servers -Include "Storage Spaces Direct",Inventory,Network,"System Configuration"
        if ($Cluster.IP){
            New-Cluster -Name $Cluster.Name -Node $Cluster.Servers -StaticAddress $Cluster.IP
        }else{
            New-Cluster -Name $Cluster.Name -Node $Cluster.Servers
        }
        Start-Sleep 5
        Clear-DnsClientCache
    }
    
#Configure CSV Cache
if ($RealHW){
    foreach ($Cluster in $Clusters){
            #10GB might be a good starting point. Needs tuning depending on workload
            (Get-Cluster $Cluster.Name).BlockCacheSize = 10240
        }else{
            #Starting 1709 is block cache 512. For virtual environments it does not make sense
            (Get-Cluster $Cluster.Name).BlockCacheSize = 0
    }
}

#ConfigureWitness on DC

foreach ($Cluster in $clusters){
    #Create new directory
        $WitnessName="$($Cluster.Name)Witness"
        Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);new-item -Path c:\Shares -Name $WitnessName -ItemType Directory} -ArgumentList $WitnessName
        $accounts=@()
        $accounts+="corp\$($Cluster.Name)$"
        $accounts+="corp\Domain Admins"
        New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
    #Set NTFS permissions 
        Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);(Get-SmbShare "$WitnessName").PresetPathAcl | Set-Acl} -ArgumentList $WitnessName
    #Set Quorum
        Set-ClusterQuorum -Cluster $Cluster.Name -FileShareWitness "\\DC\$WitnessName"
}
#endregion

#region Configure Cluster Networks
    foreach ($Clustername in $Clusters.Name){
        #rename networks
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name="Management"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet"0").Name="SMB"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNetwork).Name="ReplicaNetwork"
        #cofigure none role for ReplicaNetwork
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNetwork).role="none"
        #Configure Live Migration network to network with name SMB
        Get-ClusterResourceType -Cluster $Clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $Clustername | Where-Object {$_.Name -ne "SMB"}).ID))
    }

    #Configure LM to use SMB
    Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers
#endregion

#region configure Cluster-Aware-Updating
if (!$NanoServer){
        foreach ($Cluster in $Clusters){
        #Install required features on nodes.
            $ClusterNodes=(Get-ClusterNode -Cluster $Cluster.Name).Name
            foreach ($ClusterNode in $ClusterNodes){
                Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
            }
        #add role
            Add-CauClusterRole -ClusterName $Cluster.Name -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $Cluster.CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    }
}

#endregion

#region configure s2d and create volumes

    #Enable-ClusterS2D
    Enable-ClusterS2D -CimSession $Clusters.Name -confirm:0 -verbose

    #create volumes
    foreach ($Cluster in $Clusters){
        if (($Cluster.Servers).Count -le 3){
            Invoke-Command -ComputerName $cluster.Servers[0] -ScriptBlock{
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Data1 -FileSystem ReFS -AccessPath D: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Log1  -FileSystem ReFS -AccessPath E: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Data2 -FileSystem ReFS -AccessPath F: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Log2  -FileSystem ReFS -AccessPath G: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
            }
        }else{
            Invoke-Command -ComputerName $cluster.Servers[0] -ScriptBlock{
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Data1 -FileSystem ReFS -AccessPath D: -StorageTierFriendlyNames performance,capacity -StorageTierSizes 2GB,8GB
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Log1  -FileSystem ReFS -AccessPath E: -StorageTierFriendlyNames performance -StorageTierSizes 10GB
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Data2 -FileSystem ReFS -AccessPath F: -StorageTierFriendlyNames performance,capacity -StorageTierSizes 2GB,8GB
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName Log2  -FileSystem ReFS -AccessPath G: -StorageTierFriendlyNames performance -StorageTierSizes 10GB
            }
        }
    }

#endregion

#region Configure Storage Replica
    #move available storage to first node on each cluster
    foreach ($Cluster in $clusters){
        Move-ClusterGroup -Cluster $Cluster.Name -Name "available storage" -Node $Cluster.Servers[0]
    }

    #enable CredSSP to be able to work with NanoServer
        Enable-WSManCredSSP -role server -Force
        Enable-WSManCredSSP Client -DelegateComputer $Cluster1FirstNode -Force

    #Create custom credentials
    $username = "corp\Administrator"
    $password = "LS1setup!"
    $secstr = New-Object -TypeName System.Security.SecureString
    $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $CustomCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr 

    #create results folder
    New-Item -ItemType Directory -Name replicaresults -Path \\dc\c$\
    #test replica
    Invoke-Command -ComputerName $Cluster1FirstNode -Authentication Credssp -Credential $CustomCred -ArgumentList $Cluster1FirstNode,$Cluster2FirstNode -ScriptBlock  {
        param($Cluster1FirstNode,$Cluster2FirstNode);
        Test-SRTopology -SourceComputerName $Cluster1FirstNode -SourceVolumeName D: -SourceLogVolumeName E: -DestinationComputerName $Cluster2FirstNode -DestinationVolumeName D: -DestinationLogVolumeName E: -DurationInMinutes 1 -ResultPath \\dc\c$\replicaresults
    }
    #generate replica report (nano does not have charts API)
    Test-SRTopology -GenerateReport -DataPath \\dc\c$\replicaresults\

    #Add data disks to CSV
        foreach ($ClusterName in $clusters.Name){
            Add-ClusterSharedVolume -Name "Cluster Virtual Disk (Data1)" -Cluster $ClusterName
            Add-ClusterSharedVolume -Name "Cluster Virtual Disk (Data2)" -Cluster $ClusterName
        }
    #rename Volumes to match name
        foreach ($clustername in $clusters.Name){
            Get-ClusterSharedVolume -Cluster $ClusterName | ForEach-Object {
                $volumepath=$_.sharedvolumeinfo.friendlyvolumename
                $newname=$_.name.Substring(22,$_.name.Length-23)
                Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
            } 
        }

    #Grant permissions 
        Grant-SRAccess -ComputerName $Cluster1FirstNode -Cluster $Cluster2Name
        Grant-SRAccess -ComputerName $Cluster2FirstNode -Cluster $Cluster1Name

    #set SR For Site1-Site2 replication
    If ($ReplicationMode -eq "Asynchronous"){
        New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Cluster1Name -SourceRGName $SourceRGName1 -SourceVolumeName c:\ClusterStorage\Data1 -SourceLogVolumeName e: -DestinationComputerName $Cluster2Name -DestinationRGName $DestinationRGName1 -DestinationVolumeName c:\ClusterStorage\Data1 -DestinationLogVolumeName e:
    }else{
        New-SRPartnership -SourceComputerName $Cluster1Name -SourceRGName $SourceRGName1 -SourceVolumeName c:\ClusterStorage\Data1 -SourceLogVolumeName e: -DestinationComputerName $Cluster2Name -DestinationRGName $DestinationRGName1 -DestinationVolumeName c:\ClusterStorage\Data1 -DestinationLogVolumeName e:
    }

    do{
        $r=(Get-SRGroup -CimSession $Cluster2Name -Name $DestinationRGName1).replicas
        [System.Console]::Write("Number of remaining Gbytes {0}`r", $r.NumOfBytesRemaining/1GB)
        Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
    }until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
    Write-Output "Replica Status: "$r.replicationstatus

    #set SR For Site2-Site1 replication
    If ($ReplicationMode -eq "Asynchronous"){
        New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Cluster2Name -SourceRGName $SourceRGName2 -SourceVolumeName c:\ClusterStorage\Data2 -SourceLogVolumeName g: -DestinationComputerName $Cluster1Name -DestinationRGName $DestinationRGName2 -DestinationVolumeName c:\ClusterStorage\Data2 -DestinationLogVolumeName g:
    }else{
        New-SRPartnership -SourceComputerName $Cluster2Name -SourceRGName $SourceRGName2 -SourceVolumeName c:\ClusterStorage\Data2 -SourceLogVolumeName g: -DestinationComputerName $Cluster1Name -DestinationRGName $DestinationRGName2 -DestinationVolumeName c:\ClusterStorage\Data2 -DestinationLogVolumeName g:
    }

    do{
        $r=(Get-SRGroup -CimSession $Cluster1Name -Name $DestinationRGName2).replicas
        [System.Console]::Write("Number of remaining Gbytes {0}`r", $r.NumOfBytesRemaining/1GB)
        Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
    }until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
    Write-Output "Replica Status: "$r.replicationstatus

#endregion

#region configure constraints

    #configure constraints for first Cluster
    Set-SRNetworkConstraint -SourceComputerName $Cluster1Name -SourceRGName $SourceRGName1 -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $Cluster2Name -DestinationNWInterface "ReplicaNetwork" -DestinationRGName $DestinationRGName1
    Get-SRNetworkConstraint -SourceComputerName $Cluster1Name -SourceRGName $SourceRGName1 -DestinationComputerName $Cluster2Name  -DestinationRGName $DestinationRGName1

    #configure constraints for second Cluster
    Set-SRNetworkConstraint -SourceComputerName $Cluster2Name -SourceRGName $SourceRGName2 -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $Cluster1Name -DestinationNWInterface "ReplicaNetwork" -DestinationRGName $DestinationRGName2
    Get-SRNetworkConstraint -SourceComputerName $Cluster2Name -SourceRGName $SourceRGName2 -DestinationComputerName $Cluster1Name  -DestinationRGName $DestinationRGName2

#endregion

#region create VMs
    #create VMs
    if ($VHDPath){
        foreach ($Site1VMName in $Site1VMNames){
        New-Item -Path "\\$cluster1Name\ClusterStorage$\Data1\$Site1VMName\Virtual Hard Disks" -ItemType Directory
        Copy-Item -Path $VHDPath -Destination "\\$cluster1Name\ClusterStorage$\Data1\$Site1VMName\Virtual Hard Disks\$($Site1VMName)_Disk1.vhdx"
        New-VM -Name $Site1VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\Data1" -VHDPath "c:\ClusterStorage\Data1\$Site1VMName\Virtual Hard Disks\$($Site1VMName)_Disk1.vhdx" -ComputerName $Cluster1FirstNode -SwitchName SETSwitch
        Start-VM -name $Site1VMName -ComputerName $Cluster1FirstNode
        Add-ClusterVirtualMachineRole -VMName $Site1VMName -Cluster $Cluster1Name
        }

        foreach ($Site2VMName in $Site2VMNames){
        New-Item -Path "\\$cluster2Name\ClusterStorage$\Data2\$Site2VMName\Virtual Hard Disks" -ItemType Directory
        Copy-Item -Path $VHDPath -Destination "\\$cluster2Name\ClusterStorage$\Data2\$Site2VMName\Virtual Hard Disks\$($Site2VMName)_Disk1.vhdx"
        New-VM -Name $Site2VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\Data2" -VHDPath "c:\ClusterStorage\Data2\$Site2VMName\Virtual Hard Disks\$($Site2VMName)_Disk1.vhdx" -ComputerName $Cluster2FirstNode -SwitchName SETSwitch
        Start-VM -name $Site2VMName -ComputerName $Cluster2FirstNode
        Add-ClusterVirtualMachineRole -VMName $Site2VMName -Cluster $Cluster2Name
        }
    }
#endregion

#finishing
Write-Host "Script finished at $(Get-date) and was running $(((get-date) - $StartDateTime))"
 