########################################
# Paste into elevated PowerShell in DC #
########################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region LAB Config

    # 2-64 nodes
        $numberofnodes=4

    #servernames
        $ServersPrefix="1709Node"
    
    #generate names
        $servers=@()
        1..$numberofnodes | ForEach-Object {$servers+="$ServersPrefix$_"}

    #ClusterName
        $ClusterName="1709-Cluster"
    
    #Cluster IP Address
        $ClusterIP="10.0.0.111"

    #RDMA? Actually "RDMA" based design. If false, traditional converged design is deployed
        $RDMA=$false
    
    #DCB?
        $DCB=$False #$true for ROCE, $false for iWARP

    #IP addresses
        $Net1="172.16.1."
        $Net1VLAN=1 #VLAN for Storage (RDMA design) or Cluster network (traditional)
        $Net2="172.16.2."
        $Net2VLAN=2 #VLAN for LiveMigration network (traditional)
    #StartIP
        $IP=1
    
    #Additional Features
        $Bitlocker=$false #Install "Bitlocker" and "RSAT-Feature-Tools-BitLocker" on nodes?
        $StorageReplica=$false #Install "Storage-Replica" and "RSAT-Storage-Replica" on nodes?
        $Deduplication=$false #install "FS-Data-Deduplication" on nodes?

#endregion

#region Install features for management (Client needs RSAT, Server/Server Core have different features)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
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
    #Configure Active memory dump
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
            Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
        }

    #install roles and features
        #install Hyper-V using DISM (if nested virtualization is not enabled install-windowsfeature would fail)
            Invoke-Command -ComputerName $Servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
        
        #define features for Cluster Nodes
            $features="Failover-Clustering","Hyper-V-PowerShell"
            if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
            if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
            if ($Deduplication){$features+="FS-Data-Deduplication"}
        
        #install features on Cluster Nodes
            foreach ($Server in $Servers) {Install-WindowsFeature -Name $features -ComputerName $Server}

        #restart and wait for computers
            Restart-Computer $Servers -Protocol WSMan -Wait -For PowerShell
            Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region Configure Networking

    if (!$RDMA){
        Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -MinimumBandwidthMode Weight -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        #Configuring networking https://technet.microsoft.com/en-us/library/hh831829(v=ws.11).aspx
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management
            Add-VMNetworkAdapter -ManagementOS -Name "LiveMigration" -SwitchName "SETSwitch"
            Add-VMNetworkAdapter -ManagementOS -Name "Cluster" -SwitchName "SETSwitch"
            Set-VMNetworkAdapter -ManagementOS -Name "Cluster" -MinimumBandwidthWeight 40
            Set-VMNetworkAdapter -ManagementOS -Name Management -MinimumBandwidthWeight 5
            Set-VMNetworkAdapter -ManagementOS -Name "LiveMigration" -MinimumBandwidthWeight 20
            Set-VMSwitch "SETSwitch" -DefaultFlowMinimumBandwidthWeight 3
        }

        #Configure the host vNIC to use a Vlan.
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName Cluster -VlanId $Net1VLAN -Access -ManagementOS -CimSession $servers
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName LiveMigration -VlanId $Net2VLAN -Access -ManagementOS -CimSession $servers
        #Restart each host vNIC adapter so that the Vlan is active.
        Restart-NetAdapter "vEthernet (Cluster)" -CimSession $servers
        Restart-NetAdapter "vEthernet (LiveMigration)" -CimSession $servers


        $servers | ForEach-Object {
            New-NetIPAddress -IPAddress ($Net1+$IP.ToString()) -InterfaceIndex (Get-NetAdapter -Name *Cluster*       -CimSession $_).InterfaceIndex -CimSession $_ -PrefixLength 24
            New-NetIPAddress -IPAddress ($Net2+$IP.ToString()) -InterfaceIndex (Get-NetAdapter -Name *LiveMigration* -CimSession $_).InterfaceIndex -CimSession $_ -PrefixLength 24
            $IP++
        }
    }

    if ($RDMA){
        Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        $Servers | ForEach-Object {
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB_1 -SwitchName SETSwitch -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB_2 -SwitchName SETSwitch -Cimsession $_
            #configure IP Addresses
            New-NetIPAddress -IPAddress ($Net1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB_1)" -CimSession $_ -PrefixLength 24
            $IP++
            New-NetIPAddress -IPAddress ($Net1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB_2)" -CimSession $_ -PrefixLength 24
            $IP++
        }
        Start-Sleep 5
        Clear-DnsClientCache

        #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_1 -VlanId $Net1VLAN -Access -ManagementOS -CimSession $Servers
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_2 -VlanId $Net1VLAN -Access -ManagementOS -CimSession $Servers

        #Restart each host vNIC adapter so that the Vlan is active.
        Restart-NetAdapter "vEthernet (SMB_1)" -CimSession $Servers 
        Restart-NetAdapter "vEthernet (SMB_2)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each vRDMA NIC is mapped to separate pRDMA NIC)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $physicaladapters=Get-NetAdapter | where status -eq up | where Name -NotLike vEthernet* | Sort-Object
            Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_1" -ManagementOS -PhysicalNetAdapterName ($physicaladapters[0]).name
            Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_2" -ManagementOS -PhysicalNetAdapterName ($physicaladapters[1]).name
        }
        #Validate mapping
        Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | ft ComputerName,NetAdapterName,ParentAdapter 

        #Enable RDMA on the host vNIC adapters
        Enable-NetAdapterRDMA "vEthernet (SMB_1)","vEthernet (SMB_2)" -CimSession $Servers

        #verify RDMA
        Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | ft systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
    }

    #Verify that the VlanID is set
    Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | ft ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName

    #verify ip config 
    Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername

    if ($DCB -eq $True){
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

        #Create a Traffic class and give SMB Direct 30% of the bandwidth minimum.  The name of the class will be "SMB"
            Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB" -Priority 3 -BandwidthPercentage 30 -Algorithm ETS}
    }

    #Configure Hyper-V Port Load Balancing algorithm (in 1709 its already Hyper-V, therefore setting only for Windows Server 2016)
        Invoke-Command -ComputerName $servers -scriptblock {
            if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
                Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
            }
        }

#endregion

#region Create Cluster
    #create new cluster #
        New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
        Start-Sleep 5
        Clear-DnsClientCache
#endregion

#region Add CSVs and Witness disk
    #add csv disks
        $CSV_disks    = get-disk -cimsession $servers[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB} | sort number
        $i=1
        foreach ($CSV_disk in $CSV_disks){
            $volumename=("CSV"+($i).ToString())
            $CSV_disk      | Initialize-Disk -PartitionStyle GPT
            Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $servers[0] -Confirm:$false
            $CSV_disk     | set-disk -IsOffline $true
            $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterName
            $clusterDisk=Add-ClusterDisk -Cluster $ClusterName -InputObject $ClusterDisk
            $clusterDisk.name = $volumename
            $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterName -InputObject $ClusterDisk
            $ClusterSharedVolume.Name = $volumename
            $path=$ClusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
            $path=$path.Substring($path.LastIndexOf("\")+1)
            $FullPath = Join-Path -Path "c:\ClusterStorage\" -ChildPath $Path
                        Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ArgumentList $fullpath,$volumename -ScriptBlock {
            param($fullpath,$volumename);
            Rename-Item -Path $FullPath -NewName $volumename -PassThru
        }
            $i++
        }

    #add witness disks
        $witness_disk = get-disk -cimsession $servers[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
        $witness_disk  | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $servers[0] -Confirm:$false
        $witness_disk | Set-Disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterName
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterName -InputObject $ClusterDisk
        $clusterDisk.name = "Witness Disk"
        Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterName

#endregion

#region configure cluster networks
    if (!$RDMA){   
        #Rename networks
            (Get-ClusterNetwork -Cluster $clustername | where Role -eq ClusterAndClient).Name="Management"
            (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net1"0").Name="Cluster"
            (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net2"0").Name="LiveMigration"
            (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net2"0").role="None"

        #Set network for Live Migration https://blogs.msdn.microsoft.com/virtual_pc_guy/2013/05/02/using-powershell-to-configure-live-migration-networks-in-a-hyper-v-cluster/
            Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -ne "LiveMigration"}).ID))


    }else{
        #Rename networks
            (Get-ClusterNetwork -Cluster $clustername | where Role -eq ClusterAndClient).Name="Management"
            (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net1"0").Name="SMB"
        
        #Set network for Live Migration https://blogs.msdn.microsoft.com/virtual_pc_guy/2013/05/02/using-powershell-to-configure-live-migration-networks-in-a-hyper-v-cluster/
            Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -ne "SMB"}).ID))
        
        #set Live Migration to SMB on Hyper-V hosts
            Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $Servers

    }

#endregion

#test cluster
    Test-Cluster -Cluster $ClusterName 

#region Create some dummy VMs
    #grab CVSs, to create some VMs on each
        $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
    
    foreach ($CSV in $CSVs){
        1..3 | ForEach-Object {
            $VMName="TestVM$($CSV)_$_"
            Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterName).name[0] -ArgumentList $CSV,$VMName -ScriptBlock {
                param($CSV,$VMName);
                New-VM -Name $VMName -NewVHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 32GB -SwitchName SETSwitch -Generation 2 -Path "c:\ClusterStorage\$CSV\"
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
        }
    }

    #Set memory startup bytes for VMs to 32MB (just to show how you can work with all custer VMs)
        $nodes=(Get-ClusterNode -Cluster $ClusterName).Name
        Get-VM -CimSession $nodes | Set-VM -MemoryStartupBytes 32MB
#endregion

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
