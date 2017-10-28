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
    #Nano server?
    $NanoServer=$false
    #RDMA? Actually "RDMA" based design. If false, traditional converged design is deployed
    $RDMA=$false
    $DCB=$False #$true for ROCE, $false for iWARP


    #IPs
    $Net1="172.16.1."
    $Net1VLAN=1 #VLAN for Storage (RDMA design) or Cluster network (traditional)
    $Net2="172.16.2."
    $Net2VLAN=2 #VLAN for LiveMigration network (traditional)
    #StartIP
    $IP=1
#endregion

#region install features for management (this is bit complex as it tests if its Server or Client...)
    $WindowsInstallationType=(Get-ComputerInfo).WindowsInstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
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

#Configure roles
    if (-not $NanoServer){
        #install Hyper-V for core servers - in case you are deploying core servers instead of Nano
        Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
        foreach ($server in $servers) {Install-WindowsFeature -Name "Failover-Clustering","Data-Center-Bridging","Hyper-V-PowerShell" -ComputerName $server} 
        #restart and wait for computers
        Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 20 #Failsafe
    }

#region configure Networking
    #Configuring networking https://technet.microsoft.com/en-us/library/hh831829(v=ws.11).aspx
    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -MinimumBandwidthMode Weight -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

    if (!$RDMA){
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
        ###Configure networking###
        Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -MinimumBandwidthMode Weight -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        $Servers | ForEach-Object {
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
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_1 -VlanId $Net1VLAN -Access -ManagementOS -CimSession $Servers
        Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_2 -VlanId $Net1VLAN -Access -ManagementOS -CimSession $Servers

        #Restart each host vNIC adapter so that the Vlan is active.
        Restart-NetAdapter "vEthernet (SMB_1)" -CimSession $Servers 
        Restart-NetAdapter "vEthernet (SMB_2)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each vRDMA NIC is mapped to separate pRDMA NIC)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $physicaladapters=Get-NetAdapter | where status -eq up | where Name -NotLike vEthernet* | Sort-Object
            Set-VMNetworkAdapterTeamMapping –VMNetworkAdapterName "SMB_1" –ManagementOS –PhysicalNetAdapterName ($physicaladapters[0]).name
            Set-VMNetworkAdapterTeamMapping –VMNetworkAdapterName "SMB_2" –ManagementOS –PhysicalNetAdapterName ($physicaladapters[1]).name
        }
        #Validate mapping
        Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | ft ComputerName,NetAdapterName,ParentAdapter 

        #Enable RDMA on the host vNIC adapters
        Enable-NetAdapterRDMA "vEthernet (SMB_1)","vEthernet (SMB_2)" -CimSession $Servers

        #verify RDMA
        Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | ft systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
    }

  
    #Verify that the VlanID is set
    Get-VMNetworkAdapterVlan –ManagementOS -CimSession $servers |Sort-Object -Property Computername | ft ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName

    #verify ip config 
    Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername

    if ($DCB -eq $True){
        ##Configure QoS
        New-NetQosPolicy "SMB" –NetDirectPortMatchCondition 445 –PriorityValue8021Action 3 -CimSession $servers

        #Turn on Flow Control for SMB
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl –Priority 3}

        #Disable flow control for other traffic
            Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl –Priority 0,1,2,4,5,6,7}

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
            Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB" –Priority 3 –BandwidthPercentage 30 –Algorithm ETS}
    }

#endregion

#region Create and configure Cluster
    #create new cluster #
        New-Cluster –Name $ClusterName –Node $servers -StaticAddress $ClusterIP
        Start-Sleep 5
        Clear-DnsClientCache

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


    if (!$RDMA){   
        #Set networks
        (Get-ClusterNetwork -Cluster $clustername | where Role -eq ClusterAndClient).Name="Management"
        (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net1"0").Name="Cluster"
        (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net2"0").Name="LiveMigration"
        (Get-ClusterNetwork -Cluster $clustername | where Address -eq $net2"0").role="None"

        #Set network for Live Migration https://blogs.msdn.microsoft.com/virtual_pc_guy/2013/05/02/using-powershell-to-configure-live-migration-networks-in-a-hyper-v-cluster/
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -ne "LiveMigration"}).ID))


    }

    #test cluster
    Test-Cluster -Cluster $ClusterName 
    
    # Add some VMs
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