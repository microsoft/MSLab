########################################
# Paste into elevated PowerShell in DC #
########################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region LAB Config

    #Site1
        #Cluster and RB Name
        $ClusterNameSite1="RC-Site1"
        $BrokerNameSite1="RC-Site1RB"

        #win2012Names
        $ServersSite1="S1_W2012_1","S1_W2012_2"

        #win2016names
        $Servers2016Site1="S1_W2016_1","S1_W2016_2"


    #Site2
        #Cluster and RB Name
        $ClusterNameSite2="RC-Site2"
        $BrokerNameSite2="RC-Site2RB"

        #win2012Names
        $ServersSite2="S2_W2012_1","S2_W2012_2"

        #win2016names
        $Servers2016Site2="S2_W2016_1","S2_W2016_2"

    #Site3
        #Cluster and RB Name
        $ClusterNameSite3="RC-Site3"
        $BrokerNameSite3="RC-Site3RB"

        #win2012Names
        $ServersSite3="S3_W2012_1","S3_W2012_2"

        #win2016names
        $Servers2016Site3="S3_W2016_1","S3_W2016_2"
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

#region Install roles on 2012R2 servers

    #install hyper-v and clustering 
    $servers=$ServersSite1+$ServersSite2+$ServersSite3

    Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
    foreach ($server in $servers) {Install-WindowsFeature -Name Failover-Clustering,RSAT-Clustering-PowerShell,Hyper-V-PowerShell -ComputerName $server} 
    #restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#endregion

#region create Clusters

    New-Cluster -Name $ClusterNameSite1 -Node $ServersSite1
    New-Cluster -Name $ClusterNameSite2 -Node $ServersSite2
    New-Cluster -Name $ClusterNameSite3 -Node $ServersSite3
    Start-Sleep 5
    Clear-DnsClientCache

#endregion

#region Configure Site 1 Cluster

    #add csv disks
    $CSV_disks = get-disk -cimsession $ServersSite1[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB}
    $i=1
    foreach ($CSV_disk in $CSV_disks){
        $volumename=("CSV"+($i).ToString())
        $CSV_disk | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $ServersSite1[0] -Confirm:$false
        $CSV_disk | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite1
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite1 -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterNameSite1 -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $NodeName = (Resolve-DnsName -Name $ClusterSharedVolume.OwnerNode | select -First 1).Name
        $Path = $ClusterSharedVolume.SharedVolumeInfo[0].FriendlyVolumeName.Replace( ":", "$" )
        $FullPath = Join-Path -Path "\\$NodeName" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru
        $i++
    }

    #add witness disks
    $witness_disk = get-disk -cimsession $ServersSite1[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $ServersSite1[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite1
    $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite1 -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterNameSite1

    #test cluster
    Test-Cluster -Cluster $ClusterNameSite1

#endregion

#region Configure Site 2 Cluster
    #add csv disks
    $CSV_disks    = get-disk -cimsession $ServersSite2[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB}
    $i=1
    foreach ($CSV_disk in $CSV_disks){
        $volumename=("CSV"+($i).ToString())
        $CSV_disk      | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $ServersSite2[0] -Confirm:$false
        $CSV_disk     | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite2
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite2 -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterNameSite2 -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $NodeName = ( Resolve-DnsName -Name $ClusterSharedVolume.OwnerNode | select -First 1).Name
        $Path = $ClusterSharedVolume.SharedVolumeInfo[0].FriendlyVolumeName.Replace( ":", "$" )
        $FullPath = Join-Path -Path "\\$NodeName" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru
        $i++
    }

    #add witness disks
    $witness_disk = get-disk -cimsession $ServersSite2[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $ServersSite2[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNameSite2
    $clusterDisk=Add-ClusterDisk -Cluster $ClusterNameSite2 -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterNameSite2

    #test cluster
    Test-Cluster -Cluster $ClusterNameSite2

#endregion

#region Configure Site 3 Cluster
    #add csv disks
    $CSV_disks    = get-disk -cimsession $Serverssite3[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB}
    $i=1
    foreach ($CSV_disk in $CSV_disks){
        $volumename=("CSV"+($i).ToString())
        $CSV_disk      | Initialize-Disk -PartitionStyle GPT
        Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $CSV_disk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumename -CimSession $Serverssite3[0] -Confirm:$false
        $CSV_disk     | set-disk -IsOffline $true
        $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNamesite3
        $clusterDisk=Add-ClusterDisk -Cluster $ClusterNamesite3 -InputObject $ClusterDisk
        $clusterDisk.name = $volumename
        $ClusterSharedVolume = Add-ClusterSharedVolume -Cluster $ClusterNamesite3 -InputObject $ClusterDisk
        $ClusterSharedVolume.Name = $volumename
        $NodeName = ( Resolve-DnsName -Name $ClusterSharedVolume.OwnerNode | select -First 1).Name
        $Path = $ClusterSharedVolume.SharedVolumeInfo[0].FriendlyVolumeName.Replace( ":", "$" )
        $FullPath = Join-Path -Path "\\$NodeName" -ChildPath $Path
        Rename-Item -Path $FullPath -NewName $volumename -PassThru
        $i++
    }

    #add witness disks
    $witness_disk = get-disk -cimsession $Serverssite3[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $Serverssite3[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $ClusterNamesite3
    $clusterDisk=Add-ClusterDisk -Cluster $ClusterNamesite3 -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $ClusterNamesite3

    #test cluster
    Test-Cluster -Cluster $ClusterNamesite3

#endregion

#region add some blank VMs in site1
    $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterNameSite1).Name
    foreach ($CSV in $CSVs){
        1..3 | ForEach-Object {
            $VMName="TestVM$($CSV)_$_"
            Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterNameSite1).name[0] -ArgumentList $CSV,$VMName -ScriptBlock {
                param($CSV,$VMName);
                New-VM -Name $VMName -NewVHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\$CSV\"
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterNameSite1
        }
    }
#endregion

#region enable Hyper-V Replica https://technet.microsoft.com/en-us/library/jj134207(v=ws.11).aspx

    #enable firewall rules on servers
    Enable-NetFirewallRule -CimSession ($ServersSite1+$ServersSite2+$ServersSite3) -DisplayName "Hyper-V Replica*"

    #add replica broker
    Add-ClusterServerRole   -Cluster $ClusterNameSite1 -Name $BrokerNameSite1
    Add-ClusterServerRole   -Cluster $ClusterNameSite2 -Name $BrokerNameSite2
    Add-ClusterServerRole   -Cluster $ClusterNameSite3 -Name $BrokerNameSite3
    
    Add-ClusterResource     -Cluster $ClusterNameSite1 -Name "Virtual Machine Replication Broker" -Type "Virtual Machine Replication Broker" -Group $BrokerNameSite1
    Add-ClusterResource     -Cluster $ClusterNameSite2 -Name "Virtual Machine Replication Broker" -Type "Virtual Machine Replication Broker" -Group $BrokerNameSite2
    Add-ClusterResource     -Cluster $ClusterNameSite3 -Name "Virtual Machine Replication Broker" -Type "Virtual Machine Replication Broker" -Group $BrokerNameSite3

    Add-ClusterResourceDependency -Cluster $ClusterNameSite1 "Virtual Machine Replication Broker" $BrokerNameSite1
    Add-ClusterResourceDependency -Cluster $ClusterNameSite2 "Virtual Machine Replication Broker" $BrokerNameSite2
    Add-ClusterResourceDependency -Cluster $ClusterNameSite3 "Virtual Machine Replication Broker" $BrokerNameSite3
    
    Start-ClusterGroup $BrokerNameSite1 -Cluster $ClusterNameSite1
    Start-ClusterGroup $BrokerNameSite2 -Cluster $ClusterNameSite2
    Start-ClusterGroup $BrokerNameSite3 -Cluster $ClusterNameSite3

    #configure replication
    Invoke-Command -ComputerName ($ServersSite1+$ServersSite2+$ServersSite3) -ScriptBlock {
        Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos -ReplicationAllowedFromAnyServer $true -DefaultStorageLocation c:\Clusterstorage\CSV1 
    }

    #configure Site1 to site2 replication

    (Get-ClusterNode -Cluster $ClusterNameSite1).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            Get-VM | Enable-VMReplication -ReplicaServerName $using:BrokerNameSite2 -ReplicaServerPort 80 -AuthenticationType Kerberos -RecoveryHistory 0 -ReplicationFrequencySec 30
        }
    }

    #start initial replication
    (Get-ClusterNode -Cluster $ClusterNameSite1).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            Get-VM | Start-VMInitialReplication
        }
    }

    #extend replication to site 3
    (Get-ClusterNode -Cluster $ClusterNameSite2).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            Get-VM | Enable-VMReplication -ReplicaServerName $using:BrokerNameSite3 -ReplicaServerPort 80 -AuthenticationType Kerberos -RecoveryHistory 0 -ReplicationFrequencySec 300
        }
    }

    #start initial replication
    (Get-ClusterNode -Cluster $ClusterNameSite2).Name | ForEach-Object {
        Invoke-Command -ComputerName $_ -ScriptBlock {
            Get-VM | Start-VMInitialReplication
        }
    }

#endregion

#region Prepare 2016 nodes
    $servers=$Servers2016Site1+$Servers2016Site2+$Servers2016Site3

    Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
    foreach ($server in $servers) {Install-WindowsFeature -Name Failover-Clustering,RSAT-Clustering-PowerShell,Hyper-V-PowerShell -ComputerName $server} 
    #restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

    #enable firewall for replica
    Enable-NetFirewallRule -CimSession $servers -DisplayName "Hyper-V Replica*"

#endregion

#region Roll the upgrade
    #Site 3 first
    #Note Cluster update versions
    Get-Cluster -Name $ClusterNamesite3 | fl Clus*

    #remove 2012 nodes and add 2016
    1..($Serverssite3).Count | ForEach-Object {
        $temp=$_-1
        Suspend-ClusterNode -Cluster $ClusterNamesite3 -Drain -Name $Serverssite3[$temp] -Wait
        Remove-ClusterNode -Cluster $ClusterNamesite3 -Name $Serverssite3[$temp] -Force 
        Add-ClusterNode -Cluster $ClusterNamesite3 -Name $Servers2016site3[$temp] 
    }
    #Note Cluster update versions
    Get-Cluster -Name $ClusterNamesite3 | fl Clus*
    # upgrade Cluster version
    Update-ClusterFunctionalLevel -Cluster $ClusterNamesite3 -Force
    #and version after upgrade
    Get-Cluster -Name $ClusterNamesite3 | fl Clus*

    #then site 2
    #remove 2012 nodes and add 2016
    1..($ServersSite2).Count | ForEach-Object {
        $temp=$_-1
        Suspend-ClusterNode -Cluster $ClusterNameSite2 -Drain -Name $ServersSite2[$temp] -Wait
        Remove-ClusterNode -Cluster $ClusterNameSite2 -Name $ServersSite2[$temp] -Force 
        Add-ClusterNode -Cluster $ClusterNameSite2 -Name $Servers2016Site2[$temp] 
    }
    # upgrade Cluster version
    Update-ClusterFunctionalLevel -Cluster $ClusterNameSite2 -Force

    #and then Site 1
    #remove 2012 nodes and add 2016
    1..($ServersSite1).Count | ForEach-Object {
        $temp=$_-1
        Suspend-ClusterNode -Cluster $ClusterNameSite1 -Drain -Name $ServersSite1[$temp] -Wait
        Remove-ClusterNode -Cluster $ClusterNameSite1 -Name $ServersSite1[$temp] -Force 
        Add-ClusterNode -Cluster $ClusterNameSite1 -Name $Servers2016Site1[$temp] 
    }
    # upgrade Cluster version
    Update-ClusterFunctionalLevel -Cluster $ClusterNameSite1 -Force

    # upgrade VMs version (VMs has to turned off)
    Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterNameSite1).Name | Update-VMVersion -Force
    # destination sites needs to be also manually updated, othervise replica stops
    Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterNameSite2).Name | Update-VMVersion -Force
    Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterNameSite3).Name | Update-VMVersion -Force
#endregion

#region move all VMs to their CSVs

    foreach ($ClusterNode in ($Servers2016Site2,$Servers2016Site3)){
        $VMs=get-vm -CimSession $ClusterNode
        foreach ($VM in $VMs){
            if ($VM.Name -like "*CSV1*"){
                $PathtoCSV="C:\ClusterStorage\CSV1"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
            elseif($VM.Name -like "*CSV2*"){
                $PathtoCSV="C:\ClusterStorage\CSV2"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
            elseif($VM.Name -like "*CSV3*"){
                $PathtoCSV="C:\ClusterStorage\CSV3"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
            elseif($VM.Name -like "*CSV4*"){
                $PathtoCSV="C:\ClusterStorage\CSV4"
                $DestinationStoragePath="$($PathtoCSV)\$($VM.name)"
                $VM | Move-VMStorage -DestinationStoragePath $DestinationStoragePath
            }
        }
        
    }

#endregion

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
 