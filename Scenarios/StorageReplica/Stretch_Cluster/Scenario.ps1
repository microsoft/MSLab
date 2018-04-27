
#stretch cluster using shared storage. More info here https://technet.microsoft.com/en-us/windows-server-docs/storage/storage-replica/stretch-cluster-replication-using-shared-storage

#####################################
# Run from DC or management machine #
#####################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region LabConfig

$Site1Servers='Replica1','Replica2'
$Site2Servers='Replica3','Replica4'

$ClusterName='Stretch-Cluster'
$ClusterIP="10.0.0.112"

$ReplicaNetwork="172.16.1.0"

$ReplicationMode="Synchronous" #Synchronous or Asynchronous
$AsyncRPO=300  #Recovery point objective in seconds. Default is 5M

$Site1VMNames="TestVM1_Site1","TestVM2_Site1"
$Site2VMNames="TestVM1_Site2","TestVM2_Site2"

$Servers=$Site1Servers+$Site2Servers

#Nano server?
$NanoServer=$False

#Diskconfig
## Note: GroupID is not used. It can be used if multiple Data disks are present in each site.
$diskconfig=@()
$diskconfig+=@{DiskNumber=1 ; FriendlyName="Log1"  ; FileSystem="REFS" ; Site="Seattle"   ; PrimarySite="Seattle"   ; Role="Log"  ; GroupID=1 ; RGName="Data1Source"      }
$diskconfig+=@{DiskNumber=2 ; FriendlyName="Log2"  ; FileSystem="REFS" ; Site="Seattle"   ; PrimarySite="Bellevue"  ; Role="Log"  ; GroupID=2 ; RGName="Data2Destination" }
$diskconfig+=@{DiskNumber=1 ; FriendlyName="Log1"  ; FileSystem="REFS" ; Site="Bellevue"  ; PrimarySite="Seattle"   ; Role="Log"  ; GroupID=1 ; RGName="Data1Destination" }
$diskconfig+=@{DiskNumber=2 ; FriendlyName="Log2"  ; FileSystem="REFS" ; Site="Bellevue"  ; PrimarySite="Bellevue"  ; Role="Log"  ; GroupID=2 ; RGName="Data2Source"      }
$diskconfig+=@{DiskNumber=3 ; FriendlyName="Data1" ; FileSystem="REFS" ; Site="Seattle"   ; PrimarySite="Seattle"   ; Role="Data" ; GroupID=1 ; RGName="Data1Source"      ; CSVFolderName="Data1"}
$diskconfig+=@{DiskNumber=4 ; FriendlyName="Data2" ; FileSystem="REFS" ; Site="Seattle"   ; PrimarySite="Bellevue"  ; Role="Data" ; GroupID=2 ; RGName="Data2Destination" }
$diskconfig+=@{DiskNumber=3 ; FriendlyName="Data1" ; FileSystem="REFS" ; Site="Bellevue"  ; PrimarySite="Seattle"   ; Role="Data" ; GroupID=1 ; RGName="Data1Destination" }
$diskconfig+=@{DiskNumber=4 ; FriendlyName="Data2" ; FileSystem="REFS" ; Site="Bellevue"  ; PrimarySite="Bellevue"  ; Role="Data" ; GroupID=2 ; RGName="Data2Source"      ; CSVFolderName="Data2"}

#ask for parent vhdx
## Note: easiest is to use Nano server VHD from Windows Server 2016 lab parent disks folder.
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
    }
    $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
    If($openFile.ShowDialog() -eq "OK"){
        Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
    } 
    if (!$openFile.FileName){
        Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
    }
    $VHDPath = $openFile.FileName

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

#region install roles and features to servers
    #Install required roles
        if ($NanoServer -eq $True){
            foreach ($server in $servers) {Install-WindowsFeature -Name Storage-Replica,RSAT-Storage-Replica,FS-FileServer -ComputerName $server} 
        }else{
            foreach ($server in $servers) {Install-WindowsFeature -Name "Storage-Replica","RSAT-Storage-Replica","FS-FileServer","Failover-Clustering" -ComputerName $server} 
        }

    #install Hyper-V
        if ($NanoServer -eq $false){
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
            foreach ($server in $servers) {Install-WindowsFeature -Name "Hyper-V-PowerShell" -ComputerName $server} 
        }

    #restart those servers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 10 #Failsafe
#endregion

#note: for sake of complexity, creating switches is skipped

#region create and configure cluster

    #create cluster
        if ($ClusterIP){
            New-Cluster -Name $ClusterName -Node $servers -NoStorage -StaticAddress $ClusterIP
        }else{
            New-Cluster -Name $ClusterName -Node $servers -NoStorage 
        }
        Start-Sleep 5
        Clear-DnsClientCache

    #configure fault domains
        New-ClusterFaultDomain -Name Seattle -Type Site -Description "Primary" -Location "Seattle Datacenter" -CimSession $ClusterName
        New-ClusterFaultDomain -Name Bellevue -Type Site -Description "Secondary" -Location "Bellevue Datacenter" -CimSession $ClusterName

        foreach ($Site1Server in $Site1Servers){
            Set-ClusterFaultDomain -Name $Site1Server -Parent Seattle -CimSession $ClusterName    
        }
        foreach ($Site2Server in $Site2Servers){
            Set-ClusterFaultDomain -Name $Site2Server -Parent Bellevue -CimSession $ClusterName    
        }

        (Get-Cluster -Name $ClusterName).PreferredSite="Seattle"  

    #get Cluster Fault domain XML to validate configuration
        Get-ClusterFaultDomainXML -CimSession $ClusterName

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
    
    #rename storage replica network
        (Get-ClusterNetwork -Cluster $ClusterName | where Address -eq $ReplicaNetwork).Name="ReplicaNetwork"

#endregion

#region format disks
    foreach ($disk in $diskconfig){
        if ($Disk.site -eq "Seattle"){
            New-Volume -DiskNumber $disk.DiskNumber -FriendlyName $disk.FriendlyName -FileSystem $disk.FileSystem -CimSession $Site1Servers[0] -ErrorAction SilentlyContinue
        }
        if ($Disk.site -eq "Bellevue") {
            New-Volume -DiskNumber $disk.DiskNumber -FriendlyName $disk.FriendlyName -FileSystem $disk.FileSystem -CimSession $Site2Servers[0] -ErrorAction SilentlyContinue
        }
    }

#endregion

#region list storage and add paths to Diskconfig variable
    #List available disks for replication on Node $Site1Servers[0] and add path to diskconfig
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site1Servers[0]

    $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        $disk=Get-Disk -CimSession $Site1Servers[0] | where Guid -eq $DiskGuidValue.Value
        $volume=$disk | Get-Partition | Get-Volume
        #add path to diskconfig
        ($diskconfig | where Site -eq Seattle | where DiskNumber -eq $disk.Number).Path=$volume.Path
        #list volume
        $volume |Select-Object @{N="Name"; E={$DiskResource.Name}}, @{N="Status"; E={$DiskResource.State}}, DriveLetter, Path, FileSystemLabel, Size, SizeRemaining | FT -AutoSize
    }

#List available disks for replication on Node $Site2Servers[0]
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site2Servers[0]
    $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        $disk=Get-Disk -CimSession $Site2Servers[0] | where Guid -eq $DiskGuidValue.Value
        $volume=$disk | Get-Partition | Get-Volume
        #add path to diskconfig
        ($diskconfig | where Site -eq Bellevue | where DiskNumber -eq $disk.Number).Path=$volume.Path
        #list volume
        $volume |Select-Object @{N="Name"; E={$DiskResource.Name}}, @{N="Status"; E={$DiskResource.State}}, DriveLetter, Path, FileSystemLabel, Size, SizeRemaining | FT -AutoSize
    }
    
#move group back
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site1Servers[0]

#endregion

#region rename cluster disk resources for easier identification

    #rename cluster disk resources for easier identification in Seattle
        $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
        foreach ($DiskResource in $DiskResources){
            $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
            $filesystemlabel=(Get-Disk -CimSession $Site1Servers[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume).FilesystemLabel
                $DiskResource.name="$($filesystemlabel)_Seattle"
        }
    
    #move available disks group to Bellevue
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site2Servers[0]

    #rename cluster disk resources for easier identification in Bellevue
    $DiskResources = Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.ResourceType -eq 'Physical Disk' -and $_.State -eq 'Online' }
    foreach ($DiskResource in $DiskResources){
        $DiskGuidValue = $DiskResource | Get-ClusterParameter DiskIdGuid
        $filesystemlabel=(Get-Disk -CimSession $Site2Servers[0] | where { $_.Guid -eq $DiskGuidValue.Value } | Get-Partition | Get-Volume).FilesystemLabel
            $DiskResource.name="$($filesystemlabel)_Bellevue"
    }
    
    #move available disks group to Redmond again
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site1Servers[0]

#endregion

#region add Data disks to CSVs

    #add disk from site1
    $CSVConfig=$diskconfig | where site -eq Seattle | where CSVFoldername #grab CSV name from diskconfig for site1
    $CSV=Get-ClusterResource -Cluster $ClusterName -name "$($CSVConfig.FriendlyName)_Seattle" | Add-ClusterSharedVolume
    #rename csv
    Invoke-Command -ComputerName $CSV.OwnerNode -ScriptBlock {Rename-Item -Path $using:csv.SharedVolumeInfo.friendlyvolumename -NewName $using:CSVConfig.CSVFolderName}

    #move available disks group to Bellevue
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site2Servers[0]

    #add data 2 to CSV
    $CSVConfig=$diskconfig | where site -eq Bellevue | where CSVFoldername #grab CSV name from diskconfig for site1
    $CSV=Get-ClusterResource -Cluster $ClusterName -name "$($CSVConfig.FriendlyName)_Bellevue" | Add-ClusterSharedVolume
    #rename csv to Data2
    Invoke-Command -ComputerName $CSV.OwnerNode  -ScriptBlock {Rename-Item -Path $using:csv.SharedVolumeInfo.friendlyvolumename -NewName $using:CSVConfig.CSVFolderName}

    #move group back
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site1Servers[0]

#endregion

#region enable replication
    #enable replication from Seattle
    $Sourcelog=        $diskconfig  | where site -eq Seattle  | where role -eq log  | where PrimarySite -eq Seattle
    $Sourcedata=       $diskconfig  | where site -eq Seattle  | where role -eq data | where PrimarySite -eq Seattle
    $Destinationlog =  $diskconfig  | where site -eq Bellevue | where role -eq log  | where PrimarySite -eq Seattle
    $Destinationdata = $diskconfig  | where site -eq Bellevue | where role -eq data | where PrimarySite -eq Seattle

    if ($ReplicationMode -eq "Asynchronous"){
        New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Site1Servers[0] -SourceRGName $SourceData.RGName -SourceVolumeName "C:\ClusterStorage\$($sourceData.CSVFolderName)" -SourceLogVolumeName $sourcelog.Path -DestinationComputerName $Site2Servers[0] -DestinationRGName $DestinationData.RGName -DestinationVolumeName $destinationdata.Path -DestinationLogVolumeName $destinationlog.Path
    }else{
        New-SRPartnership -SourceComputerName $Site1Servers[0] -SourceRGName $SourceData.RGName -SourceVolumeName "C:\ClusterStorage\$($sourceData.CSVFolderName)" -SourceLogVolumeName $sourcelog.Path -DestinationComputerName $Site2Servers[0] -DestinationRGName $DestinationData.RGName -DestinationVolumeName $destinationdata.Path -DestinationLogVolumeName $destinationlog.Path
    }

    #configure storage replica network
    Start-Sleep 5
    Set-SRNetworkConstraint -SourceComputerName $ClusterName -SourceRGName $SourceData.RGName -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $ClusterName -DestinationRGName $DestinationData.RGName -DestinationNWInterface "ReplicaNetwork" -ErrorAction SilentlyContinue  
    Get-SRNetworkConstraint -SourceComputerName $ClusterName -SourceRGName $SourceData.RGName -DestinationComputerName $ClusterName -DestinationRGName $DestinationData.RGName

    #Wait until synced
    do{
        $r=(Get-SRGroup -CimSession $Site2Servers[0] -Name $Destinationdata.RGName).replicas
        [System.Console]::Write("Number of remaining Gbytes {0}`r", $r.NumOfBytesRemaining/1GB)
        Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
    }until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
    Write-Output "Replica Status: "$r.replicationstatus

    
    #enable replication from Bellevue
    #move available disks group to Bellevuefirst
    Move-ClusterGroup -Cluster $ClusterName -Name "available storage" -Node $Site2Servers[0]
    
    $Sourcelog =       $diskconfig  | where site -eq Bellevue | where role -eq log  | where PrimarySite -eq Bellevue
    $Sourcedata =      $diskconfig  | where site -eq Bellevue | where role -eq data | where PrimarySite -eq Bellevue
    $Destinationlog =  $diskconfig  | where site -eq Seattle  | where role -eq log  | where PrimarySite -eq Bellevue
    $Destinationdata = $diskconfig  | where site -eq Seattle  | where role -eq data | where PrimarySite -eq Bellevue

    if ($ReplicationMode -eq "Asynchronous"){
        New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Site2Servers[0] -SourceRGName $SourceData.RGName -SourceVolumeName "C:\ClusterStorage\$($sourceData.CSVFolderName)" -SourceLogVolumeName $sourcelog.Path -DestinationComputerName $Site1Servers[0] -DestinationRGName $DestinationData.RGName -DestinationVolumeName $destinationdata.Path -DestinationLogVolumeName $destinationlog.Path
    }else{
        New-SRPartnership -SourceComputerName $Site2Servers[0] -SourceRGName $SourceData.RGName -SourceVolumeName "C:\ClusterStorage\$($sourceData.CSVFolderName)" -SourceLogVolumeName $sourcelog.Path -DestinationComputerName $Site1Servers[0] -DestinationRGName $DestinationData.RGName -DestinationVolumeName $destinationdata.Path -DestinationLogVolumeName $destinationlog.Path
    }

    #configure storage replica network
    Start-Sleep 5
    Set-SRNetworkConstraint -SourceComputerName $ClusterName -SourceRGName $SourceData.RGName -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $ClusterName -DestinationRGName $DestinationData.RGName -DestinationNWInterface "ReplicaNetwork" -ErrorAction SilentlyContinue    
    Get-SRNetworkConstraint -SourceComputerName $ClusterName -SourceRGName $SourceData.RGName -DestinationComputerName $ClusterName -DestinationRGName $DestinationData.RGName
    
    #Wait until synced
    do{
        $r=(Get-SRGroup -CimSession $Site1Servers[0] -Name $Destinationdata.RGName).replicas
        [System.Console]::Write("Number of remaining Gbytes {0}`r", $r.NumOfBytesRemaining/1GB)
        Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
    }until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
    Write-Output "Replica Status: "$r.replicationstatus

#endregion

#region Create VMs
    
    #Create some VMs in Redmond
    $CSVConfig=$diskconfig | where site -eq Seattle | where CSVFoldername #grab CSV name from diskconfig for site1
    if ($VHDPath){
        foreach ($Site1VMName in $Site1VMNames){
            New-Item -Path "\\$clusterName\ClusterStorage$\$($CSVConfig.CSVFolderName)\$Site1VMName\Virtual Hard Disks" -ItemType Directory
            Copy-Item -Path $VHDPath -Destination "\\$clusterName\ClusterStorage$\$($CSVConfig.CSVFolderName)\$Site1VMName\Virtual Hard Disks\$($Site1VMName)_Disk1.vhdx"
            New-VM -Name $Site1VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\$($CSVConfig.CSVFolderName)" -VHDPath "c:\ClusterStorage\$($CSVConfig.CSVFolderName)\$Site1VMName\Virtual Hard Disks\$($Site1VMName)_Disk1.vhdx" -ComputerName $Site1Servers[0]
            Start-VM -name $Site1VMName -ComputerName $Site1Servers[0]
            Add-ClusterVirtualMachineRole -VMName $Site1VMName -Cluster $clusterName
        }
    }

    #Create some VMs in Bellevue
    $CSVConfig=$diskconfig | where site -eq Bellevue | where CSVFoldername #grab CSV name from diskconfig for site1
    if ($VHDPath){
        foreach ($Site2VMName in $Site2VMNames){
            New-Item -Path "\\$clusterName\ClusterStorage$\$($CSVConfig.CSVFolderName)\$Site2VMName\Virtual Hard Disks" -ItemType Directory
            Copy-Item -Path $VHDPath -Destination "\\$clusterName\ClusterStorage$\$($CSVConfig.CSVFolderName)\$Site2VMName\Virtual Hard Disks\$($Site2VMName)_Disk1.vhdx"
            New-VM -Name $Site2VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\$($CSVConfig.CSVFolderName)" -VHDPath "c:\ClusterStorage\$($CSVConfig.CSVFolderName)\$Site2VMName\Virtual Hard Disks\$($Site2VMName)_Disk1.vhdx" -ComputerName $Site2Servers[0]
            Start-VM -name $Site2VMName -ComputerName $Site2Servers[0]
            Add-ClusterVirtualMachineRole -VMName $Site2VMName -Cluster $clusterName
        }
    }

#endregion

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
 