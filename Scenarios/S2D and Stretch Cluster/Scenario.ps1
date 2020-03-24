#region install prereqs
    #install management features
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica
#endregion

#region install features and configure hw timeout for virtual environment
        $servers="Site1S2D1","Site1S2D2","Site2S2D1","Site2S2D2"

        #install roles and features
        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
            if ($result.ExitCode -eq "failed"){
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            }
        }
        #install features
        $features="Failover-Clustering","Hyper-V-PowerShell","Storage-Replica","RSAT-Storage-Replica"
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 

        #IncreaseHW Timeout for virtual environments to 30s
        Invoke-Command -ComputerName $servers -ScriptBlock {
            #New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -ItemType Directory
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530
        }
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA )
        $servers="Site1S2D1","Site1S2D2","Site2S2D1","Site2S2D2"
        $vSwitchName="vSwitch"
        $StorNet1="172.16.1."
        $StorNet2="172.16.2."
        $StorVLAN1=1
        $StorVLAN2=2
        $IP=1 #StartIP

        #Create Virtual Switches and Virtual Adapters
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

        $Servers | ForEach-Object {
            #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName $vSwitchName -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName $vSwitchName -Cimsession $_

            #configure IP Addresses
            New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
            New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
            $IP++
        }

        Start-Sleep 5
        Clear-DnsClientCache

        #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $Servers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $Servers

        #Restart each host vNIC adapter so that the Vlan is active.
            Restart-NetAdapter "vEthernet (SMB01)" -CimSession $Servers 
            Restart-NetAdapter "vEthernet (SMB02)" -CimSession $Servers

        #Enable RDMA on the host vNIC adapters (should be done just for real environments)
            Enable-NetAdapterRDMA "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
            Invoke-Command -ComputerName $servers -ScriptBlock {
                    $physicaladapters=(get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions | Sort-Object
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
                }
#endregion

#region Create cluster and configure witness (file share or Azure)
    $servers="Site1S2D1","Site1S2D2","Site2S2D1","Site2S2D2"
    $ClusterName="S2D-S-Cluster"
    $WitnessType="Cloud" #or FileShare
    $ResourceGroupName="WSLabCloudWitness"
    $StorageAccountName="wslabcloudwitness$(Get-Random -Minimum 100000 -Maximum 999999)"

    if ($WitnessType -eq "Cloud"){
        #download Azure modules
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name Az.Accounts -Force
        Install-Module -Name Az.Resources -Force
        Install-Module -Name Az.Storage -Force

        #login to Azure
        Login-AzAccount -UseDeviceAuthentication
        #select context if more available
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context | Out-GridView -OutpuMode Single | Set-AzContext
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
    }

    Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
    #Create new cluster using Distributed ManagementPoint
    New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType Distributed -NoStorage
    #or you can create cluster with traditional A record on CNO.
    #New-Cluster -Name $ClusterName -Node $servers -NoStorage

    Start-Sleep 5
    Clear-DnsClientCache

    if ($WitnessType -eq "Azure"){
        Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $StorageAccountName -AccessKey $StorageAccountAccessKey -Endpoint "core.windows.net"
    }else{
        #Configure Witness on DC 
            #Create new directory
                $WitnessName=$Clustername+"Witness"
                Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
                $accounts=@()
                $accounts+="corp\$ClusterName$"
                $accounts+="corp\Domain Admins"
                New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
            #Set NTFS permissions 
                Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
            #Set Quorum
                Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
    }
#endregion

#region Configure Cluster Networks
    $ClusterName="S2D-S-Cluster"
    $StorNet1="172.16.1."
    $StorNet2="172.16.2."
    $ReplicaNet1="172.16.11."
    $ReplicaNet2="172.16.12."

    #configure Replica Networks role
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet1"0").Role="none"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet2"0").Role="none"

    #rename networks
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB1"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB2"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet1"0").Name="ReplicaNet1"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet2"0").Name="ReplicaNet2"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name="Management"

    #configure Live Migration networks to use only SMB nics
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value  ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -notlike "smb*"}).ID))
        Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers
#endregion

#region configure Cluster-Aware-Updating
    $ClusterName="S2D-S-Cluster"
    $CAURoleName="S2D-S-Clus-CAU"
    #Install required features on nodes.
        $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
        foreach ($ClusterNode in $ClusterNodes){
            Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
        }
    #add role
        Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
#endregion

#region Configure Fault Domains (just an example) https://docs.microsoft.com/en-us/windows-server/failover-clustering/fault-domains
    #either static

    $ClusterName="S2D-S-Cluster"
    $xml =  @"
    <Topology>
        <Site Name="DC01SEA" Location="Contoso DC1, 123 Example St, Room 4010, Seattle">
            <Node Name="Site1S2D1"/>
            <Node Name="Site1S2D2"/>
        </Site>
        <Site Name="DC02RED" Location="Contoso DC2, 123 Example St, Room 4010, Redmond">
            <Node Name="Site2S2D1"/>
            <Node Name="Site2S2D2"/>
        </Site>
    </Topology>
"@
    <# or with rack info (note, it will configure Rack FaultDomainAwarenessDefault after enable cluster s2d as multiple racks are present. Also logic for querying nodes in sites needs to be changed )
    $xml =  @"
    <Topology>
        <Site Name="DC01SEA" Location="Contoso DC1, 123 Example St, Room 4010, Seattle">
            <Rack Name="SEA-Rack01" Location="Contoso DC1, Room 4010, Aisle A, Rack 01">
                <Node Name="Site1S2D1"/>
                <Node Name="Site1S2D2"/>
            </Rack>
        </Site>
        <Site Name="DC02RED" Location="Contoso DC2, 123 Example St, Room 4010, Redmond">
            <Rack Name="RED-Rack01" Location="Contoso DC2, Room 4010, Aisle A, Rack 01">
                <Node Name="Site2S2D1"/>
                <Node Name="Site2S2D2"/>
            </Rack>
        </Site>
    </Topology>
"@
#>
    Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName

    #validate
    Get-ClusterFaultDomainXML -CimSession $ClusterName

    <#or bit more dynamic
    $Site1Name="DC01SEA"
    $Site2Name="DC02RED"
    $Site1NamesPrefix="Site1S2D"
    $Site2NamesPrefix="Site2S2D"
    $NumberOfNodesPerSite=2

    New-ClusterFaultDomain -Name "$Site1Name" -FaultDomainType Site -Location "Contoso HQ, 123 Example St, Room 4010" -CimSession $ClusterName
    New-ClusterFaultDomain -Name "$Site2Name" -FaultDomainType Site -Location "Contoso HQ, 123 Example St, Room 4010" -CimSession $ClusterName
    New-ClusterFaultDomain -Name "$Site1Name-Rack01" -FaultDomainType Rack -Location "Contoso DC1, Room 4010, Aisle A, Rack 01" -CimSession $ClusterName
    New-ClusterFaultDomain -Name "$Site2Name-Rack01" -FaultDomainType Rack -Location "Contoso DC1, Room 4010, Aisle A, Rack 01" -CimSession $ClusterName

    #add rack to sites
    Set-ClusterFaultDomain -Name "$Site1Name-Rack01"  -Parent "$Site1Name" -CimSession $ClusterName
    Set-ClusterFaultDomain -Name "$Site2Name-Rack01"  -Parent "$Site2Name" -CimSession $ClusterName

    #add nodes to racks
    1..$NumberOfNodesPerSite | ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_"  -Parent "$Site1Name-Rack01" -CimSession $ClusterName}
    1..$NumberOfNodesPerSite | ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_"  -Parent "$Site2Name-Rack01" -CimSession $ClusterName}

    #validate
    Get-ClusterFaultDomainXML -CimSession $ClusterName
    #>
#endregion

#region Enable Cluster S2D and check Pool and Tiers
$ClusterName="S2D-S-Cluster"
#Enable-ClusterS2D
Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

#display pool
Get-StoragePool -IsPrimordial $false -CimSession $ClusterName

#Display disks
Get-StoragePool -IsPrimordial $false -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

#Get Storage Tiers
Get-StorageTier -CimSession $ClusterName

#Wait for Clusterperformance history, just to make sure all finished before creating volumes
do{Start-Sleep 5}until(
    Get-VirtualDisk -FriendlyName ClusterPerformanceHistory -CimSession $clustername -ErrorAction Ignore
)

#endregion

#region Create Volumes
    $ClusterName="S2D-S-Cluster"
    $NumberOfVolumesPerSite=4 #2 per node for source (for each node 1), 2 per node for destination from other site (+logs)
    $VolumeSize=1TB
    $LogSize=100GB
    $VolumeNamePrefix="vDisk"
    $LogDiskPrefix="Log-vDisk"

    $sites=(Get-StorageFaultDomain -CimSession $ClusterName -Type StorageSite).FriendlyName
    #$pools=Get-StoragePool -CimSession $clustername -IsPrimordial $false

    foreach ($site in $sites){
        $PoolID=(Get-StoragePool -CimSession $ClusterName -FriendlyName "Pool for Site $site").UniqueId.TrimStart("{").TrimEnd("}")
        $PoolOwnerNode=(Get-ClusterGroup -Name $PoolID -Cluster $ClusterName).OwnerNode.Name
        #Move Available Storage to Same node as Pool (just to have it in the same site)
        $AvailableStorageCG=Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage"
        $AvailableStorageCG | Stop-ClusterGroup
        $AvailableStorageCG | Move-ClusterGroup -Node $PoolOwnerNode
        1..$NumberOfVolumesPerSite | ForEach-Object {
            #create data volume
            New-Volume -CimSession $ClusterName -FileSystem ReFS -StoragePoolFriendlyName "Pool for Site $site" -Size $VolumeSize -FriendlyName "$($VolumeNamePrefix)$_"
            #create log volume
            New-Volume -CimSession $ClusterName -FileSystem ReFS -StoragePoolFriendlyName "Pool for Site $site" -Size $LogSize -FriendlyName "$($LogDiskPrefix)$_"
        }
    }

    #Start Cluster Group
    $AvailableStorageCG | Start-ClusterGroup

#endregion

#region Enable SR for volumes
$ClusterName="S2D-S-Cluster"
$NumberOfVolumesPerSite=4 #2 per node for data (source,destination)
$VolumeNamePrefix="vDisk"
$LogDiskPrefix="Log-vDisk"
$NumberOfVolumesPerSite=4

$ReplicationMode="Synchronous" #Synchronous or Asynchronous
$AsyncRPO=300  #Recovery point objective in seconds. Default is 5M

$sites=(Get-StorageFaultDomain -CimSession $ClusterName -Type StorageSite).FriendlyName
$Site1Node=(Get-ClusterNode -Cluster $ClusterName | Where-Object FaultDomain -Contains "Site:$($sites[0])" | Get-Random -Count 1).Name
$Site2Node=(Get-ClusterNode -Cluster $ClusterName | Where-Object FaultDomain -Contains "Site:$($sites[1])" | Get-Random -Count 1).Name

$SourceRGNamePrefix="RG-$($Sites[0])-$($VolumeNamePrefix)"
$DestinationRGNamePrefix="RG-$($Sites[1])-$($VolumeNamePrefix)"

$Numbers=1..$NumberOfVolumesPerSite
foreach ($Number in $Numbers){
    #move available storage to first site
    #Move Available Storage to Same node as Pool (just to have it in the same site)
    Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage" | Move-ClusterGroup -Node $Site1Node
    Get-ClusterResource -Cluster $clustername -Name "Cluster Virtual Disk ($($VolumeNamePrefix)$Number)" | Add-ClusterSharedVolume -Cluster $ClusterName
    $Site1DataDiskPath = "c:\ClusterStorage\$($VolumeNamePrefix)$Number"
    $Site1LogDiskPath = (Get-Volume -CimSession $Site1Node -FriendlyName "$($LogDiskPrefix)$Number").Path

    #move available storage to second site
    #Move Available Storage to Same node as Pool (just to have it in the same site)
    Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage" | Move-ClusterGroup -Node $Site2Node
    $Site2DataDiskPath = (Get-Volume -CimSession $Site2Node -FriendlyName "$($VolumeNamePrefix)$Number" | Where-Object FileSystem -NotLike "CSVFS*").Path
    $Site2LogDiskPath = (Get-Volume -CimSession $Site2Node -FriendlyName "$($LogDiskPrefix)$Number").Path

    #move available storage to first site again
    Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage" | Move-ClusterGroup -Node $Site1Node

    #generate RG Names
    $SourceRGName="$SourceRGNamePrefix$Number"
    $DestinationRGName="$DestinationRGNamePrefix$Number"

    #enable SR
    if ($ReplicationMode -eq "Asynchronous"){
        New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Site1Node -SourceRGName $SourceRGName -SourceVolumeName $Site1DataDiskPath -SourceLogVolumeName $Site1LogDiskPath -DestinationComputerName $Site2Node -DestinationRGName $DestinationRGName -DestinationVolumeName $Site2DataDiskPath -DestinationLogVolumeName $Site2LogDiskPath
    }else{
        New-SRPartnership -ReplicationMode Synchronous -SourceComputerName $Site1Node -SourceRGName $SourceRGName -SourceVolumeName $Site1DataDiskPath -SourceLogVolumeName $Site1LogDiskPath -DestinationComputerName $Site2Node -DestinationRGName $DestinationRGName -DestinationVolumeName $Site2DataDiskPath -DestinationLogVolumeName $Site2LogDiskPath
    }
}

#Configure Network Constraints
$Numbers=1..$NumberOfVolumesPerSite
foreach ($Number in $Numbers){
    $SourceRGName="$SourceRGNamePrefix$Number"
    $DestinationRGName="$DestinationRGNamePrefix$Number"
    Set-SRNetworkConstraint -SourceComputerName $ClusterName -DestinationComputerName $ClusterName -SourceRGName $SourceRGName -DestinationRGName $DestinationRGName -SourceNWInterface "ReplicaNet1","ReplicaNet2" -DestinationNWInterface "ReplicaNet1","ReplicaNet2" -ErrorAction Ignore
}

#Validate Network Constraints
Get-SRNetworkConstraint -SourceComputerName $ClusterName -DestinationComputerName $ClusterName

#Validate Replication Status
$Numbers=1..$NumberOfVolumesPerSite
$Records=@()
foreach ($number in $Numbers){
    $DestinationRGName="RG-$($Sites[1])-$($VolumeNamePrefix)$Number"
    $r=Get-SRGroup -CimSession $ClusterName -Name $DestinationRGName | Select -ExpandProperty Replicas 

    $Records += [PSCustomObject]@{
        RgName = $DestinationRGName
        ReplicationMode = $r.ReplicationMode
        ReplicationStatus = $r.ReplicationStatus
        NumberOfGBRemaining = [Math]::Round($r.NumOfBytesRemaining/1GB, 2)
        PercentRemaining = [Math]::Round($r.NumOfBytesRemaining/$r.PartitionSize*100, 2)
        RawData = $r
    }
}

$Records | Format-Table RGName,Rep*,NumberOfGBRemaining,PercentRemaining

#validate network communication
Get-SmbMultichannelConnection -CimSession $ClusterName -SmbInstance CSV
Get-SmbMultichannelConnection -CimSession $ClusterName -SmbInstance SBL
Get-SmbMultichannelConnection -CimSession $ClusterName -SmbInstance SR
Get-ClusterNetwork -Cluster $ClusterName | Select-Object Address,Name,Role

#endregion

#region create some VMs
$NumberOfVMsPerVolume=1
$ClusterName="s2d-s-cluster"

#ask for VHD
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title="Please select parent VHDx." # Preferably create NanoServer as it's small"
}
$openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
If($openFile.ShowDialog() -eq "OK"){
    Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
} 
if (!$openFile.FileName){
    Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
}
$VHDPath = $openFile.FileName

#create VMs
$CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName | Where-Object Name -NotLike *Log*).Name
foreach ($CSV in $CSVs){
    1..$NumberOfVMsPerVolume | ForEach-Object {
        $CSV=$CSV.Substring(22)
        $CSV=$CSV.TrimEnd(")")
        $VMName="TestVM$($CSV)_$_"
        New-Item -Path "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks" -ItemType Directory
        Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" 
        New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\$CSV\" -VHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random)
        Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
    }
}
#Start all VMs
Start-VM -VMname * -CimSession (Get-ClusterNode -Cluster $clustername).Name
#endregion

#region move odd CSVs and it's respective VMs to site1 and even to site2 
$ClusterName="s2d-s-cluster"

$CSVs=Get-ClusterSharedVolume -Cluster $ClusterName | Where-Object Name -NotLike *Log*
$sites=Get-ClusterFaultDomain -CimSession $ClusterName -Type Site

$i=1
foreach ($CSV in $CSVs){
    if (($i % 2) -eq 1){
        if ($sites[1].childrennames -contains $csv.OwnerNode){ #if CSV ownership is in another site, move it to first
            $CSV | Move-ClusterSharedVolume -Cluster $ClusterName -Node ($sites[0].ChildrenNames | Get-Random -Count 1)
        }
    }elseif(($i % 2) -eq 0){
        if ($sites[0].childrennames -contains $csv.OwnerNode){ #if CSV ownership is in another site, move it to first
            $CSV | Move-ClusterSharedVolume -Cluster $ClusterName -Node ($sites[1].ChildrenNames | Get-Random -Count 1)
        }
    }
    $i++
}

#move VMs to the nodes where is volume owner
$VMS=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name

foreach ($VM in $VMs){
    $CSVName=$vm.path.split("\") |Select-Object -First 3 | Select-Object -Last 1
    $CSVOwnerNode=(Get-ClusterSharedVolume -Cluster $ClusterName -Name "Cluster Virtual Disk ($CSVName)").OwnerNode
    Move-ClusterVirtualMachineRole -Cluster $ClusterName -Name $VM.Name -Node $CSVOwnerNode.Name -MigrationType Live
}
#endregion

#region configure Affinity rules
$ClusterName="s2d-s-cluster"
$CSVs=Get-ClusterSharedVolume -Cluster $ClusterName | Where-Object Name -NotLike *Log*
$VMS=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name

#add rule to keep VMs with CSV on the same node (optional, not really needed, just as example)
foreach ($CSV in $CSVs){
    $CSVName=$csv.name.TrimEnd(")").split("(") | Select-Object -Last 1
    New-ClusterAffinityRule -Name $CSVName -RuleType SameNode -CimSession $ClusterName
    $VMsOnCSV=$vms | Where-Object -Property Path -Like "C:\ClusterStorage\$CSVName*"
    $groups=@()
    foreach ($VM in $VMsOnCSV){
        $groups+=Get-ClusterGroup -Name $VM.name -Cluster $ClusterName
    }
    Add-ClusterGroupToAffinityRule -Name $CSVName -Groups $Groups -CimSession $ClusterName
    Add-ClusterSharedVolumeToAffinityRule -Name $CSVName -ClusterSharedVolumes $CSV -CimSession $ClusterName
}

Get-ClusterAffinityRule -CimSession $ClusterName

#endregion