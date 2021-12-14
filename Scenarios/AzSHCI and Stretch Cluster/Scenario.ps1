#region install prereqs
    #install management features
    Install-WindowsFeature -Name RSAT-AD-PowerShell,RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica,RSAT-DNS-Server

    #configure sites and subnets in Active Directory
    New-ADReplicationSite -Name "Site1-Redmond"
    New-ADReplicationSite -Name "Site2-Seattle"
    New-ADReplicationSubnet -Name "10.0.0.0/24" -Site "Site1-Redmond" -Location "Redmond, WA"
    New-ADReplicationSubnet -Name "10.0.1.0/24" -Site "Site2-Seattle" -Location "Seattle, WA"
#endregion

#region install features and configure hw timeout for virtual environment
        $servers="Site1AzSHCI1","Site1AzSHCI2","Site2AzSHCI1","Site2AzSHCI2"

        #install roles and features
        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
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
        Start-Sleep 30 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA )
        [array]$Site1Servers="Site1AzSHCI1","Site1AzSHCI2"
        [array]$Site2Servers="Site2AzSHCI1","Site2AzSHCI2"
        [array]$servers=$Site1Servers+$Site2Servers
        $vSwitchName="vSwitch"
        $Site1StorNet1="172.16.1."
        $Site1StorNet2="172.16.2."
        $Site1StorVLAN1=1
        $Site1StorVLAN2=2
        $Site2StorNet1="172.16.3."
        $Site2StorNet2="172.16.4."
        $Site2StorVLAN1=3
        $Site2StorVLAN2=4
        $IP=1 #StartIP

        #Create Virtual Switches and Virtual Adapters
            Invoke-Command -ComputerName $Servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

        #configure configure vNICs on Site1
        $Site1Servers | ForEach-Object {
            #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName $vSwitchName -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName $vSwitchName -Cimsession $_

            #configure IP Addresses
            New-NetIPAddress -IPAddress ($Site1StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
            New-NetIPAddress -IPAddress ($Site1StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
            $IP++
        }

        #configure configure vNICs on Site2
        $Site2Servers | ForEach-Object {
            #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName $vSwitchName -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName $vSwitchName -Cimsession $_

            #configure IP Addresses
            New-NetIPAddress -IPAddress ($Site2StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
            New-NetIPAddress -IPAddress ($Site2StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
            $IP++
        }

        Start-Sleep 5
        Clear-DnsClientCache

        #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $Site1StorVLAN1 -Access -ManagementOS -CimSession $Site1Servers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $Site1StorVLAN2 -Access -ManagementOS -CimSession $Site1Servers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $Site2StorVLAN1 -Access -ManagementOS -CimSession $Site2Servers
            Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $Site2StorVLAN2 -Access -ManagementOS -CimSession $Site2Servers

        #Restart each host vNIC adapter so that the Vlan is active.
            Restart-NetAdapter -Name "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $Servers 

        #Enable RDMA on the host vNIC adapters (should be done just for real environments)
            Enable-NetAdapterRDMA -Name "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
            Invoke-Command -ComputerName $servers -ScriptBlock {
                    $physicaladapters=(get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions | Sort-Object
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
                }
#endregion

#region Create cluster and configure witness (file share or Azure)
    $servers="Site1AzSHCI1","Site1AzSHCI2","Site2AzSHCI1","Site2AzSHCI2"
    $ClusterName="AzSHCI-S-Clus"
    $WitnessType="FileShare" #or Cloud
    $ResourceGroupName="WSLabCloudWitness"
    $StorageAccountName="wslabcloudwitness$(Get-Random -Minimum 100000 -Maximum 999999)"

    if ($WitnessType -eq "Cloud"){
        #download Azure modules
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name Az.Accounts -Force
        Install-Module -Name Az.Resources -Force
        Install-Module -Name Az.Storage -Force

        #login to Azure
        Connect-AzAccount -UseDeviceAuthentication
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
    }

    Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
    #Create new cluster using Distributed ManagementPoint
    New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType Distributed -NoStorage
    #or you can create cluster with traditional A record on CNO.
    #New-Cluster -Name $ClusterName -Node $servers -NoStorage

    Start-Sleep 5
    Clear-DnsClientCache

    if ($WitnessType -eq "Cloud"){
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
    $ClusterName="AzSHCI-S-Clus"
    $StorNet1="172.16.1."
    $StorNet2="172.16.2."
    $StorNet3="172.16.3."
    $StorNet4="172.16.4."
    $ReplicaNet1="172.16.11."
    $ReplicaNet2="172.16.12."

    #configure Replica Networks role
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet1"0").Role="none"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet2"0").Role="none"

    #rename networks
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="Site1-SMB01"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="Site1-SMB02"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet3"0").Name="Site2-SMB01"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet4"0").Name="Site2-SMB02"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet1"0").Name="ReplicaNet1"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $ReplicaNet2"0").Name="ReplicaNet2"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name="Site1-Management"
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.1.0").Name="Site2-Management"

    #configure Live Migration networks to use only SMB nics
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value  ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -notlike "*smb*"}).ID))
        Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers
#endregion

#region configure Cluster-Aware-Updating
    $ClusterName="AzSHCI-S-Clus"
    $CAURoleName="S2D-S-Clus-CAU"
    #Install required features on nodes.
        $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
        foreach ($ClusterNode in $ClusterNodes){
            Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
        }
    #add role
        Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
#endregion

#region Configure Fault Domains (just an example if AD sites not set) https://docs.microsoft.com/en-us/windows-server/failover-clustering/fault-domains

    <#either static

    $ClusterName="AzSHCI-S-Clus"
    $xml =  @"
    <Topology>
        <Site Name="DC01SEA" Location="Contoso DC1, 123 Example St, Room 4010, Seattle">
            <Node Name="Site1AzSHCI1"/>
            <Node Name="Site1AzSHCI2"/>
        </Site>
        <Site Name="DC02RED" Location="Contoso DC2, 123 Example St, Room 4010, Redmond">
            <Node Name="Site2AzSHCI1"/>
            <Node Name="Site2AzSHCI2"/>
        </Site>
    </Topology>
"@
    #>
    <# or with rack info (note, it will configure Rack FaultDomainAwarenessDefault after enable cluster s2d as multiple racks are present if -confirm:0 in Enable-ClusterS2D.)
    $xml =  @"
    <Topology>
        <Site Name="DC01SEA" Location="Contoso DC1, 123 Example St, Room 4010, Seattle">
            <Rack Name="SEA-Rack01" Location="Contoso DC1, Room 4010, Aisle A, Rack 01">
                <Node Name="Site1AzSHCI1"/>
                <Node Name="Site1AzSHCI2"/>
            </Rack>
        </Site>
        <Site Name="DC02RED" Location="Contoso DC2, 123 Example St, Room 4010, Redmond">
            <Rack Name="RED-Rack01" Location="Contoso DC2, Room 4010, Aisle A, Rack 01">
                <Node Name="Site2AzSHCI1"/>
                <Node Name="Site2AzSHCI2"/>
            </Rack>
        </Site>
    </Topology>
"@
#>
    #configure fault domains
    #Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName

    #validate
    #Get-ClusterFaultDomainXML -CimSession $ClusterName

    <#or bit more dynamic
    $Site1Name="DC01SEA"
    $Site2Name="DC02RED"
    $Site1NamesPrefix="Site1AzSHCI"
    $Site2NamesPrefix="Site2AzSHCI"
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
$ClusterName="AzSHCI-S-Clus"
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

#region register AzSHCI to Azure
$ClusterName="AzSHCI-S-Clus"

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
Connect-AzAccount -UseDeviceAuthentication
<# or download edge and do it without device authentication
#download
Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
Connect-AzAccount
#>
<#or use IE for autentication
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2
Connect-AzAccount
#>
#select context if more available
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context | Out-GridView -OutputMode Single | Set-AzContext
}

#grab subscription ID
$subscriptionID=(Get-AzContext).Subscription.id

#Register AZSHCi without prompting for creds
$armTokenItemResource = "https://management.core.windows.net/"
$graphTokenItemResource = "https://graph.windows.net/"
$azContext = Get-AzContext
$authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
$graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
$armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
$id = $azContext.Account.Id
Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

<# or register Azure Stack HCI with device authentication
Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication
#>
<# or with standard authentication
#add some trusted sites (to be able to authenticate with Register-AzStackHCI)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2
#and register
Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName
#>
<# or with location picker
#grab location
if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
    Install-Module -Name Az.Resources -Force
}
$Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single
Register-AzStackHCI -SubscriptionID $subscriptionID -Region $location.location -ComputerName $ClusterName -UseDeviceAuthentication
#>

#Install Azure Stack HCI RSAT Tools to all nodes
$Servers=(Get-ClusterNode -Cluster $ClusterName).Name
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Install-WindowsFeature -Name RSAT-Azure-Stack-HCI
}

#Validate registration (query on just one node is needed)
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-AzureStackHCI
}
#endregion

#region Create Volumes
    $ClusterName="AzSHCI-S-Clus"
    $NumberOfVolumesPerSite=4 #2 per node for source (for each node 1), 2 per node for destination from other site (+logs)
    $VolumeSize=100GB #scaled down as initial replica takes some time
    $LogSize=10GB
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
$ClusterName="AzSHCI-S-Clus"
$NumberOfVolumesPerSite=4 #2 per node for data (source,destination)
$VolumeNamePrefix="vDisk"
$LogDiskPrefix="Log-vDisk"

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
    do{
        Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage" | Move-ClusterGroup -Node $Site1Node
        Start-Sleep 5
    }until(
        (Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage").OwnerNode.Name -eq $Site1Node
    )

    Get-ClusterResource -Cluster $clustername -Name "Cluster Virtual Disk ($($VolumeNamePrefix)$Number)" | Add-ClusterSharedVolume -Cluster $ClusterName
    $Site1DataDiskPath = "c:\ClusterStorage\$($VolumeNamePrefix)$Number"
    $Site1LogDiskPath = (Get-Volume -CimSession $Site1Node -FriendlyName "$($LogDiskPrefix)$Number").Path

    #move available storage to second site
    #Move Available Storage to Same node as Pool (just to have it in the same site)
    do{
        Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage" | Move-ClusterGroup -Node $Site2Node
        Start-Sleep 5
    }until(
        (Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage").OwnerNode.Name -eq $Site2Node
    )

    $Site2DataDiskPath = (Get-Volume -CimSession $Site2Node -FriendlyName "$($VolumeNamePrefix)$Number" | Where-Object FileSystem -NotLike "CSVFS*").Path
    $Site2LogDiskPath = (Get-Volume -CimSession $Site2Node -FriendlyName "$($LogDiskPrefix)$Number").Path

    #move available storage to first site again
    do{
        Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage" | Move-ClusterGroup -Node $Site1Node
        Start-Sleep 5
    }until(
        (Get-ClusterGroup -Cluster $ClusterName -Name "Available Storage").OwnerNode.Name -eq $Site1Node
    )

    #generate RG Names
    $SourceRGName="$SourceRGNamePrefix$Number"
    $DestinationRGName="$DestinationRGNamePrefix$Number"

    #enable SR
    if ($ReplicationMode -eq "Asynchronous"){
        New-SRPartnership -ReplicationMode Asynchronous -AsyncRPO $AsyncRPO -SourceComputerName $Site1Node -SourceRGName $SourceRGName -SourceVolumeName $Site1DataDiskPath -SourceLogVolumeName $Site1LogDiskPath -DestinationComputerName $Site2Node -DestinationRGName $DestinationRGName -DestinationVolumeName $Site2DataDiskPath -DestinationLogVolumeName $Site2LogDiskPath
    }else{
        New-SRPartnership -ReplicationMode Synchronous -SourceComputerName $Site1Node -SourceRGName $SourceRGName -SourceVolumeName $Site1DataDiskPath -SourceLogVolumeName $Site1LogDiskPath -DestinationComputerName $Site2Node -DestinationRGName $DestinationRGName -DestinationVolumeName $Site2DataDiskPath -DestinationLogVolumeName $Site2LogDiskPath
    }
    
    #get some rest
    Start-Sleep 10
}

#Wait for SR to finish
    do{
        $r=(Get-SRGroup -CimSession $ClusterName).replicas
        $RemainingGB=($r.NumOfBytesRemaining |Measure-Object -Sum).Sum/1GB
        [System.Console]::Write("Number of remaining Gbytes {0}`r", $RemainingGB)
        Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
    }while($r.ReplicationStatus -contains "InitialBlockCopy")
    Write-Output "Replica Status:"
    $r | where Datavolume -like "C:\ClusterStorage*" | select Datavolume,ReplicationStatus

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
$ClusterName="AzSHCI-S-Clus"

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
        $CSV=($csv -split '\((.*?)\)')[1]
        $VMName="TestVM$($CSV)_$_"
        New-Item -Path "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks" -ItemType Directory
        Start-BitsTransfer -Source $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" 
        New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\$CSV\" -VHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random)
        Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
    }
}
#Start all VMs
Start-VM -VMname * -CimSession (Get-ClusterNode -Cluster $clustername).Name
#endregion

#region move odd CSVs and it's respective VMs to site1 and even to site2 
$ClusterName="AzSHCI-S-Clus"

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

#region configure Affinity rules (just an example, not really needed )

<#
$ClusterName="AzSHCI-S-Clus"
$CSVs=Get-ClusterSharedVolume -Cluster $ClusterName | Where-Object Name -NotLike *Log*
$VMS=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name

foreach ($CSV in $CSVs){
    $CSVName=$csv.name.TrimEnd(")").split("(") | Select-Object -Last 1
    $VMsOnCSV=$vms | Where-Object -Property Path -Like "C:\ClusterStorage\$CSVName*"
    
    Invoke-Command -ComputerName $Clustername -ScriptBlock {
        New-ClusterAffinityRule -Name $using:CSVName -RuleType SameNode
        $groups=@()
        foreach ($VM in $using:VMsOnCSV){
            $groups+=Get-ClusterGroup -Name $VM.name
        }
        Add-ClusterGroupToAffinityRule -Name $using:CSVName -Groups $Groups
        Add-ClusterSharedVolumeToAffinityRule -Name $using:CSVName -ClusterSharedVolumes $using:CSV
    }
}

Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-ClusterAffinityRule
}

#>
#endregion

#region install Windows Admin Center GW

$GatewayServerName="WACGW"

#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
}
#Create PS Session and copy install files to remote server
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
}

$Session | Remove-PSSession

#add certificate to trusted root certs
start-sleep 10
$cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
$cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

#Configure Resource-Based constrained delegation
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter *).Name

foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}

#Install Edge
Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

#Install SR RSAT on WAC GW
Install-WindowsFeature -name RSAT-Storage-Replica -ComputerName $GatewayServerName

#endregion
