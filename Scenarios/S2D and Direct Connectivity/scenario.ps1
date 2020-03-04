<#region Run from hyper-v host: Configure Networking to simulate direct connections ()
$Servers="s2d1","s2d2","s2d3","s2d4","s2d5"
$serverscount=$servers.Count

#configure VLANs to simulate direct connection
$serverset1=$servers[0..($serverscount-2)]
$serverset2=$servers[1..($serverscount-1)]

#configure VLANs to simulate direct connection for side 1
$number=$serverscount-1 #will be used to select ports
$VLANNumber=1 #will be increased each time Netadapter is configured
foreach ($server in $serverset1){
    $ports=Get-VMNetworkAdapter -VMName *$server | Sort-Object Name | Select-Object -Last ($serverscount-1)
    foreach ($port in ($ports | Select-Object -Last $number)){
        $port | Set-VMNetworkAdapterVlan -Untagged
        $port | Set-VMNetworkAdapterVlan -VlanId $VLANNumber -Access
        $VLANNumber++
    }
    $number--
}

#configure VLANs to simulate direct connection for side 2
$number=$serverscount-1 #will be used to select servers
$VLANNumber=1 #will be increased each time Netadapter is configured
while ($number -ge 1){
    foreach ($server in ($serverset2 | Select-Object -Last $number)){
        $ports = Get-VMNetworkAdapter -VMName *$server | Sort-Object Name | Select-Object -Last ($serverscount-1)
        $port = $ports | Select-Object -Last $number | Select-Object -First 1
        $port | Set-VMNetworkAdapterVlan -Untagged
        $port | Set-VMNetworkAdapterVlan -VlanId $VLANNumber -Access
        $VLANNumber++
    }
    $number--
}

#validate VLANs
Get-VMNetworkAdapterVlan -VMName * | Where-Object AccessVlanID -ne 0 | Sort-Object AccessVlanId | Format-Table -GroupBy AccessVLANID

#start VMs
foreach ($server in $servers){
    Start-VM -VMName *$server
}
#endregion
#>

#region Install features for S2D Cluster
$Servers="s2d1","s2d2","s2d3","s2d4","s2d5"

#install management features on local machine
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

#install Hyper-V using DISM 
Invoke-Command -ComputerName $servers -ScriptBlock {
    Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
}
#install other features
$features="Failover-Clustering","Hyper-V-PowerShell"
Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features}
#restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
Start-Sleep 20 #just to settle things down

#endregion

#region Explore IPv6 Networks
$Servers="s2d1","s2d2","s2d3","s2d4","s2d5"

$Adapters=foreach ($server in $servers) {get-netadapter -CimSession $server | Sort-Object MacAddress | Select-Object -Last ($servers.count-1)}
$IPs=$Adapters | Get-NetIPAddress -AddressFamily IPv6

$output=@()
Foreach ($IP in $IPs){
    $Output += [PSCustomObject]@{
        "PSComputerName" = $IP.PSComputerName
        "InterfaceAlias" = $IP.InterfaceAlias
        "IPAddress" = ($IP.IPAddress) -split "%" | Select-Object -First 1
        "SubnetID" = ($IP.IPAddress) -split "%" | Select-Object -Last 1
    }
}
$output | Sort-Object SubnetID | Format-Table -GroupBy SubnetID

#endregion

#region Create virtual switch and add static IP Addresses to interconnects
$Servers="s2d1","s2d2","s2d3","s2d4","s2d5"
$serverscount=$servers.Count
$vSwitchName="vSwitch"
$StorageAddressPrefix="172.16"
$serverset1=$servers[0..($serverscount-2)]
$serverset2=$servers[1..($serverscount-1)]

#Create vSwitch and rename Management vNIC
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Management -CimSession $servers

#add static IP address prefix
#configure first side with static address
$number=$serverscount-1 #will be used to select ports
$IPNumber=1 #will be increased each time Netadapter is configured
foreach ($server in $serverset1){
    $ports=get-netadapter -CimSession $server | Sort-Object MacAddress | Select-Object -Last $serverscount
    foreach ($port in ($ports | Select-Object -Last $number)){
        $port | New-NetIPAddress -IPAddress "$StorageAddressPrefix.$IPNumber.1" -PrefixLength 24
        $port | Rename-NetAdapter -NewName "Pair$IPNumber"
        $IPNumber++
    }
    $number--
}

#configure second side with static address
$number=$serverscount-1 #will be used to select servers
$IPNumber=1 #will be increased each time Netadapter is configured
while ($number -ge 1){
    foreach ($server in ($serverset2 | Select-Object -Last $number)){
        $ports = Get-NetAdapter -CimSession $server | Sort-Object MacAddress | Select-Object -Last ($servers.count-1)
        $port = $ports | Select-Object -Last $number | Select-Object -First 1
        $port | New-NetIPAddress -IPAddress "$StorageAddressPrefix.$IPNumber.2" -PrefixLength 24
        $port | Rename-NetAdapter -NewName "Pair$IPNumber"
        $IPNumber++
    }
    $number--
}

#validate NICs
Get-NetIPAddress -AddressFamily IPv4 -IPAddress $StorageAddressPrefix* -CimSession $servers | Sort-Object InterfaceAlias | Format-Table InterfaceAlias,IPAddress,PSComputerName -GroupBy InterfaceAlias
#endregion

#region Test and create Cluster
$Servers="s2d1","s2d2","s2d3","s2d4","s2d5"
$ClusterName="S2D-Cluster"

Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
New-Cluster -Name $ClusterName -Node $servers
Start-Sleep 5
Clear-DnsClientCache

#configure witness
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
#endregion

#region Configure Cluster networks
$Servers="s2d1","s2d2","s2d3","s2d4","s2d5"
$ClusterName="S2D-Cluster"
$StorageAddressPrefix="172.16"
$NumberOfConnections=(1..($servers.count-1) | Measure-Object -Sum).Sum

foreach ($number in 1..$NumberOfConnections){
    (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "$StorageAddressPrefix.$number.0").Name="Pair$number"
}
(Get-ClusterNetwork -Cluster $ClusterName | Where-Object Role -eq "ClusterAndClient").Name="Management"

#configure Live Migration networks
Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -eq "Management"}).ID))
#configure Live Migration to use SMB
Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -CimSession $servers

#endregion

#region Enable Cluster S2D and create volumes
$ClusterName="S2D-Cluster"

#Enable-ClusterS2D
Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

#calculate size of volume (assuming this is not 3 tier system)
$numberofNodes=$servers.count
$pool=Get-StoragePool -CimSession $clustername -FriendlyName s2D*
$Capacity = ($pool |Get-PhysicalDisk -CimSession $clustername | Measure-Object -Property Size -Sum).Sum
$MaxSize =  ($pool |Get-PhysicalDisk -CimSession $clustername | Measure-Object -Property Size -Maximum).Maximum
$CapacityToUse=$Capacity-($numberofNodes*$MaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
$sizeofvolume=$CapacityToUse/3/$numberofNodes

#create volumes
1..$numberofNodes | ForEach-Object {
        New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size $sizeofvolume -FriendlyName "MyVolume$_"
}
#endregion