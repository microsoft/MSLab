<!-- TOC -->

- [S2D Networks deep dive](#s2d-networks-deep-dive)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [Sample LabConfig for Windows Server 2019](#sample-labconfig-for-windows-server-2019)
    - [About the lab](#about-the-lab)
    - [Prereqs](#prereqs)
    - [Little bit theory](#little-bit-theory)
        - [Live Migration](#live-migration)
        - [Cluster communication](#cluster-communication)
        - [Backup](#backup)
        - [Management](#management)
    - [Converged Networks](#converged-networks)
    - [Traditional networking](#traditional-networking)
    - [Conservative networking](#conservative-networking)
    - [Wrap Up](#wrap-up)

<!-- /TOC -->

# S2D Networks deep dive

## LabConfig Windows Server 2016

```Powershell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = '2NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '2NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '4NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '4NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '6NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=6 }
$LabConfig.VMs += @{ VMName = '6NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=6 }

#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'WinAdminCenter' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## Sample LabConfig for Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = '2NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '2NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '4NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '4NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '6NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=6 }
$LabConfig.VMs += @{ VMName = '6NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=6 }

#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## About the lab

This lab is deep dive into different network configurations. There are several options I saw in the field. I would categorize it into 2 main options:

* **Converged** - 2 pNICs in SET Switch, 2 vNICs for SMB (RDMA enabled), 1vNIC for management. One Subnet for east-west

* **Traditional** - 2 pNICs for SMB, 2 pNICs in SET switch, 1vNIC for managemement. Two subnets for east-west

* **Conservative** - 2pNICs in SET for management, 2pNICs for SMB, 2pNICs in SET switch. Two subnets for east-west

For each option are 2 servers hydrated, so multi-server management can be demonstrated. Every configuration is bit more complex than the one before demonstrating diffent options for deployment

Run all scripts from DC or management machine.

## Prereqs

Run following code from DC or management machine

```PowerShell
$servers="2NICs1","2NICs2","4NICs1","4NICs2","6NICs1","6NICs2"

# Install features for management
    Install-WindowsFeature -Name RSAT-Hyper-V-Tools

# Install features on servers
    Invoke-Command -computername $servers -ScriptBlock {
        Install-WindowsFeature -Name "Hyper-V","Hyper-V-PowerShell"
    }
# restart servers
    Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
 
```

## Little bit theory

Each option uses SMB networks. RDMA (SMB Direct) is preferred as it has almost no CPU overhead. In S2D clusters we can see different traffic types flowing:

### Live Migration

Live Migration is by default using proprietary TCP/IP connection (LM with Compression). Since RDMA is available, it's better to configure it to use SMB instead of default.

### Cluster communication

There are 3 different cluster communication traffic types.

* Traffic coming from CSV redirection. ReFS is always File System redirected (see [this](https://github.com/Microsoft/WSLab/tree/master/Scenarios/TestingCSVRedirection) scenario)

* Traffic from Storage Bus Layer (Software Storage Bus)

* Heartbeat. It's using virtual adapter that maps to any available adapter. This traffic is negligible.

CSV redirection and SBL layer is SMB, that's why RDMA is preferred choice.

### Backup

This traffic is not covered in these examples

### Management

Management adapter is the one that is used for communication with node. Agents also use this network, that's why this network should be highly available and not multi-homed.

Converged option is the recommended option only if you have RDMA enabled networks. If RDMA networks are not available, traditional option is preferred.

## Converged Networks

To create virtual switch from all available adapters with IP address 10.*, you can run following command. It's recommended to use SR-IOV if possible as SR-IOV offers higher speeds (trade off is less security). In all examples SR-IOV will be requested (but not enabled since environment is virtual)

```PowerShell
$servers="2NICs1","2NICs2"
#create SET Switch
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
 
```

![](/Scenarios/S2D%20and%20Networks%20deep%20dive/Screenshots/IOVEnabledNotWorking.png)

The next step would be to configure load balancing algorithm. By default in Windows Server 2016 is Dynamic, while in Server 2019 is HyperVPort. The recommendation for S2D environment would be HyperVPort. Following script will configure HyperVPort on Windows Server 2016 only.

```PowerShell
$servers="2NICs1","2NICs2"
Invoke-Command -ComputerName $servers -scriptblock {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
        Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
    }
}
 
```

The next step would be to configure vNICs. When SET switch is created, it will create also vNIC exposed to management OS with the same name as vSwitch. Let's rename it and add 2 vNICs for SMB.

```PowerShell
$servers="2NICs1","2NICs2"
#Configure vNICs
Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Mgmt -ComputerName $servers
Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName SETSwitch -CimSession $servers
Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName SETSwitch -CimSession $servers
 
```

Let's configure static IP addresses now with one subnet.

```PowerShell
$StorNet="172.16.1."
$IP=1
$servers="2NICs1","2NICs2"
$servers | foreach-object {
    #configure IP Addresses
    New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
    $IP++
    New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
    $IP++
}
 
```

To configure SMB NICs to use VLAN use following script

```PowerShell
$StorVLAN=1
$servers="2NICs1","2NICs2"
Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN -Access -ManagementOS -CimSession $servers

Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN -Access -ManagementOS -CimSession $servers

#Restart each host vNIC adapter so that the Vlan is active.
Restart-NetAdapter "vEthernet (SMB01)" -CimSession $servers
Restart-NetAdapter "vEthernet (SMB02)" -CimSession $servers
 
```

Enable RDMA on SMB vNICs and map vNICS to pNICs

```PowerShell
$servers="2NICs1","2NICs2"
#enable RDMA
Enable-NetAdapterRDMA "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $servers

#map each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
Invoke-Command -ComputerName $servers -ScriptBlock {
    $physicaladapters=(get-vmswitch SETSwitch).NetAdapterInterfaceDescriptions | Sort-Object
    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
}
 
```

To verify networking run following scripts

```PowerShell
$servers="2NICs1","2NICs2"
#verify mapping
    Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | ft ComputerName,NetAdapterName,ParentAdapter 
#Verify that the VlanID is set
    Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | ft ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName
#verify RDMA
    Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | ft systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
#verify ip config 
    Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
 
```

## Traditional networking

With traditional networking, let's pick 2 even adapters and let's rename it to SMB01 and SMB02 (like Nic1 Port 2 and NIC2 Port 2). In this example we will sort NICs by MAC Address and choosing Index 1 and 3 for SMB Adapters and Index 0 and 2 for SETSwitch.

```PowerShell
$servers="4NICs1","4NICs2"
foreach ($server in $servers){
    $number=1
    $SMBNics=get-netadapter -CimSession $server | sort macaddress | Select-Object -Index 1,3
    foreach ($SMBNIC in $SMBNics) {
        $SMBNic | Rename-NetAdapter -NewName "SMB0$number"
        $number++
    }
}
 
```

The next step would be to configure static IP addresses on SMB01 and SMB02 adapters. Now we will demonstrate two different subnets.

```PowerShell
$StorNet1="172.16.1."
$Stornet2="172.16.2."
$IP=5
$servers="4NICs1","4NICs2"
$servers | foreach-object {
    #configure IP Addresses
    New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "SMB01" -CimSession $_ -PrefixLength 24
    New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "SMB02" -CimSession $_ -PrefixLength 24
    $IP++
}
 
```

It is also convenient to configure VLAN. To do so, run following command

```PowerShell
$StorVLAN1=1
$StorVLAN2=2
$servers="4NICs1","4NICs2"
Set-NetAdapter -VlanID $StorVLAN1 -InterfaceAlias SMB01 -CimSession $servers -confirm:0
Set-NetAdapter -VlanID $StorVLAN2 -InterfaceAlias SMB02 -CimSession $servers -confirm:0

#Restart each host vNIC adapter so that the Vlan is active.
Restart-NetAdapter "SMB01" -CimSession $servers
Restart-NetAdapter "SMB02" -CimSession $servers
 
```

The last step would be to configure virtual switch. This step is almost the same as in converged setup. Let's demonstrate creating SET with one NIC only and then adding second one (to use specific adapters MAC and IP address). 

```PowerShell
$servers="4NICs1","4NICs2"
#create SET Switch
Invoke-Command -ComputerName $servers -ScriptBlock {
    New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (get-netadapter | Sort-Object macaddress | Select-Object -Index 0).InterfaceAlias
}
#add second NIC to SETSwitch
Invoke-Command -ComputerName $servers -ScriptBlock {
    Add-VMSwitchTeamMember -VMSwitchName SETSwitch -NetAdapterName (Get-NetAdapter | Sort-Object macaddress | Select-Object -Index 3).InterfaceAlias
}
#configure hyperVport
Invoke-Command -ComputerName $servers -scriptblock {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
        Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
    }
}
#Rename management vNIC
Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Mgmt -ComputerName $servers
 
```

## Conservative networking

I did not see this configuration in the field much, but let's cover it too, to separate team for Management (in case you need to have physically separated networks).

First we will create vSwitch for management

```PowerShell
$servers="6NICs1","6NICs2"
#create MGMT vSwitch
Invoke-Command -ComputerName $servers -ScriptBlock {
    New-VMSwitch -Name MGMTSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (get-netadapter | Sort-Object macaddress | Select-Object -last 2).InterfaceAlias
}

#configure hyperVport
Invoke-Command -ComputerName $servers -scriptblock {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
        Set-VMSwitchTeam -Name MGMTSwitch -LoadBalancingAlgorithm HyperVPort
    }
}

#Rename management vNIC
Rename-VMNetworkAdapter -ManagementOS -Name MGMTSwitch -NewName Mgmt -ComputerName $servers
 
```

Next step is to configure SMB NICs

```PowerShell
$servers="6NICs1","6NICs2"
foreach ($server in $servers){
    $number=1
    $SMBNics=get-netadapter -CimSession $server | Sort-Object macaddress | Select-Object -First 4 | Select-Object -Last 2
    foreach ($SMBNIC in $SMBNics) {
        $SMBNic | Rename-NetAdapter -NewName "SMB0$number"
        $number++
    }
}

$StorVLAN1=1
$StorVLAN2=2
Set-NetAdapter -VlanID $StorVLAN1 -InterfaceAlias SMB01 -CimSession $servers -confirm:0
Set-NetAdapter -VlanID $StorVLAN2 -InterfaceAlias SMB02 -CimSession $servers -confirm:0

#Restart each host vNIC adapter so that the Vlan is active.
Restart-NetAdapter "SMB01" -CimSession $servers
Restart-NetAdapter "SMB02" -CimSession $servers
 

$StorNet1="172.16.1."
$StorNet2="172.16.2."
$IP=10

$servers | foreach-object {
    #configure IP Addresses
    New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "SMB01" -CimSession $_ -PrefixLength 24
    New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "SMB02" -CimSession $_ -PrefixLength 24
    $IP++
}
 
```

And finally the last step is to create SET Switch from last 2 NICs.

```PowerShell
$servers="6NICs1","6NICs2"
#create SET Switch
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -AllowManagementOS $false -NetAdapterName (get-netadapter | Sort-Object macaddress | Select-Object -first 2).InterfaceAlias}
#configure hyperVport
Invoke-Command -ComputerName $servers -scriptblock {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
        Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
    }
}
 
```

Note: as IP of server is changed, you may see reconnection during script execution. It's sometimes necessary to flushDNS as you can see on screenshot below.

![](/Scenarios/S2D%20and%20Networks%20deep%20dive/Screenshots/flushdns.png)

## Wrap Up

As you can see, we demonstrated different ways to achieve the same. Different customers, different approaches. There is no single answer to the problem, you always need to consider all options and based on pros and cons choose the one that suits you and your environment.

![](/Scenarios/S2D%20and%20Networks%20deep%20dive/Screenshots/NICsServerManager.png)
