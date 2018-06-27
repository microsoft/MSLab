<!-- TOC -->

- [S2D Networks deep dive](#s2d-networks-deep-dive)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [LabConfig insider preview](#labconfig-insider-preview)
    - [About the lab](#about-the-lab)
    - [Prereqs](#prereqs)
    - [Little bit theory](#little-bit-theory)
    - [Converged Networks](#converged-networks)
    - [Traditional networking](#traditional-networking)

<!-- /TOC -->

# S2D Networks deep dive

## LabConfig Windows Server 2016

```Powershell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = '2NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '2NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '4NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '4NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }

#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'WinAdminCenter' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## LabConfig insider preview

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider-'; SwitchName = 'LabSwitch'; DCEdition='4' ; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = '2NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17692.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '2NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17692.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True}
$LabConfig.VMs += @{ VMName = '4NICs1' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17692.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }
$LabConfig.VMs += @{ VMName = '4NICs2' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17692.vhdx' ; MemoryStartupBytes= 512MB ; NestedVirt=$True ; MGMTNICs=4 }

#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'WinAdminCenter' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }

$LabConfig.ServerVHDs += @{
    Edition="4"
    VHDName="Win2019_17692.vhdx"
    Size=60GB
}
$LabConfig.ServerVHDs += @{
    Edition="3"
    VHDName="Win2019Core_17692.vhdx"
    Size=30GB
}
 
```

## About the lab

This lab is deep dive into different network configurations. There are several options I saw in the field. I would categorize it into 2 main options:

* Converged - 2 pNICs in SET Switch, 2 vNICs for SMB (RDMA enabled), 1vNIC for management.

* Traditional - 2 pNICs for SMB, 2 pNICs in SET switch, 1vNIC for managemement.

For each option are 2 servers hydrated, so multi-server management can be demonstrated.

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

Each option uses SMB networks. RDMA (SMB Direct) is preferred as it has almost no CPU overhead.

In S2D clusters we can see different traffic flowing:

**Live Migration**

Live Migration is by default using proprietary TCP/IP connection (LM with Compression). Since RDMA is available, it's better to configure it to use SMB instead of default

**Cluster communication**

There are 3 different cluster communication traffic.

One is traffic coming from CSV redirection. ReFS is always File System redirected (see [this](https://github.com/Microsoft/WSLab/tree/master/Scenarios/TestingCSVRedirection) scenario)

Second is traffic from Storage Bus Layer (Software Storage Bus)

Third is heartbeat. It's using virtual adapter that maps to any available adapter. This traffic is negligible.

CSV redirection and SBL layer is SMB, that's why RDMA is preferred choice.

**Backup**

This traffic is not covered in these examples

**Management**

Management adapter is the one that is used for communication with node. Agents also use this network, that's why this network should be highly available and not multi-homed.

Converged option is the recommended option only if you have RDMA enabled networks. If RDMA networks are not available, traditional option is preferred.

## Converged Networks

To create virtual switch from all available adapters with IP address 10.*, you can run following command. It's recommended to use SR-IOV if possible as SR-IOV offers higher speeds (trade off is less security). In all examples SR-IOV will be requested (but not enabled since environment is virtual)

```PowerShell
$servers="2NICs1","2NICs2"
#create SET Switch
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
 
```

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
Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management -ComputerName $servers
Add-VMNetworkAdapter -ManagementOS -Name SMB_1 -SwitchName SETSwitch -CimSession $servers
Add-VMNetworkAdapter -ManagementOS -Name SMB_2 -SwitchName SETSwitch -CimSession $servers
```

Let's configure static IP addresses now

```PowerShell
$StorNet="172.16.1."
$IP=1
$servers="2NICs1","2NICs2"
$servers | foreach-object {
    #configure IP Addresses
    New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB_1)" -CimSession $_ -PrefixLength 24
    $IP++
    New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB_2)" -CimSession $_ -PrefixLength 24
    $IP++
}
 
```

To configure SMB NICs to use VLAN use following script

```PowerShell
$StorVLAN=1
$servers="2NICs1","2NICs2"
Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_1 -VlanId $StorVLAN -Access -ManagementOS -CimSession $servers

Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_2 -VlanId $StorVLAN -Access -ManagementOS -CimSession $servers

#Restart each host vNIC adapter so that the Vlan is active.
Restart-NetAdapter "vEthernet (SMB_1)" -CimSession $servers
Restart-NetAdapter "vEthernet (SMB_2)" -CimSession $servers
 
```

Enable RDMA on SMB vNICs and associate vNICS to pNICs

```PowerShell
$servers="2NICs1","2NICs2"
#enable RDMA
Enable-NetAdapterRDMA "vEthernet (SMB_1)","vEthernet (SMB_2)" -CimSession $servers

#Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each vRDMA NIC is mapped to separate pRDMA NIC)
Invoke-Command -ComputerName $servers -ScriptBlock {
    $physicaladapters=(get-vmswitch SETSwitch).NetAdapterInterfaceDescriptions | Sort-Object
    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_1" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB_2" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
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

With traditional networking, let's pick 2 last adapters and let's rename it to SMB_1 and SMB_2.

```PowerShell
$servers="4NICs1","4NICs2"
foreach ($server in $servers){
    $number=1
    $SMBNics=get-netadapter -CimSession $server | sort name  | select -Last 2
    foreach ($SMBNIC in $SMBNics) {
        $SMBNic | Rename-NetAdapter -NewName "SMB_$number"
        $number++
    }
}
 
```

The next step would be to configure static IP addresses on SMB_1 and SMB_2 adapters.

```PowerShell
$StorNet="172.16.1."
$IP=5
$servers="4NICs1","4NICs2"
$servers | foreach-object {
    #configure IP Addresses
    New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "SMB_1" -CimSession $_ -PrefixLength 24
    $IP++
    New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "SMB_2" -CimSession $_ -PrefixLength 24
    $IP++
}
 
```

It is also convenient to configure VLAN. To do so, run following command

```PowerShell
$StorVLAN=1
$servers="4NICs1","4NICs2"
Set-NetAdapter -VlanID $StorVLAN -InterfaceAlias SMB_1 -CimSession $servers -confirm:0
Set-NetAdapter -VlanID $StorVLAN -InterfaceAlias SMB_2 -CimSession $servers -confirm:0

#Restart each host vNIC adapter so that the Vlan is active.
Restart-NetAdapter "SMB_1" -CimSession $servers
Restart-NetAdapter "SMB_2" -CimSession $servers
 
```

The last step would be to configure virtual switch. This step is almost the same as in converged setup.

```PowerShell
$servers="4NICs1","4NICs2"
#create SET Switch
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
#configure hyperVport
Invoke-Command -ComputerName $servers -scriptblock {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
        Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
    }
}
#Configure vNICs
Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management -ComputerName $servers
 
``` 