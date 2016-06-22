# Scenario Description

* In this scenario 4-16 node S2D cluster can be created.
* It is just simulation "how it would look like". Performance is not a subject here.
* It is just to test look and feel
* THis is TP5 script. It will likely change in RTM.


# Scenario requirements

* Windows 10 1511 with enabled Hyper-V
* 8GB Memory or 20GB if nested virtualization is used (for 4 node configuration)
* SSD (with HDD it is really slow)

# Variables.ps1


* Without Nested Virtualization
````PowerShell
$LabConfig=@{AdminPassword='LS1setup!'; DomainAdminName='Claus'; Prefix = 's2d_HyperConverged-'; SecureBoot='Off'; CreateClientParent='No';DCEdition='ServerDataCenter'}
$NetworkConfig=@{SwitchName = 'LabSwitch' ; StorageNet1='172.16.1.'; StorageNet2='172.16.2.'}
$LAbVMs = @()
1..4| % {"S2D$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } } 
````

* With Nested Virtualization
````PowerShell
$LabConfig=@{AdminPassword='LS1setup!'; DomainAdminName='Claus'; Prefix = 'S2DLabNested-'; SecureBoot='On'; CreateClientParent='No';DCEdition='ServerDataCenter';ClientEdition='Enterprise'}
$NetworkConfig=@{SwitchName = 'LabSwitch' ; StorageNet1='172.16.1.'; StorageNet2='172.16.2.'}
$LAbVMs = @()
1..4 | % {"S2D$_"}  | % { $LAbVMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt='Yes'} }
````

# Configuration Script
This script needs to run in DC

* This part sets some variables. For example how many nodes you want to provision or how many disks you want to create
````PowerShell
# 3,4,8, or 16 nodes
$numberofnodes=4

#servernames
1..$numberofnodes | ForEach-Object {$servers=$servers+@("S2D$_")}

#Cluster Name
$ClusterName="S2D-Cluster"

#?Networking
$Networking='Yes'

#Number of MultiResiliencyDisks Created
$MRTNumber=$numberofnodes
````

* This part will install required roles for DC to manage features
````PowerShell
#install features for management
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools
````

* If you want to run Core servers, then you will need to enable hyper-v and another roles. Skip if you have NanoServers
````PowerShell
Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
foreach ($server in $servers) {Install-WindowsFeature -Name Failover-Clustering,Failover-Clustering-S2D,Hyper-V-PowerShell -ComputerName $server} 

#restart and wait for computers
Invoke-Command -ComputerName $servers -ScriptBlock {Restart-Computer -Force}
Start-Sleep 60
````

* In this part networking is configured. Just to see how SET Switch looks like and how it looks like when you have 2 vNICS. In real world scenario you would have the same, except vNICs should be configured as vRDMA NICs
````PowerShell
if ($Networking -eq "Yes"){
    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -MinimumBandwidthMode Weight -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    $Servers | ForEach-Object {
        Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management1 -ComputerName $_
        Add-VMNetworkAdapter    -ManagementOS -Name Management2 -SwitchName SETSwitch -ComputerName $_
    }
    Start-Sleep 5
    Clear-DnsClientCache
}
````

* Test and Create new cluster. ClearDNSCLientCace is the same as ipconfig /flushdns. Its needed to know about new cluster dns record.

````PowerShell
Test-Cluster –Node $servers –Include “Storage Spaces Direct”,Inventory,Network,”System Configuration”
New-Cluster –Name $ClusterName –Node $servers –NoStorage 
Start-Sleep 5
Clear-DnsClientCache
````

* Enable S2D. It is specific to TP5 as you need to skip automatic configuration and skip eligibility checks (because all disks report with mediatype unknown, therefore eligibility check would fail)

```PowerShell
Enable-ClusterS2D -CimSession $ClusterName -AutoConfig:0 -Confirm:$false -SkipEligibilityChecks
````

* TP5 fix to disable SpaceManagerTask, that consumes all CPU.
```PowerShell
Invoke-Command -ComputerName $servers -ScriptBlock {Get-ScheduledTask "SpaceManagerTask" | Disable-ScheduledTask}
````

* To work with remote storage subsystem from DC, it is useful to register it with this command. I'm using $ClusterName, so I'll always work with some node that's online.
```PowerShell
Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName
````

* Create Pool. On real systems this is not needed, because StoragePool is automatically created during Enable-ClusterS2D

```PowerShell
$phydisk = Get-StorageSubSystem -FriendlyName *$ClusterName | Get-PhysicalDisk -CanPool $true
Write-Host "Number of physical disks found:" $phydisk.count -ForegroundColor Cyan

$pool=New-StoragePool -FriendlyName  DirectPool -PhysicalDisks $phydisk -StorageSubSystemFriendlyName *$ClusterName 
````

* Set Mediatype. This is workaround to simulate SSDs and HDDs. Again, on real systems this is not needed

```PowerShell
$pool | get-physicaldisk | where Size -le 900GB | Set-PhysicalDisk -MediaType SSD
$pool | get-physicaldisk | where Size -ge 900GB | Set-PhysicalDisk -MediaType HDD
````

* Create Tiers. On real system this is done automatically during Enable-ClusterS2D. Here is a logic for 3 node configuration, where capacity tier needs to be also 3 way mirror to protect from 2 node failure.

```PowerShell
$Perf = New-StorageTier -FriendlyName Performance  -MediaType SSD -ResiliencySettingName Mirror -StoragePoolFriendlyName $pool.friendlyname  -PhysicalDiskRedundancy 2
if  ($numberofnodes -ne 3){
    $Cap  = New-StorageTier -FriendlyName Capacity     -MediaType HDD -ResiliencySettingName Parity -StoragePoolFriendlyName $pool.friendlyname  -PhysicalDiskRedundancy 2
}
if  ($numberofnodes -eq 3){
    $Cap  = New-StorageTier -FriendlyName Capacity     -MediaType HDD -ResiliencySettingName Mirror -StoragePoolFriendlyName $pool.friendlyname  -PhysicalDiskRedundancy 2
}
````

* Create virtual disks. Here you really need April 2016 Cumulative Update to run successfully. On May/June CU I see various errors. This should be fixed in RTM

```PowerShell
1..$MRTNumber | ForEach-Object {
New-Volume -StoragePoolFriendlyName $pool.friendlyname -FriendlyName MultiResiliencyDisk$_ -FileSystem CSVFS_ReFS -StorageTiers $perf,$cap -StorageTierSizes 1TB,10TB
}
````

* Rename all CSVs to match virtual disks names
```PowerShell
Get-ClusterSharedVolume -Cluster $ClusterName | % {
    $volumepath=$_.sharedvolumeinfo.friendlyvolumename
    $newname=$_.name.Substring(22,$_.name.Length-23)
    Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
} 
````

* Configure Quorum (File Share Witness)

```PowerShell
#Create new directory
Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name S2DWitness -ItemType Directory}
$nodes=@()
1..$numberofnodes | % {$nodes+="corp\S2D$_$"}
$nodes+="corp\$ClusterName$"
$nodes+="corp\Administrator"
New-SmbShare -Name S2DWitness -Path c:\Shares\S2DWitness -FullAccess $nodes -CimSession DC
# Set NTFS permissions 
Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare S2DWitness).PresetPathAcl | Set-Acl}
#Set Quorum
Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness \\DC\S2DWitness
````

* On real systems you should not forget to configure CSV Cache
```PowerShell
(Get-Cluster $ClusterName).BlockCacheSize = 1024 
````

* If you want to play with some new Diagnostic Tools, run these commands. This is still work in progress, so it will likely change in RTM

```PowerShell
#show errors... 
Get-StorageSubSystem *$ClusterName | Debug-StorageSubSystem

#get healthreport
Get-StorageSubSystem *$ClusterName  | Get-StorageHealthReport -Count 5

#get cluster diagnostic
Get-ClusterDiagnostics -ClusterName $ClusterName

#storagedisagnostic
Get-StorageSubSystem -FriendlyName *$ClusterName | Get-StorageDiagnosticInfo -DestinationPath c:\temp
````


# How it looks like end-to-end (when you just paste the script). 
Note, there are small differences (we did not configure fault domains, but it is displayed on GIF as I did it a while ago.

![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/s2d_Hyperconverged.gif)
