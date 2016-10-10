# Scenario Description

* In this scenario 4 node S2D cluster can be created.
* It is just simulation "how it would look like". Performance is not a subject here.
* It is just to test look and feel


# Scenario requirements

* Windows 10 1511 with enabled Hyper-V or Windows 10 1607 (if nested virtualization is enabled)
* 8GB Memory or 20GB if nested virtualization is used (for 4 node configuration)
* SSD (with HDD it is really slow)

# Labconfig.ps1


* Without Nested Virtualization
````PowerShell
$LabConfig=@{
    DomainAdminName='Claus'; 			
	AdminPassword='LS1setup!'; 			
    Prefix = 'S2DHyperConverged-'; 		
    SwitchName = 'LabSwitch';			
    DCEdition='ServerDataCenter';		
    VMs=@()								
} 

1..4 | % { 
	$VMNames="S2D"; 							
	$LABConfig.VMs += @{ 
		VMName = "$VMNames$_" ; 
		Configuration = 'S2D' ; 				
		ParentVHD = 'Win2016NanoHV_G2.vhdx';	
		SSDNumber = 0; 							
		SSDSize=800GB ; 						
		HDDNumber = 12; 						
		HDDSize= 4TB ; 							
		MemoryStartupBytes= 512MB 				
	} 
} 
````

* With Nested Virtualization
````PowerShell
$LabConfig=@{
    DomainAdminName='Claus'; 			
	AdminPassword='LS1setup!'; 			
    Prefix = 'S2DHyperConverged-'; 		
    SwitchName = 'LabSwitch';			
    DCEdition='ServerDataCenter';		
    VMs=@()								
} 

1..4 | % { 
	$VMNames="S2D"; 							
	$LABConfig.VMs += @{ 
		VMName = "$VMNames$_" ; 
		Configuration = 'S2D' ; 				
		ParentVHD = 'Win2016NanoHV_G2.vhdx';	
		SSDNumber = 0; 							
		SSDSize=800GB ; 						
		HDDNumber = 12; 						
		HDDSize= 4TB ; 							
		MemoryStartupBytes= 4GB;
        NestedVirt=$True 				
	} 
}
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

* In this part networking is configured. Just to see how SET Switch looks like and how it looks like when you have 2 NICS teamed with SET Switch
````PowerShell
if ($Networking -eq "Yes"){
    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -MinimumBandwidthMode Weight -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    $Servers | ForEach-Object {
        Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management -ComputerName $_
    }
    Start-Sleep 5
    Clear-DnsClientCache
}
````

* Test and Create new cluster. ClearDNSCLientCace is the same as ipconfig /flushdns. Its needed to know about new cluster dns record.

````PowerShell
Test-Cluster –Node $servers –Include “Storage Spaces Direct”,Inventory,Network,”System Configuration”
New-Cluster –Name $ClusterName –Node $servers
Start-Sleep 5
Clear-DnsClientCache
````

* Enable S2D. It is specific to TP5 as you need to skip automatic configuration and skip eligibility checks (because all disks report with mediatype unknown, therefore eligibility check would fail)

```PowerShell
Enable-ClusterS2D -CimSession $ClusterName -AutoConfig:0
````

* To work with remote storage subsystem from DC, it is useful to register it with this command. I'm using $ClusterName, so I'll always work with some node that's online.
```PowerShell
Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName
````

* Display what was configured with Enable-Clusters2D
```PowerShell
#display pool
$pool=Get-StoragePool *$Clustername
$pool

#Display disks
Get-StoragePool *$Clustername | Get-PhysicalDisk

#display tiers (notice only capacity is available and is )
Get-StorageTier
````

* Create virtual disks. 

```PowerShell
if ($numberofnodes -le 3){
    1..$MRTNumber | ForEach-Object {
    New-Volume -StoragePoolFriendlyName $pool.FriendlyName -FriendlyName MultiResiliencyDisk$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes 2TB
    }
}else{
    1..$MRTNumber | ForEach-Object {
    New-Volume -StoragePoolFriendlyName $pool.FriendlyName -FriendlyName MultiResiliencyDisk$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames performance,capacity -StorageTierSizes 1TB,9TB
    }
}
start-sleep 10
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
###Configure quorum###
#ConfigureWitness
#Create new directory
$WitnessName=$Clustername+"Witness"
Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);new-item -Path c:\Shares -Name $WitnessName -ItemType Directory} -ArgumentList $WitnessName
$accounts=@()
$Servers | % {$accounts+="corp\$_$"}
$accounts+="corp\$ClusterName$"
$accounts+="corp\Domain Admins"
New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
# Set NTFS permissions 
Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);(Get-SmbShare "$WitnessName").PresetPathAcl | Set-Acl} -ArgumentList $WitnessName
#Set Quorum
Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

````

# How it looks like end-to-end (when you just paste the script). 
Note, there are small differences (we did not configure fault domains, but it is displayed on GIF as I did it a while ago.

![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/s2d_Hyperconverged.gif)
