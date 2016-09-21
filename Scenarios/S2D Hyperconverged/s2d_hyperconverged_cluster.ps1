##S2D Cluster##
#This scenario simulates hyperconverged cluster consisting of 3,4,8,or 16 nodes. This simulates 3tier configuration, but without S2D cache

##### VMS Config in variables.ps1 #####
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

#### Or with Nested Virtualization. But you need host with (almost) same build number (win 10 insider preview, or Windows Server TP5 #####

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

#######################################
# Paste into PowerShell running in DC #
#######################################

Start-Transcript -Path '.\S2DHydration.log'

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

##### LAB Config #####

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

###############

#install features for management
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools

<#install Hyper-V for core servers - in case you are deploying core servers instead of Nano
Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
foreach ($server in $servers) {Install-WindowsFeature -Name Failover-Clustering,Failover-Clustering-S2D,Hyper-V-PowerShell -ComputerName $server} 
#restart and wait for computers
Invoke-Command -ComputerName $servers -ScriptBlock {Restart-Computer -Force}
Start-Sleep 60
#>

if ($Networking -eq "Yes"){
    ###Configure networking - this creates Switch Embedded Team (SET) switch with 2 vNICs representing 2 vRDMA adapters in real environment ###
    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -MinimumBandwidthMode Weight -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    $Servers | ForEach-Object {
        Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Management1 -ComputerName $_
        Add-VMNetworkAdapter    -ManagementOS -Name Management2 -SwitchName SETSwitch -ComputerName $_

    }
    Start-Sleep 5
    Clear-DnsClientCache
}

###Test and create new cluster ###
Test-Cluster –Node $servers –Include “Storage Spaces Direct”,Inventory,Network,”System Configuration”
New-Cluster –Name $ClusterName –Node $servers –NoStorage 
Start-Sleep 5
Clear-DnsClientCache
   
#Enable-ClusterS2D
Enable-ClusterS2D -CimSession $ClusterName -confirm:0

#register storage provider 
Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName

#display pool
$pool=Get-StoragePool *$Clustername
$pool

#Display disks
Get-StoragePool *$Clustername | Get-PhysicalDisk

#display tiers (notice only capacity is available and is )
Get-StorageTier


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

#rename CSV(s)
Get-ClusterSharedVolume -Cluster $ClusterName | % {
    $volumepath=$_.sharedvolumeinfo.friendlyvolumename
    $newname=$_.name.Substring(22,$_.name.Length-23)
    Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
} 


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

#unregister StorageSubsystem
#$ss=Get-StorageSubSystem -FriendlyName *$ClusterName
#Unregister-StorageSubsystem -ProviderName "Windows Storage Management Provider" -StorageSubSystemUniqueId $ss.UniqueId

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript