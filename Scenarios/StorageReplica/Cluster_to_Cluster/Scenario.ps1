
#more info about scenario is here https://technet.microsoft.com/en-us/windows-server-docs/storage/storage-replica/cluster-to-cluster-storage-replication

###############
# Run from DC #
###############

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

##### LAB Config #####

$Cluster1Servers='Replica1','Replica2'
$Cluster2Servers='Replica3','Replica4'

$Cluster1Name="ReplicaCluster1"
$Cluster2Name="ReplicaCluster2"

$SourceRGName="RG01"
$DestinationRGName="RG02"

$Servers=$Cluster1Servers+$Cluster2Servers

$ReplicaNetwork="172.16.1.0"
#######################

#install features for management
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools

##Install required roles
foreach ($server in $servers) {Install-WindowsFeature -Name Storage-Replica,RSAT-Storage-Replica,FS-FileServer -ComputerName $server} 

#restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#Create 2 Clusters
New-Cluster -Name $Cluster1Name -Node $Cluster1Servers -NoStorage
New-Cluster -Name $Cluster2Name -Node $Cluster2Servers -NoStorage
Start-Sleep 5
Clear-DnsClientCache

##format and initialize disks
new-volume -DiskNumber 1 -FriendlyName Data -FileSystem ReFS -AccessPath D: -CimSession $Cluster1Servers[0] 
new-volume -DiskNumber 2 -FriendlyName Log -FileSystem ReFS -AccessPath E: -CimSession $Cluster1Servers[0]
new-volume -DiskNumber 1 -FriendlyName Data -FileSystem ReFS -AccessPath D: -CimSession $Cluster2Servers[0]
new-volume -DiskNumber 2 -FriendlyName Log -FileSystem ReFS -AccessPath E: -CimSession $Cluster2Servers[0]

Move-ClusterGroup -Cluster $Cluster1Name -Name "available storage" -Node $Cluster1Servers[0]
Move-ClusterGroup -Cluster $Cluster2Name -Name "available storage" -Node $Cluster2Servers[0]

#enable CredSSP to be able to work with NanoServer
Enable-WSManCredSSP -role server -Force
Enable-WSManCredSSP Client -DelegateComputer $Cluster1Servers[0] -Force

#Create custom credentials
$username = "corp\Administrator"
$password = "LS1setup!"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$CustomCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr 

#create results folder
New-Item -ItemType Directory -Name replicaresults -Path \\dc\c$\
#test replica
Invoke-Command -ComputerName $Cluster1Servers[0] -Authentication Credssp -Credential $CustomCred -ArgumentList $Cluster1Servers,$Cluster2Servers -ScriptBlock  {
    param($Cluster1Servers,$Cluster2Servers);
    Test-SRTopology -SourceComputerName $Cluster1Servers[0] -SourceVolumeName D: -SourceLogVolumeName E: -DestinationComputerName $Cluster2Servers[0] -DestinationVolumeName D: -DestinationLogVolumeName E: -DurationInMinutes 1 -ResultPath \\dc\c$\replicaresults
} 
#generate replica report (nano does not have charts API)
Test-SRTopology -GenerateReport -DataPath \\dc\c$\replicaresults\

Add-ClusterSharedVolume -Name "Cluster Disk 1" -Cluster $Cluster1Name
Add-ClusterSharedVolume -Name "Cluster Disk 1" -Cluster $Cluster2Name

Grant-SRAccess -ComputerName $Cluster1Servers[0]  -Cluster $Cluster2Name
Grant-SRAccess -ComputerName $Cluster2Servers[0]  -Cluster $Cluster1Name

New-SRPartnership -SourceComputerName $Cluster1Name -SourceRGName $SourceRGName -SourceVolumeName c:\ClusterStorage\Volume1 -SourceLogVolumeName e: -DestinationComputerName $Cluster2Name -DestinationRGName $DestinationRGName -DestinationVolumeName c:\ClusterStorage\Volume1 -DestinationLogVolumeName e:

do{
    $r=(Get-SRGroup -CimSession $Cluster2Name -Name $DestinationRGName).replicas
    [System.Console]::Write("Number of remaining bytes {0}`r", $r.NumOfBytesRemaining)
    Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
}until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
Write-Output "Replica Status: "$r.replicationstatus

#create VM
New-VM -Name TestVMReplica -MemoryStartupBytes 32MB -NewVHDPath "C:\ClusterStorage\Volume1\TestVMReplica\Virtual Hard Disks\TestVMReplica_Disk1.vhdx" -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\Volume1" -ComputerName $Cluster1Servers[0]
Start-VM -name TestVMReplica -ComputerName $Cluster1Servers[0]
Add-ClusterVirtualMachineRole -VMName TestVMReplica -Cluster $Cluster1Name



#Flip replication
Set-SRPartnership -NewSourceComputerName $Cluster2Name -SourceRGName $SourceRGName -DestinationComputerName $Cluster1Name -DestinationRGName $DestinationRGName -confirm:$false

#Import all VMs on Site2
Invoke-Command -ComputerName $Cluster2Servers[0] -ScriptBlock{
    get-childitem C:\ClusterStorage -Recurse | where {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
	    Import-VM -Path $_.FullName
    }
}

#Add VMs as Highly available and Start
$VMnames=(Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name).Name
$VMNames | ForEach-Object {Add-ClusterVirtualMachineRole -VMName $_ -Cluster $Cluster2Name}
Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name | Start-VM
Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name

##Flip Replication back
#turnOff VMs on destination with the same name on source as on destination
Stop-VM -TurnOff -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name -Name (Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name).Name
#Flip Replication
Set-SRPartnership -NewSourceComputerName $Cluster1Name -SourceRGName $SourceRGName -DestinationComputerName $Cluster2Name -DestinationRGName $DestinationRGName -confirm:$false
#Start VMs
Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name | Start-VM
#and again if it was in saved state and error occured
Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name | Start-VM

#And Again :)
#turnOff VMs on destination with the same name on source as on destination
Stop-VM -TurnOff -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name -Name (Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name).Name
#Flip Replication
Set-SRPartnership -NewSourceComputerName $Cluster2Name -SourceRGName $DestinationRGName -DestinationComputerName $Cluster1Name -DestinationRGName $SourceRGName -confirm:$false
#Start VMs
Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster2Name).Name | Start-VM
#and again if it was in saved state and error occured
Get-VM -CimSession (Get-ClusterNode -Cluster $Cluster1Name).Name | Start-VM 

#Set network constraint to use 172.16.1. network for SR-

(Get-ClusterNetwork -Cluster $Cluster1Name | where Address -eq $ReplicaNetwork).Name="ReplicaNetwork"
(Get-ClusterNetwork -Cluster $Cluster2Name | where Address -eq $ReplicaNetwork).Name="ReplicaNetwork"
Set-SRNetworkConstraint -SourceComputerName $Cluster1Name -SourceRGName (Get-SRGroup -CimSession $Cluster1Name).Name  -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $Cluster2Name -DestinationNWInterface "ReplicaNetwork" -DestinationRGName (Get-SRGroup -CimSession $Cluster2Name).Name


Get-SRNetworkConstraint -SourceComputerName $Cluster1Name -SourceRGName (Get-SRGroup -CimSession $Cluster1Name).Name  -DestinationComputerName $Cluster2Name  -DestinationRGName (Get-SRGroup -CimSession $Cluster2Name).Name


#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
