###############
# Run from DC #
###############

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

##### LAB Config #####

$Cluster1Servers='Site1S2D1','Site1S2D2'
$Cluster2Servers='Site2S2D1','Site2S2D2'

$Cluster1Name="S2DSRCluster1"
$Cluster2Name="S2DSRCluster2"

$SourceRGName="RG01"
$DestinationRGName="RG02"

$Servers=$Cluster1Servers+$Cluster2Servers

$ReplicaNetwork="172.16.1.0"

$TypeOfWorkload="IWFS" # IWFS or VMs = Informational Work File SHare or VMs
#######################


#install features for management
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools

##Install required roles
foreach ($server in $servers) {Install-WindowsFeature -Name Storage-Replica,RSAT-Storage-Replica,FS-FileServer -ComputerName $server} 

##restart those servers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#Create 2 Clusters
New-Cluster -Name $Cluster1Name -Node $Cluster1Servers
New-Cluster -Name $Cluster2Name -Node $Cluster2Servers
Start-Sleep 5
Clear-DnsClientCache

#Configure Witness
foreach ($clustername in ($Cluster1Name,$Cluster2Name)){
    $WitnessName=$Clustername+"Witness"
    Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);new-item -Path c:\Shares -Name $WitnessName -ItemType Directory} -ArgumentList $WitnessName
    $accounts=@()
    (Get-ClusterNode -Cluster $ClusterName).Name | % {$accounts+="corp\$_$"}
    $accounts+="corp\$ClusterName$"
    $accounts+="corp\Domain Admins"
    New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
    # Set NTFS permissions 
    Invoke-Command -ComputerName DC -ScriptBlock {param($WitnessName);(Get-SmbShare "$WitnessName").PresetPathAcl | Set-Acl} -ArgumentList $WitnessName
    #Set Quorum
    Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
}

#Enable-ClusterS2D
Enable-ClusterS2D -CimSession $Cluster1Name -confirm:0 -verbose
Enable-ClusterS2D -CimSession $Cluster2Name -confirm:0 -verbose

#register storage provider 
Get-StorageProvider | Register-StorageSubsystem -ComputerName $Cluster1Name
Get-StorageProvider | Register-StorageSubsystem -ComputerName $Cluster2Name

#Get Pools
$Cluster1Pool=Get-StoragePool *$Cluster1name
$Cluster2Pool=Get-StoragePool *$Cluster2name

#create volumes


if ($Cluster1Servers.Count -le 3){
    New-Volume -StoragePoolUniqueId $Cluster1Pool.UniqueId -FriendlyName Data -FileSystem ReFS -AccessPath D: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
    New-Volume -StoragePoolUniqueId $Cluster2Pool.UniqueId -FriendlyName Data -FileSystem ReFS -AccessPath D: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
    New-Volume -StoragePoolUniqueId $Cluster1Pool.UniqueId -FriendlyName Log  -FileSystem ReFS -AccessPath E: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
    New-Volume -StoragePoolUniqueId $Cluster2Pool.UniqueId -FriendlyName Log  -FileSystem ReFS -AccessPath E: -StorageTierFriendlyNames capacity -StorageTierSizes 10GB
}else{
    New-Volume -StoragePoolUniqueId $Cluster1Pool.UniqueId -FriendlyName Data -FileSystem ReFS -AccessPath D: -StorageTierFriendlyNames performance,capacity -StorageTierSizes 1GB,9GB
    New-Volume -StoragePoolUniqueId $Cluster2Pool.UniqueId -FriendlyName Data -FileSystem ReFS -AccessPath D: -StorageTierFriendlyNames performance,capacity -StorageTierSizes 1GB,9GB
    New-Volume -StoragePoolUniqueId $Cluster1Pool.UniqueId -FriendlyName Log  -FileSystem ReFS -AccessPath E: -StorageTierFriendlyNames performance -StorageTierSizes 10GB
    New-Volume -StoragePoolUniqueId $Cluster2Pool.UniqueId -FriendlyName Log  -FileSystem ReFS -AccessPath E: -StorageTierFriendlyNames performance -StorageTierSizes 10GB
}


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

Add-ClusterSharedVolume -Name "Cluster Virtual Disk (Data)" -Cluster $Cluster1Name
Add-ClusterSharedVolume -Name "Cluster Virtual Disk (Data)" -Cluster $Cluster2Name


#rename Volumes to match name
foreach ($clustername in ($Cluster1Name,$Cluster2Name)){
    Get-ClusterSharedVolume -Cluster $ClusterName | % {
        $volumepath=$_.sharedvolumeinfo.friendlyvolumename
        $newname=$_.name.Substring(22,$_.name.Length-23)
        Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
    } 
}

Grant-SRAccess -ComputerName $Cluster1Servers[0]  -Cluster $Cluster2Name
Grant-SRAccess -ComputerName $Cluster2Servers[0]  -Cluster $Cluster1Name

New-SRPartnership -SourceComputerName $Cluster1Name -SourceRGName $SourceRGName -SourceVolumeName c:\ClusterStorage\Data -SourceLogVolumeName e: -DestinationComputerName $Cluster2Name -DestinationRGName $DestinationRGName -DestinationVolumeName c:\ClusterStorage\Data -DestinationLogVolumeName e:

do{
    $r=(Get-SRGroup -CimSession $Cluster2Name -Name $DestinationRGName).replicas
    [System.Console]::Write("Number of remaining bytes {0}`r", $r.NumOfBytesRemaining)
    Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
}until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
Write-Output "Replica Status: "$r.replicationstatus

#Set network constraint to use $ReplicaNetwork network for SR-
(Get-ClusterNetwork -Cluster $Cluster1Name | where Address -eq $ReplicaNetwork).Name="ReplicaNetwork"
(Get-ClusterNetwork -Cluster $Cluster2Name | where Address -eq $ReplicaNetwork).Name="ReplicaNetwork"
Set-SRNetworkConstraint -SourceComputerName $Cluster1Name -SourceRGName (Get-SRGroup -CimSession $Cluster1Name).Name  -SourceNWInterface "ReplicaNetwork" -DestinationComputerName $Cluster2Name -DestinationNWInterface "ReplicaNetwork" -DestinationRGName (Get-SRGroup -CimSession $Cluster2Name).Name
Get-SRNetworkConstraint -SourceComputerName $Cluster1Name -SourceRGName (Get-SRGroup -CimSession $Cluster1Name).Name  -DestinationComputerName $Cluster2Name  -DestinationRGName (Get-SRGroup -CimSession $Cluster2Name).Name

    If ($TypeOfWorkload -eq "VMs"){
    #create VM
    New-VM -Name TestVMReplica -MemoryStartupBytes 32MB -NewVHDPath "C:\ClusterStorage\Data\TestVMReplica\Virtual Hard Disks\TestVMReplica_Disk1.vhdx" -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\Data" -ComputerName $Cluster1Servers[0]
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
}

if ($TypeOfWorkload -eq "IWFS"){
    Add-ClusterScaleOutFileServerRole -Name SOFS1 -Cluster $Cluster1Name
    Add-ClusterScaleOutFileServerRole -Name SOFS2 -Cluster $Cluster2Name
    #create share
    New-SmbShare -CimSession $Cluster1Name -Path "C:\ClusterStorage\Data\" -ScopeName SOFS1 -Name "Share" -FullAccess Everyone
    #disable CA
    Set-SMBShare -CimSession $Cluster1Name -Name Share -ContinuouslyAvailable $false -Force
    #Flip replication
    Set-SRPartnership -NewSourceComputerName $Cluster2Name -SourceRGName $DestinationRGName -DestinationComputerName $Cluster1Name -DestinationRGName $SourceRGName -confirm:$false
    #create share
    New-SmbShare -CimSession $Cluster2Name -Path "C:\ClusterStorage\Data\" -ScopeName SOFS2 -Name "Share" -FullAccess Everyone
    #disable CA
    Set-SMBShare -CimSession $Cluster2Name -Name Share -ContinuouslyAvailable $false -Force

    #configure DFS-N
    New-Item -Type Directory -Path \\dc\c$\DFS\MyDFSNRoot
    New-SmbShare -CimSession dc -Path c:\DFS\MyDFSNRoot\ -Name MyDFSNRoot
    New-DfsnRoot -Path \\corp.contoso.com\MyDFSNRoot -TargetPath \\DC.corp.contoso.com\MyDFSNRoot -Type DomainV2
    New-DfsnFolderTarget -Path \\corp.contoso.com\MyDFSNRoot\Share -TargetPath \\SOFS1\Share
    New-DfsnFolderTarget -Path \\corp.contoso.com\MyDFSNRoot\Share -TargetPath \\SOFS2\Share

}
#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
