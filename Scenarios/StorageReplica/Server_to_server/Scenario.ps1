
##### Server to Server, DFSR replacement scenario #####
#more info here https://technet.microsoft.com/en-us/windows-server-docs/storage/storage-replica/server-to-server-storage-replication

###############
# Run from DC #
###############

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

##### LAB Config #####
$Server1="Replica1"
$Server2="Replica2"

$SourceRGName="RG01"
$DestinationRGName="RG02"

$ReplicaNetwork="172.16.1."

######################

#install features for management
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Storage-Replica,RSAT-Hyper-V-Tools


##Install required roles
$server1,$server2 | ForEach-Object {Install-WindowsFeature -Name Storage-Replica,RSAT-Storage-Replica,FS-FileServer -ComputerName $_} 

#restart and wait for computers
Restart-Computer ($server1,$server2) -Protocol WSMan -Wait -For PowerShell

##format and initialize disks
new-volume -DiskNumber 1 -FriendlyName Data -FileSystem NTFS -AccessPath D: -CimSession $Server1
new-volume -DiskNumber 2 -FriendlyName Log -FileSystem NTFS -AccessPath E: -CimSession $Server1
new-volume -DiskNumber 1 -FriendlyName Data -FileSystem NTFS -AccessPath D: -CimSession $Server2
new-volume -DiskNumber 2 -FriendlyName Log -FileSystem NTFS -AccessPath E: -CimSession $Server2

##Test SR topology

#enable CredSSP to be able to work with NanoServer
Enable-WSManCredSSP -role server -Force
Enable-WSManCredSSP Client -DelegateComputer $Server1 -Force

#Create custom credentials
$username = "corp\Administrator"
$password = "LS1setup!"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$CustomCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

#create results folder
New-Item -ItemType Directory -Name replicaresults -Path \\dc\c$\
#test replica
Invoke-Command -ComputerName $Server1 -Authentication Credssp -Credential $CustomCred -ArgumentList $server1,$server2 -ScriptBlock {
    param($server1,$server2);
    Test-SRTopology -SourceComputerName $Server1 -SourceVolumeName D: -SourceLogVolumeName E: -DestinationComputerName $Server2 -DestinationVolumeName D: -DestinationLogVolumeName E: -DurationInMinutes 1 -ResultPath \\dc\c$\replicaresults
} 
#generate replica report (nano does not have charts API)
Test-SRTopology -GenerateReport -DataPath \\dc\c$\replicaresults\

New-SRPartnership -SourceComputerName $Server1 -SourceRGName $SourceRGName -SourceVolumeName d: -SourceLogVolumeName e: -DestinationComputerName $Server2 -DestinationRGName $DestinationRGName -DestinationVolumeName d: -DestinationLogVolumeName e:

do{
    $r=(Get-SRGroup -CimSession $Server2 -Name "$DestinationRGName").replicas
    [System.Console]::Write("Number of remaining bytes {0}`r", $r.NumOfBytesRemaining)
    Start-Sleep 5 #in production you should consider higher timeouts as querying wmi is quite intensive
}until($r.ReplicationStatus -eq 'ContinuouslyReplicating')
Write-Output "Replica Status: "$r.replicationstatus

#review completion logs
Get-WinEvent -ComputerName $Server2 -ProviderName Microsoft-Windows-StorageReplica | Where-Object {$_.ID -eq "1215"} | fl  

#review logs
Get-WinEvent -ComputerName $Server2 -ProviderName Microsoft-Windows-StorageReplica | FL

#Configure constraints to use just replica network
Set-SRNetworkConstraint -SourceComputerName $Server1 -SourceRGName (Get-SRGroup -CimSession $Server1).Name  -SourceNWInterface (Get-NetIPAddress -CimSession $Server1 -IPAddress "$ReplicaNetwork*").InterfaceIndex -DestinationComputerName $Server2 -DestinationNWInterface (Get-NetIPAddress -CimSession $Server1 -IPAddress "$ReplicaNetwork*").InterfaceIndex -DestinationRGName (Get-SRGroup -CimSession $Server2).Name

Get-SRNetworkConstraint -SourceComputerName $Server1 -SourceRGName (Get-SRGroup -CimSession $Server1).Name  -DestinationComputerName $Server2  -DestinationRGName (Get-SRGroup -CimSession $Server2).Name


#Configure DFSN
New-Item -Type Directory -Path \\dc\c$\DFS\MyDFSNRoot
New-SmbShare -CimSession dc -Path c:\DFS\MyDFSNRoot\ -Name MyDFSNRoot
New-DfsnRoot -Path \\corp.contoso.com\MyDFSNRoot -TargetPath \\DC.corp.contoso.com\MyDFSNRoot -Type DomainV2
New-DfsnFolderTarget -Path \\corp.contoso.com\MyDFSNRoot\FileShare -TargetPath \\$Server1\FileShare
New-DfsnFolderTarget -Path \\corp.contoso.com\MyDFSNRoot\FileShare -TargetPath \\$Server2\FileShare

#install graphical management tools for dfs validation 
#Install-WindowsFeature -Name RSAT-DFS-Mgmt-Con

#createfileshare
New-Item -Type Directory -Path \\$Server1\d$\ -Name fileshare
New-SmbShare -CimSession $Server1 -Path d:\fileshare -Name FileShare -FullAccess "corp\Domain Admins"
$value=@"
Hello World
"@
Set-Content -Value $value -Path \\corp\MyDFSNRoot\FileShare\testfile.txt
Test-Path \\corp\MyDFSNRoot\FileShare\testfile.txt

#flush disk
Write-FileSystemCache -DriveLetter d -CimSession $Server1
Write-VolumeCache -DriveLetter d -CimSession $Server1

#Flip replication
Set-SRPartnership -NewSourceComputerName $Server2 -SourceRGName $DestinationRGName -DestinationComputerName $Server1 -DestinationRGName $SourceRGName -confirm:$false

#createfileshare
New-SmbShare -CimSession $Server2 -Path d:\fileshare -Name FileShare -FullAccess "corp\Domain Admins"

#Flip replication again
Set-SRPartnership -NewSourceComputerName $Server1 -SourceRGName $SourceRGName -DestinationComputerName $Server2 -DestinationRGName $DestinationRGName -confirm:$false


#inspect events
Get-WinEvent -ComputerName $Server1 -ProviderName Microsoft-Windows-StorageReplica
Get-WinEvent -ComputerName $Server2 -ProviderName Microsoft-Windows-StorageReplica


#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
