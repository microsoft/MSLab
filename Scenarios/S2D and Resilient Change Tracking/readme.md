<!-- TOC -->

- [S2D and Resilient Change Tracking (Work in progress!)](#s2d-and-resilient-change-tracking-work-in-progress)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Prereq](#prereq)
    - [The lab: Backup VMs to another CSV](#the-lab-backup-vms-to-another-csv)
        - [Prepare PowerShell module](#prepare-powershell-module)
        - [Perform full backup](#perform-full-backup)
        - [Perform incremental backup](#perform-incremental-backup)
    - [Todo: Work with checkpoints and reference points](#todo-work-with-checkpoints-and-reference-points)
    - [Todo: Backup VMs to file share](#todo-backup-vms-to-file-share)

<!-- /TOC -->

# S2D and Resilient Change Tracking (Work in progress!)

## About the lab

In this lab you will learn how to backup VMs using Resilient Change Tracking. More information in this session from 2019 https://channel9.msdn.com/Events/TechEd/Europe/2014/CDP-B318 and also in original scripts https://www.powershellgallery.com/packages/xHyper-VBackup/1.0.3 published by Taylor Brown.

Original scripts were modified by [@vladimirmach](https://twitter.com/vladimirmach) as there were minor bugs and he published it under his github repo https://github.com/machv/xhyper-vbackup

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@()}

#S2D Cluster
$LABConfig.VMs += @{ VMName = "S2D1" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }
$LABConfig.VMs += @{ VMName = "S2D2" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }

#Backup destination
$LabConfig.VMs += @{ VMName = 'BackupDest'; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 1GB; AddToolsVHD = $True }

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win1019H1_G2.vhdx'; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }
 
```

## Prereq

Note: script does not follow all best practices. For best practices visit S2D Hyperconverged scenario.

```PowerShell
# variables
    $ClusterNodes="S2D1","S2D2"
    $ClusterName="S2D-Cluster"
    $VMNames="VM01","VM02"

#ask for VHD (you can provide nano or core)
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
    }
    $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
    If($openFile.ShowDialog() -eq "OK"){
        Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
    } 
    if (!$openFile.FileName){
        Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
    }
    $VHDPath = $openFile.FileName

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Client"){
        #Install RSAT tools
        $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        foreach ($Capability in $Capabilities){
            Add-WindowsCapability -Name $Capability -Online
        }
    }

# Install features on servers
    Invoke-Command -computername $ClusterNodes -ScriptBlock {
        Install-WindowsFeature -Name "Hyper-V","Failover-Clustering","Hyper-V-PowerShell","RSAT-Clustering-PowerShell" #RSAT is needed for Windows Admin Center if used
    }

#restart all servers since failover clustering in 2019 requires reboot
    Restart-Computer -ComputerName $ClusterNodes -Protocol WSMan -Wait -For PowerShell

#create cluster
    New-Cluster -Name $ClusterName -Node $ClusterNodes
    Start-Sleep 5
    Clear-DNSClientCache


#add file share witness
    #Create new directory
        $WitnessName=$ClusterName+"Witness"
        Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
        $accounts=@()
        $accounts+="corp\$($ClusterName)$"
        $accounts+="corp\Domain Admins"
        New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
    #Set NTFS permissions
        Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
    #Set Quorum
        Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

#Enable S2D
    Enable-ClusterS2D -CimSession $ClusterName -Verbose -Confirm:0

#Create Volumes
    New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MyVolume" -FileSystem CSVFS_ReFS -Size 1TB -CimSession $ClusterName
    New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MyBackupVolume" -FileSystem CSVFS_ReFS -Size 1TB -CimSession $ClusterName

#Create VMs
    foreach ($VMName in $VMNames){
        New-Item -Path "\\$ClusterName\ClusterStorage$\MyVolume\$VMName\Virtual Hard Disks" -ItemType Directory
        Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\MyVolume\$VMName\Virtual Hard Disks\$VMName.vhdx" 
        New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\MyVolume\" -VHDPath "c:\ClusterStorage\MyVolume\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random)
        Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
    }
#Start all VMs
    Get-VM -Cimsession (Get-ClusterNode -Cluster $ClusterName).Name | Start-VM
 
```

## The lab: Backup VMs to another CSV

### Prepare PowerShell module

```PowerShell
#Install required features
Install-WindowsFeature -Name "Hyper-V-PowerShell","RSAT-Clustering-PowerShell","RSAT-AD-PowerShell"

#Download PSModule
Invoke-WebRequest -Uri https://github.com/machv/xhyper-vbackup/archive/master.zip -UseBasicParsing -OutFile $env:USERPROFILE\Downloads\xhyper-vbackup-master.zip

#Copy module to cluster nodes
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name #Select failover cluster
$Servers=(Get-ClusterNode -Cluster $CLusterName).Name

$Sessions=New-PSSession -ComputerName $Servers

foreach ($Session in $Sessions){
    Copy-Item -Path $env:USERPROFILE\Downloads\xhyper-vbackup-master.zip -Destination $env:USERPROFILE\Downloads -ToSession $Session
}

#extract to PSModules on destination
Invoke-Command -ComputerName $Servers -ScriptBlock {
    #Remove-Item -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\xhyper-vbackup-master -Force
    #Remove-Item -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\xhyper-vbackup -Force
    Expand-Archive -Path $env:USERPROFILE\Downloads\xhyper-vbackup-master.zip -DestinationPath C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ -Force
    Rename-Item -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\xhyper-vbackup-master -NewName xhyper-vbackup
    Remove-Item -Path $env:USERPROFILE\Downloads\xhyper-vbackup-master.zip
}
 
```

### Perform full backup

```PowerShell
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name #Select failover cluster
$Servers=(Get-ClusterNode -Cluster $CLusterName).Name
#Choose VM for Backup
$VMsToBackup=Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple
$Destination="c:\clusterstorage\MyBackupVolume\Full"
#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel CrashConsistent
        Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name) -BackupCheckpoint $checkpoint
    }
}

```

### Perform incremental backup

```PowerShell
#Create incremental backup
#Choose VM for Backup
$VMsToBackup=hyper-v\Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple
$Destination="c:\clusterstorage\MyBackupVolume\Diff"
#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel CrashConsistent
        $referencePoint = Get-VmReferencePoints -VmName $using:vm.Name
        # Exports differential backup of the machine 
        Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name) -BackupCheckpoint $checkpoint -ReferencePoint $referencePoint
        # Removes backup snapshot and converts it as reference point for future incremental backups
        Convert-VmBackupCheckpoint -BackupCheckpoint $checkpoint
    }
}
 
```

## Todo: Work with checkpoints and reference points

## Todo: Backup VMs to file share