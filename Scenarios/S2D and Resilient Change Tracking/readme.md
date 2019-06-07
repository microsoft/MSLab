<!-- TOC -->

- [S2D and Resilient Change Tracking](#s2d-and-resilient-change-tracking)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Prereq](#prereq)
    - [The lab: Backup VMs to another CSV](#the-lab-backup-vms-to-another-csv)
        - [Prepare PowerShell module](#prepare-powershell-module)
        - [Perform full backup](#perform-full-backup)
            - [Create checkpoint and export VM](#create-checkpoint-and-export-vm)
            - [Remove Checkpoint](#remove-checkpoint)
        - [Playing with Reference Points](#playing-with-reference-points)
            - [Perform full backup while preserving reference point](#perform-full-backup-while-preserving-reference-point)
            - [Perform incremental backup](#perform-incremental-backup)
            - [Perform Full backup again, but remove all reference points first](#perform-full-backup-again-but-remove-all-reference-points-first)
            - [Just cleanup all reference points](#just-cleanup-all-reference-points)
            - [Remove all subfolders in clusterstorage\MyBackupVolume](#remove-all-subfolders-in-clusterstorage\mybackupvolume)
        - [Let's try end-to-end scenario](#lets-try-end-to-end-scenario)
            - [Backup VM (create full if not full, create diff if full exist)](#backup-vm-create-full-if-not-full-create-diff-if-full-exist)
            - [Delete both VMs](#delete-both-vms)
            - [Restore VM from differential checkpoint](#restore-vm-from-differential-checkpoint)

<!-- /TOC -->

# S2D and Resilient Change Tracking

## About the lab

In this lab you will learn how to backup VMs using Resilient Change Tracking. More information in this session from 2014 https://channel9.msdn.com/Events/TechEd/Europe/2014/CDP-B318 and also in original scripts https://www.powershellgallery.com/packages/xHyper-VBackup/1.0.3 published by Taylor Brown.

It's just POC. Use on prod with caution! You should use backup solutions such as DPM that are using RCT. You can use this just to learn about RCT and how to work with checkpoints/referencepoints

Why I think this feature is cool? Imagine if you would Storage Replicate your backup volume to another location, wouldn't it be a perfect DR solution? Ultimately all can be scripted.

Original scripts were modified by [@vladimirmach](https://twitter.com/vladimirmach) as there were minor [bugs](https://github.com/machv/xhyper-vbackup/commits/master) and he published it under his [github repo](https://github.com/machv/xhyper-vbackup)

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; AdditionalNetworksConfig=@(); VMs=@()}

#S2D Cluster
$LABConfig.VMs += @{ VMName = "S2D1" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }
$LABConfig.VMs += @{ VMName = "S2D2" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }

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
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single -Title "Select failover cluster where xHyper-VBackup will be copied").Name #Select failover cluster
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
    #remove leftovers
    Rename-Item -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\xhyper-vbackup-master -NewName xhyper-vbackup
    Remove-Item -Path $env:USERPROFILE\Downloads\xhyper-vbackup-master.zip
}
 
```

Once powerShell module is installed, on remote nodes will be following commands available.

```PowerShell
Invoke-Command -ComputerName s2d1 -ScriptBlock {Get-Command -Module xHyper-VBackup}
 
```

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/xhyper-vbackup01.png)


### Perform full backup

#### Create checkpoint and export VM

Following script will create backup checkpoint and copies it into remote destination. It will let you select cluster and VM. For VM, choose VM01. Keep same powershell window open for all tasks to keep variables.

Note: since consistency level is applicationconsistent, you need to wait till VMs are booted into OS.

```PowerShell
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single -Title "Select failover cluster").Name #Select failover cluster
$Servers=(Get-ClusterNode -Cluster $CLusterName).Name
#Choose VM for Backup (Choose VM01)
$VMsToBackup=Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple -Title "Choose VM for Backup (Choose VM01)"
$Destination="c:\clusterstorage\MyBackupVolume\"
#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel ApplicationConsistent #or CrashConsistent
        Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name)\Full-$($checkpoint.CreationTime) -BackupCheckpoint $checkpoint
    }
}
 
```

The backup checkpoint was created and it was exported to another CSV as specified in example above.

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/VM01Checkpoint.png)

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/VM01BackupCheckpointInGUI.png)

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/ExportedVM01Posh.png)

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/ExportedVM01Explorer.png)


#### Remove Checkpoint

Since you don't want to have checkpoint on your machine, you can remove it with following command. Notice, that in GUI is Export only since this is recovery checkpoint.

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/VM01ExportOnly.png)

```PowerShell
Get-VMCheckpoint -VMName VM01 -CimSession $Servers | Remove-VMCheckpoint
 
```

### Playing with Reference Points

Above example is not very convenient as you would have to do full backups all the time. It's bit easier to perform full backup, and instead of removing checkpoint, you want to keep reference point, so if you do backup again, you can do incremetal backup

#### Perform full backup while preserving reference point

```PowerShell
#Choose VM for Backup (Choose VM01)
$VMsToBackup=Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple -Title "Choose VM for Backup (Choose VM01)"
$Destination="c:\clusterstorage\MyBackupVolume\"
#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel ApplicationConsistent #or CrashConsistent
        Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name)\Full-$($checkpoint.CreationTime) -BackupCheckpoint $checkpoint
        # Removes backup snapshot and converts it as reference point for future incremental backups
        Convert-VmBackupCheckpoint -BackupCheckpoint $checkpoint
    }
}
 
```

#### Perform incremental backup

```PowerShell
#Choose VM for Backup (Choose VM01 again)
$VMsToBackup=hyper-v\Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple -Title "Choose VM for Backup (Choose VM01)"
$Destination="c:\clusterstorage\MyBackupVolume\"
#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel ApplicationConsistent #or CrashConsistent
        $referencePoints = Get-VmReferencePoints -VmName $using:vm.Name
        $lastreferencepoint=Get-VmReferencePoints -vmname $using:vm.Name | sort Res* |select -Last 1
        $lastreferencepointID=($lastreferencepoint.ResilientChangeTrackingIdentifiers).split(":") | select -Last 1
        # Exports differential backup of the machine 
        Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name)\Diff-$lastreferencepointID -BackupCheckpoint $checkpoint -ReferencePoint $lastreferencepoint
        # Removes backup snapshot and converts it as reference point for future incremental backups
        Convert-VmBackupCheckpoint -BackupCheckpoint $checkpoint
    }
}
 
```

#### Perform Full backup again, but remove all reference points first

```PowerShell
#Choose VM for Backup (Choose VM01)
$VMsToBackup=Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple
$Destination="c:\clusterstorage\MyBackupVolume\"
#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $refs=Get-VmReferencePoints -VmName $using:vm.Name
        foreach ($ref in $refs){Remove-VmReferencePoint -ReferencePoint $ref}
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel ApplicationConsistent #or CrashConsistent
        Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name)\Full-$($checkpoint.CreationTime) -BackupCheckpoint $checkpoint
        # Removes backup snapshot and converts it as reference point for future incremental backups
        Convert-VmBackupCheckpoint -BackupCheckpoint $checkpoint
    }
}
 
```

As you can see, we have now multiple full backups and one diff (sorted by data modified). Script generated the filenames, but you can modify it as you wish.

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/Backup01.png)

#### Just cleanup all reference points

```PowerShell
#Choose VM for cleanup (Choose VM01)
$VMsToCleanup=Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple "Choose VM for cleanup ref points (Choose VM01)"
#cleanup chosen VMs
foreach ($VM in $VMsToCleanup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $refs=Get-VmReferencePoints -VmName $using:vm.Name
        foreach ($ref in $refs){Remove-VmReferencePoint -ReferencePoint $ref}
    }
}
 
```

#### Remove all subfolders in clusterstorage\MyBackupVolume

```PowerShell
Remove-Item -Path \\s2d-cluster\clusterstorage$\MyBackupVolume\* -Recurse
 
```

### Let's try end-to-end scenario

#### Backup VM (create full if not full, create diff if full exist)

Run below code multiple times just to create multiple checkpoints. Backup both VM01 and VM02.

```PowerShell
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name #Select failover cluster
$Servers=(Get-ClusterNode -Cluster $CLusterName).Name
#Choose CSV where to backup (Choose MyBackupVolume)
$Destination=(Invoke-Command -ComputerName $ClusterName -scriptblock {Get-ChildItem -Path "c:\clusterstorage\" | Select Name,FullName} | Out-GridView -OutputMode Single -Title "Choose CSV where to backup (Choose MyBackupVolume)").FullName
#Choose VM for Backup (Choose both VM01 and VM02)
$VMsToBackup=Get-VM -CimSession $Servers | Out-GridView -OutputMode Multiple -Title "Choose VM for Backup (Choose both VM01 and VM02)"

#backup chosen VMs
foreach ($VM in $VMsToBackup){
    Invoke-Command -ComputerName $vm.ComputerName -ScriptBlock {
        $referencePoints = Get-VmReferencePoints -VmName $using:vm.Name
        $checkpoint = New-VmBackupCheckpoint -VmName $using:vm.Name -ConsistencyLevel ApplicationConsistent #or CrashConsistent
        if ($referencePoints){
            #perform diff
            $referencePoints = Get-VmReferencePoints -VmName $using:vm.Name
            $lastreferencepoint=Get-VmReferencePoints -vmname $using:vm.Name | sort Res* |select -Last 1
            $lastreferencepointID=($lastreferencepoint.ResilientChangeTrackingIdentifiers).split(":") | select -Last 1
            Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name)\Diff-$lastreferencepointID -BackupCheckpoint $checkpoint -ReferencePoint $lastreferencepoint
        }else{
            #perform full
            Export-VMBackupCheckpoint -VmName $using:vm.Name -DestinationPath $using:destination\$($using:vm.name)\Full-$($checkpoint.CreationTime) -BackupCheckpoint $checkpoint
        }
        Convert-VmBackupCheckpoint -BackupCheckpoint $checkpoint
    }
}
 
```

As you can see, each VM has multiple diff backups as I ran above script multiple times.

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/Backups02.png)

VM01 starts with diff-00000005 since we were playing wiht backup checkpoints before

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/Backups03.png)

#### Delete both VMs

```PowerShell
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single).Name #Select failover cluster

#select VMs to delete (select both VM01 and VM02)
$VMGroups=Get-ClusterGroup -Cluster $clustername | where grouptype -like Virt* | Out-GridView -OutputMode Multiple -Title "select VMs to delete (select both VM01 and VM02)"
foreach ($VMGroup in $VMGroups){
    #remove cluster resource group
    $OwnerNode=$VMGroup.OwnerNode.Name
    $VMGroup | Remove-ClusterGroup -RemoveResources -Force
    $VM=Get-VM -Cimsession $OwnerNode -Name $vmgroup.name
    $vm | Stop-VM -Force -TurnOff
    $vm | remove-VM -Force
    Invoke-Command -ComputerName $ownernode -ScriptBlock {Remove-Item -Path $using:VM.Path -Recurse -Force}
}
 
```

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/AllVMsDeleted.png)

#### Restore VM from differential checkpoint

```PowerShell
$Clustername=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single -Title "Select Failover Cluster").Name #Select failover cluster

$BackupCSV=(Invoke-Command -ComputerName $ClusterName -scriptblock {Get-ChildItem -Path "c:\clusterstorage\" | Select Name,FullName} | Out-GridView -OutputMode Single -Title "Select CSV where backups are located (MyBackupVolume)").Name
$RestoreCSV=(Invoke-Command -ComputerName $ClusterName -scriptblock {Get-ChildItem -Path "c:\clusterstorage\" | Select Name,FullName} | Out-GridView -OutputMode Single -Title "Select CSV where backups will be restored (MyVolume)").Name

$VMsToRestore=(Invoke-Command -ComputerName $clusterName -scriptblock {Get-ChildItem -Path c:\ClusterStorage\$using:BackupCSV | select Name,FullName } | Out-GridView -OutputMode Multiple -Title "Select VM to restore (Both VM01 and VM02)").Name

foreach ($VMToRestore in $VMsToRestore){
    $CheckpointToRestore=(Invoke-Command -ComputerName $clustername -scriptblock {Get-ChildItem -Path c:\clusterstorage\$using:backupcsv\$using:VMToRestore | Select Name,FullName }| Out-GridView -OutputMode Multiple -Title "Select checkpoint to restore (random diff-xxxxxxx)").FullName

    #Copy selected checkpoint to destination
    Invoke-Command -computername $ClusterName -ScriptBlock {
        New-Item "c:\ClusterStorage\$using:RestoreCSV\$using:VMToRestore" -ItemType Directory
        Copy-Item -Path "$using:CheckpointToRestore\*" -Destination "c:\ClusterStorage\$using:RestoreCSV\$using:VMToRestore" -Recurse 
    }

    #Copy remaining vhds
    Invoke-Command -computername $clustername -scriptblock {
        $AVHDXs=get-childitem -Path "c:\ClusterStorage\$using:RestoreCSV\$using:VMToRestore\Virtual Hard Disks" | where extension -eq .avhdx
        $allfiles=get-childitem -path c:\ClusterStorage\$using:BackupCSV\$using:VMToRestore -recurse
        foreach ($avhdx in $avhdxs){
            $vhd=get-vhd -Path $avhdx.FullName
            do {
                if ($vhd.parentpath){
                    $Parent=($vhd.ParentPath) | split-Path -leaf
                    #find avhdx in BackupCSV\VMName
                    $ParentFile=($allfiles | where Name -eq $Parent).FullName
                    Copy-Item -path $parentfile -destination "c:\ClusterStorage\$using:RestoreCSV\$using:VMToRestore\Virtual Hard Disks"
                    $vhd=get-vhd -path $parentfile
                }else{
                    $quit=$true
                }
            }until(
                $quit -eq $true
            )
        }
    }

    #import VM
    Invoke-Command -ComputerName $clustername -scriptblock {
        $configfile=(Get-ChildItem -Path "c:\ClusterStorage\$using:RestoreCSV\$using:VMToRestore\Virtual Machines" | where extension -eq .vmcx).fullname
        Import-VM -Path $configfile
    }

    #add to cluster
    Add-ClusterVirtualMachineRole -VMName $VMToRestore -Cluster $ClusterName
    
    #Start VM
    Start-VM -Name $VMToRestore -CimSession $clustername
}
 
```

![](/Scenarios/S2D%20and%20Resilient%20Change%20Tracking/Screenshots/AllVMsRestored.png)
