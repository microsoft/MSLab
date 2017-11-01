# Enabling BitLocker on S2D cluster

Enabling BitLocker on S2D is covered in [this](https://technet.microsoft.com/en-us/library/dn383585(v=ws.11).aspx) TechNet article. Enabling BitLocker on CSV is a bit complex task. This scenario will help you understand steps needed and also contains sample script, that rapidly simlifies it.

To try this scenario, deploy [S2D HyperConverged cluster](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged) first. To enable BitLocker, you can just run the [script](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/BitLocker%20on%20S2D%20cluster/EnableBitlockerOnS2D.ps1), and it will take care of everything.

## High level overview

To Successfully encrypt CSV, you first need BitLocker feature and BitLocker PowerShell module on all nodes (as all BitLocker commands must run from cluster nodes). The catch is, that if you did not install it before, you will have to restart each S2D cluster node. To safely reboot, you can wait to next Windows Update cycle (so CAU will take care) or you have to safely reboot all nodes manually (that’s really annoying) or with script. After BitLocker feature is enabled, you may want to configure BitLocker recovery password backup to Active Directory. This can be done after registry keys or editing local/domain GPO. After all this is done, you may proceed to enabling BitLocker. The caveat is, that BitLocker can be enabled on CSV only when its suspended. And Suspended volume means also, that all VMs that have VHD located on that volume would go offline (in case of 2016 server it will not BlueScreen, but it will go into the Paused-Critical state instead and when volume is resumed, VMs will resume also). You may want to shut these VMs off or use Storage Live Migration to move it. Once CSV is suspended, you can start adding protectors to the volume. First one is RecoveryPasswordProtector, that can (should) be backed into AD Computer Account. As all actions are done from volume owner, it will be backed into owner AD Account. Then you will enable BitLocker with AD Account Protector. To do this, you have to use your account to work with AD. As you are doing this from management machine, you just get into the Double-Hop issue (where you have your credentials in your Management machine, you use it in S2D Cluster Node and from there you need to authenticate to AD). This is because of BitLocker commands do not have -CimSession parameter, you have to push all commands with invoke-command to remote computer. To be able to successfully set this up, you need to temporarily enable CredSSP authentication. After BitLocker is enabled, you can resume volume and VMs. What I like to do is backing RecoveryPasswordProtector to all other cluster nodes, so you will be safe if someone deletes one node from AD.

## Install Required features and safely reboot nodes

This Posh is bit complex. It runs node by node, checking if Bitlocker,RSAT-Feature-Tools-BitLocker is installed and if reboot is required. If reboot is required, it will check, if there are any running storage repair jobs. If so, it will show how much GB are processed and how much GB is it processing in total. I did have minor issue in my lab (running in laptop), that sometimes I was seeing suspended repair job, that was blocking suspending cluster node (as one volume was unhealthy due to repair job). So the script includes logic to check for this job and resuming it by invoking volume repair. Once this is done, cluster node is suspended, restarted and then resumed again.

Notice, that all suspend/resume actions are being tried until it succeeds.

````PowerShell
#install features and wait for servers to reboot
    foreach ($ClusterNode in $ClusterNodes){
        Write-Output "Installing Bitlocker Feature on $ClusterNode"
        $result=Install-WindowsFeature -Name Bitlocker,RSAT-Feature-Tools-BitLocker -computername $ClusterNode
        $result
        if ($result.restartneeded -eq "Yes"){
            Write-Output "Restart is needed. Checking for active repair storage jobs"
                #check for repair jobs, if found, wait until finished
                if ((Get-StorageSubSystem -CimSession $ClusterName -FriendlyName Clus* | Get-StorageJob -CimSession $ClusterName | Where-Object Name -eq Repair) -ne $Null){
                    do{
                        $jobs=(Get-StorageSubSystem -CimSession $ClusterName -FriendlyName Clus* | Get-StorageJob -CimSession $ClusterName)
                        if ($jobs | Where-Object Name -eq Repair){
                            $count=($jobs | Measure-Object).count
                            $BytesTotal=($jobs | Measure-Object BytesTotal -Sum).Sum
                            $BytesProcessed=($jobs | Measure-Object BytesProcessed -Sum).Sum
                            [System.Console]::Write("$count Repair Storage Job(s) Running. GBytes Processed: $($BytesProcessed/1GB) GBytes Total: $($BytesTotal/1GB)               `r")
                            #Check for Suspended jobs (if there are no running repair jobs, only suspended and still unhealthy disks). Kick the repair with Repair-Virtual disk if so... 
                            if ((($jobs | where-Object Name -eq Repair | where-Object JobState -eq "Running") -eq $Null) -and ($jobs | where-Object Name -eq Repair | where-Object JobState -eq "Suspended") -and (Get-VirtualDisk -CimSession $ClusterName | where healthstatus -ne Healthy)){
                                Write-Output "Suspended repair job and Degraded virtual disk found. Invoking Virtual Disk repair"
                                Get-VirtualDisk -CimSession $ClusterName | where-Object HealthStatus -ne "Healthy" | Repair-VirtualDisk
                            }
                            Start-Sleep 5
                        }
                    }until (($jobs | Where-Object Name -eq Repair) -eq $null)
                }
            Write-Output ""
            Write-Output "Checking if all disks are healthy"
            if(((Get-VirtualDisk -CimSession $ClusterName).healthstatus | Select-Object -Unique) -eq "Healthy"){
                Write-Output "All Disks are healthy"
            }else{
                Write-Output "Waiting for disks to become healthy"
                do{ Start-Sleep 5}until(((Get-VirtualDisk -CimSession $ClusterName).healthstatus | Select-Object -Unique) -eq "Healthy")
            }
            Write-Output "Suspending Cluster Node $ClusterNode"
            do{
                Start-Sleep 10 
                Suspend-ClusterNode -Name $ClusterNode -Cluster $ClusterName -Drain -ErrorAction SilentlyContinue
            }until((Get-ClusterNode -Cluster $ClusterName -Name $ClusterNodes).State -eq "Paused")
            Write-Output "Restarting Cluster Node $ClusterNode"
            Restart-Computer -ComputerName $ClusterNode -Protocol WSMan -Wait -For PowerShell
            Write-Output "Resuming Cluster node $ClusterNode"
            do{
                Start-Sleep 10 
                Resume-ClusterNode -Name $ClusterNode -Cluster $ClusterName -ErrorAction SilentlyContinue
            }until((Get-ClusterNode -Cluster $ClusterName -Name $ClusterNodes).State -eq "Up")
        }
    }

````

## Add Bitlocker registry keys

To be able to backup recovery key to AD, policy or registry has to be set. Following commented registries are the the same regs as will are created when GPO on screenshot below is set (I also like checkbox in the bottom to not enable BitLocker, if recovery info is not stored in AD). Only 2 registries are actually needed.

![](/Scenarios/BitLocker%20on%20S2D%20cluster/Screenshots/BitLockerGPO.png)

````PowerShell
    Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
        #Create FVE key if not exist
        if (-not (Get-Item -path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ErrorAction SilentlyContinue)){
            New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE
        }

        #Configure required registries to enable Recovery and AD Backup (FDVActiveDirectoryBackup and FDVRecovery). FDV stands for Fixed Disk Volume.
        if (-not (Get-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup -ErrorAction SilentlyContinue)){
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup -Value 1 -PropertyType DWORD
        }elseif((Get-ItemPropertyValue -path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup -ErrorAction SilentlyContinue) -ne 1){
            Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup -Value 1
        }

        if (-not (Get-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery -ErrorAction SilentlyContinue)){
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery -Value 1 -PropertyType DWORD
        }elseif((Get-ItemPropertyValue -path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery -ErrorAction SilentlyContinue) -ne 1){
            Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery -Value 1
        }
    
        <# these are registries that are set by GPO 
            New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup        -Value 1 -PropertyType DWORD -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryInfoToStore   -Value 1 -PropertyType DWORD -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVManageDRA                    -Value 1 -PropertyType DWORD -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery                     -Value 1 -PropertyType DWORD -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecoveryKey                  -Value 2 -PropertyType DWORD -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecoveryPassword             -Value 2 -PropertyType DWORD -ErrorAction SilentlyContinue
            New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRequireActiveDirectoryBackup -Value 1 -PropertyType DWORD -ErrorAction SilentlyContinue
        #>
    }

````
## Move workload away, suspend CSV and enable BitLocker

I really like Out-GridView as it can provide GUI, so you don't have to type anything. In this case it will help filling $CSVs variable with CSVs of your choice. Script identifies owner node, checks if volume is decrypted (if encrypted, it skips it). If its dectrypted, it will go and shuts all VMs on volume off and then suspends volume.

Script checks if there is an RecoveryPassword protector, if not, it will generate new one and backs it into the Active Directory.

As already described in high level overview, CredSSP is needed. In this case I consider, that there is no CredSSP configured, as all CredSSP config is later removed. CredSSP is unfortunately needed for sucessful enablement of ADAccount protector. Script uses XTSAES128 and encrypts used space only.

After BitLocker is enabled, CSV is resumed and VMs started. The last step is to move CSV to other nodes and initiate backup of PasswordProtector to AD.

````PowerShell
$CSVs=Get-ClusterSharedVolume -Cluster $clustername | Out-GridView -PassThru -Title "Please select CSVs to encrypt. Selected CSV will be put in maintenance mode, bitlockered and then resumed"

foreach ($CSV in $CSVs){
    $owner=$csv.ownernode.name
    $CsvPath = ($CSV).SharedVolumeInfo.FriendlyVolumeName
    #check if already encrypted
    $Status=Invoke-Command -ComputerName $owner -ArgumentList $CSVPath -ScriptBlock {param($CsvPath); Get-BitLockerVolume -MountPoint $CSVPath}
    if ($status.VolumeStatus -eq "FullyDecrypted"){

        #Grab all VMs on CSV, that will be suspended and shut it down
        $VMs=(Get-VMHardDiskDrive -CimSession $clusternodes -vmname * | Where-Object path -like $csvpath*).VMName | Select-Object -Unique
        Write-Output "Following VMs will be Shut down:"
        $VMs
        foreach ($VM in $VMs){
            Get-VM -CimSession $ClusterNodes | Where-Object Name -eq $VM | Stop-VM -Force
        }

        #suspend CSV
        Write-Output "Volume $CSVPath is Decrypted, suspending"
        $CSV | Suspend-ClusterResource -Force

        #Add recovery protector if not exist
        Invoke-Command -ComputerName $owner -ArgumentList $CsvPath -ScriptBlock {
            param($CsvPath);
            $KeyProtectorId=((Get-BitLockerVolume $CsvPath).KeyProtector | Where-Object KeyProtectorType -Eq "RecoveryPassword").KeyProtectorId
            if (-not $KeyProtectorId){
                Add-BitLockerKeyProtector $CsvPath -RecoveryPasswordProtector
                $KeyProtectorId=((Get-BitLockerVolume $CsvPath).KeyProtector | Where-Object KeyProtectorType -Eq "RecoveryPassword").KeyProtectorId
            }
            Backup-BitLockerKeyProtector -MountPoint $CsvPath -KeyProtectorId $KeyProtectorId
        }

        #Enable CredSSP delegation to be able to encrypt CSV
        Write-Output "Enabling CredSSP delegation to $owner"
        Enable-WSManCredSSP Client –DelegateComputer $owner -Force
        Invoke-Command -ComputerName $owner -ScriptBlock {Enable-WSManCredSSP Server -Force}

        #Encrypt Volume
        Invoke-Command -ArgumentList $CsvPath,$clustername -Credential $cred -Authentication Credssp -ComputerName $owner -ScriptBlock {
            param($CsvPath,$clustername);
            Enable-BitLocker $CsvPath -EncryptionMethod XtsAes128 -UsedSpaceOnly -AdAccountOrGroupProtector -ADAccountOrGroup "$clustername$"
        }

        #Disable CredSSP
        Write-Output "Disabling CredSSP"
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $owner -ScriptBlock {Disable-WSManCredSSP Server}

        $CSV | Resume-ClusterResource
        
        #Start VMs again
        foreach ($VM in $VMs){
            Get-VM -CimSession $ClusterNodes | Where-Object Name -eq $VM | Start-VM -ErrorAction SilentlyContinue
        }

        #backup to AD to another computer objects... 
            Write-Host "Backing up Recovery key to another Nodes AD Objects"
            foreach ($ClusterNode in $ClusterNodes){
                if ($Clusternode -ne $owner){
                    Write-Host "Moving ownership to $ClusterNode and initializing backup"
                    $CSV | Move-ClusterSharedVolume -Node $ClusterNode
                    Invoke-Command -ComputerName $ClusterNode -ArgumentList $CSVPath -ScriptBlock {
                        param($CsvPath); 
                        $KeyProtectorId=((Get-BitLockerVolume $CsvPath).KeyProtector | Where-Object KeyProtectorType -Eq "RecoveryPassword").KeyProtectorId
                        Backup-BitLockerKeyProtector -MountPoint $CsvPath -KeyProtectorId $KeyProtectorId}
                }
            }
    }else{
        Write-Host "Volume $CSVPath is not FullyDecrypted"
    }
}

````
## Some Screenshots

![](/Scenarios/BitLocker%20on%20S2D%20cluster/Screenshots/ClusterSelect.png)

![](/Scenarios/BitLocker%20on%20S2D%20cluster/Screenshots/CredentialsForCredSSP.png)

![](/Scenarios/BitLocker%20on%20S2D%20cluster/Screenshots/CSVsSelection.png)

![](/Scenarios/BitLocker%20on%20S2D%20cluster/Screenshots/BitLockerRecoveryKeys.png)

### CheckBitlockerOnS2D.ps1

![](/Scenarios/BitLocker%20on%20S2D%20cluster/Screenshots/CheckBitlockerOnS2D.png)

