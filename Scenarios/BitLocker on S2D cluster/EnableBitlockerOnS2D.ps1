#Install AD PowerShell if not available
$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster").Name

if (-not $ClusterName){
    Write-Output "No cluster was selected. Exitting"
    Start-Sleep 5
    Exit
}

$cred=Get-Credential -Message "Please provide credentials for configuring ADAccountProtector"

$ClusterNodes=(Get-ClusterNode -Cluster $clustername).name

#check if Nano is installed
$installationType=Invoke-Command -computername $clustername -scriptblock { (get-computerinfo).WindowsInstallationType} 

if ($installationType -eq "Nano Server"){
    Write-Output "Installation type is Nano Server. Bitlocker on CSV does not work there. Exitting"
    Start-Sleep 5
    Exit
}

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

#enable policies to backup Bitlocker key to AD
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

#if you want to encrypt all volumes
#$CSVs=Get-ClusterSharedVolume -Cluster $clustername

#or if you want to encrypt just some CSVs:
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
        Enable-WSManCredSSP Client -DelegateComputer $owner -Force
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
