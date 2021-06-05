################################
# Run from DC or Management VM #
################################

#region update machines to 21H2

#Variables
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"

# Update servers - this will install updates and also latest SSU
    Invoke-Command -ComputerName $servers -ScriptBlock {
        #Grab updates
        $SearchCriteria = "IsInstalled=0"
        #$SearchCriteria = "IsInstalled=0 and DeploymentAction='OptionalInstallation'" #does not work, not sure why
        $ScanResult=Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria=$SearchCriteria}
        #apply updates (if not empty)
        if ($ScanResult.Updates){
            Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName InstallUpdates -Arguments @{Updates=$ScanResult.Updates}
        }
    }

#restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

# Update servers with all updates (including preview - 5C - that will enable 21H2 preview as an option)
    #configure virtual acount to avoid using CredSSP
    Invoke-Command -ComputerName $servers -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore

    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
    }

#restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#validate if at least 5C update was installed https://support.microsoft.com/en-us/topic/may-20-2021-preview-update-kb5003237-0c870dc9-a599-4a69-b0d2-2e635c6c219c
    $RevisionNumbers=Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name UBR
    }

    foreach ($item in $RevisionNumbers) {
        if ($item -lt 1737){
            Write-Output "Something went wrong. UBR is $item. Should be higher thah 1737"
        }else{
            Write-Output "UBR is $item, you're good to go"
        }
    }


#once updated to at least 1737, you can configure preview channel
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Set-PreviewChannel
    }

#reboot machines to apply
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#validate if all is OK
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-PreviewChannel
    }

#install Feature Update 
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
        #Commit
        $Committer = $Session.CreateUpdateInstaller()
        $Committer.Updates = $SearchResult
        $Committer.Commit(0)
    }

#remove temporary PSsession config
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }

#reboot machines to apply
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell


#install management features to DC
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica

#install roles and features
    #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
        if ($result.ExitCode -eq "failed"){
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        }
    }

    #define features
    $features="Failover-Clustering","Hyper-V-PowerShell"
    if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
    if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
    if ($Deduplication){$features+="FS-Data-Deduplication"}
    if ($SystemInsights){$features+="System-Insights","RSAT-System-Insights"}

    #install features
    Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
    #restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
    Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#validate if at least may C update was installed https://support.microsoft.com/en-us/topic/may-20-2021-preview-update-kb5003237-0c870dc9-a599-4a69-b0d2-2e635c6c219c
$RevisionNumbers=Invoke-Command -ComputerName $Servers -ScriptBlock {
    Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name UBR
}

foreach ($item in $RevisionNumbers) {
    if ($item -lt 1737){
        $UpdateNeeded=$true
    }
}

#run update once again if needed
if ($UpdateNeeded){
    # Update servers with all updates (including preview)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    # Run Windows Update via ComObject.
    Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
    }
    #remove temporary PSsession config
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
    }
}
#endregion

#region validate if servers are updaated ot 21H2

#endregion