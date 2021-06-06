################################
# Run from DC or Management VM #
################################

#region Create cluster and perform CAU to push cluster to preview
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
    $ClusterName="AzSHCI-Cluster"
    $CAURoleName="AzSHCI-Cl-CAU"

#install features for management remote cluster
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica

#install roles and features to servers
    #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
        if ($result.ExitCode -eq "failed"){
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        }
    }
    #define features
    $features="Failover-Clustering","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
    #install features
    Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
    #restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
    Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#Create Cluster
    New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"

#configure Witness on DC
    #Create new directory
        $WitnessName=$Clustername+"Witness"
        Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
        $accounts=@()
        $accounts+="corp\$ClusterName$"
        $accounts+="corp\Domain Admins"
        New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
    #Set NTFS permissions 
        Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
    #Set Quorum
        Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

        #Install required features on nodes.
        $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
        foreach ($ClusterNode in $ClusterNodes){
            Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
        }
    #add role
        Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose

#endregion

#region invoke CAU update including preview updates
    $ClusterName="AzSHCI-Cluster"

    $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}
    $scan | Select NodeName,UpdateTitle | Out-GridView

    Invoke-CauRun -ClusterName $ClusterName -MaxFailedNodes 0 -MaxRetriesPerNode 1 -RequireAllNodesOnline -Force -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}

#endregion

#region configure AzSHCI preview channel

$Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"

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

#unload module for next step
Remove-Module -Name ClusterAwareUpdating

Read-Host "Posh will now exit. Press a key"
exit

#endregion

#region perform Rolling Upgrade
$ClusterName="AzSHCI-Cluster"

#copy CAU plugin from cluster
    #download NTFSSecurity module to replace permissions to be able to delete existing version
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module NTFSSecurity -Force
    $items=Get-ChildItem -Path "c:\Windows\system32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating"
    $items | Set-NTFSOwner -Account $env:USERNAME
    $items | Get-NTFSAccess | Add-NTFSAccess -Account "Administrators" -AccessRights FullControl
    Remove-Item c:\Windows\system32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating -Recurse -Force
    $session=New-PSSession -ComputerName $ClusterName
    Copy-Item -FromSession $Session -Path c:\Windows\system32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating -Destination C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ -Recurse
    Import-Module -Name ClusterAwareUpdating
    $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.RollingUpgradePlugin" -CauPluginArguments @{'WuConnected'='true';} -Verbose
    $scan.upgradeinstallproperties.WuUpdatesInfo | Out-GridView

    Invoke-CauRun -ClusterName $ClusterName -Force -CauPluginName "Microsoft.RollingUpgradePlugin" -CauPluginArguments @{'WuConnected'='true';} -Verbose

#endregion