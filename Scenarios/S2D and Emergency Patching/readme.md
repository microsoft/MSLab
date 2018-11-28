<!-- TOC -->

- [S2D and Emergency Patching](#s2d-and-emergency-patching)
    - [Sample LabConfig for Windows Server 2016](#sample-labconfig-for-windows-server-2016)
    - [Sample LabConfig for Windows Server 2019](#sample-labconfig-for-windows-server-2019)
    - [Prerequisites](#prerequisites)
    - [Emergency shutdown and patching process](#emergency-shutdown-and-patching-process)
        - [Invoke Windows Update](#invoke-windows-update)
        - [Shut down VMs](#shut-down-vms)
        - [Stop all cluster resources and services](#stop-all-cluster-resources-and-services)
        - [Reboot all machines](#reboot-all-machines)
        - [Check Windows Version](#check-windows-version)
        - [Check installed updates](#check-installed-updates)
        - [Check Reboot Pending](#check-reboot-pending)
    - [Start Cluster](#start-cluster)
        - [Start cluster service](#start-cluster-service)
        - [Start Cluster resources](#start-cluster-resources)
        - [Start VMs](#start-vms)

<!-- /TOC -->

# S2D and Emergency Patching

Following scenario is useful if you want to avoid nodes resync, or it's also useful just to shut down cluster gracefully or if you want to apply critical update immediately.

## Sample LabConfig for Windows Server 2016

Following LabConfig uses 4GB for each VM and nested virt to be able to play with real workload. It's possible to also use standard LabConfig, but VMs would be turned off. Note that Internet is also set to $True to provide internet connectivity to download updates.

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}
1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }}
 
```

## Sample LabConfig for Windows Server 2019

Note: Enable-ClusterS2D requires you to reach support to get steps to make it work on 2019 RTM as WSSD programme will be officially launched starting 2019.

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4'; PullServerDC=$false ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True }}

```

## Prerequisites

Deploy [S2D Hyperconverged Scenario](/Scenarios/S2D%20Hyperconverged/) You can change $RealVMs to $True (so you will be asked for VHD and real VMs will be created). I would recommend to use something small (Linux or Nano Server). To Create NanoServer, use script in ParentDisks folder to create NanoServer VHD out of Windows Server 2016 ISO.

## Emergency shutdown and patching process

### Invoke Windows Update

To shorten maintenance window as much as possible you can invoke update installation with following command. Note the difference between 2016 and 2019. You can take a look into this [scenario](/Scenarios/Windows%20Update/) that covers all details.

```PowerShell
#Following command is using RSAT-Clustering-PowerShell (Install-WindowsFeature -Name RSAT-Clustering-PowerShell)
$ClusterName="S2D-Cluster"
$servers=(Get-ClusterNode -Cluster $ClusterName).Name

Invoke-Command -ComputerName $servers -ScriptBlock {
    $ReleaseID=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name ReleaseID
    if ($ReleaseID -eq 1607){
        #Script for Windows Server 2016
        $Instance = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
        $ScanResult=$instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
        if ($ScanResult.updates){
            $instance | Invoke-CimMethod -MethodName DownloadUpdates -Arguments @{Updates=$ScanResult.updates}
            $instance | Invoke-CimMethod -MethodName InstallUpdates  -Arguments @{Updates=$ScanResult.updates}
        }
    }
    if ($ReleaseID -eq 1809){
        #Script for Windows Server 2019
        $ScanResult=Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1"}
        if ($ScanResult.Updates){
            Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName InstallUpdates -Arguments @{Updates=$ScanResult.Updates}
        }
    }
}
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/2019UpdateResult.png)

To check reboot pending you can run following command

```PowerShell
$ClusterName="S2D-Cluster"
$servers=(Get-ClusterNode -Cluster $ClusterName).Name

Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName IsPendingReboot
 
```

As you can notice, there is no pending reboot in my environment since updates that I installed were only for Defender.

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/PendingReboot.png)

### Shut down VMs

There are 2 options actually. You can either save all VMs (it might take some time since all memory needs to be written to storage), or you can shut down all VMs (but starting VMs will take some time too)

```PowerShell
$ClusterName="S2D-Cluster"
$servers=(Get-ClusterNode -Cluster $ClusterName).Name

#Save all VMs
Stop-VM -Name * -CimSession $servers -Save -Force

#or Shut down all VMs
#Stop-VM -Name * -CimSession $servers -Force
 
```

To check if VMs are not running you can run following command

```PowerShell
$ClusterName="S2D-Cluster"
$servers=(Get-ClusterNode -Cluster $ClusterName).Name

Get-VM -CimSession $servers
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/VMs_Saved.png)

### Stop all cluster resources and services

To make all resources offline, run following commands. Note: this approach is extremely cautious. Just stopping cluster service would also work, but I prefer it this way as it's bit cleaner.

```PowerShell
$ClusterName="S2D-Cluster"
$servers=(Get-ClusterNode -Cluster $ClusterName).Name

#Stop CSVs
Get-ClusterSharedVolume -Cluster $ClusterName | Stop-ClusterResource
#Stop Performance History Volume
Get-ClusterResource -Cluster $ClusterName -Name *ClusterPerformanceHistory* | Stop-ClusterResource
#Stop Pool
Get-ClusterResource -Cluster $ClusterName | where-object ResourceType -eq "Storage Pool" | Stop-ClusterResource
#Stop CAU
$CAUOwnerGroup=(Get-ClusterResource -Cluster $ClusterName | where-object ResourceType -eq "ClusterAwareUpdatingResource").OwnerGroup
$CAUOwnerGroup | Stop-ClusterGroup
#Stop ClusterCoreResources
Get-ClusterGroup -Cluster s2d-cluster -Name "Cluster Group" | Stop-ClusterGroup
#Stop Clussvc and disable autostart
Invoke-Command -ComputerName $servers -ScriptBlock {
    Stop-Service -Name ClusSvc
    Set-Service -Name ClusSvc -StartupType Disabled
}
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/StoppingClusterResources.png)

### Reboot all machines

This task is relatively easy. It's just simple command

```PowerShell
#Since Cluster Service is not running, nodes has to be provided manually
$Servers=1..4 | Foreach-Object {"S2D$_"} #This is just easier way to type "s2d1","s2d2","s2d3","s2d4"

Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
 
```

### Check Windows Version

Check if updates were applied

```PowerShell
$Servers=1..4 | Foreach-Object {"S2D$_"}

$Sessions=New-PSSession -ComputerName $servers
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$ComputerInfo  = foreach ($Session in $Sessions) {
    New-Object PSObject -Property @{
        ComputerName       = $session.ComputerName
        BuildBranch        = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name BuildBranch}
        BuildLab           = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name BuildLab}
        CurrentBuildNumber = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name CurrentBuildNumber}
        EditionID          = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name EditionID}
        InstallationType   = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name InstallationType}
        ProductName        = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name ProductName}
        ReleaseId          = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name ReleaseId}
        RevisionNumber     = Invoke-Command -Session $Session -ScriptBlock {Get-ItemPropertyValue -Path $using:RegistryPath -Name UBR}
    }
}
$Sessions | Remove-PSSession
$ComputerInfo | ft ComputerName,CurrentBuildNumber,RevisionNumber
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/CheckWindowsVersion.png)

### Check installed updates

```PowerShell
Invoke-Command -ComputerName $servers -ScriptBlock {
$ReleaseID=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name ReleaseID
    if ($ReleaseID -eq 1607){
        #Command for Windows Server 2016
        $Instance = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
        $ScanResult=$instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=1";OnlineScan=$true}
        $ScanResult.updates
    }
    if ($ReleaseID -eq 1809){
        #Command for Windows Server 2019
        $ScanResult=Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=1"}
        $ScanResult.updates
    }
}
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/InstalledUpdates.png)


### Check Reboot Pending

Check if reboot is pending

```PowerShell
$Servers=1..4 | Foreach-Object {"S2D$_"}
Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName IsPendingReboot
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/PendingReboot1.png)

## Start Cluster

### Start cluster service

```PowerShell
$Servers=1..4 | Foreach-Object {"S2D$_"}
#enable autostart and start Clussvc
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-Service -Name ClusSvc -StartupType Automatic
    Start-Service -Name ClusSvc
}
 
```

### Start Cluster resources

You can notice that all cluster resources are down `Get-ClusterResource -Cluster S2D1` . So let's start it.

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/ClusterResourcesOffline.png)

```PowerShell
$Server="S2D1" #specify one server that is up
$ClusterName="S2D-Cluster"

#Start ClusterCoreResources
Get-ClusterGroup -Cluster $Server -Name "Cluster Group" | Start-ClusterGroup
#Start CAU
$CAUOwnerGroup=(Get-ClusterResource -Cluster $ClusterName | where-object ResourceType -eq "ClusterAwareUpdatingResource").OwnerGroup
$CAUOwnerGroup | Start-ClusterGroup
#Start Pool
Get-ClusterResource -Cluster $ClusterName | where-object ResourceType -eq "Storage Pool" | Start-ClusterResource
#Start Performance History Volume (should be already started)
Get-ClusterResource -Cluster $ClusterName -Name *ClusterPerformanceHistory* | Start-ClusterResource
#Start CSVs
Get-ClusterSharedVolume -Cluster $ClusterName | Start-ClusterResource
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/StartingClusterResources.png)

### Start VMs

Since all VM configurations are in failed state, it's needed to make it online first and then start all VMs

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/FailedVMResources.png)

```PowerShell
$ClusterName="S2D-Cluster"
$servers=(Get-ClusterNode -Cluster $ClusterName).Name

#Make all VM Configurations online (it's most probably in failed state)
Get-ClusterResource -Cluster $ClusterName | Where State -eq Failed | Start-ClusterResource

#Start all VMs
Start-VM -Name * -CimSession $servers
Get-VM -CimSession $Servers
 
```

![](/Scenarios/S2D%20and%20Emergency%20Patching/Screenshots/VMsRunningAgain.png)
