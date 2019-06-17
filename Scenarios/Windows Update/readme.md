<!-- TOC -->

- [Scripting Windows Update](#scripting-windows-update)
    - [About the lab](#about-the-lab)
    - [LabConfig (notice it uses both 2016 and 2019 vhdx files)](#labconfig-notice-it-uses-both-2016-and-2019-vhdx-files)
    - [List available updates on 2016 and 2019](#list-available-updates-on-2016-and-2019)
    - [Exploring CimInstance](#exploring-ciminstance)
    - [List available updates on 2016 and 2019 revised](#list-available-updates-on-2016-and-2019-revised)
    - [Apply updates on 2016 and 2019](#apply-updates-on-2016-and-2019)
    - [Update validation](#update-validation)
        - [Display installed updates](#display-installed-updates)
        - [Display pending reboot on all Domain Computers](#display-pending-reboot-on-all-domain-computers)
        - [Display Last Installation Date on all Domain Computers](#display-last-installation-date-on-all-domain-computers)
        - [Display Last Scan Success Date on all Domain Computers](#display-last-scan-success-date-on-all-domain-computers)
        - [Display update level](#display-update-level)
        - [Check if servers are up-to-date](#check-if-servers-are-up-to-date)

<!-- /TOC -->

# Scripting Windows Update

## About the lab

Following lab is inspired with NanoServer patching. There is following documentation available https://blogs.technet.microsoft.com/nanoserver/2016/01/16/updating-nano-server-using-windows-update-or-windows-server-update-service/ https://docs.microsoft.com/en-us/windows-server/get-started/update-nano-server

## LabConfig (notice it uses both 2016 and 2019 vhdx files)

You can create 2016 VHDs using CreateParentDisks.ps1 located in tools folder. Or you can copy it from 2016 lab into parent disks.

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = '2016_1'   ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = '2016_2'   ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = '2019_1'   ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = '2019_2'   ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
 
```

## List available updates on 2016 and 2019

[Documentation](https://docs.microsoft.com/en-us/windows-server/get-started/update-nano-server) says, that in 2016 you can query updates with following command (I bit modified it to work with multiple servers). Scan for updates might take some time.

```PowerShell
$servers="2016_1","2016_2"
$Instances = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession -CimSession $servers
$ScanResult=foreach ($instance in $instances){
    $instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
}
$ScanResult.updates
 
```

![](/Scenarios/Windows%20Update/Screenshots/ScanResult2016.png)

If you will try the same, against 2019 servers, you will get following error.

```PowerShell
$servers="2019_1","2019_2"
$Instances = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession -CimSession $servers
$ScanResult=foreach ($instance in $instances){
    $instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
}
$ScanResult.updates
 
```

![](/Scenarios/Windows%20Update/Screenshots/ScanResult2019Error.png)

Let's explore what's changed

## Exploring CimInstance

To list classes run following command. As you can see, there is a different name. In 2016 is MSFT_WUOperationsSession while in 2019 is just MSFT_WUOperations

```PowerShell
#List Windows Server 2016 Classes from computer 2016_1
Get-CimClass -Namespace root/Microsoft/Windows/WindowsUpdate -CimSession "2016_1" | Where CimClassMethods -ne $null

#List Windows Server 2019 Classes from computer 2019_1
Get-CimClass -Namespace root/Microsoft/Windows/WindowsUpdate -CimSession "2019_1" | Where CimClassMethods -ne $null
 
```

![](/Scenarios/Windows%20Update/Screenshots/2016Classes.png)

![](/Scenarios/Windows%20Update/Screenshots/2019Classes.png)

Let's explore Methods from WUOperations and WUOperationsSession now.

```PowerShell
#List Windows Server 2016 methods from MSFT_WUOperationsSession class from computer 2016_1
Get-CimClass -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession -CimSession "2016_1" | Select-Object -ExpandProperty CimClassMethods

#List Windows Server 2019 methods from MSFT_WUOperations class from computer 2019_1
Get-CimClass -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperations -CimSession "2019_1" | Select-Object -ExpandProperty CimClassMethods
 
```

![](/Scenarios/Windows%20Update/Screenshots/2016Methods.png)

![](/Scenarios/Windows%20Update/Screenshots/2019Methods.png)

Hmm, there have been changes too! Let's explore what changed then...

## List available updates on 2016 and 2019 revised

As you can see on following update, the cleanup we did in WindowsUpdate instance is not necessary bad. Scanning for updates is now easier as there is no need to create instance first.

```PowerShell
#Invoke Scan on Windows Server 2016
$servers="2016_1","2016_2"
$Instances = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession -CimSession $servers
$ScanResult=foreach ($instance in $instances){
    $instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
}
$ScanResult.updates

#Invoke Scan on Windows Server 2019
$servers="2019_1","2019_2"
$ScanResult=Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1"}
$ScanResult.updates
 
```

![](/Scenarios/Windows%20Update/Screenshots/ScanResult2016_1.png)

![](/Scenarios/Windows%20Update/Screenshots/ScanResult2019_1.png)

## Apply updates on 2016 and 2019

In 2016 you can apply updates using ApplyApplicableUpdates Method like this.

```PowerShell
$servers="2016_1","2016_2"
$Instances = New-CimInstance -CimSession $Servers -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
foreach ($Instance in $Instances){
    Invoke-CimMethod -InputObject $Instance -MethodName ApplyApplicableUpdates
}
 
```

But this method is not available in 2019. Let's explore different way then.

```PowerShell
#Invoke Scan on Windows Server 2016 and apply all updates
$servers="2016_1","2016_2"
$Instances = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession -CimSession $servers
foreach ($instance in $instances){
    #find updates
    $ScanResult=$instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
    #apply updates (if not empty)
    if ($ScanResult.Updates){
        $instance | Invoke-CimMethod -MethodName DownloadUpdates -Arguments @{Updates=$ScanResult.Updates}
        $instance | Invoke-CimMethod -MethodName InstallUpdates -Arguments @{Updates=$ScanResult.Updates}
    }
}
 
```

To make it faster you can invoke it as block

```PowerShell
#Invoke Scan on Windows Server 2016 and apply all updates using invoke-command
$servers="2016_1","2016_2"
Invoke-Command -ComputerName $servers -ScriptBlock {
    $Instance = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
    #find updates
    $ScanResult=$instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
    #apply updates (if not empty)
    if ($ScanResult.Updates){
        $instance | Invoke-CimMethod -MethodName DownloadUpdates -Arguments @{Updates=$ScanResult.Updates}
        $instance | Invoke-CimMethod -MethodName InstallUpdates  -Arguments @{Updates=$ScanResult.Updates}
    }
}
 
```

And finally to just apply critical updates you can run this

```PowerShell
#Invoke Scan on Windows Server 2016 and apply all critical updates using invoke-command
$servers="2016_1","2016_2"
Invoke-Command -ComputerName $servers -ScriptBlock {
    $Instance = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
    #find updates
    $ScanResult=$instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1";OnlineScan=$true}
    #apply updates (if not empty)
    $CriticalUpdates= $ScanResult.updates | where MsrcSeverity -eq Critical
    if ($CriticalUpdates){
        $instance | Invoke-CimMethod -MethodName DownloadUpdates -Arguments @{Updates=[ciminstance[]]$CriticalUpdates}
        $instance | Invoke-CimMethod -MethodName InstallUpdates  -Arguments @{Updates=[ciminstance[]]$CriticalUpdates}
    }
}
 
```

![](/Scenarios/Windows%20Update/Screenshots/ApplyResult2016.png)

Let's run update 2019 server too

```PowerShell
#Invoke Scan on Windows Server 2019 and apply all updates using invoke-command
$servers="2019_1","2019_2"
Invoke-Command -ComputerName $servers -ScriptBlock {
    #Grab updates
    $ScanResult=Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0 AND AutoSelectOnWebSites=1"}
    if ($ScanResult.Updates){
        Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName InstallUpdates -Arguments @{Updates=$ScanResult.Updates}
    }
}
 
```

![](/Scenarios/Windows%20Update/Screenshots/ApplyResult2019.png)

## Update validation

### Display installed updates

```PowerShell
#Display installed updates on Windows Server 2016
$servers="2016_1","2016_2"
$Instances = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession -CimSession $servers
$ScanResult=foreach ($instance in $instances){
    $instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=1";OnlineScan=$true}
}
$ScanResult.updates

#Display installed updates on Windows Server 2019
$servers="2019_1","2019_2"
$ScanResult=Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=1"}
$ScanResult.updates
 
```

### Display pending reboot on all Domain Computers

```PowerShell
$servers=(get-ADComputer -filter *).Name
Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName IsPendingReboot
 
```

![](/Scenarios/Windows%20Update/Screenshots/PendingReboot.png)

You can easily reboot machines with pending reboot like this

```PowerShell
$servers=(get-ADComputer -filter *).Name
$result=Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName IsPendingReboot
$ServersToReboot=($result | where PendingReboot -eq True).PSComputerName
Restart-Computer -ComputerName $ServersToReboot -Protocol WSMan -Wait -For PowerShell
 
```

### Display Last Installation Date on all Domain Computers

Interestingly does not show meaningful information

```PowerShell
$servers=(get-ADComputer -filter *).Name
Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName GetLastUpdateInstallationDate
 
```

![](/Scenarios/Windows%20Update/Screenshots/LastUpdateInstallationDate.png)

### Display Last Scan Success Date on all Domain Computers

```PowerShell
$servers=(get-ADComputer -filter *).Name
Invoke-CimMethod -CimSession $Servers -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUSettings" -MethodName GetLastScanSuccessDate
 
```

![](/Scenarios/Windows%20Update/Screenshots/LastScanSuccessDate.png)

### Display update level

```PowerShell
$servers=(Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$ComputerInfo  = Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-ItemProperty -Path $using:RegistryPath
}
$ComputerInfo | sort PSComputerName | ft PSComputerName,ProductName,EditionID,InstallationType,ReleaseID,UBR 
#$ComputerInfo | Out-GridView
 
```

![](/Scenarios/Windows%20Update/Screenshots/UpdateLevels.png)

### Check if servers are up-to-date

First grab latest available patches from Windows 10 update history web page. This piece of code will create hash table with latest UBR.

```PowerShell
$versions=@()
$versions+=@{ReleaseID=1903;URI="https://support.microsoft.com/en-us/help/4498140"}
$versions+=@{ReleaseID=1809;URI="https://support.microsoft.com/en-us/help/4464619"}
$versions+=@{ReleaseID=1803;URI="https://support.microsoft.com/en-us/help/4099479"}
$versions+=@{ReleaseID=1709;URI="https://support.microsoft.com/en-us/help/4043454"}
$versions+=@{ReleaseID=1703;URI="https://support.microsoft.com/en-us/help/4018124"}
$versions+=@{ReleaseID=1607;URI="https://support.microsoft.com/en-us/help/4000825"}
foreach ($version in $versions){
    $web=Invoke-WebRequest -Uri $version.uri -UseBasicParsing
    $startstring='        "releaseVersion": "OS Build '
    $start=$web.content.IndexOf($startstring)
    $start=$start+$startstring.Length
    $result=$web.content.Substring($start,10).TrimEnd('"').split(".")
    $version.CurrentBuild=$result[0]
    $version.UBR=$result[1]
}
 
```

Let's compare it with our servers

```PowerShell
$servers=(Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
$ComputersInfo  = Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-ItemProperty -Path $using:RegistryPath
}

Foreach ($ComputerInfo in $computersinfo){
    $latestUBR=($versions | where ReleaseID -eq $computerinfo.releaseid).UBR
    if ($latestUBR -gt $computerInfo){
        $ComputerInfo | Add-Member -MemberType NoteProperty -Name IsUpToDate -Value $false
        $ComputerInfo | Add-Member -MemberType NoteProperty -Name LatestUBR -Value $LatestUBR
    }else{
        $ComputerInfo | Add-Member -MemberType NoteProperty -Name IsUpToDate -Value $true
        $ComputerInfo | Add-Member -MemberType NoteProperty -Name LatestUBR -Value $LatestUBR
    }
}

$ComputersInfo | ft PSComputerName,IsUpToDate,UBR,LatestUBR
 
```

![](/Scenarios/Windows%20Update/Screenshots/UpdateLevelsUpToDate.png)
