
# AppAttach

## About the lab

In following lab you learn how AppAttach works. The environment is similar to Windows Virtual Desktop, where you have multiple Windows 10 session hosts. App attach will be demonstrated on PowerShell 7 msix app that will be downloaded from PowerShell repository.

```PowerShell
#sample labconfig with enabled telemetry (Full)

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#$LabConfig.VMs += @{ VMName = 'Management' ; ParentVHD = 'Win2019_G2.vhdx'; MGMTNICs=1}
$LabConfig.VMs += @{ VMName = 'Win10' ; ParentVHD = 'Win1020H1_G2.vhdx'; MGMTNICs=1 ; EnableWinRM=$true}
$LabConfig.VMs += @{ VMName = 'Win10_1' ; ParentVHD = 'Win1020H1_G2.vhdx'; MGMTNICs=1 ; EnableWinRM=$true}
#$LabConfig.VMs += @{ VMName = 'Win10_2' ; ParentVHD = 'Win1020H1_G2.vhdx'; MGMTNICs=1 ; EnableWinRM=$true}
 
```

## The Lab - simple scenario

### Download example MSIX package

Run following code from DC or Management machine

```powershell
$ProgressPreference="SilentlyContinue"
Invoke-WebRequest -Uri "https://github.com/PowerShell/PowerShell/releases/download/v7.0.2/PowerShell-7.0.2-win-x64.msix" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\PowerShell-7.0.2-win-x64.msix"
$ProgressPreference="Continue"
 
```

### Install Hyper-V (to be able to mount-vhd) and reboot

```powershell
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart
Install-WindowsFeature -Name Hyper-V-PowerShell
Restart-Computer
 
```

### Transform MSIX package to VHDx

Download [Create_VHDx_from_msix.ps1](/Scenarios/AppAttach/Create_VHDx_from_msix.ps1), right-click it, and run with PowerShell.

Or simplified version of the same

```powershell
$folder="c:\temp"

#ask for MSIX file(s)
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$openFiles = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Multiselect = $true;
    Title="Please select msix file(s)"
}
$openFiles.Filter = "msix files (*.msix)|*.msix"


If($openFiles.ShowDialog() -eq "OK"){
    Write-Host "Selected Files:" -ForegroundColor Cyan
    foreach ($filename in $openFiles.Filenames){
        Write-Host "`t $FileName" -ForegroundColor Cyan
    }
}

#Download MSIX Image tool if not available"
if (!(Test-Path "$folder\msixmgr\x64\msixmgr.exe")){
    Invoke-WebRequest -Uri https://aka.ms/msixmgr -OutFile "$folder\msixmgr.zip"
    Expand-Archive -Path "$folder\msixmgr.zip" -DestinationPath "$folder\msixmgr"
}

foreach ($File in $openFiles.FileNames){
    $appname=($file | Split-Path -Leaf).TrimEnd(".msix")
    if (!(test-path -Path $folder)){
        New-Item -Path $folder -ItemType Directory
    }
    $vhd=New-VHD -SizeBytes 100GB -path $folder\$appname.vhdx -dynamic -confirm:$false
    #mount and format VHD
    $VHDMount=Mount-VHD $vhd.Path -Passthru
    $vhddisk = $vhdmount | Get-Disk
    $vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -Filesystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $appname

    Start-Process -FilePath "$folder\msixmgr\x64\msixmgr.exe" -ArgumentList  "-Unpack -packagePath `"$File`" -destination $($vhddiskpart.driveletter):\ -applyacls" -Wait

    Dismount-VHD $vhddisk.number
}
 
```

![](/Scenarios/AppAttach/Screenshots/PowerShell01.png)

As result, you will find VHDx file under temp file (if you used script example above)

![](/Scenarios/AppAttach/Screenshots/Explorer01.png)


### Create File Share and copy VHDx there

Assuming you can run it from everywhere, following example is using invoke-command. It will create fileshare, where users and computers have read only access and copies all VHDs from c:\temp into it. Assuming you created your app in c:\temp

```powershell
#Create new FileShare on DC
$ComputerName="DC"
$FolderName="FileShare"
Invoke-Command -ComputerName $ComputerName -ScriptBlock {new-item -Path c:\Shares -Name $using:FolderName -ItemType Directory}
$accounts=@()
$accounts+="corp\Domain Computers"
$accounts+="corp\Domain Users"
New-SmbShare -Name $FolderName -Path "c:\Shares\$FolderName" -ReadAccess $accounts -CimSession $ComputerName
#Set NTFS permissions
Invoke-Command -ComputerName $ComputerName -ScriptBlock {(Get-SmbShare $using:FolderName).PresetPathAcl | Set-Acl}

#Copy VHDx there
Copy-Item -Path C:\temp\*.vhdx -Destination \\dc\c$\Shares\FileShare
 
```

### Stage application on Windows 10

This step will mount all VHDs with application located in fileshare in read-only mode and create junction in c:\ProgramData\AppAttach (you can use any location). The next step is, that App will be staged (registered) into c:\program files\windows apps the same way as any other windows app. Since mounting VHD will not survive reboot, it's needed to run this script every reboot, and also every time you add new application into share.

Run this script while logged in Win10 machine. It requires admin permissions. In real world scenario, you would run this code as scheduled task under system or with SCCM.

```powershell
#https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach#prepare-powershell-scripts-for-msix-app-attach
$fileshare="\\dc\FileShare"
$msixJunction = "C:\ProgramData\AppAttach\"
#grab all VHDs
$VHDs = Get-ChildItem -Path $fileshare -Name "*.vhd*"
foreach ($vhd in $VHDs){
    #region mountvhd
    $diskimage=$null
    $diskimage=Mount-Diskimage -ImagePath $fileshare\$vhd -NoDriveLetter -Access ReadOnly -PassThru -ErrorAction Ignore

    if (!($diskimage)){
        Write-Host "Application " -NoNewline
        Write-Host "$vhd " -NoNewLine -ForegroundColor Green
        Write-Host "VHD was is mounted, app was probably already provisioned"
    }else{
        #Create Junction link
        $msixDest=(Get-Disk -Number $diskimage.Number | Get-Partition | where PartitionNumber -eq 2 | Get-Volume).Path
        #$msixDest = "\\?\Volume{" + $volumeGuid + "}\"
        if (!(Test-Path $msixJunction)){md $msixJunction}
        $packageName=$vhd.TrimEnd(".vhdx")
        $msixJunction = $msixJunction + $packageName
        cmd.exe /c mklink /j $msixJunction $msixDest
        #stage app into c:\program files\windowsapps
        $path=(Get-ChildItem -Path $msixJunction | select -First 1).FullName
        [Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime] | Out-Null
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where { $_.ToString() -eq 'System.Threading.Tasks.Task`1[TResult] AsTask[TResult,TProgress](Windows.Foundation.IAsyncOperationWithProgress`2[TResult,TProgress])'})[0]
        $asTaskAsyncOperation = $asTask.MakeGenericMethod([Windows.Management.Deployment.DeploymentResult], [Windows.Management.Deployment.DeploymentProgress])
        $packageManager = [Windows.Management.Deployment.PackageManager]::new()
        #$path = $msixJunction + $parentFolder + $packageName # needed if we do the pbisigned.vhd
        $path = ([System.Uri]$path).AbsoluteUri
        $asyncOperation = $packageManager.StagePackageAsync($path, $null, "StageInPlace")
        $task = $asTaskAsyncOperation.Invoke($null, @($asyncOperation))
        $task
    }
}
 
```

### Register App

Following code will register app for current user, so user will see it in start menu. There can be multiple application names in variable, but in the example is only one. Run code from win10 machine

```PowerShell
#register application for user (needs to run under user context
$applications="Microsoft.PowerShellPreview_7.0.2.0_x64__8wekyb3d8bbwe"
foreach ($application in $applications){
    $AppxPackagePath = "C:\Program Files\WindowsApps\" + $application + "\AppxManifest.xml"
    Add-AppxPackage -Path $AppxPackagePath -DisableDevelopmentMode -Register
}
 
```

## The Lab - real-world scenario

In real world scenario you need to distribute different application to different users. You also need to make sure, staging is done every time VM starts and also right after you publish new app, it will be available to users.

### Create scheduled task to run AppAttachStaging script

```powershell
#Save powershell script for AppAttach staging to FileShare
$scriptblock=@'
    #https://docs.microsoft.com/en-us/azure/virtual-desktop/app-attach#prepare-powershell-scripts-for-msix-app-attach
    $fileshare="\\dc\FileShare"
    $msixJunction = "C:\ProgramData\AppAttach\"
    #grab all VHDs
    $VHDs = Get-ChildItem -Path $fileshare -Name "*.vhd*"
    foreach ($vhd in $VHDs){
        #region mountvhd
        $diskimage=$null
        $diskimage=Mount-Diskimage -ImagePath $fileshare\$vhd -NoDriveLetter -Access ReadOnly -PassThru -ErrorAction Ignore

        if (!($diskimage)){
            Write-Host "Application " -NoNewline
            Write-Host "$vhd " -NoNewLine -ForegroundColor Green
            Write-Host "VHD was is mounted, app was probably already provisioned"
        }else{
            #Create Junction link
            $msixDest=(Get-Disk -Number $diskimage.Number | Get-Partition | where PartitionNumber -eq 2 | Get-Volume).Path
            #$msixDest = "\\?\Volume{" + $volumeGuid + "}\"
            if (!(Test-Path $msixJunction)){md $msixJunction}
            $packageName=$vhd.TrimEnd(".vhdx")
            $msixJunction = $msixJunction + $packageName
            cmd.exe /c mklink /j $msixJunction $msixDest
            #stage app into c:\program files\windowsapps
            $path=(Get-ChildItem -Path $msixJunction | select -First 1).FullName
            [Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime] | Out-Null
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where { $_.ToString() -eq 'System.Threading.Tasks.Task`1[TResult] AsTask[TResult,TProgress](Windows.Foundation.IAsyncOperationWithProgress`2[TResult,TProgress])'})[0]
            $asTaskAsyncOperation = $asTask.MakeGenericMethod([Windows.Management.Deployment.DeploymentResult], [Windows.Management.Deployment.DeploymentProgress])
            $packageManager = [Windows.Management.Deployment.PackageManager]::new()
            #$path = $msixJunction + $parentFolder + $packageName # needed if we do the pbisigned.vhd
            $path = ([System.Uri]$path).AbsoluteUri
            $asyncOperation = $packageManager.StagePackageAsync($path, $null, "StageInPlace")
            $task = $asTaskAsyncOperation.Invoke($null, @($asyncOperation))
            $task
        }
    }
'@
$scriptblock | out-file \\dc\c$\Shares\FileShare\AppAttachStaging.ps1
 
```

```powershell
#schedule a task on computer win10_1 to run on every system startup.
$ComputerName="Win10_1"
$TaskName="AppAttachStagingTask"
$ScriptPath="\\DC\FileShare\AppAttachStaging.ps1"


$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -file $ScriptPath"
$trigger=@()
$trigger += New-ScheduledTaskTrigger -AtStartup
$trigger += New-ScheduledTaskTrigger -At "0:00" -RepetitionInterval "00:10" -RandomDelay "00:05"-Once
$task=Register-ScheduledTask -Action $action -TaskName $TaskName -trigger $trigger -CimSession $ComputerName -User "NT Authority\System"
$task.Settings.DisallowStartIfOnBatteries=$false
$settings=$task.settings
Set-ScheduledTask -CimSession $ComputerName -TaskName $TaskName -Settings $settings
Start-ScheduledTask -CimSession $ComputerName -TaskName $TaskName
$task=Get-ScheduledTask -CimSession $ComputerName -TaskName $TaskName
while ($task.State -ne "Ready"){
    $task=Get-ScheduledTask -CimSession $ComputerName -TaskName $TaskName
    Start-Sleep 1
    Write-Host "." -NoNewline
}
#Unregister-ScheduledTask -CimSession $ComputerName -TaskName $TaskName -Confirm:0
#endregion
 
```

### Generate application list on fileshare

```powershell
#location of VHDs where i have right to write
$VHDLocation="\\dc\c$\Shares\FileShare"
$vhds=Get-ChildItem -Path $vhdlocation -Name *.vhdx

#mount in read only mode, grab app name and save it into vhd location share
foreach ($vhd in $vhds){
    $diskimage=$null
    $diskimage=Mount-Diskimage -ImagePath $VHDLocation\$vhd -NoDriveLetter -Access ReadOnly -PassThru -ErrorAction Ignore
    $path=(Get-Disk -Number $diskimage.Number | Get-Partition | where PartitionNumber -eq 2 | Get-Volume).Path
    #create temp junction
    cmd.exe /c mklink /j "$env:temp\TempJunction" $path
    #grab app name
    $appname=(get-childitem -path "$env:temp\TempJunction").Name
    #create file in $VHDLocation
    New-Item -Name $appname -Path $VHDLocation -ItemType File -ErrorAction Ignore
    #dismount VHD
    Dismount-DiskImage -ImagePath $vhdlocation\$vhd | Out-Null
    #delete junction
    Remove-Item "$env:temp\TempJunction" -Force
}
 
```

### Strip Permissions from files with 0 size (app names)

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module ntfssecurity -Force
$items=Get-ChildItem -Path '\\dc\c$\shares\FileShare\' | where length -eq 0
foreach ($item in $items){
    $item | Get-NTFSAccess | Remove-NTFSAccess -Account "Corp\Domain Users"
}
 
```

### Create task to add apps once user is logged on + every 10 minutes

Create script on fileshare

```powershell
$scriptblock=@'
$fileshare="\\dc\FileShare"
$applications=(get-childitem -path $fileshare | where length -eq 0).Name
foreach ($application in $applications){
    $AppxPackagePath = "C:\Program Files\WindowsApps\" + $application + "\AppxManifest.xml"
    Add-AppxPackage -Path $AppxPackagePath -DisableDevelopmentMode -Register
}
 
'@
$scriptblock | out-file \\dc\c$\Shares\FileShare\AppAttachRegistration.ps1
 
```

Schedule task on user logon + every 10 minutes

```powershell
$ComputerName="Win10_1"
$TaskName="AppAttachRegistrationTask"
$ScriptPath="\\DC\FileShare\AppAttachRegistration.ps1"

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -file $ScriptPath"
$trigger=@()
$trigger += New-ScheduledTaskTrigger -AtLogon
$trigger += New-ScheduledTaskTrigger -At "0:00" -RepetitionInterval "00:10" -RandomDelay "00:05"-Once
$task=Register-ScheduledTask -Action $action -TaskName $TaskName -trigger $trigger -CimSession $ComputerName
$task.Settings.DisallowStartIfOnBatteries=$false
$settings=$task.settings
Set-ScheduledTask -CimSession $ComputerName -TaskName $TaskName -Settings $settings
Start-ScheduledTask -CimSession $ComputerName -TaskName $TaskName
$task=Get-ScheduledTask -CimSession $ComputerName -TaskName $TaskName
while ($task.State -ne "Ready"){
    $task=Get-ScheduledTask -CimSession $ComputerName -TaskName $TaskName
    Start-Sleep 1
    Write-Host "." -NoNewline
}
#Unregister-ScheduledTask -CimSession $ComputerName -TaskName $TaskName -Confirm:0
 
```

### Test

Create 2 users. One with access and one without access on app file name. And login into win10 to see if app was provisioned

Bob will have PS7 and Rob not once they will log in.

```powershell
New-ADUser -Name Bob -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
New-ADUser -Name Rob -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
#assign read only perm for Bob for Posh7
$appname="Microsoft.PowerShellPreview_7.0.2.0_x64__8wekyb3d8bbwe"
$fileshare="\\dc\c$\shares\Fileshare"
Add-NTFSAccess -Path "$fileshare\$appname" -Account "Corp\Bob" -AccessRights Read
 
```

