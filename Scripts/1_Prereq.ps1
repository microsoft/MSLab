# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (-not $isAdmin) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1

    if($PSVersionTable.PSEdition -eq "Core") {
        Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } else {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    }

    exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output
1..10 | ForEach-Object { Write-Host "" }

#region Functions
. $PSScriptRoot\0_Shared.ps1 # [!build-include-inline]

function  Get-WindowsBuildNumber {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    return [int]($os.BuildNumber)
}
#endregion

#region Initialization

# grab Time and start Transcript
    Start-Transcript -Path "$PSScriptRoot\Prereq.log"
    $StartDateTime = Get-Date
    WriteInfo "Script started at $StartDateTime"
    WriteInfo "`nMSLab Version $mslabVersion"

#Load LabConfig....
    . "$PSScriptRoot\LabConfig.ps1"

# Telemetry Event
    if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
        WriteInfo "Telemetry is set to $(Get-TelemetryLevel) level from $(Get-TelemetryLevelSource)"
        Send-TelemetryEvent -Event "Prereq.Start" -NickName $LabConfig.TelemetryNickName | Out-Null
    }

#define some variables if it does not exist in labconfig
    If (!$LabConfig.DomainNetbiosName) {
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName) {
        $LabConfig.DomainName="Corp.contoso.com"
    }

#set TLS 1.2 for github downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#endregion

#region OS checks and folder build

# Check if not running in root folder
    if (($psscriptroot).Length -eq 3) {
        WriteErrorAndExit "`t MSLab canot run in root folder. Please put MSLab scripts into a folder. Exiting"
    }

# Checking for Compatible OS
    WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"

    $BuildNumber=Get-WindowsBuildNumber
    if ($BuildNumber -ge 10586){
        WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
    }else{
        WriteErrorAndExit "`t Windows version  $BuildNumber detected. Version 10586 and newer is needed. Exiting"
    }

# Checking Folder Structure
    "ParentDisks","Temp","Temp\DSC","Temp\ToolsVHD\DiskSpd","Temp\ToolsVHD\SCVMM\ADK","Temp\ToolsVHD\SCVMM\ADKWinPE","Temp\ToolsVHD\SCVMM\SQL","Temp\ToolsVHD\SCVMM\SCVMM","Temp\ToolsVHD\SCVMM\UpdateRollup" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } }

    "Temp\ToolsVHD\SCVMM\ADK\Copy_ADK_with_adksetup.exe_here.txt","Temp\ToolsVHD\SCVMM\ADKWinPE\Copy_ADKWinPE_with_adkwinpesetup.exe_here.txt","Temp\ToolsVHD\SCVMM\SQL\Copy_SQL2017_or_SQL2019_with_setup.exe_here.txt","Temp\ToolsVHD\SCVMM\SCVMM\Copy_SCVMM_with_setup.exe_here.txt","Temp\ToolsVHD\SCVMM\UpdateRollup\Copy_SCVMM_Update_Rollup_MSPs_here.txt" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type File -Path "$PSScriptRoot\$_" } }
#endregion

#region Download Scripts

#add scripts for VMM
    $filenames = "1_SQL_Install", "2_ADK_Install", "3_SCVMM_Install"
    foreach ($filename in $filenames) {
        $Path = "$PSScriptRoot\Temp\ToolsVHD\SCVMM\$filename.ps1"
        if (Test-Path -Path $Path) {
            WriteSuccess "`t $Filename is present, skipping download"
        } else {
            $FileContent = $null

            try {
                # try to download tagged version first
                $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/$mslabVersion/Tools/$filename.ps1").Content
            } catch {
                WriteInfo "Download $filename failed with $($_.Exception.Message), trying master branch now"
                # if that fails, try master branch
                $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/$filename.ps1").Content
            }

            if ($FileContent) {
                $script = New-Item $Path -type File -Force
                $FileContent=$FileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword #only applies to 1_SQL_Install and 3_SCVMM_Install.ps1
                $FileContent=$FileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName #only applies to 1_SQL_Install and 3_SCVMM_Install.ps1
                Set-Content -Path $script -value $FileContent
            } else {
                WriteErrorAndExit "Unable to download $Filename."
            }
        }
    }

# add createparentdisks, DownloadLatestCU and PatchParentDisks scripts to Parent Disks folder
    $fileNames = "CreateParentDisk", "DownloadLatestCUs", "PatchParentDisks", "CreateVMFleetDisk"
    if($LabConfig.Linux) {
        $fileNames += "CreateLinuxParentDisk"
    }
    foreach ($filename in $fileNames) {
        $path = "$PSScriptRoot\ParentDisks\$FileName.ps1"
        If (Test-Path -Path $path) {
            WriteSuccess "`t $filename is present, skipping download"
        } else {
            $FileContent = $null

            try {
                # try to download release version first
                Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/microsoft/MSLab/releases/download/$mslabVersion/$Filename.ps1" -OutFile $path
            } catch {
                WriteInfo "Download $filename failed with $($_.Exception.Message), trying master branch now"

                # if that fails, try master branch
                $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/$FileName.ps1").Content
                if ($FileContent) {
                    $script = New-Item $path -type File -Force
                    Set-Content -Path $script -value $FileContent
                } else {
                    WriteErrorAndExit "Unable to download $Filename."
                }
            }
        }
    }

# Download convert-windowsimage into Temp
    WriteInfoHighlighted "Testing Convert-windowsimage presence"
    $convertWindowsImagePath = "$PSScriptRoot\Temp\Convert-WindowsImage.ps1"
    If (Test-Path -Path $convertWindowsImagePath) {
        WriteSuccess "`t Convert-windowsimage.ps1 is present, skipping download"
    } else {
        WriteInfo "`t Downloading Convert-WindowsImage"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/microsoft/MSLab/releases/download/$mslabVersion/Convert-WindowsImage.ps1" -OutFile $convertWindowsImagePath
        } catch {
            try {
                WriteInfo "Download Convert-windowsimage.ps1 failed with $($_.Exception.Message), trying master branch now"
                Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/Convert-WindowsImage.ps1" -OutFile $convertWindowsImagePath
            } catch {
                WriteError "`t Failed to download Convert-WindowsImage.ps1!"
            }
        }
    }
#endregion

#region some tools to download
# Downloading diskspd if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing diskspd presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.exe" ) {
        WriteSuccess "`t Diskspd is present, skipping download"
    }else{
        WriteInfo "`t Diskspd not there - Downloading diskspd"
        try {
            <# aka.ms/diskspd changed. Commented
            $webcontent  = Invoke-WebRequest -Uri "https://aka.ms/diskspd" -UseBasicParsing
            if($PSVersionTable.PSEdition -eq "Core") {
                $link = $webcontent.Links | Where-Object data-url -Match "/Diskspd.*zip$"
                $downloadUrl = "{0}://{1}{2}" -f $webcontent.BaseResponse.RequestMessage.RequestUri.Scheme, $webcontent.BaseResponse.RequestMessage.RequestUri.Host, $link.'data-url'
            } else {
                $downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
            }
            #>
            $downloadurl="https://github.com/microsoft/diskspd/releases/download/v2.1/DiskSpd.ZIP"
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip"
        }catch{
            WriteError "`t Failed to download Diskspd!"
        }
        # Unnzipping and extracting just diskspd.exe x64
            Microsoft.PowerShell.Archive\Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\Unzip"
            Copy-Item -Path (Get-ChildItem -Path "$PSScriptRoot\Temp\ToolsVHD\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
    }

#endregion

#region Downloading required Posh Modules
# Downloading modules into Temp folder if needed.

    $modules=("ActiveDirectoryDsc","6.3.0"),("xDHCPServer","3.1.1"),("DnsServerDsc","3.0.0"),("NetworkingDSC","9.0.0"),("xPSDesiredStateConfiguration","9.1.0")
    foreach ($module in $modules){
        WriteInfoHighlighted "Testing if modules are present"
        $modulename=$module[0]
        $moduleversion=$module[1]
        if (!(Test-Path "$PSScriptRoot\Temp\DSC\$modulename\$Moduleversion")){
            WriteInfo "`t Module $module not found... Downloading"
            #Install NuGET package provider
            if ((Get-PackageProvider -Name NuGet) -eq $null){
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force
            }
            Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path "$PSScriptRoot\Temp\DSC"
        }else{
            WriteSuccess "`t Module $modulename version found... skipping download"
        }
    }

# Installing DSC modules if needed
    foreach ($module in $modules) {
        WriteInfoHighlighted "Testing DSC Module $module Presence"
        # Check if Module is installed
        if ((Get-DscResource -Module $Module[0] | where-object {$_.version -eq $module[1]}) -eq $Null) {
            # module is not installed - install it
            WriteInfo "`t Module $module will be installed"
            $modulename=$module[0]
            $moduleversion=$module[1]
            Copy-item -Path "$PSScriptRoot\Temp\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
            WriteSuccess "`t Module was installed."
            Get-DscResource -Module $modulename
        } else {
            # module is already installed
            WriteSuccess "`t Module $Module is already installed"
        }
    }

#endregion

#region Linux prereqs
if($LabConfig.Linux -eq $true) {
    WriteInfoHighlighted "Testing Linux prerequisites"
    WriteInfo "`t Test Packer availability"

    # Packer
    if (Get-Command "packer.exe" -ErrorAction SilentlyContinue)
    {
        WriteSuccess "`t Packer is in PATH."
    } else {
        WriteInfo "`t`t Downloading latest Packer binary"

        WriteInfo "`t`t Creating packer directory"
        $linuxToolsDirPath = "$PSScriptRoot\LAB\bin"
        New-Item $linuxToolsDirPath -ItemType Directory -Force | Out-Null

        if(-not (Test-Path (Join-Path $linuxToolsDirPath "packer.exe"))) {
            $packerReleaseInfo = Invoke-RestMethod -Uri "https://checkpoint-api.hashicorp.com/v1/check/packer"
            $downloadUrl = "https://releases.hashicorp.com/packer/$($packerReleaseInfo.current_version)/packer_$($packerReleaseInfo.current_version)_windows_amd64.zip"
            Start-BitsTransfer -Source $downloadUrl -Destination (Join-Path $linuxToolsDirPath "packer.zip")
            Expand-Archive -Path (Join-Path $linuxToolsDirPath "packer.zip")  -DestinationPath $linuxToolsDirPath -Force
            Remove-Item -Path (Join-Path $linuxToolsDirPath "packer.zip")
        }

        WriteInfo "`t`t Creating Packer firewall rule"
        $id = $PSScriptRoot -replace '[^a-zA-Z0-9]'
        $fwRule = Get-NetFirewallRule -Name "mslab-packer-$id" -ErrorAction SilentlyContinue
        if(-not $fwRule) {
            New-NetFirewallRule -Name "mslab-packer-$id" -DisplayName "Allow MSLab Packer ($($PSScriptRoot))" -Action Allow -Program (Join-Path $linuxToolsDirPath "packer.exe") -Profile Any -ErrorAction SilentlyContinue
        }
    }

    # Packer templates
    WriteInfo "`t`t Downloading Packer templates"
    $packerTemplatesDirectory = "$PSScriptRoot\ParentDisks\PackerTemplates\"
    if (-not (Test-Path $packerTemplatesDirectory)) {
        New-Item -Type Directory -Path $packerTemplatesDirectory
    }

    $templatesBase = "https://github.com/microsoft/mslab-templates/releases/latest/download/"
    $templatesFile = "$($packerTemplatesDirectory)\templates.json"

    Invoke-WebRequest -Uri "$($templatesBase)/templates.json" -OutFile $templatesFile
    if(-not (Test-Path -Path $templatesFile)) {
        WriteErrorAndExit "Download of packer templates failed"
    }

    $templatesInfo = Get-Content -Path $templatesFile | ConvertFrom-Json
    foreach($template in $templatesInfo.templates) {
        $templateZipFile = Join-Path $packerTemplatesDirectory $template.package
        Invoke-WebRequest -Uri "$($templatesBase)/$($template.package)" -OutFile $templateZipFile
        Expand-Archive -Path $templateZipFile -DestinationPath (Join-Path $packerTemplatesDirectory $template.directory)
        Remove-Item -Path $templateZipFile
    }

    # OpenSSH
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
    if($capability.State -ne "Installed") {
        WriteInfoHighlighted "`t Enabling OpensSH Client"
        Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
        Set-Service ssh-agent -StartupType Automatic
        Start-Service ssh-agent
    }

    # SSH Key
    WriteInfoHighlighted "`t SSH key"
    if($LabConfig.SshKeyPath) {
        if(-not (Test-Path $LabConfig.SshKeyPath)) {
            WriteError "`t Cannot find specified SSH key $($LabConfig.SshKeyPath)."
        }

        $private = ssh-keygen.exe -y -e -f $LabConfig.SshKeyPath
        $public = ssh-keygen.exe -y -e -f "$($LabConfig.SshKeyPath).pub"
        $comparison = Compare-Object -ReferenceObject $private -DifferenceObject $public
        if($comparison) {
            WriteError "`t SSH Keypair $($LabConfig.SshKeyPath) does not match."
        }
    }
    else
    {
        WriteInfo "`t`t Generating new SSH key pair"
        $sshKeyDir = "$PSScriptRoot\LAB\.ssh"
        $key = "$sshKeyDir\lab_rsa"
        New-Item -ItemType Directory $sshKeyDir -ErrorAction SilentlyContinue | Out-Null
        ssh-keygen.exe -t rsa -b 4096 -C "$($LabConfig.DomainAdminName)" -f $key -q -N '""'
    }
}
#endregion

# Telemetry Event
if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
    $metrics = @{
        'script.duration' = ((Get-Date) - $StartDateTime).TotalSeconds
    }

    Send-TelemetryEvent -Event "Prereq.End" -Metrics $metrics -NickName $LabConfig.TelemetryNickName | Out-Null
}

# finishing
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

Stop-Transcript

If (!$LabConfig.AutoClosePSWindows) {
    WriteSuccess "Press enter to continue..."
    Read-Host | Out-Null
}
