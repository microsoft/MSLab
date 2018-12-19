# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output
1..10 |% { Write-Host ""}

#region Functions

function WriteInfo($message){
        Write-Host $message
    }

function WriteInfoHighlighted($message){
    Write-Host $message -ForegroundColor Cyan
}

function WriteSuccess($message){
    Write-Host $message -ForegroundColor Green
}

function WriteError($message){
    Write-Host $message -ForegroundColor Red
}

function WriteErrorAndExit($message){
    Write-Host $message -ForegroundColor Red
    Write-Host "Press enter to continue ..."
    Stop-Transcript
    Read-Host | Out-Null
    Exit
}

function  Get-WindowsBuildNumber { 
    $os = Get-WmiObject -Class Win32_OperatingSystem 
    return [int]($os.BuildNumber) 
} 

#endregion

#region Initializtion

# grab Time and start Transcript
    Start-Transcript -Path "$PSScriptRoot\Prereq.log"
    $StartDateTime = get-date
    WriteInfo "Script started at $StartDateTime"

#Load LabConfig....
    . "$PSScriptRoot\LabConfig.ps1"

#define some variables if it does not exist in labconfig
    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

#set TLS 1.2 for github downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#endregion

#region OS checks and folder build
# Checking for Compatible OS
    WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"

    $BuildNumber=Get-WindowsBuildNumber
    if ($BuildNumber -ge 10586){
        WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
    }else{
        WriteErrorAndExit "`t Windows version  $BuildNumber detected. Version 10586 and newer is needed. Exiting"
    }

# Checking Folder Structure
    "ParentDisks","Temp","Temp\DSC","Temp\ToolsVHD\DiskSpd","Temp\ToolsVHD\SCVMM\ADK","Temp\ToolsVHD\SCVMM\ADKWinPE","Temp\ToolsVHD\SCVMM\SQL","Temp\ToolsVHD\SCVMM\SCVMM","Temp\ToolsVHD\SCVMM\UpdateRollup","Temp\ToolsVHD\VMFleet" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } }

    "Temp\ToolsVHD\SCVMM\ADK\Copy_ADK_with_adksetup.exe_here.txt","Temp\ToolsVHD\SCVMM\ADKWinPE\Copy_ADKWinPE_with_adkwinpesetup.exe_here.txt","Temp\ToolsVHD\SCVMM\SQL\Copy_SQL2016_or_SQL2017_with_setup.exe_here.txt","Temp\ToolsVHD\SCVMM\SCVMM\Copy_SCVMM_with_setup.exe_here.txt","Temp\ToolsVHD\SCVMM\UpdateRollup\Copy_SCVMM_Update_Rollup_MSPs_here.txt" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type File -Path "$PSScriptRoot\$_" } }
#endregion

#region Download Scripts

#add scripts for VMM
    $Filenames="1_SQL_Install","2_ADK_Install","3_SCVMM_Install"
    foreach ($Filename in $filenames){
        $Path="$PSScriptRoot\Temp\ToolsVHD\SCVMM\$Filename.ps1"
        If (Test-Path -Path $Path){
            WriteSuccess "`t $Filename is present, skipping download"
        }else{
            $FileContent=$null
            $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/Microsoft/WSLab/master/Tools/$Filename.ps1").Content
            if ($FileContent){
                $script = New-Item $Path -type File -Force
                $FileContent=$FileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword #only applies to 1_SQL_Install and 3_SCVMM_Install.ps1
                $FileContent=$FileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName #only applies to 1_SQL_Install and 3_SCVMM_Install.ps1
                Set-Content -path $script -value $FileContent
            }else{
                WriteErrorAndExit "Unable to download $Filename."
            }
        }
    }

#Download SetupVMFleet script
    $Filename="SetupVMFleet"
    $Path="$PSScriptRoot\Temp\ToolsVHD\$FileName.ps1"
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, skipping download"
    }else{
        $FileContent = $null
        $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/Microsoft/WSLab/master/Tools/$Filename.ps1").Content
        if ($FileContent){
            $script = New-Item $Path -type File -Force
            $FileContent=$FileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword
            $FileContent=$FileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName
            Set-Content -path $script -value $FileContent
        }else{
            WriteErrorAndExit "Unable to download $Filename."
        }
    }

# add createparentdisks script
    $Filename="CreateParentDisk"
    $Path="$PSScriptRoot\ParentDisks\$FileName.ps1"
    If (Test-Path -Path $Path){
        WriteSuccess "`t $Filename is present, skipping download"
    }else{
        $FileContent = $null
        $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/Microsoft/WSLab/master/Tools/CreateParentDisk.ps1).Content
        if ($FileContent){
            $script = New-Item "$PSScriptRoot\ParentDisks\CreateParentDisk.ps1" -type File -Force
            Set-Content -path $script -value $FileContent
        }else{
            WriteErrorAndExit "Unable to download $Filename."
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
            $webcontent  = Invoke-WebRequest -Uri aka.ms/diskspd -UseBasicParsing
            $downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip"
        }catch{
            WriteError "`t Failed to download Diskspd!"
        }
        # Unnzipping and extracting just diskspd.exe x64
            Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\Unzip"
            Copy-Item -Path (Get-ChildItem -Path "$PSScriptRoot\Temp\ToolsVHD\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
    }

#Download VMFleet
    WriteInfoHighlighted "Testing VMFleet presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\VMFleet\install-vmfleet.ps1" ) {
        WriteSuccess "`t VMFleet is present, skipping download"
    }else{ 
        WriteInfo "`t VMFleet not there - Downloading VMFleet"
        try {
            $downloadurl = "https://github.com/Microsoft/diskspd/archive/master.zip"
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\VMFleet\VMFleet.zip"
        }catch{
            WriteError "`t Failed to download VMFleet!"
        }
        # Unnzipping and extracting just VMFleet
            Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\VMFleet\VMFleet.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\VMFleet\Unzip"
            Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\VMFleet\Unzip\diskspd-master\Frameworks\VMFleet\*" -Destination "$PSScriptRoot\Temp\ToolsVHD\VMFleet\"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\VMFleet\VMFleet.zip"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\VMFleet\Unzip" -Recurse -Force
    }

# Download convert-windowsimage into Temp
    WriteInfoHighlighted "Testing convert-windowsimage presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\convert-windowsimage.ps1" ) {
        WriteSuccess "`t Convert-windowsimage.ps1 is present, skipping download"
    }else{ 
        WriteInfo "`t Downloading Convert-WindowsImage"
        try{
            Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/live/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\Temp\convert-windowsimage.ps1"
        }catch{
            WriteError "`t Failed to download convert-windowsimage.ps1!"
        }
    }
#endregion

#region Downloading required Posh Modules
# Downloading modules into Temp folder if needed.

    $modules=("xActiveDirectory","2.19.0.0"),("xDHCpServer","2.0.0.0"),("xDNSServer","1.11.0.0"),("NetworkingDSC","6.0.0.0"),("xPSDesiredStateConfiguration","8.4.0.0")
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

# finishing 
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
WriteSuccess "Press enter to continue..."
Read-Host | Out-Null
