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
        Write-Host "Press any key to continue ..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
        $HOST.UI.RawUI.Flushinputbuffer()
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
        "Tools\DSC","Tools\ToolsVHD\DiskSpd","Tools\ToolsVHD\SCVMM\ADK","Tools\ToolsVHD\SCVMM\SQL","Tools\ToolsVHD\SCVMM\SCVMM","Tools\ToolsVHD\SCVMM\UpdateRollup" | ForEach-Object {
            if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } }
    
        "Tools\ToolsVHD\SCVMM\ADK\Copy_ADK_with_adksetup.exe_here.txt","Tools\ToolsVHD\SCVMM\SQL\Copy_SQL2016_with_setup.exe_here.txt","Tools\ToolsVHD\SCVMM\SCVMM\Copy_SCVMM_with_setup.exe_here.txt","Tools\ToolsVHD\SCVMM\UpdateRollup\Copy_SCVMM_Update_Rollup_MSPs_here.txt" | ForEach-Object {
            if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type File -Path "$PSScriptRoot\$_" } }
#endregion

#region add scripts for SCVMM
    #adding scripts for SQL install
        if (!( Test-Path "$PSScriptRoot\Tools\ToolsVHD\SCVMM\1_SQL_Install.ps1" )) {  
            $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SCVMM\1_SQL_Install.ps1" -type File
            $fileContent =  @'
    
# Sample SQL Install

# You can grab eval version here: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016

# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

Start-Transcript -Path "$PSScriptRoot\SQL_Install.log"

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

<#
#check for .net 3.5
if ((Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State -ne 'Enabled'){
    do{
        If (Test-Path -Path "$PSScriptRoot\dotNET\microsoft-windows-netfx3-ondemand-package.cab"){
            $dotNET = Get-Item -Path "$PSScriptRoot\dotNET\microsoft-windows-netfx3-ondemand-package.cab" -ErrorAction SilentlyContinue
            Write-Host "microsoft-windows-netfx3-ondemand-package.cab found in dotNET folder... installing" -ForegroundColor Cyan
        }else{
            Write-Host "No .NET found in $PSScriptRoot\dotNET" -ForegroundColor Cyan
            Write-Host "please browse for dotNET package (microsoft-windows-netfx3-ondemand-package.cab)" -ForegroundColor Green

            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $openFile = New-Object System.Windows.Forms.OpenFileDialog
            $openFile.Filter = "cab files (*.cab)|*.cab|All files (*.*)|*.*" 
            If($openFile.ShowDialog() -eq "OK"){
                Write-Host  "File $openfile selected" -ForegroundColor Cyan
                $dotNET = Get-Item -Path $openfile.filename -ErrorAction SilentlyContinue
            }
            if (!$openFile.FileName){
                Write-Host  "CAB was not selected... Exitting" -ForegroundColor Red
                Write-Host "Press any key to continue ..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
                $HOST.UI.RawUI.Flushinputbuffer()
                Exit 
             } 
        }
    install-windowsfeature WAS-NET-Environment -Source $dotnet.Directory    
    }
    until ((Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State -eq 'Enabled')
}
#>

#install SQL

If (Test-Path -Path "$PSScriptRoot\SQL\setup.exe"){
    $setupfile = (Get-Item -Path "$PSScriptRoot\SQL\setup.exe" -ErrorAction SilentlyContinue).fullname
    Write-Host "$Setupfile found..." -ForegroundColor Cyan
}else{
    # Open File dialog
    Write-Host "Please locate SQL Setup.exe" -ForegroundColor Green
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog
    $openFile.Filter = "setup.exe files |setup.exe|All files (*.*)|*.*" 
    If($openFile.ShowDialog() -eq "OK")
    {
       $setupfile=$openfile.filename
       Write-Host  "File $setupfile selected" -ForegroundColor Cyan
    }
    if (!$openFile.FileName){
            Write-Host  "setup.exe was not selected... Exitting" -ForegroundColor Red
            Write-Host "Press any key to continue ..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
            $HOST.UI.RawUI.Flushinputbuffer()
            Exit 
    }
}  
     
Write-Host "Installing SQL..." -ForegroundColor Green
& $setupfile /q /ACTION=Install /FEATURES=SQLEngine /INSTANCENAME=MSSQLSERVER /SQLSVCACCOUNT="DomainNameGoesHere\SQL_SA" /SQLSVCPASSWORD="PasswordGoesHere" /SQLSYSADMINACCOUNTS="DomainNameGoesHere\Domain admins" /AGTSVCACCOUNT="DomainNameGoesHere\SQL_Agent" /AGTSVCPASSWORD="PasswordGoesHere" /TCPENABLED=1 /IACCEPTSQLSERVERLICENSETERMS /Indicateprogress /UpdateEnabled=0

Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript

Write-Host "Job Done..." -ForegroundColor Green
Start-Sleep 5
exit

'@
            $fileContent=$fileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword
            $fileContent=$fileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName
            Set-Content -path $script -value $fileContent
        }
    # adding scripts for ADK install
        if (!( Test-Path "$PSScriptRoot\Tools\ToolsVHD\SCVMM\2_ADK_Install.ps1" )) {  
            $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SCVMM\2_ADK_Install.ps1" -type File
            $fileContent =  @'

#Sample ADK install

# You can grab ADK here:     https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx

# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}


Start-Transcript -Path "$PSScriptRoot\ADK_Install.log"

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"


If (Test-Path -Path "$PSScriptRoot\ADK\ADKsetup.exe"){
    $setupfile = (Get-Item -Path "$PSScriptRoot\ADK\ADKsetup.exe" -ErrorAction SilentlyContinue).fullname
}else{
    # Open File dialog
    Write-Host "Please locate ADKSetup.exe" -ForegroundColor Green

    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog
    $openFile.Filter = "ADKSetup.exe files |ADKSetup.exe|All files (*.*)|*.*" 
    If($openFile.ShowDialog() -eq "OK")
    {
       $setupfile=$openfile.filename
       Write-Host  "File $setupfile selected" -ForegroundColor Cyan
    }
}

Write-Host "Installing ADK..." -ForegroundColor Cyan

Write-Host "ADK Is being installed..." -ForegroundColor Cyan
Start-Process -Wait -FilePath $setupfile -ArgumentList "/features OptionID.DeploymentTools OptionID.WindowsPreinstallationEnvironment /quiet"
Write-Host "ADK install finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
Write-Host "Job Done..." -ForegroundColor Green
Start-Sleep 5
exit

'@
            Set-Content -path $script -value $fileContent
        }
    
    # adding scripts for SCVMM install
        if (!( Test-Path "$PSScriptRoot\Tools\ToolsVHD\SCVMM\3_SCVMM_Install.ps1" )) {  
            $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SCVMM\3_SCVMM_Install.ps1" -type File
            $fileContent =  @'

# Sample VMM Install

# You can grab eval version here: http://www.microsoft.com/en-us/evalcenter/evaluate-system-center-technical-preview

# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

Start-Transcript -Path "$PSScriptRoot\SCVMM_Install.log"

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

if ((get-service MSSQLServer).Status -ne "Running"){
    do{
        Write-Host "Waiting for SQL Service to start"
        Start-Sleep 1
    }until ((get-service MSSQLServer).Status -eq "Running")
}

If (Test-Path -Path "$PSScriptRoot\SCVMM\setup.exe"){
    $setupfile = (Get-Item -Path "$PSScriptRoot\SCVMM\setup.exe" -ErrorAction SilentlyContinue).fullname
    Write-Host "$Setupfile found..." -ForegroundColor Cyan
}else{
# Open File dialog
    Write-Host "Please locate Setup.exe" -ForegroundColor Green

    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog
    $openFile.Filter = "setup.exe files |setup.exe|All files (*.*)|*.*" 
    If($openFile.ShowDialog() -eq "OK")
    {
       $setupfile=$openfile.filename
       Write-Host  "File $setupfile selected" -ForegroundColor Cyan
    } 
}

Write-Host "Installing VMM..." -ForegroundColor Green

###Get workdirectory###
#Install VMM
$unattendFile = New-Item "$PSScriptRoot\VMServer.ini" -type File
$fileContent = @"
[OPTIONS]
CompanyName=Contoso
CreateNewSqlDatabase=1
SqlInstanceName=MSSQLServer
SqlDatabaseName=VirtualManagerDB
SqlMachineName=DC
LibrarySharePath=C:\ProgramData\Virtual Machine Manager Library Files
LibraryShareName=MSSCVMMLibrary
SQMOptIn = 1
MUOptIn = 1
"@
Set-Content $unattendFile $fileContent

Write-Host "VMM is being installed..." -ForegroundColor Cyan
& $setupfile /server /i /f $PSScriptRoot\VMServer.ini /IACCEPTSCEULA /VmmServiceDomain DomainNameGoesHere /VmmServiceUserName vmm_SA /VmmServiceUserPassword PasswordGoesHere
do{
    Start-Sleep 1
}until ((Get-Process | Where-Object {$_.Description -eq "Virtual Machine Manager Setup"} -ErrorAction SilentlyContinue) -eq $null)
Write-Host "VMM is Installed" -ForegroundColor Green

Remove-Item "$PSScriptRoot\VMServer.ini" -ErrorAction Ignore

Write-Host "VMM install finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

$StartDateTime = get-date
$URs=(Get-ChildItem -Path $PSScriptRoot\UpdateRollup -Recurse | where extension -eq .msp).FullName

Foreach ($UR in $URs){
    Write-Host "Update Rollup $UR is being installed"
    Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/update $UR /quiet /norestart"
}
If ($URs){
    Write-Host "UpdateRollups install finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
}

Stop-Transcript
Write-Host "Job Done..." -ForegroundColor Green
start-sleep 5
Exit

'@

            $fileContent=$fileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword
            $fileContent=$fileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName
            Set-Content -path $script -value $fileContent
        }

    # adding createparentdisks script
        if (!( Test-Path "$PSScriptRoot\Tools\CreateParentDisk.ps1" )) {  
            $script = New-Item "$PSScriptRoot\Tools\CreateParentDisk.ps1" -type File
            $fileContent =  @'
# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}


#############
# Functions #
#############

function WriteInfo($message)
{
    Write-Host $message
}

function WriteInfoHighlighted($message)
{
    Write-Host $message -ForegroundColor Cyan
}

function WriteSuccess($message)
{
    Write-Host $message -ForegroundColor Green
}

function WriteError($message)
{
    Write-Host $message -ForegroundColor Red
}

function WriteErrorAndExit($message)
{
    Write-Host $message -ForegroundColor Red
    Write-Host "Press any key to continue ..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
    $HOST.UI.RawUI.Flushinputbuffer()
    Exit
}




#Ask for ISO
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title="Please select ISO image with Windows Server 2016"
}
$openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
If($openFile.ShowDialog() -eq "OK")
{
    WriteInfo  "File $($openfile.FileName) selected"
} 
if (!$openFile.FileName){
        WriteErrorAndExit  "Iso was not selected... Exitting"
    }
$ISOServer = Mount-DiskImage -ImagePath $openFile.FileName -PassThru

$ServerMediaPath = (Get-Volume -DiskImage $ISOServer).DriveLetter+':'


#ask for MSU patches
WriteInfoHighlighted "Please select latest Server Cumulative Update (.MSU)"
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$ServerPackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Multiselect = $true;
    Title="Please select latest Windows Server 2016 Cumulative Update"
}
$ServerPackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
If($ServerPackages.ShowDialog() -eq "OK"){
WriteInfoHighlighted  "Following patches selected:"
WriteInfo "`t $($ServerPackages.filenames)"
} 

#exit if nothing is selected
if (!$ServerPackages.FileNames){
        $ISOServer | Dismount-DiskImage
        WriteErrorAndExit "no msu was selected... Exitting"
}

if (!(Test-Path "$PSScriptRoot\convert-windowsimage.ps1")){
    #download latest convert-windowsimage
    # Download convert-windowsimage if its not in tools folder

    WriteInfo "`t Downloading Convert-WindowsImage"
    try{
        Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\convert-windowsimage.ps1"
    }catch{
        WriteErrorAndExit "`t Failed to download convert-windowsimage.ps1!"
    }
}

#load convert-windowsimage
. "$PSScriptRoot\convert-windowsimage.ps1"

#ask for server edition
$Edition=(Get-WindowsImage -ImagePath "$ServerMediaPath\sources\install.wim" | Out-GridView -OutputMode Single).ImageName

#ask for imagename
$vhdname=(Read-Host -Prompt "Please type VHD name (if nothing specified, Win2016_G2.vhdx is used")
if(!$vhdname){$vhdname="Win2016_G2.vhdx"}

#ask for size
[int64]$size=(Read-Host -Prompt "Please type size of the Image in GB. If nothing specified, 60 is used")
$size=$size*1GB
if (!$size){$size=60GB}

#Create VHD
Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI -Package $serverpackages.FileNames

WriteInfo "Dismounting ISO Image"
if ($ISOServer -ne $Null){
$ISOServer | Dismount-DiskImage
}

WriteSuccess "Job Done. Press any key to continue..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL

'@

            Set-Content -path $script -value $fileContent
        }

#endregion

#region some tools to download
    # Downloading diskspd if its not in tools folder
        WriteInfoHighlighted "Testing diskspd presence"
        If ( Test-Path -Path "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.exe" ) {
            WriteSuccess "`t Diskspd is present, skipping download"
        }else{ 
            WriteInfo "`t Diskspd not there - Downloading diskspd"
            try {
                $webcontent  = Invoke-WebRequest -Uri aka.ms/diskspd -UseBasicParsing
                $downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
                Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.zip"
            }catch{
                WriteError "`t Failed to download Diskspd!"
            }
            # Unnzipping and extracting just diskspd.exe x64
                Expand-Archive "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\Unzip"
                Copy-Item -Path (Get-ChildItem -Path "$PSScriptRoot\tools\toolsvhd\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64fre*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\"
                Remove-Item -Path "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.zip"
                Remove-Item -Path "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
        }

    # Download convert-windowsimage if its not in tools folder
        WriteInfoHighlighted "Testing convert-windowsimage presence"
        If ( Test-Path -Path "$PSScriptRoot\Tools\convert-windowsimage.ps1" ) {
            WriteSuccess "`t Convert-windowsimage.ps1 is present, skipping download"
        }else{ 
            WriteInfo "`t Downloading Convert-WindowsImage"
            try{
                Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\Tools\convert-windowsimage.ps1"
            }catch{
                WriteError "`t Failed to download convert-windowsimage.ps1!"
            }
        }    
#endregion

#region Downloading required Posh Modules
    # Downloading modules into Tools folder if needed.

        $modules=("xActiveDirectory","2.16.0.0"),("xDHCpServer","1.6.0.0"),<#("xDNSServer","1.8.0.0"),#>("xNetworking","5.1.0.0"),("xPSDesiredStateConfiguration","7.0.0.0")
        foreach ($module in $modules){
            WriteInfoHighlighted "Testing if modules are present" 
            $modulename=$module[0]
            $moduleversion=$module[1]
            if (!(Test-Path "$PSScriptRoot\Tools\DSC\$modulename\$Moduleversion")){
                WriteInfo "`t Module $module not found... Downloading"
                #Install NuGET package provider   
                if ((Get-PackageProvider -Name NuGet) -eq $null){   
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force
                }
                Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path "$PSScriptRoot\Tools\DSC"
            }else{
                WriteSuccess "`t Module $modulename version found... Skipping Download"
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
                Copy-item -Path "$PSScriptRoot\Tools\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
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
    WriteSuccess "Press any key to continue..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL