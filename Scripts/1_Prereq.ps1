# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
	Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Sleep -Seconds 1
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
	exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output

 1..10 |% { Write-Host ""}

# Functions
function  Get-WindowsBuildNumber { 
    $os = Get-WmiObject -Class Win32_OperatingSystem 
    return [int]($os.BuildNumber) 
} 


# Get workdirectory and Start Time
$workdir       = Split-Path $script:MyInvocation.MyCommand.Path
Start-Transcript -Path $workdir'\Prereq.log'
$StartDateTime = get-date
Write-host	"Script started at $StartDateTime"

# Checking for Compatible OS
Write-Host "Checking if OS is Windows 10 TH2/Server 2016 TP4 or newer" -ForegroundColor Cyan

$BuildNumber=Get-WindowsBuildNumber
if ($BuildNumber -ge 10586){
	Write-Host "`t OS is Windows 10 TH2/Server 2016 TP4 or newer" -ForegroundColor Green
    }else{
    Write-Host "`t Windows 10/ Server 2016 not detected. Exiting" -ForegroundColor Red
    Write-Host "Press any key to continue ..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
    $HOST.UI.RawUI.Flushinputbuffer()
    Exit
}

# Checking Folder Structure
'OSClient','OSServer','Tools\DSC','Tools\ToolsVHD\DiskSpd','OSServer\Packages','OSClient\Packages' | ForEach-Object {
    if (!( Test-Path "$Workdir\$_" )) { New-Item -Type Directory -Path "$workdir\$_" } }

If (!( Test-Path -Path "$workdir\OSServer\Copy_WindowsServer_ISO_or_its_content_here.txt" )) { 
	   New-Item -Path "$workdir\OSServer\" -Name Copy_WindowsServer_ISO_or_its_content_here.txt -ItemType File }

If (!( Test-Path -Path "$workdir\OSClient\Copy_WindowsClient_ISO_or_its_content_here.txt" )) { 
	   New-Item -Path "$workdir\OSClient\" -Name Copy_WindowsClient_ISO_or_its_content_here.txt -ItemType File }

If (!( Test-Path -Path "$workdir\OSServer\Packages\Copy_MSU_or_Cab_packages_here.txt" )) { 
	   New-Item -Path "$workdir\OSServer\Packages\" -Name Copy_MSU_or_Cab_packages_here.txt -ItemType File }

If (!( Test-Path -Path "$workdir\OSClient\Packages\Copy_MSU_or_Cab_packages_here.txt" )) { 
	   New-Item -Path "$workdir\OSClient\Packages\" -Name Copy_MSU_or_Cab_packages_here.txt -ItemType File }
# Downloading diskspd if its not in tools folder
Switch ( Test-Path -Path "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.exe" ) {
	$false { 
		Write-Host "Downloading diskspd" -ForegroundColor Cyan
		
		$webcontent  = Invoke-WebRequest -Uri aka.ms/diskspd
		$downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
		Invoke-WebRequest -Uri $downloadurl -OutFile "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip"
		# Unnzipping and extracting just diskspd.exe x64
		Expand-Archive "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$workdir\Tools\ToolsVHD\DiskSpd\Unzip"
		Copy-Item -Path (Get-ChildItem -Path "$workdir\tools\toolsvhd\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64fre*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$workdir\Tools\ToolsVHD\DiskSpd\"
		Remove-Item -Path "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip"
		Remove-Item -Path "$workdir\Tools\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
	}
}

# Download convert-windowsimage if its not in tools folder
Switch ( Test-Path -Path "$workdir\Tools\convert-windowsimage.ps1" ) {
	$false { 
		Write-Host "Downloading Convert-WindowsImage" -ForegroundColor Cyan
		Invoke-WebRequest -Uri https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$workdir\Tools\convert-windowsimage.ps1"
	}
}

# Specify needed modules and required version
$modules=("xActiveDirectory","2.10.0.0"),("xDHCpServer","1.3.0.0"),("xNetworking","2.8.0.0"),("xPSDesiredStateConfiguration","3.9.0.0")

# Downloading modules into Tools folder if needed.
foreach ($module in $modules){
	#testing if modules are present
	Write-Host "Testing if modules are present" -ForegroundColor Cyan
	$modulename=$module[0]
    $moduleversion=$module[1]
	if (!(Test-Path $workdir'\Tools\DSC\'$modulename'\')){
		Write-Host "Module $module not found... Downloading"
		### Install NuGET package provider ###   
		if ((Get-PackageProvider -Name NuGet) -eq $null){   
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
			}
		Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path $workdir'\Tools\DSC'
	}else{
		Write-Host "Module $modulename version found... Skipping Download"
	}
}

# Installing modules if needed
foreach ($module in $modules) {
    Write-Host "Testing DSC Module $module Presence" -ForegroundColor Cyan
    # Check if Module is installed
    if ((Get-DscResource -Module $Module[0] | where-object {$_.version -eq $module[1]}) -eq $Null) {
        # module is not installed - install it
        Write-Host "Module $module will be installed"
        $modulename=$module[0]
        $moduleversion=$module[1]
        Copy-item -Path "$workdir\Tools\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
        Write-Host "Module was installed." -ForegroundColor Green
        Get-DscResource -Module $modulename
        Write-Host ""
    } else {
        # module is already installed
        Write-Host "Module $Module is already installed"
        Write-Host ""
    }
}
# finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
Write-Host "Press any key to continue..." -ForegroundColor Green
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL