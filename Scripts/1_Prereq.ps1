# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
	Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Sleep -Seconds 1
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
	exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output

 1..10 |% { Write-Host ""}

#############
# Functions #
#############

function  Get-WindowsBuildNumber { 
    $os = Get-WmiObject -Class Win32_OperatingSystem 
    return [int]($os.BuildNumber) 
} 

##########
# Checks #
##########

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

##########################
# Some stuff to download #
##########################

# Downloading diskspd if its not in tools folder
Write-Host "Testing diskspd presence" -ForegroundColor Cyan
If ( Test-Path -Path "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.exe" ) {
		Write-Host "`t Diskspd is present, skipping download" -ForegroundColor Green
}else{ 
		Write-Host "`t Diskspd not there - Downloading diskspd" -ForegroundColor Cyan
		try {
			$webcontent  = Invoke-WebRequest -Uri aka.ms/diskspd
			$downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
			Invoke-WebRequest -Uri $downloadurl -OutFile "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip"
		}catch{
			Write-Host "`t Failed to download Diskspd!" -ForegroundColor Red
		}
		# Unnzipping and extracting just diskspd.exe x64
		Expand-Archive "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$workdir\Tools\ToolsVHD\DiskSpd\Unzip"
		Copy-Item -Path (Get-ChildItem -Path "$workdir\tools\toolsvhd\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64fre*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$workdir\Tools\ToolsVHD\DiskSpd\"
		Remove-Item -Path "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip"
		Remove-Item -Path "$workdir\Tools\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
}

# Download convert-windowsimage if its not in tools folder
Write-Host "Testing convert-windowsimage presence" -ForegroundColor Cyan
If ( Test-Path -Path "$workdir\Tools\convert-windowsimage.ps1" ) {
	Write-Host "`t Convert-windowsimage.ps1 is present, skipping download" -ForegroundColor Green	
}else{ 
		Write-Host "`t Downloading Convert-WindowsImage" -ForegroundColor Cyan
		try{
			Invoke-WebRequest -Uri https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$workdir\Tools\convert-windowsimage.ps1"
		}catch{
			Write-Host "`t Failed to download convert-windowsimage.ps1!" -ForegroundColor Red
		}
}	


# Downloading modules into Tools folder if needed.

$modules=("xActiveDirectory","2.10.0.0"),("xDHCpServer","1.3.0.0"),("xNetworking","2.8.0.0"),("xPSDesiredStateConfiguration","3.9.0.0")
foreach ($module in $modules){
	#testing if modules are present
	Write-Host "Testing if modules are present" -ForegroundColor Cyan
	$modulename=$module[0]
    $moduleversion=$module[1]
	if (!(Test-Path $workdir'\Tools\DSC\'$modulename'\')){
		Write-Host "`t Module $module not found... Downloading"
		#Install NuGET package provider   
		if ((Get-PackageProvider -Name NuGet) -eq $null){   
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
			}
		Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path $workdir'\Tools\DSC'
	}else{
		Write-Host "`t Module $modulename version found... Skipping Download" -ForegroundColor Green
	}
}

# Installing DSC modules if needed
foreach ($module in $modules) {
    Write-Host "Testing DSC Module $module Presence" -ForegroundColor Cyan
    # Check if Module is installed
    if ((Get-DscResource -Module $Module[0] | where-object {$_.version -eq $module[1]}) -eq $Null) {
        # module is not installed - install it
        Write-Host "`t Module $module will be installed"
        $modulename=$module[0]
        $moduleversion=$module[1]
        Copy-item -Path "$workdir\Tools\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
        Write-Host "`t Module was installed." -ForegroundColor Green
        Get-DscResource -Module $modulename
    } else {
        # module is already installed
        Write-Host "`t Module $Module is already installed" -ForegroundColor Green
    }
}

#############
# finishing #
#############

Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
Write-Host "Press any key to continue..." -ForegroundColor Green
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL