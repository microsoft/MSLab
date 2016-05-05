<#
.Synopsis
   Preps for the creation of the Lab VMs
.Description
	Creates the required directories; downloads the tools diskspd.exe, convert-windowsimage.ps1, and the required DSC resources 
.EXAMPLE
   .\1_Prereq.ps1
.EXAMPLE
   .\1_Prereq.ps1 -verbose
#> 
#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Write-Verbose -Message "Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output"
 1..10 |% { Write-Host ""}

Write-Verbose -Message "Loading Functions"
. .\functions.ps1

Write-Verbose -Message "Get workdirectory and Start Time"
$workdir       = Get-ScriptDirectory
Start-Transcript -Path $workdir'\Prereq.log' -Append
$StartDateTime = get-date
Write-Information -MessageData "Script started at $StartDateTime" -InformationAction Continue

Write-Verbose -Message "Checking if OS is Windows 10 TH2/Server 2016 TP4 or newer"
$BuildNumber=Get-WindowsBuildNumber
if ($BuildNumber -ge 10586){
	Write-Verbose -Message "OS is Windows 10 TH2/Server 2016 TP4 or newer"
    }else{
    Write-Error "Windows 10/ Server 2016 not detected. Exiting"
	Exit
}

Write-Verbose -Message "Checking Folder Structure"
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
Write-Verbose -Message "Downloading diskspd if its not in tools folder"
Switch ( Test-Path -Path "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.exe" ) {
	$false { 
		Write-Information -MessageData "Downloading diskspd" -InformationAction Continue
		try{
			$webcontent  = Invoke-WebRequest -Uri aka.ms/diskspd
			$downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
			Invoke-WebRequest -Uri $downloadurl -OutFile "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip"
		}catch{
			Write-Error -Message "Failed to download diskspd!"
		}
			Write-Verbose -Message "Unnzipping and extracting just diskspd.exe x64"
			Expand-Archive "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$workdir\Tools\ToolsVHD\DiskSpd\Unzip"
			Copy-Item -Path (Get-ChildItem -Path "$workdir\tools\toolsvhd\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64fre*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$workdir\Tools\ToolsVHD\DiskSpd\"
			Remove-Item -Path "$workdir\Tools\ToolsVHD\DiskSpd\diskspd.zip"
			Remove-Item -Path "$workdir\Tools\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
		
	}
}

Write-Verbose -Message "Download convert-windowsimage if its not in tools folder"
Switch ( Test-Path -Path "$workdir\Tools\convert-windowsimage.ps1" ) {
	$false { 
		Write-Information -MessageData "Downloading Convert-WindowsImage" -InformationAction Continue
		try {
			Invoke-WebRequest -Uri https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/master/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$workdir\Tools\convert-windowsimage.ps1"
		}
		catch {
			Write-Error -Message "Failed to download Convert-WindowsImage!"
		}
	}
}

Write-Verbose -Message "Specify needed modules and required version"
$modules=("xActiveDirectory","2.10.0.0"),("xDHCpServer","1.3.0.0"),("xNetworking","2.8.0.0"),("xPSDesiredStateConfiguration","3.9.0.0")

Write-Verbose -Message "Downloading modules into Tools folder if needed."
foreach ($module in $modules){
	Write-Verbose -Message "Testing if modules are present"
	$modulename=$module[0]
    $moduleversion=$module[1]
	if (!(Test-Path $workdir'\Tools\DSC\'$modulename'\')){
		Write-Information -MessageData "Module $module not found... Downloading"   
		if ((Get-PackageProvider -Name NuGet) -eq $null){
			Write-Verbose -Message "Install NuGET package provider"
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
			}
		Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path $workdir'\Tools\DSC'
	}else{
		Write-Information -MessageData "Module $modulename version found... Skipping Download" -InformationAction Continue
	}
}

Write-Verbose -Message "Installing modules if needed"
foreach ($module in $modules) {
    Write-Information -MessageData "Testing DSC Module $module Presence"
    if ((Get-DscResource -Module $Module[0] | where-object {$_.version -eq $module[1]}) -eq $Null) {
        Write-Information -MessageData "Module $module will be installed" -InformationAction Continue
        $modulename=$module[0]
        $moduleversion=$module[1]
        Copy-item -Path "$workdir\Tools\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
        Write-Information -MessageData "Module was installed." -InformationAction Continue
        Get-DscResource -Module $modulename
    } else {
        Write-Information -MessageData "Module $Module is already installed" -InformationAction Continue
    }
}
# finishing
Write-Information -MessageData "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes" -InformationAction Continue
Stop-Transcript