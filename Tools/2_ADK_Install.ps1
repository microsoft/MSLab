
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
    $setupfile = Get-Item -Path "$PSScriptRoot\ADK\ADKsetup.exe" -ErrorAction SilentlyContinue
}else{
    # Open File dialog
    Write-Host "Please locate ADKSetup.exe" -ForegroundColor Green

    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog
    $openFile.Filter = "ADKSetup.exe files |ADKSetup.exe|All files (*.*)|*.*" 
    If($openFile.ShowDialog() -eq "OK"){
        $setupfile=$openfile.filename
        Write-Host  "File $setupfile selected" -ForegroundColor Cyan
    }
}

if ($setupfile.versioninfo.ProductBuildPart -ge 17763){
    If (Test-Path -Path "$PSScriptRoot\ADKwinPE\adkwinpesetup.exe"){
        $winpesetupfile = Get-Item -Path "$PSScriptRoot\ADKwinPE\adkwinpesetup.exe" -ErrorAction SilentlyContinue
    }else{
        # Open File dialog
        Write-Host "Please locate adkwinpesetup.exe" -ForegroundColor Green
    
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog
        $openFile.Filter = "adkwinpesetup.exe files |adkwinpesetup.exe|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK"){
            $setupfile=$openfile.filename
            Write-Host  "File $setupfile selected" -ForegroundColor Cyan
        }
    }
}

Write-Host "Installing ADK..." -ForegroundColor Cyan

if ($SetupFile.versioninfo.ProductBuildPart -ge 17763){
    Write-Host "ADK $($SetupFile.versioninfo.ProductBuildPart) Is being installed..." -ForegroundColor Cyan
    Start-Process -Wait -FilePath $setupfile.fullname -ArgumentList "/features OptionID.DeploymentTools /quiet"
    Write-Host "ADKwinPE $($winpeSetupFile.versioninfo.ProductBuildPart) Is being installed..." -ForegroundColor Cyan
    Start-Process -Wait -FilePath $winpesetupfile.fullname -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /quiet"
}else{
    Write-Host "ADK $($SetupFile.versioninfo.ProductBuildPart) Is being installed..." -ForegroundColor Cyan
    Start-Process -Wait -FilePath $setupfile.fullname -ArgumentList "/features OptionID.DeploymentTools OptionID.WindowsPreinstallationEnvironment /quiet"
}
Write-Host "ADK install finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
Write-Host "Job Done..." -ForegroundColor Green
Start-Sleep 5
exit
