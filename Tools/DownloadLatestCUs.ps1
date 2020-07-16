If ((Get-ExecutionPolicy) -ne "RemoteSigned"){
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
}

#download LatestUpdate module
Write-Output "Checking if LatestUpdate PS Module is Installed"
if (!(Get-InstalledModule -Name LatestUpdate)){
    # Verify Running as Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If (!( $isAdmin )) {
        Write-Host "-- Restarting as Administrator to install Modules" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
        exit
    }
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name LatestUpdate -Force
}

#check if latest json is added
$jsonweb=(Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/aaronparker/LatestUpdate/master/LatestUpdate/LatestUpdate.json).content | ConvertFrom-Json 
$jsonlocal=Get-Content -Path "$((Get-InstalledModule -Name LatestUpdate).InstalledLocation)\LatestUpdate.json" | ConvertFrom-Json
if (($jsonlocal.ParameterValues.Windows10Versions).Count -ne ($jsonweb.ParameterValues.Windows10Versions).Count){
    Write-Output "JSON on Local web is different, replacing local JSON"
    #elevate process
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If (!( $isAdmin )) {
        Write-Host "-- Restarting as Administrator to replace JSON in LatestUpdate Module" -ForegroundColor Cyan ; Sleep -Seconds 1
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
        exit
    }
    $jsonweb | ConvertTo-Json | Out-File "$((Get-InstalledModule -Name LatestUpdate).InstalledLocation)\LatestUpdate.json"
    If ((Get-ExecutionPolicy) -ne "RemoteSigned"){
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
    }
}

#grab folder to download to
$folder=Read-Host -Prompt "Please type path to download. For example `"c:\temp`" (if nothing specified, $PSScriptRoot is used)"
if(!$folder){$folder=$PSScriptRoot}

#grab versions to download
$versions=$jsonweb.ParameterValues.Windows10Versions | Out-GridView -OutputMode Multiple -Title "Select versions to download"

foreach ($Version in $versions){
    Write-Output "Fetching for latest CU info from web"
    $latestCU=Get-LatestCumulativeUpdate -OperatingSystem Windows10 -Version $Version | Where-Object -Property Note -Like "*Windows 10*x64*" | Select-Object -First 1 #1903 has 2 objects
    $CUFilename=$latestCU.URL.Split('/') | Select-Object -Last 1
    $path="$folder\$version\$($latestCU.Note.Substring(0,7))"
    New-Item -Path $path -ItemType Directory -ErrorAction Ignore | Out-Null
    if (Test-Path -Path "$path\$CUFilename"){
        Write-Output "$CUFilename already present. Skipping download"
    }else{
        Write-Output "Downloading $CUFilename"
        $latestCU | Save-LatestUpdate -Path $path
    }

    Write-Output "Fetching for latest SSU info from web"
    $latestSSU=Get-LatestServicingStackUpdate -OperatingSystem Windows10 -Version $Version | Where-Object -Property Note -Like "*Windows 10*x64*"
    $SSUFilename=$latestSSU.URL.Split('/') | Select-Object -Last 1
    if (Test-Path -Path "$path\$SSUFilename"){
        Write-Output "$SSUFilename already present. Skipping download"
    }else{
        Write-Output "Downloading $SSUFilename"
        $latestSSU | Save-LatestUpdate -Path $path
    }
}

Write-Host "Job finished. Press enter to continue" -ForegroundColor Green
Read-Host