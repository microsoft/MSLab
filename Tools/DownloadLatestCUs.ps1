If ((Get-ExecutionPolicy) -ne "RemoteSigned"){
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
}

#try import module
Import-Module LatestUpdate -ErrorAction Ignore

#download LatestUpdate module
if (!(get-module -Name LatestUpdate)){
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

#grab folder to download to
$folder=Read-Host -Prompt "Please type path to download. For example `"c:\temp`" (if nothing specified, $PSScriptRoot is used)"
if(!$folder){$folder=$PSScriptRoot}

#grab versions to download
$versions="1607","1703","1709","1803","1809","1903" | Out-GridView -OutputMode Multiple -Title "Select versions to download"

foreach ($Version in $versions){
    Write-Output "Fetching info from web"
    $latestCU=Get-LatestCumulativeUpdate -OperatingSystem WindowsServer -Version $Version | Select-Object -First 1 #1903 has 2 objects
    $latestSSU=Get-LatestServicingStackUpdate -OperatingSystem Windows10 -Version $Version | Where-Object -Property Note -Like "*server*" 
    $CUFilename=$latestCU.URL.Split('/') | Select-Object -Last 1
    $SSUFilename=$latestSSU.URL.Split('/') | Select-Object -Last 1
    $path="$folder\$version\$($latestCU.Note.Substring(0,7))"
    
    New-Item -Path $path -ItemType Directory -ErrorAction Ignore | Out-Null

    if (Test-Path -Path "$path\$CUFilename"){
        Write-Output "$CUFilename already present. Skipping download"
    }else{
        Write-Output "Downloading $CUFilename"
        $latestCU | Save-LatestUpdate -Path $path
    }
    if (Test-Path -Path "$path\$SSUFilename"){
        Write-Output "$SSUFilename already present. Skipping download"
    }else{
        Write-Output "Downloading $SSUFilename"
        $latestSSU | Save-LatestUpdate -Path $path
    }
}

Write-Host "Job finished. Press enter to continue" -ForegroundColor Green
Read-Host