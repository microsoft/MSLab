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

$folder=$PSScriptRoot
#$folder="c:\temp"

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
    $vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -Filesystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel MSIX

    Start-Process -FilePath "$folder\msixmgr\x64\msixmgr.exe" -ArgumentList  "-Unpack -packagePath `"$File`" -destination $($vhddiskpart.driveletter):\ -applyacls" -Wait

    Dismount-VHD $vhddisk.number
}

Read-Host "job done. Press enter to exit"
 