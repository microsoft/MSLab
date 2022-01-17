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
        Read-Host | Out-Null
        Exit
    }

#endregion

#region Ask for VHDs
    WriteInfoHighlighted "Please select VHDx file(s)"
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $VHDs = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $true;
        Title="Please select VHDx file(s)"
    }
    $VHDs.Filter = "vhdx files (*.vhdx)|*.vhdx|All files (*.*)|*.*" 
    If($VHDs.ShowDialog() -eq "OK"){
        WriteInfo  "File $($VHDs.FileName) selected"
    }
    if (!$VHDs.FileName){
        WriteErrorAndExit  "VHDx was not selected... Exitting"
    }
#endregion

#region ask for MSU packages
    WriteInfoHighlighted "Please select msu packages you want to add to VHDx."
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $msupackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $true;
        Title="Please select msu packages you want to add to VHDx."
    }
    $msupackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
    If($msupackages.ShowDialog() -eq "OK"){
        WriteInfoHighlighted  "Following patches selected:"
        foreach ($filename in $msupackages.FileNames){
            WriteInfo "`t $filename"
        }
    }else{
        WriteErrorAndExit "No update package selected, exitting"
    }

    #sort packages by size (to apply Servicing Stack Update first)
    if ($msupackages.Filenames){
        $files=@()
        foreach ($Filename in $msupackages.FileNames){$files+=Get-ChildItem -Path $filename}
        $packages=($files |Sort-Object -Property Length).Fullname
    }
#endregion

# region mount and patch VHD
    foreach ($FileName in $VHDs.FileNames) {
        WriteInfoHighlighted "Patching VHD $FileName"
        $Mount=Mount-VHD $FileName -Passthru
        #Grab letter
        $DriveLetter=(Get-Disk -Number $Mount.Number |Get-Partition | Where-Object Driveletter).DriveLetter
        #Patch
        foreach ($package in $packages){
            Add-WindowsPackage -PackagePath $package -Path "$($DriveLetter):\"
        }
        #Dismount
        $Mount | Dismount-VHD
    }
#endregion

WriteSuccess "Job Done. Press enter to continue..."
Read-Host | Out-Null