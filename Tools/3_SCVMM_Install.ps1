
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
        Start-Sleep 10
        Start-Service -Name MSSQLServer
    }until ((get-service MSSQLServer).Status -eq "Running")
    Write-Host "SQL Service is running"
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
VmmServiceLocalAccount=0
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