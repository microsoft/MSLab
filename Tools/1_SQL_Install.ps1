# Sample SQL Install

# You can grab eval version here: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2017

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