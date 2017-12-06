# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output
1..10 |% { Write-Host ""}

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
    Stop-Transcript
    $exit=Read-Host
    Exit
}

function  Get-WindowsBuildNumber { 
    $os = Get-WmiObject -Class Win32_OperatingSystem 
    return [int]($os.BuildNumber) 
} 

#endregion

#region Initializtion

# grab Time and start Transcript
    Start-Transcript -Path "$PSScriptRoot\Prereq.log"
    $StartDateTime = get-date
    WriteInfo "Script started at $StartDateTime"

#Load LabConfig....
    . "$PSScriptRoot\LabConfig.ps1"

#define some variables if it does not exist in labconfig
    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

#endregion

#region OS checks and folder build
# Checking for Compatible OS
    WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"

    $BuildNumber=Get-WindowsBuildNumber
    if ($BuildNumber -ge 10586){
        WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
    }else{
        WriteErrorAndExit "`t Windows version  $BuildNumber detected. Version 10586 and newer is needed. Exiting"
    }

# Checking Folder Structure
    "Tools\DSC","Tools\ToolsVHD\DiskSpd","Tools\ToolsVHD\SCVMM\ADK","Tools\ToolsVHD\SCVMM\SQL","Tools\ToolsVHD\SCVMM\SCVMM","Tools\ToolsVHD\SCVMM\UpdateRollup","Tools\ToolsVHD\VMFleet" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } }

    "Tools\ToolsVHD\SCVMM\ADK\Copy_ADK_with_adksetup.exe_here.txt","Tools\ToolsVHD\SCVMM\SQL\Copy_SQL2016_with_setup.exe_here.txt","Tools\ToolsVHD\SCVMM\SCVMM\Copy_SCVMM_with_setup.exe_here.txt","Tools\ToolsVHD\SCVMM\UpdateRollup\Copy_SCVMM_Update_Rollup_MSPs_here.txt" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type File -Path "$PSScriptRoot\$_" } }
#endregion

#region add scripts for SCVMM
#adding scripts for SQL install
    $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SCVMM\1_SQL_Install.ps1" -type File -Force
    $fileContent =  @'

# Sample SQL Install

# You can grab eval version here: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016

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

'@
    $fileContent=$fileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword
    $fileContent=$fileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName
    Set-Content -path $script -value $fileContent

# adding scripts for ADK install
    $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SCVMM\2_ADK_Install.ps1" -type File -Force
    $fileContent =  @'

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
$setupfile = (Get-Item -Path "$PSScriptRoot\ADK\ADKsetup.exe" -ErrorAction SilentlyContinue).fullname
}else{
# Open File dialog
Write-Host "Please locate ADKSetup.exe" -ForegroundColor Green

[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$openFile = New-Object System.Windows.Forms.OpenFileDialog
$openFile.Filter = "ADKSetup.exe files |ADKSetup.exe|All files (*.*)|*.*" 
If($openFile.ShowDialog() -eq "OK")
{
   $setupfile=$openfile.filename
   Write-Host  "File $setupfile selected" -ForegroundColor Cyan
}
}

Write-Host "Installing ADK..." -ForegroundColor Cyan

Write-Host "ADK Is being installed..." -ForegroundColor Cyan
Start-Process -Wait -FilePath $setupfile -ArgumentList "/features OptionID.DeploymentTools OptionID.WindowsPreinstallationEnvironment /quiet"
Write-Host "ADK install finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
Write-Host "Job Done..." -ForegroundColor Green
Start-Sleep 5
exit

'@
    Set-Content -path $script -value $fileContent

# adding scripts for SCVMM install 
    $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SCVMM\3_SCVMM_Install.ps1" -type File -Force
    $fileContent =  @'

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

'@

    $fileContent=$fileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword
    $fileContent=$fileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName
    Set-Content -path $script -value $fileContent


# adding createparentdisks script

    $script = New-Item "$PSScriptRoot\Tools\CreateParentDisk.ps1" -type File -Force
    $fileContent =  @'
# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
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
        $exit=Read-Host
        Exit
    }

#endregion


#region Ask for ISO
    WriteInfoHighlighted "Please select ISO image"
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Title="Please select ISO image"
    }
    $openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
    If($openFile.ShowDialog() -eq "OK"){
        WriteInfo  "File $($openfile.FileName) selected"
    }
    if (!$openFile.FileName){
        WriteErrorAndExit  "Iso was not selected... Exitting"
    }
    $ISOServer = Mount-DiskImage -ImagePath $openFile.FileName -PassThru

    $ServerMediaPath = (Get-Volume -DiskImage $ISOServer).DriveLetter+':'

#endregion

#region ask for MSU packages
    WriteInfoHighlighted "Please select msu packages you want to add to image. Click cancel if you don't want any."
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $ServerPackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Multiselect = $true;
        Title="Please select msu packages you want to add to image. Click cancel if you don't want any."
    }
    $ServerPackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
    If($ServerPackages.ShowDialog() -eq "OK"){
        WriteInfoHighlighted  "Following patches selected:"
        WriteInfo "`t $($ServerPackages.filenames)"
    } 

    #Write info if nothing is selected
    if (!$ServerPackages.FileNames){
        WriteError "No msu was selected..."
    }

#endregion

#region download convert-windowsimage if needed and load it

    if (!(Test-Path "$PSScriptRoot\convert-windowsimage.ps1")){
        WriteInfo "`t Downloading Convert-WindowsImage"
        try{
            Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/live/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\convert-windowsimage.ps1"
        }catch{
        WriteErrorAndExit "`t Failed to download convert-windowsimage.ps1!"
        }
    }

    #load convert-windowsimage
    . "$PSScriptRoot\convert-windowsimage.ps1"

#endregion

#region do the job
    #ask for server edition
    $Edition=(Get-WindowsImage -ImagePath "$ServerMediaPath\sources\install.wim" | Out-GridView -OutputMode Single).ImageName

    #ask for imagename
    $vhdname=(Read-Host -Prompt "Please type VHD name (if nothing specified, Win2016_G2.vhdx is used")
    if(!$vhdname){$vhdname="Win2016_G2.vhdx"}

    #ask for size
    [int64]$size=(Read-Host -Prompt "Please type size of the Image in GB. If nothing specified, 60 is used")
    $size=$size*1GB
    if (!$size){$size=60GB}

    #Create VHD
    if ($serverpackages.FileNames -ne $null){
        Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI -Package $serverpackages.FileNames
    }else{
        Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI
    }
    WriteInfo "Dismounting ISO Image"
    if ($ISOServer -ne $Null){
    $ISOServer | Dismount-DiskImage
    }

    WriteSuccess "Job Done. Press enter to continue..."
    $exit=Read-Host
#endregion
'@

    Set-Content -path $script -value $fileContent

# adding SetupVMFleet script

    $script = New-Item "$PSScriptRoot\Tools\ToolsVHD\SetupVMFleet.ps1" -type File -Force
    $fileContent =  @'
# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

#region functions

    function WriteInfo($message)
    {
        Write-Host $message
    }

    function WriteInfoHighlighted($message)
    {
        Write-Host $message -ForegroundColor Cyan
    }

    function WriteSuccess($message)
    {
        Write-Host $message -ForegroundColor Green
    }

    function WriteError($message)
    {
        Write-Host $message -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        Write-Host $message -ForegroundColor Red
        Write-Host "Press enter to continue ..."
        $exit=Read-Host
        Exit
    }

#endregion

    #region grab variables
    #verify management tools to be able to list S2D Cluster
        if ((Get-WmiObject Win32_OperatingSystem).ProductType -ne 1){
            #Install AD PowerShell if not available
            if (-not (Get-WindowsFeature RSAT-AD-PowerShell)){
                Install-WindowsFeature RSAT-AD-PowerShell
            }
        }else{
            #detect RSAT
            if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                Write-Host "Please install RSAT, Exitting in 5s"
                Start-Sleep 5
                Exit
            }
        }

    #Grab S2D Cluster
        WriteInfoHighlighted "Asking for S2D Cluster"
        $ClusterName=((Get-ADComputer -Filter 'serviceprincipalname -like "MSServercluster/*"').Name | ForEach-Object {get-cluster -Name $_ | Where-Object S2DEnabled -eq 1} | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster(s)").Name

        if (-not $ClusterName){
            Write-Output "No cluster was selected. Exitting"
            Start-Sleep 5
            Exit
        }

    #Grab ClusterNodes
        $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name

    #ask for Password that will be configured inside VHD
        WriteInfoHighlighted "Please provide password that will be injected as admin password into VHD"
        $AdminPassword=Read-Host

    #Ask for VHD
        WriteInfoHighlighted "Please select VHD created by convert-windowsimage. Click cancel if you want to create it"
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select VHD created by convert-windowsimage. Click cancel if you want to create it"
        }
        $openFile.Filter = "vhdx files (*.vhdx)|*.vhdx|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK"){
            WriteInfo  "File $($openfile.FileName) selected"
        }
        $VHDPath=$openfile.FileName

#endregion

#region if VHD not selected, create one
    if (-not $VHDPath){
        #Ask for ISO
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select ISO image with Windows Server 2016"
        }
        $openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK")
        {
            WriteInfo  "File $($openfile.FileName) selected"
        } 
        if (!$openFile.FileName){
                WriteErrorAndExit  "Iso was not selected... Exitting"
            }
        $ISOServer = Mount-DiskImage -ImagePath $openFile.FileName -PassThru

        $ServerMediaPath = (Get-Volume -DiskImage $ISOServer).DriveLetter+':'

        if (!(Test-Path "$PSScriptRoot\convert-windowsimage.ps1")){
            #download latest convert-windowsimage
            # Download convert-windowsimage if its not in tools folder
            WriteInfo "`t Downloading Convert-WindowsImage"
            try{
                Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/live/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\convert-windowsimage.ps1"
            }catch{
                WriteErrorAndExit "`t Failed to download convert-windowsimage.ps1!"
            }
        }

        #load convert-windowsimage
        . "$PSScriptRoot\convert-windowsimage.ps1"

        #ask for server edition
        $Edition=(Get-WindowsImage -ImagePath "$ServerMediaPath\sources\install.wim" | Out-GridView -OutputMode Single).ImageName

        #ask for imagename
        $vhdname=(Read-Host -Prompt "Please type VHD name (if nothing specified, Win2016_G2.vhdx is used")
        if(!$vhdname){$vhdname="Win2016_G2.vhdx"}

        #ask for size
        [int64]$size=(Read-Host -Prompt "Please type size of the Image in GB. If nothing specified, 40 is used")
        $size=$size*1GB
        if (!$size){$size=40GB}

        #Create VHD
        Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI

        WriteInfo "Dismounting ISO Image"
        if ($ISOServer -ne $Null){
        $ISOServer | Dismount-DiskImage
        }

        $VHDPath="$PSScriptRoot\$vhdname"

    }
#endregion

#region Mount VHD and apply unattend
    WriteInfoHighlighted "`t Applying Unattend"
    if (Test-Path "$PSScriptRoot\Temp\*"){
            Remove-Item -Path "$PSScriptRoot\Temp\*" -Recurse
    }
    New-item -type directory -Path $PSScriptRoot\Temp\mountdir -force
    Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
    New-item -type directory -Path "$PSScriptRoot\Temp\mountdir\Users\Administrator" -force
    New-item -type directory -Path "$PSScriptRoot\Temp\mountdir\Windows\Panther" -force
    $unattendFile = New-Item "$PSScriptRoot\Temp\mountdir\Windows\Panther\unattend.xml" -type File -Force
    $fileContent =  @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

<settings pass="offlineServicing">
<component
    xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    language="neutral"
    name="Microsoft-Windows-PartitionManager"
    processorArchitecture="amd64"
    publicKeyToken="31bf3856ad364e35"
    versionScope="nonSxS"
    >
</component>
</settings>
<settings pass="specialize">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <RegisteredOwner>PFE</RegisteredOwner>
    <RegisteredOrganization>Contoso</RegisteredOrganization>
</component>
</settings>
<settings pass="oobeSystem">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
    <AutoLogon>
    <Password>
        <Value>$AdminPassword</Value>
        <PlainText>true</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <LogonCount>999</LogonCount>
    <Username>administrator</Username>
    </AutoLogon>
    <UserAccounts>
    <AdministratorPassword>
        <Value>$AdminPassword</Value>
        <PlainText>true</PlainText>
    </AdministratorPassword>
    </UserAccounts>
    <OOBE>
    <HideEULAPage>true</HideEULAPage>
    <SkipMachineOOBE>true</SkipMachineOOBE> 
    <SkipUserOOBE>true</SkipUserOOBE> 
    </OOBE>
    <TimeZone>Pacific Standard Time</TimeZone>
</component>
</settings>
</unattend>

"@
    Set-Content -path $unattendFile -value $fileContent -Force

    #close VHD and apply changes
        WriteInfoHighlighted "`t Applying changes to VHD"
        Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save

    #cleanup mountdir
        Remove-Item -Path "$PSScriptRoot\Temp" -Recurse

#endregion

#region create volumes
WriteInfoHighlighted "Create Volumes"
Foreach ($ClusterNode in $ClusterNodes){
    WriteInfo "Creating Volume $ClusterNode"
    if (-not (Get-VirtualDisk -CimSession $ClusterName -FriendlyName $ClusterNode -ErrorAction SilentlyContinue)){
        New-Volume -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $ClusterNode -FileSystem CSVFS_ReFS -StorageTierfriendlyNames Performance -StorageTierSizes 1TB
    }
}
WriteInfo "Creating Volume collect"
if (-not (Get-VirtualDisk -CimSession $ClusterName -FriendlyName "Collect" -ErrorAction SilentlyContinue)){
    New-Volume -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName collect -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Performance -StorageTierSizes 1TB
}

#rename CSV(s) to match name
    Get-ClusterSharedVolume -Cluster $ClusterName | % {
        $volumepath=$_.sharedvolumeinfo.friendlyvolumename
        $newname=$_.name.Substring(22,$_.name.Length-23)
        Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
    }

#Install Failover Clustering PowerShell on nodes
    foreach ($ClusterNode in $ClusterNodes){
        Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
    }

#copy VMfleet and VHD to one node 
    New-item -Path "\\$($ClusterNodes[0])\c$\" -Name VMFleet -Type Directory -Force
    WriteInfoHighlighted "Copying Scripts to \\$($ClusterNodes[0])\c$\VMFleet"
    Copy-Item "$PSScriptRoot\VMFleet\*" -Destination "\\$($ClusterNodes[0])\c$\VMFleet"
    WriteInfoHighlighted "Copying $VHDPath to \\$ClusterName\ClusterStorage$\Collect\FleetImage.vhdx" 
    if (-not (Test-Path -Path "\\$ClusterName\ClusterStorage$\Collect\FleetImage.vhdx")){
        Copy-Item $VHDPath -Destination "\\$ClusterName\ClusterStorage$\Collect\FleetImage.vhdx"
    }

WriteInfoHighlighted "Run following commands from $($ClusterNodes[0])"
"c:\VMFleet\install-vmfleet.ps1 -source C:\VMFleet"
"Copy-Item \\DC\D$\DiskSpd\Diskspd.exe -Destination c:\ClusterStorage\Collect\Control\Tools\Diskspd.exe"
"c:\VMFleet\create-vmfleet.ps1 -basevhd C:\ClusterStorage\Collect\FleetImage.vhdx -vms 1 -adminpass $AdminPassword -connectuser DomainNameGoesHere\Administrator -connectpass PasswordGoesHere -FixedVHD:"+'$False'
"c:\VMFleet\set-vmfleet.ps1 -ProcessorCount 2 -MemoryStartupBytes 512MB -MemoryMinimumBytes 512MB -MemoryMaximumBytes 2GB"
"c:\VMFleet\Start-Vmfleet.ps1"
"c:\VMFleet\start-sweep.ps1 -b 4 -t 2 -o 40 -w 0 -d 300"
"c:\VMFleet\watch-cluster.ps1"

WriteSuccess "Press enter to exit..."
$exit=Read-Host

'@
    $fileContent=$fileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword
    $fileContent=$fileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName
    Set-Content -path $script -value $fileContent

#endregion

#region some tools to download
# Downloading diskspd if its not in tools folder
    WriteInfoHighlighted "Testing diskspd presence"
    If ( Test-Path -Path "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.exe" ) {
        WriteSuccess "`t Diskspd is present, skipping download"
    }else{ 
        WriteInfo "`t Diskspd not there - Downloading diskspd"
        try {
            $webcontent  = Invoke-WebRequest -Uri aka.ms/diskspd -UseBasicParsing
            $downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.zip"
        }catch{
            WriteError "`t Failed to download Diskspd!"
        }
        # Unnzipping and extracting just diskspd.exe x64
            Expand-Archive "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\Unzip"
            Copy-Item -Path (Get-ChildItem -Path "$PSScriptRoot\tools\toolsvhd\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64fre*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\"
            Remove-Item -Path "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\diskspd.zip"
            Remove-Item -Path "$PSScriptRoot\Tools\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
    }

#Download VMFleet
    WriteInfoHighlighted "Testing VMFleet presence"
    If ( Test-Path -Path "$PSScriptRoot\Tools\ToolsVHD\VMFleet\install-vmfleet.ps1" ) {
        WriteSuccess "`t VMFleet is present, skipping download"
    }else{ 
        WriteInfo "`t VMFleet not there - Downloading VMFleet"
        try {
            $downloadurl = "https://github.com/Microsoft/diskspd/archive/master.zip"
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Tools\ToolsVHD\VMFleet\VMFleet.zip"
        }catch{
            WriteError "`t Failed to download VMFleet!"
        }
        # Unnzipping and extracting just VMFleet
            Expand-Archive "$PSScriptRoot\Tools\ToolsVHD\VMFleet\VMFleet.zip" -DestinationPath "$PSScriptRoot\Tools\ToolsVHD\VMFleet\Unzip"
            Copy-Item -Path "$PSScriptRoot\Tools\ToolsVHD\VMFleet\Unzip\diskspd-master\Frameworks\VMFleet\*" -Destination "$PSScriptRoot\Tools\ToolsVHD\VMFleet\"
            Remove-Item -Path "$PSScriptRoot\Tools\ToolsVHD\VMFleet\VMFleet.zip"
            Remove-Item -Path "$PSScriptRoot\Tools\ToolsVHD\VMFleet\Unzip" -Recurse -Force
    }

# Download convert-windowsimage into ToolsRoot and ToolsVHD
    WriteInfoHighlighted "Testing convert-windowsimage presence"
    If ( Test-Path -Path "$PSScriptRoot\Tools\convert-windowsimage.ps1" ) {
        WriteSuccess "`t Convert-windowsimage.ps1 is present, skipping download"
    }else{ 
        WriteInfo "`t Downloading Convert-WindowsImage"
        try{
            Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/live/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\Tools\convert-windowsimage.ps1"
        }catch{
            WriteError "`t Failed to download convert-windowsimage.ps1!"
        }
    }

    If ( Test-Path -Path "$PSScriptRoot\Tools\ToolsVHD\convert-windowsimage.ps1" ) {
        WriteSuccess "`t Convert-windowsimage.ps1 is in ToolsVHD, skipping copy"
    }else{
        WriteInfo "`t Copying Convert-windowsimage.ps1 into ToolsVHD"
        Copy-Item -Path "$PSScriptRoot\Tools\convert-windowsimage.ps1" -Destination "$PSScriptRoot\Tools\ToolsVHD\convert-windowsimage.ps1"
    }

#endregion

#region Downloading required Posh Modules
# Downloading modules into Tools folder if needed.

    $modules=("xActiveDirectory","2.16.0.0"),("xDHCpServer","1.6.0.0"),<#("xDNSServer","1.8.0.0"),#>("xNetworking","5.1.0.0"),("xPSDesiredStateConfiguration","7.0.0.0")
    foreach ($module in $modules){
        WriteInfoHighlighted "Testing if modules are present" 
        $modulename=$module[0]
        $moduleversion=$module[1]
        if (!(Test-Path "$PSScriptRoot\Tools\DSC\$modulename\$Moduleversion")){
            WriteInfo "`t Module $module not found... Downloading"
            #Install NuGET package provider   
            if ((Get-PackageProvider -Name NuGet) -eq $null){   
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force
            }
            Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path "$PSScriptRoot\Tools\DSC"
        }else{
            WriteSuccess "`t Module $modulename version found... skipping download"
        }
    }

# Installing DSC modules if needed
    foreach ($module in $modules) {
        WriteInfoHighlighted "Testing DSC Module $module Presence"
        # Check if Module is installed
        if ((Get-DscResource -Module $Module[0] | where-object {$_.version -eq $module[1]}) -eq $Null) {
            # module is not installed - install it
            WriteInfo "`t Module $module will be installed"
            $modulename=$module[0]
            $moduleversion=$module[1]
            Copy-item -Path "$PSScriptRoot\Tools\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
            WriteSuccess "`t Module was installed."
            Get-DscResource -Module $modulename
        } else {
            # module is already installed
            WriteSuccess "`t Module $Module is already installed"
        }
    }

#endregion

# finishing 
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript
WriteSuccess "Press enter to continue..."
$exit=Read-Host