#Create VMFleet Image
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
    #Ask for VHD
        WriteInfoHighlighted "Please select VHD (Windows Server Core) created using CreateParentDisk.ps1 located in ParentDisks folder."
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select VHD created by convert-windowsimage. Click cancel if you want to create it"
        }
        $openFile.Filter = "vhdx files (*.vhdx)|*.vhdx|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK"){
            WriteInfo  "File $($openfile.FileName) selected"
        }
        $VHDPath=$openfile.FileName
    #ask for Password that will be configured inside VHD
        WriteInfoHighlighted "Please provide password that will be injected as administrator password into VHD"
        $AdminPassword=Read-Host
#endregion

#region Mount VHD and apply unattend
    #Copy image
    $Destination="$($VHDPath | Split-Path -Parent)\FleetImage.vhdx"
    WriteInfoHighlighted "`t Copying Image to $Destination"
    Copy-Item -Path $VHDPath -Destination $Destination -Force
    WriteInfoHighlighted "`t Applying Unattend"
    if (Test-Path "$PSScriptRoot\Temp\*"){
            Remove-Item -Path "$PSScriptRoot\Temp\*" -Recurse
    }
    New-item -type directory -Path $PSScriptRoot\Temp\mountdir -force
    Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $Destination -Index 1
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

Write-Output "Job Done. Press enter to exit..."
$exit=Read-Host