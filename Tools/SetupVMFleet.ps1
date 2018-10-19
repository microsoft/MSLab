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
        $vhdname=(Read-Host -Prompt "Please type VHD name (if nothing specified, Win10_G2.vhdx is used")
        if(!$vhdname){$vhdname="Win10_G2.vhdx"}

        #ask for size
        [int64]$size=(Read-Host -Prompt "Please type size of the Image in GB. If nothing specified, 60 is used")
        $size=$size*1GB
        if (!$size){$size=60GB}

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