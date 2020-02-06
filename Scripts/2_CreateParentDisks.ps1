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
        Stop-Transcript
        Read-Host | Out-Null
        Exit
    }

    #Create Unattend for VHD 
    Function CreateUnattendFileVHD{
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Computername,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $Path,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone
        )

        if ( Test-Path "$path\Unattend.xml" ) {
            Remove-Item "$Path\Unattend.xml"
        }
        $unattendFile = New-Item "$Path\Unattend.xml" -type File
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
      <SanPolicy>1</SanPolicy>
    </component>
 </settings>
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
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
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content -path $unattendFile -value $fileContent

        #return the file object
        Return $unattendFile 
    }

#endregion

#region Initialization
    #Start Log
        Start-Transcript -Path "$PSScriptRoot\CreateParentDisks.log"
        $StartDateTime = get-date
        WriteInfo "Script started at $StartDateTime"

    #Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

    #create variables if not already in LabConfig
        If (!$LabConfig.DomainNetbiosName){
            $LabConfig.DomainNetbiosName="Corp"
        }

        If (!$LabConfig.DomainName){
            $LabConfig.DomainName="Corp.contoso.com"
        }

        If (!$LabConfig.DefaultOUName){
            $LabConfig.DefaultOUName="Workshop"
        }

        If ($LabConfig.PullServerDC -eq $null){
            $LabConfig.PullServerDC=$true
        }

        If (!$LabConfig.DHCPscope){
            $LabConfig.DHCPscope="10.0.0.0"
        }


    #create some built-in variables
        $DN=$null
        $LabConfig.DomainName.Split(".") | ForEach-Object {
            $DN+="DC=$_,"
        }
        
        $LabConfig.DN=$DN.TrimEnd(",")

        $AdminPassword=$LabConfig.AdminPassword
        $Switchname="DC_HydrationSwitch_$([guid]::NewGuid())"
        $DCName='DC'

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

    #Grab Installation type
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType

    #DCHP scope
    $DHCPscope = $LabConfig.DHCPscope
    $ReverseDNSrecord = $DHCPscope -replace '^(\d+)\.(\d+)\.\d+\.(\d+)$','$3.$2.$1.in-addr.arpa'
    $DHCPscope = $DHCPscope.Substring(0,$DHCPscope.Length-1) 

#endregion

#region Check prerequisites

    #check Hyper-V    
        WriteInfoHighlighted "Checking if Hyper-V is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
        }

        WriteInfoHighlighted "Checking if Hyper-V Powershell module is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V tools are not installed. Please install Hyper-V management tools. Exiting"
        }

    #check if VMM prereqs files are present if InstallSCVMM or SCVMM prereq is requested and tools.vhdx not present
        if (-not (Get-ChildItem -Path "$PSScriptRoot\ParentDisks" -ErrorAction SilentlyContinue).name -contains "tools.vhdx"){
            if ($LabConfig.InstallSCVMM -eq "Yes"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SCVMM\setup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe","Temp\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SCVMM install not found. Exitting"
                    }
                }    
            }

            if ($LabConfig.InstallSCVMM -eq "Prereqs"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe","Temp\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SCVMM Prereqs install not found. Exitting"
                    }
                } 
            }
        
            if ($LabConfig.InstallSCVMM -eq "SQL"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Temp\ToolsVHD\SCVMM\SQL\setup.exe" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for SQL install not found. Exitting"
                    }
                }
            }    

            if ($LabConfig.InstallSCVMM -eq "ADK"){
                "Temp\ToolsVHD\SCVMM\ADK\ADKsetup.exe" | ForEach-Object {
                    if(!(Test-Path -Path "$PSScriptRoot\$_")){
                        WriteErrorAndExit "file $_ needed for ADK install not found. Exitting"
                    }
                }
            }
        }

    #check if parent images already exist (this is useful if you have parent disks from another lab and you want to rebuild for example scvmm)
        WriteInfoHighlighted "Testing if some parent disk already exists and can be used"
        
        #grab all files in parentdisks folder
            $ParentDisksNames=(Get-ChildItem -Path "$PSScriptRoot\ParentDisks" -ErrorAction SilentlyContinue).Name

    #check if running on Core Server and check proper values in LabConfig
        If ($WindowsInstallationType -eq "Server Core"){
            If (!$LabConfig.ServerISOFolder){
                WriteErrorAndExit "Server Core detected. Please use ServerISOFolder variable in LabConfig to specify Server iso location"
            }
        }

    #Check if at least 2GB (+200Mb just to be sure) memory is available
    WriteInfoHighlighted "Checking if at least 2GB RAM is available"
    $MemoryAvailableMB=(Get-Ciminstance Win32_OperatingSystem).FreePhysicalMemory/1KB
    if ($MemoryAvailableMB -gt (2048+200)){
        WriteSuccess "`t $("{0:n0}" -f $MemoryAvailableMB) MB RAM Available"
    }else{
        WriteErrorAndExit "`t Please make sure you have at least 2 GB available memory. Exiting"
    }

#endregion

#region Ask for ISO images and Cumulative updates
    #Grab Server ISO
        if ($LabConfig.ServerISOFolder){
            $ServerISOItem = Get-ChildItem -Path $LabConfig.ServerISOFolder -Recurse -Include '*.iso' -ErrorAction SilentlyContinue
            if ($ServerISOItem.count -gt 1){
                WriteInfoHighlighted "Multiple ISO files found. Please select Server ISO one you want"
                $ServerISOItem=$ServerISOItem | Select-Object Name,FullName | Out-GridView -Title "Multiple ISO files found. Please select Server ISO you want" -OutputMode Single
            }
            if (!$ServerISOItem){
                WriteErrorAndExit  "No iso was found in $($LabConfig.ServerISOFolder) ... Exitting"
            }
            $ISOServer = Mount-DiskImage -ImagePath $ServerISOItem.FullName -PassThru
        }else{
            WriteInfoHighlighted "Please select ISO image with Windows Server 2016, 2019 or Server Insider"
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Title="Please select ISO image with Windows Server 2016, 2019 or Server Insider"
            }
            $openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
            If($openFile.ShowDialog() -eq "OK"){
                WriteInfo  "File $($openfile.FileName) selected"
            } 
            if (!$openFile.FileName){
                WriteErrorAndExit  "Iso was not selected... Exitting"
            }
            #Mount ISO
                $ISOServer = Mount-DiskImage -ImagePath $openFile.FileName -PassThru
        }
    #Grab Server Media Letter
        $ServerMediaDriveLetter = (Get-Volume -DiskImage $ISOServer).DriveLetter

    #Test if it's server media
        WriteInfoHighlighted "Testing if selected ISO is Server Media"
        $WindowsImage=Get-WindowsImage -ImagePath "$($ServerMediaDriveLetter):\sources\install.wim"
        If ($WindowsImage.ImageName[0].contains("Server")){
            WriteInfo "`t Server Edition found"
        }else{
            $ISOServer | Dismount-DiskImage
            WriteErrorAndExit "`t Selected media does not contain Windows Server. Exitting."
        }
        if ($WindowsImage.ImageName[0].contains("Server") -and $windowsimage.count -eq 2){
            WriteInfo "`t Semi-Annual Server Media detected"
            $ISOServer | Dismount-DiskImage
            WriteErrorAndExit "Please provide LTSC media. Exitting."
        }
    #Test if it's Windows Server 2016 and newer
        $BuildNumber=(Get-ItemProperty -Path "$($ServerMediaDriveLetter):\setup.exe").versioninfo.FileBuildPart
        If ($BuildNumber -lt 14393){
            $ISOServer | Dismount-DiskImage
            WriteErrorAndExit "Please provide Windows Server 2016 and newer. Exitting."
        }

#Grab packages
    #grab server packages
        if ($LabConfig.ServerISOFolder){
            if ($LabConfig.ServerMSUsFolder){
                $packages = (Get-ChildItem -Path $LabConfig.ServerMSUsFolder -Recurse -Include '*.msu' -ErrorAction SilentlyContinue | Sort-Object -Property Length).FullName
            }
        }elseif($WindowsInstallationType -eq "Server Core"){
            WriteInfoHighlighted "Server Core detected, MSU folder not specified. Skipping MSU prompt"
        }else{
            #ask for MSU patches
            WriteInfoHighlighted "Please select Windows Server Updates (*.msu). Click Cancel if you don't want any."
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $msupackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Multiselect = $true;
                Title="Please select Windows Server Updates (*.msu). Click Cancel if you don't want any."
            }
            $msupackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
            If($msupackages.ShowDialog() -eq "OK"){
                WriteInfoHighlighted  "Following patches selected:"
                WriteInfo "`t $($msupackages.filenames)"
            }
            $files=@()
            foreach ($Filename in $msupackages.filenames){$files+=Get-ChildItem -Path $filename}
            #sort by size (to apply Servicing Stack Update first)
            $packages=($files |Sort-Object -Property Length).Fullname
        }

#endregion

#region Generate VHD Config
    $ServerVHDs=@()

    if ($BuildNumber -eq 14393){
        #Windows Server 2016
        $ServerVHDs += @{
            Edition="4" 
            VHDName="Win2016_G2.vhdx"
            Size=60GB
        }
        $ServerVHDs += @{
            Edition="3" 
            VHDName="Win2016Core_G2.vhdx"
            Size=30GB
        }
        <# Removed since it does not work with newer than 14393.2724
        $ServerVHDs += @{
            Edition="DataCenterNano"
            VHDName="Win2016NanoHV_G2.vhdx"
            NanoPackages="Microsoft-NanoServer-DSC-Package","Microsoft-NanoServer-FailoverCluster-Package","Microsoft-NanoServer-Guest-Package","Microsoft-NanoServer-Storage-Package","Microsoft-NanoServer-SCVMM-Package","Microsoft-NanoServer-Compute-Package","Microsoft-NanoServer-SCVMM-Compute-Package","Microsoft-NanoServer-SecureStartup-Package","Microsoft-NanoServer-DCB-Package","Microsoft-NanoServer-ShieldedVM-Package"
            Size=30GB
        }
        #>
    }elseif ($BuildNumber -eq 17763){
        #Windows Server 2019
        $ServerVHDs += @{
            Edition="4" 
            VHDName="Win2019_G2.vhdx"
            Size=60GB
        }
        $ServerVHDs += @{
            Edition="3" 
            VHDName="Win2019Core_G2.vhdx"
            Size=30GB
        }
    }elseif ($BuildNumber -ge 17744 -and $SAC){
        $ServerVHDs += @{
            Edition="2" 
            VHDName="WinSrvInsiderCore_$BuildNumber.vhdx"
            Size=30GB
        }
        #DCEdition fix
        if ($LabConfig.DCEdition -gt 2){
            $LabConfig.DCEdition=2
        }
    }elseif ($BuildNumber -ge 17744){
        #Windows Sever Insider
        $ServerVHDs += @{
            Edition="4" 
            VHDName="WinSrvInsider_$BuildNumber.vhdx"
            Size=60GB
        }
        $ServerVHDs += @{
            Edition="3" 
            VHDName="WinSrvInsiderCore_$BuildNumber.vhdx"
            Size=30GB
        }
    }else{
        $ISOServer | Dismount-DiskImage
        WriteErrorAndExit "Plese provide Windows Server 2016, 2019 or Insider greater or equal to build 17744"
    }

    #Test if Tools.vhdx already exists
        if ($ParentDisksNames -contains "tools.vhdx"){
            WriteSuccess "`t Tools.vhdx already exists. Creation will be skipped"
        }else{
            WriteInfo "`t Tools.vhdx not found, will be created"
        }

    #check if DC exists
        if (Get-ChildItem -Path "$PSScriptRoot\LAB\DC\" -Recurse -ErrorAction SilentlyContinue){
            $DCFilesExists=$true
            WriteInfoHighlighted "Files found in $PSScriptRoot\LAB\DC\. DC Creation will be skipped"
        }else{
            $DCFilesExists=$false
        }

#endregion

#region Create parent disks
    #create some folders
        'ParentDisks','Temp','Temp\mountdir' | ForEach-Object {
            if (!( Test-Path "$PSScriptRoot\$_" )) {
                WriteInfoHighlighted "Creating Directory $_"
                New-Item -Type Directory -Path "$PSScriptRoot\$_" 
            }
        }

    #load Convert-WindowsImage to memory
        . "$PSScriptRoot\Temp\Convert-WindowsImage.ps1"

      #Create Servers Parent VHDs
        WriteInfoHighlighted "Creating Server Parent disk(s)"
        foreach ($ServerVHD in $ServerVHDs){
            if ($serverVHD.Edition -notlike "*nano"){
                if (!(Test-Path "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)")){
                    WriteInfo "`t Creating Server Parent $($ServerVHD.VHDName)"

                    #exit if server wim not found
                    If (!(Test-Path -Path "$($ServerMediaDriveLetter):\sources\install.wim")){
                        WriteInfo "`t Dismounting ISO Images"
                            if ($ISOServer -ne $Null){
                                $ISOServer | Dismount-DiskImage
                            }
                            if ($ISOClient -ne $Null){
                                $ISOClient | Dismount-DiskImage
                            }
                        WriteErrorAndExit "$($ServerMediaDriveLetter):\sources\install.wim not found. Can you try different Server media?"
                    }

                    if ($packages){
                        Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package $packages
                    }else{
                        Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI
                    }
                }else{
                    WriteSuccess "`t Server Parent $($ServerVHD.VHDName) found, skipping creation"
                }
            }
            if ($serverVHD.Edition -like "*nano"){
                if (!(Test-Path "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)")){
                    #grab Nano packages
                        $NanoPackages=@()
                        foreach ($NanoPackage in $serverVHD.NanoPackages){
                            $NanoPackages+=(Get-ChildItem -Path "$($ServerMediaDriveLetter):\NanoServer\" -Recurse | Where-Object Name -like $NanoPackage*).FullName
                        }
                    #create parent disks
                        WriteInfo "`t Creating Server Parent $($ServerVHD.VHDName)"
                        if ($packages){
                            Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\NanoServer\NanoServer.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package ($NanoPackages+$packages)
                        }else{
                            Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\NanoServer\NanoServer.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package $NanoPackages
                        }
                }else{
                    WriteSuccess "`t Server Parent $($ServerVHD.VHDName) found, skipping creation"
                }
            }
        }

    #create Tools VHDX from .\Temp\ToolsVHD
        if (!(Test-Path "$PSScriptRoot\ParentDisks\tools.vhdx")){
            WriteInfoHighlighted "Creating Tools.vhdx"
            $toolsVHD=New-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx" -SizeBytes 30GB -Dynamic
            #mount and format VHD
                $VHDMount = Mount-VHD $toolsVHD.Path -Passthru
                $vhddisk = $VHDMount| get-disk 
                $vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |Format-Volume -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel ToolsDisk 

            $VHDPathTest=Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\"
            if (!$VHDPathTest){
                New-Item -Type Directory -Path "$PSScriptRoot\Temp\ToolsVHD"
            }
            if ($VHDPathTest){
                WriteInfo "Found $PSScriptRoot\Temp\ToolsVHD\*, copying files into VHDX"
                Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\*" -Destination "$($vhddiskpart.DriveLetter):\" -Recurse -Force
            }else{
                WriteInfo "Files not found" 
                WriteInfoHighlighted "Add required tools into $PSScriptRoot\Temp\ToolsVHD and Press any key to continue..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
                Copy-Item -Path "$PSScriptRoot\Temp\ToolsVHD\*" -Destination ($vhddiskpart.DriveLetter+':\') -Recurse -Force
            }

            Dismount-VHD $vhddisk.Number
        }else{
            WriteSuccess "`t Tools.vhdx found in Parent Disks, skipping creation"
            $toolsVHD=Get-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx"
        }
#endregion

#region Hydrate DC
    if (-not $DCFilesExists){
        WriteInfoHighlighted "Starting DC Hydration"

        $vhdpath="$PSScriptRoot\LAB\$DCName\Virtual Hard Disks\$DCName.vhdx"
        $VMPath="$PSScriptRoot\LAB\"

        #reuse VHD if already created
            $DCVHDName=($ServerVHDs | Where-Object Edition -eq $LabConfig.DCEdition).VHDName
            if ((($DCVHDName) -ne $null) -and (Test-Path -Path "$PSScriptRoot\ParentDisks\$DCVHDName")){
                WriteSuccess "`t $DCVHDName found, reusing, and copying to $vhdpath"
                New-Item -Path "$VMPath\$DCName" -Name "Virtual Hard Disks" -ItemType Directory
                Copy-Item -Path "$PSScriptRoot\ParentDisks\$DCVHDName" -Destination $vhdpath
            }else{
                #Create Parent VHD
                WriteInfoHighlighted "`t Creating VHD for DC"
                if ($packages){
                    Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $LabConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI -package $packages
                }else{
                    Convert-WindowsImage -SourcePath "$($ServerMediaDriveLetter):\sources\install.wim" -Edition $LabConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI
                }
            }

        #If the switch does not already exist, then create a switch with the name $SwitchName
            if (-not [bool](Get-VMSwitch -Name $Switchname -ErrorAction SilentlyContinue)) {
                WriteInfoHighlighted "`t Creating temp hydration switch $Switchname"
                New-VMSwitch -SwitchType Private -Name $Switchname
            }

        #create VM DC
            WriteInfoHighlighted "`t Creating DC VM"
            if ($LabConfig.DCVMVersion){
                $DC=New-VM -Name $DCName -VHDPath $vhdpath -MemoryStartupBytes 2GB -path $vmpath -SwitchName $Switchname -Generation 2 -Version $LabConfig.DCVMVersion
            }else{
                $DC=New-VM -Name $DCName -VHDPath $vhdpath -MemoryStartupBytes 2GB -path $vmpath -SwitchName $Switchname -Generation 2
            }
            $DC | Set-VMProcessor -Count 2
            $DC | Set-VMMemory -DynamicMemoryEnabled $true -MinimumBytes 2GB
            if ($LabConfig.Secureboot -eq $False) {$DC | Set-VMFirmware -EnableSecureBoot Off}
            if ($DC.AutomaticCheckpointsEnabled -eq $True){
                $DC | Set-VM -AutomaticCheckpointsEnabled $False
            }

        #Apply Unattend to VM
            WriteInfoHighlighted "`t Applying Unattend and copying Powershell DSC Modules"
            if (Test-Path "$PSScriptRoot\Temp\mountdir"){
                Remove-Item -Path "$PSScriptRoot\Temp\mountdir\" -Recurse -Force
            }
            if (Test-Path "$PSScriptRoot\Temp\unattend"){
                Remove-Item -Path "$PSScriptRoot\Temp\unattend.xml"
            }
            $unattendfile=CreateUnattendFileVHD -Computername $DCName -AdminPassword $AdminPassword -path "$PSScriptRoot\temp\" -TimeZone $TimeZone
            New-item -type directory -Path $PSScriptRoot\Temp\mountdir -force
            Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
            Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
            #&"$PSScriptRoot\Temp\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\mountdir
            #&"$PSScriptRoot\Temp\dism\dism" /image:$PSScriptRoot\Temp\mountdir /Apply-Unattend:$unattendfile
            New-item -type directory -Path "$PSScriptRoot\Temp\mountdir\Windows\Panther" -force
            Copy-Item -Path $unattendfile -Destination "$PSScriptRoot\Temp\mountdir\Windows\Panther\unattend.xml" -force
            Copy-Item -Path "$PSScriptRoot\Temp\DSC\*" -Destination "$PSScriptRoot\Temp\mountdir\Program Files\WindowsPowerShell\Modules\" -Recurse -force

        #Create credentials for DSC

            $username = "$($LabConfig.DomainNetbiosName)\Administrator"
            $password = $AdminPassword
            $secstr = New-Object -TypeName System.Security.SecureString
            $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

        #Create DSC configuration
            configuration DCHydration
            {
                param 
                ( 
                    [Parameter(Mandatory)] 
                    [pscredential]$safemodeAdministratorCred, 
            
                    [Parameter(Mandatory)] 
                    [pscredential]$domainCred,

                    [Parameter(Mandatory)]
                    [pscredential]$NewADUserCred

                )

                Import-DscResource -ModuleName xActiveDirectory -ModuleVersion "3.0.0.0"
                Import-DscResource -ModuleName xDNSServer -ModuleVersion "1.15.0.0"
                Import-DSCResource -ModuleName NetworkingDSC -ModuleVersion "7.4.0.0"
                Import-DSCResource -ModuleName xDHCPServer -ModuleVersion "2.0.0.0"
                Import-DSCResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion "8.10.0.0"
                Import-DscResource -ModuleName PSDesiredStateConfiguration

                Node $AllNodes.Where{$_.Role -eq "Parent DC"}.Nodename 

                {
                    WindowsFeature ADDSInstall 
                    { 
                        Ensure = "Present" 
                        Name = "AD-Domain-Services"
                    }

                    WindowsFeature FeatureGPMC
                    {
                        Ensure = "Present"
                        Name = "GPMC"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    }

                    WindowsFeature FeatureADPowerShell
                    {
                        Ensure = "Present"
                        Name = "RSAT-AD-PowerShell"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 

                    WindowsFeature FeatureADAdminCenter
                    {
                        Ensure = "Present"
                        Name = "RSAT-AD-AdminCenter"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 

                    WindowsFeature FeatureADDSTools
                    {
                        Ensure = "Present"
                        Name = "RSAT-ADDS-Tools"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 

                    WindowsFeature FeatureDNSTools
                    {
                        Ensure = "Present"
                        Name = "RSAT-DNS-Server"
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    } 
            
                    xADDomain FirstDS 
                    { 
                        DomainName = $Node.DomainName 
                        DomainAdministratorCredential = $domainCred 
                        SafemodeAdministratorPassword = $safemodeAdministratorCred
                        DomainNetbiosName = $node.DomainNetbiosName
                        DependsOn = "[WindowsFeature]ADDSInstall"
                    }
                
                    xWaitForADDomain DscForestWait 
                    { 
                        DomainName = $Node.DomainName 
                        DomainUserCredential = $domainCred 
                        RetryCount = $Node.RetryCount 
                        RetryIntervalSec = $Node.RetryIntervalSec 
                        DependsOn = "[xADDomain]FirstDS" 
                    }
                    
                    xADOrganizationalUnit DefaultOU
                    {
                        Name = $Node.DefaultOUName
                        Path = $Node.DomainDN
                        ProtectedFromAccidentalDeletion = $true
                        Description = 'Default OU for all user and computer accounts'
                        Ensure = 'Present'
                        DependsOn = "[xADDomain]FirstDS" 
                    }

                    xADUser SQL_SA
                    {
                        DomainName = $Node.DomainName
                        DomainAdministratorCredential = $domainCred
                        UserName = "SQL_SA"
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[xADOrganizationalUnit]DefaultOU"
                        Description = "SQL Service Account"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    xADUser SQL_Agent
                    {
                        DomainName = $Node.DomainName
                        DomainAdministratorCredential = $domainCred
                        UserName = "SQL_Agent"
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[xADOrganizationalUnit]DefaultOU"
                        Description = "SQL Agent Account"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    xADUser Domain_Admin
                    {
                        DomainName = $Node.DomainName
                        DomainAdministratorCredential = $domainCred
                        UserName = $Node.DomainAdminName
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[xADOrganizationalUnit]DefaultOU"
                        Description = "DomainAdmin"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    xADUser VMM_SA
                    {
                        DomainName = $Node.DomainName
                        DomainAdministratorCredential = $domainCred
                        UserName = "VMM_SA"
                        Password = $NewADUserCred
                        Ensure = "Present"
                        DependsOn = "[xADUser]Domain_Admin"
                        Description = "VMM Service Account"
                        Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                        PasswordNeverExpires = $true
                    }

                    xADGroup DomainAdmins
                    {
                        GroupName = "Domain Admins"
                        DependsOn = "[xADUser]VMM_SA"
                        MembersToInclude = "VMM_SA",$Node.DomainAdminName
                    }

                    xADGroup SchemaAdmins
                    {
                        GroupName = "Schema Admins"
                        GroupScope = "Universal"
                        DependsOn = "[xADUser]VMM_SA"
                        MembersToInclude = $Node.DomainAdminName
                    }

                    xADGroup EntAdmins
                    {
                        GroupName = "Enterprise Admins"
                        GroupScope = "Universal"
                        DependsOn = "[xADUser]VMM_SA"
                        MembersToInclude = $Node.DomainAdminName
                    }

                    xADUser AdministratorNeverExpires
                    {
                        DomainName = $Node.DomainName
                        UserName = "Administrator"
                        Ensure = "Present"
                        DependsOn = "[xADDomain]FirstDS"
                        PasswordNeverExpires = $true
                    }

                    IPaddress IP
                    {
                        IPAddress = ($DHCPscope+"1/24")
                        AddressFamily = 'IPv4'
                        InterfaceAlias = 'Ethernet'
                    }
                    WindowsFeature DHCPServer
                    {
                        Ensure = "Present"
                        Name = "DHCP"
                        DependsOn = "[xADDomain]FirstDS"
                    }

                    Service DHCPServer #since insider 17035 dhcpserver was not starting for some reason
                    {
                        Name = "DHCPServer"
                        State = "Running"
                        DependsOn =  "[WindowsFeature]DHCPServer"
                    }

                    WindowsFeature DHCPServerManagement
                    {
                        Ensure = "Present"
                        Name = "RSAT-DHCP"
                        DependsOn = "[WindowsFeature]DHCPServer"
                    } 


                    xDhcpServerScope ManagementScope
                    {
                        Ensure = 'Present'
                        ScopeId = ($DHCPscope+"0")
                        IPStartRange = ($DHCPscope+"10")
                        IPEndRange = ($DHCPscope+"254")
                        Name = 'ManagementScope'
                        SubnetMask = '255.255.255.0'
                        LeaseDuration = '00:08:00'
                        State = 'Active'
                        AddressFamily = 'IPv4'
                        DependsOn = "[Service]DHCPServer"
                    }

                    xDhcpServerOption MgmtScopeRouterOption
                    {
                        Ensure = 'Present'
                        ScopeID = ($DHCPscope+"0")
                        DnsDomain = $Node.DomainName
                        DnsServerIPAddress = ($DHCPscope+"1")
                        AddressFamily = 'IPv4'
                        Router = ($DHCPscope+"1")
                        DependsOn = "[Service]DHCPServer"
                    }
                    
                    xDhcpServerAuthorization LocalServerActivation
                    {
                        Ensure = 'Present'
                    }

                    WindowsFeature DSCServiceFeature
                    {
                        Ensure = "Present"
                        Name   = "DSC-Service"
                    }

                    xDnsServerADZone addReverseADZone
                    {
                        Name = $ReverseDNSrecord
                        DynamicUpdate = "Secure"
                        ReplicationScope = "Forest"
                        Ensure = "Present"
                        DependsOn = "[xDhcpServerOption]MgmtScopeRouterOption"
                    }

                    If ($LabConfig.PullServerDC){
                        xDscWebService PSDSCPullServer
                        {
                            UseSecurityBestPractices = $false
                            Ensure                  = "Present"
                            EndpointName            = "PSDSCPullServer"
                            Port                    = 8080
                            PhysicalPath            = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
                            CertificateThumbPrint   = "AllowUnencryptedTraffic"
                            ModulePath              = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                            ConfigurationPath       = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                            State                   = "Started"
                            DependsOn               = "[WindowsFeature]DSCServiceFeature"
                        }
                        
                        File RegistrationKeyFile
                        {
                            Ensure = 'Present'
                            Type   = 'File'
                            DestinationPath = "$env:ProgramFiles\WindowsPowerShell\DscService\RegistrationKeys.txt"
                            Contents        = $Node.RegistrationKey
                        }
                    }
                }
            }

            $ConfigData = @{ 
            
                AllNodes = @( 
                    @{ 
                        Nodename = $DCName 
                        Role = "Parent DC" 
                        DomainAdminName=$LabConfig.DomainAdminName
                        DomainName = $LabConfig.DomainName
                        DomainNetbiosName = $LabConfig.DomainNetbiosName
                        DomainDN = $LabConfig.DN
                        DefaultOUName=$LabConfig.DefaultOUName
                        RegistrationKey='14fc8e72-5036-4e79-9f89-5382160053aa'
                        PSDscAllowPlainTextPassword = $true
                        PsDscAllowDomainUser= $true        
                        RetryCount = 50  
                        RetryIntervalSec = 30  
                    }         
                ) 
            } 

        #create LCM config
            [DSCLocalConfigurationManager()]          
            configuration LCMConfig
            {
                Node DC
                {
                    Settings
                    {
                        RebootNodeIfNeeded = $true
                        ActionAfterReboot = 'ContinueConfiguration'    
                    }
                }
            }

        #create DSC MOF files
            WriteInfoHighlighted "`t Creating DSC Configs for DC"
            LCMConfig       -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData
            DCHydration     -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData -safemodeAdministratorCred $cred -domainCred $cred -NewADUserCred $cred
        
        #copy DSC MOF files to DC
            WriteInfoHighlighted "`t Copying DSC configurations (pending.mof and metaconfig.mof)"
            New-item -type directory -Path "$PSScriptRoot\Temp\config" -ErrorAction Ignore
            Copy-Item -path "$PSScriptRoot\Temp\config\dc.mof"      -Destination "$PSScriptRoot\Temp\mountdir\Windows\system32\Configuration\pending.mof"
            Copy-Item -Path "$PSScriptRoot\Temp\config\dc.meta.mof" -Destination "$PSScriptRoot\Temp\mountdir\Windows\system32\Configuration\metaconfig.mof"

        #close VHD and apply changes
            WriteInfoHighlighted "`t Applying changes to VHD"
            Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
            #&"$PSScriptRoot\Temp\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\mountdir /Commit

        #Start DC VM and wait for configuration
            WriteInfoHighlighted "`t Starting DC"
            $DC | Start-VM

            $VMStartupTime = 250 
            WriteInfoHighlighted "`t Configuring DC using DSC takes a while."
            WriteInfo "`t `t Initial configuration in progress. Sleeping $VMStartupTime seconds"
            Start-Sleep $VMStartupTime
            $i=1
            do{
                $test=Invoke-Command -VMGuid $DC.id -ScriptBlock {Get-DscConfigurationStatus} -Credential $cred -ErrorAction SilentlyContinue
                if ($test -eq $null) {
                    WriteInfo "`t `t Configuration in Progress. Sleeping 10 seconds"
                    Start-Sleep 10
                }elseif ($test.status -ne "Success" -and $i -eq 1) {
                    WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                    WriteInfoHighlighted "`t `t Invoking DSC Configuration again" 
                    Invoke-Command -VMGuid $DC.id -ScriptBlock {Start-DscConfiguration -UseExisting} -Credential $cred
                    $i++
                }elseif ($test.status -ne "Success" -and $i -gt 1) {
                    WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                    WriteInfoHighlighted "`t `t Restarting DC"
                    Invoke-Command -VMGuid $DC.id -ScriptBlock {Restart-Computer} -Credential $cred
                }elseif ($test.status -eq "Success" ) {
                    WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                    WriteInfoHighlighted "`t `t DSC Configured DC Successfully" 
                }
            }until ($test.Status -eq 'Success' -and $test.rebootrequested -eq $false)
            $test

        #configure default OU where new Machines will be created using redircmp and add reverse lookup zone (as setting reverse lookup does not work with DSC)
            Invoke-Command -VMGuid $DC.id -Credential $cred -ErrorAction SilentlyContinue -ArgumentList $LabConfig -ScriptBlock {
                Param($LabConfig);
                redircmp "OU=$($LabConfig.DefaultOUName),$($LabConfig.DN)"
                Add-DnsServerPrimaryZone -NetworkID ($DHCPscope+"/24") -ReplicationScope "Forest"
            } 
        #install SCVMM or its prereqs if specified so
            if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
                $DC | Add-VMHardDiskDrive -Path $toolsVHD.Path
            }

            if ($LabConfig.InstallSCVMM -eq "Yes"){
                WriteInfoHighlighted "Installing System Center Virtual Machine Manager and its prerequisites"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\1_SQL_Install.ps1
                    d:\scvmm\2_ADK_Install.ps1  
                    Restart-Computer    
                }
                Start-Sleep 10

                WriteInfoHighlighted "$($DC.name) was restarted, waiting for Active Directory on $($DC.name) to be started."
                do{
                $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $LabConfig -ErrorAction SilentlyContinue -ScriptBlock {
                    param($LabConfig);
                    Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue}
                    Start-Sleep 5
                }
                until ($test -ne $Null)
                WriteSuccess "Active Directory on $($DC.name) is up."

                Start-Sleep 30 #Wait as sometimes VMM failed to install without this.
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\3_SCVMM_Install.ps1    
                }
            }

            if ($LabConfig.InstallSCVMM -eq "SQL"){
                WriteInfoHighlighted "Installing SQL"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\1_SQL_Install.ps1  
                }
            }

            if ($LabConfig.InstallSCVMM -eq "ADK"){
                WriteInfoHighlighted "Installing ADK"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\2_ADK_Install.ps1
                }
            }

            if ($LabConfig.InstallSCVMM -eq "Prereqs"){
                WriteInfoHighlighted "Installing System Center VMM Prereqs"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                    d:\scvmm\1_SQL_Install.ps1
                    d:\scvmm\2_ADK_Install.ps1
                }
            }

            if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
                $DC | Get-VMHardDiskDrive | Where-Object path -eq $toolsVHD.Path | Remove-VMHardDiskDrive
            }
    }
#endregion

#region backup DC and cleanup
    #cleanup DC
    if (-not $DCFilesExists){
        WriteInfoHighlighted "Backup DC and cleanup"
        #shutdown DC 
            WriteInfo "`t Disconnecting VMNetwork Adapter from DC"
            $DC | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter
            WriteInfo "`t Shutting down DC"
            $DC | Stop-VM
            $DC | Set-VM -MemoryMinimumBytes 512MB

        #Backup DC config, remove from Hyper-V, return DC config
            WriteInfo "`t Creating backup of DC VM configuration"
            Copy-Item -Path "$vmpath\$DCName\Virtual Machines\" -Destination "$vmpath\$DCName\Virtual Machines_Bak\" -Recurse
            WriteInfo "`t Removing DC"
            $DC | Remove-VM -Force
            WriteInfo "`t Returning VM config and adding to Virtual Machines.zip"
            Remove-Item -Path "$vmpath\$DCName\Virtual Machines\" -Recurse
            Rename-Item -Path "$vmpath\$DCName\Virtual Machines_Bak\" -NewName 'Virtual Machines'
            Compress-Archive -Path "$vmpath\$DCName\Virtual Machines\" -DestinationPath "$vmpath\$DCName\Virtual Machines.zip"
        #cleanup vswitch
            WriteInfo "`t Removing switch $Switchname"
            Remove-VMSwitch -Name $Switchname -Force -ErrorAction SilentlyContinue
    }

    #Cleanup The rest
        WriteInfo "`t Dismounting ISO Images"
        if ($ISOServer -ne $Null){
            $ISOServer | Dismount-DiskImage
        }

#endregion

#region finishing
    WriteSuccess "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    WriteInfoHighlighted "Do you want to cleanup unnecessary files and folders?"
    WriteInfo "`t (.\Temp\ 1_Prereq.ps1 2_CreateParentDisks.ps1 and rename 3_deploy to just deploy)"
    If ((Read-host "`t Please type Y or N") -like "*Y"){
        WriteInfo "`t `t Cleaning unnecessary items"
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse 
        "$PSScriptRoot\Temp","$PSScriptRoot\1_Prereq.ps1","$PSScriptRoot\2_CreateParentDisks.ps1" | ForEach-Object {
            WriteInfo "`t `t `t Removing $_"
            Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
        } 
        WriteInfo "`t `t `t Renaming $PSScriptRoot\3_Deploy.ps1 to Deploy.ps1"
        Rename-Item -Path "$PSScriptRoot\3_Deploy.ps1" -NewName "Deploy.ps1" -ErrorAction SilentlyContinue
    }else{
        WriteInfo "`t You did not type Y, skipping cleanup"
    }

    Stop-Transcript
    WriteSuccess "Job Done. Press enter to continue..."
    Read-Host | Out-Null

#endregion