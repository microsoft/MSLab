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
. $PSScriptRoot\0_Shared.ps1 # [!build-include-inline]
. $PSScriptRoot\0_DCHydrate.ps1 # [!build-include-inline]

#endregion

#region Initialization
    #Start Log
        Start-Transcript -Path "$PSScriptRoot\CreateParentDisks.log"
        $StartDateTime = Get-Date
        WriteInfo "Script started at $StartDateTime"
        WriteInfo "`nMSLab Version $mslabVersion"

    #Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

    # Telemetry
        if(-not (Get-TelemetryLevel)) {
            $telemetryLevel = Read-TelemetryLevel
            $LabConfig.TelemetryLevel = $telemetryLevel
            $LabConfig.TelemetryLevelSource = "Prompt"
            $promptShown = $true
        }

        if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
            if(-not $promptShown) {
                WriteInfo "Telemetry is set to $(Get-TelemetryLevel) level from $(Get-TelemetryLevelSource)"
            }
            Send-TelemetryEvent -Event "CreateParentDisks.Start" -NickName $LabConfig.TelemetryNickName | Out-Null
        }

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
    $TimeZone = (Get-TimeZone).id

    #Grab Installation type
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType

#endregion

#region Check prerequisites

    #Check if not running in root folder
    if (($PSScriptRoot).Length -eq 3) {
        WriteErrorAndExit "`t MSLab canot run in root folder. Please put MSLab scripts into a folder. Exiting"
    }

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

    #check if filesystem on volume is NTFS or ReFS
    WriteInfoHighlighted "Checking if volume filesystem is NTFS or ReFS"
    $driveletter=$PSScriptRoot -split ":" | Select-Object -First 1
    if ($PSScriptRoot -like "c:\ClusterStorage*"){
        WriteSuccess "`t Volume Cluster Shared Volume. Mountdir will be $env:Temp\MSLabMountdir"
        $mountdir="$env:Temp\MSLabMountdir"
        $VolumeFileSystem="CSVFS"
    }else{
        $mountdir="$PSScriptRoot\Temp\MountDir"
        $VolumeFileSystem=(Get-Volume -DriveLetter $driveletter).FileSystemType
        if ($VolumeFileSystem -match "NTFS"){
            WriteSuccess "`t Volume filesystem is $VolumeFileSystem"
        }elseif ($VolumeFileSystem -match "ReFS") {
            WriteSuccess "`t Volume filesystem is $VolumeFileSystem"
        }else {
            WriteErrorAndExit "`t Volume filesystem is $VolumeFileSystem. Must be NTFS or ReFS. Exiting"
        }
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
            WriteInfoHighlighted "Please select ISO image with Windows Server 2016, 2019, 2022, 2025 or Server Insider"
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Title="Please select ISO image with Windows Server 2016, 2019, 2022, 2025 or Server Insider"
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
    #Check ISO Language
        $imageInfo=(Get-WindowsImage -ImagePath "$($ServerMediaDriveLetter):\sources\install.wim" -Index 4)
        $OSLanguage=$imageInfo.Languages | Select-Object -First 1

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
                Title = "Please select Windows Server Updates (*.msu). Click Cancel if you don't want any."
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
            Kind = "Full"
            Edition="4"
            VHDName="Win2016_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2016Core_G2.vhdx"
            Size=127GB
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
            Kind = "Full"
            Edition="4"
            VHDName="Win2019_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2019Core_G2.vhdx"
            Size=127GB
        }
    }elseif ($BuildNumber -eq 20348){
        #Windows Server 2022
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="Win2022_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2022Core_G2.vhdx"
            Size=127GB
        }
    }elseif ($BuildNumber -eq 26100){
        #Windows Server 2025
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="Win2025_G2.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="Win2025Core_G2.vhdx"
            Size=127GB
        }        
    }elseif ($BuildNumber -gt 26100 -and $SAC){
        $ServerVHDs += @{
            Kind = "Core"
            Edition="2"
            VHDName="WinSrvInsiderCore_$BuildNumber.vhdx"
            Size=127GB
        }
        #DCEdition fix
        if ($LabConfig.DCEdition -gt 2){
            $LabConfig.DCEdition=2
        }
    }elseif ($BuildNumber -gt 26100){
        #Windows Sever Insider
        $ServerVHDs += @{
            Kind = "Full"
            Edition="4"
            VHDName="WinSrvInsider_$BuildNumber.vhdx"
            Size=127GB
        }
        $ServerVHDs += @{
            Kind = "Core"
            Edition="3"
            VHDName="WinSrvInsiderCore_$BuildNumber.vhdx"
            Size=127GB
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
        $vhdStatusInfo = @{}
        foreach ($ServerVHD in $ServerVHDs){
            $vhdStatus = @{
                Kind = $ServerVHD.Kind
                Name = $ServerVHD.VHDName
                AlreadyExists = $false
                BuildStartDate = Get-Date
            }
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
                    $vhdStatus.AlreadyExists = $true
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
            $vhdStatus.BuildEndDate = Get-Date

            $vhdStatusInfo[$vhdStatus.Kind] = $vhdStatus
        }

    #create Tools VHDX from .\Temp\ToolsVHD
        $toolsVhdStatus = @{
            Kind = "Tools"
            Name = "tools.vhdx"
            AlreadyExists = $false
            BuildStartDate = Get-Date
        }
        if (!(Test-Path "$PSScriptRoot\ParentDisks\tools.vhdx")){
            WriteInfoHighlighted "Creating Tools.vhdx"
            $toolsVHD=New-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx" -SizeBytes 300GB -Dynamic
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

            $toolsVhdStatus.BuildEndDate = Get-Date
        }else{
            $toolsVhdStatus.AlreadyExists = $true
            WriteSuccess "`t Tools.vhdx found in Parent Disks, skipping creation"
            $toolsVHD = Get-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx"
        }

        $vhdStatusInfo[$toolsVhdStatus.Kind] = $toolsVhdStatus
#endregion

#region Create DC VHD
if (-not $DCFilesExists){
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

    #Get VM Version
    [System.Version]$VMVersion=(Get-WindowsImage -ImagePath $VHDPath -Index 1).Version
    WriteInfo "`t VM Version is $($VMVersion.Build).$($VMVersion.Revision)"
}
#endregion


#region create DC if it does not exist
    if (-not $DCFilesExists) {
        if (-not $LabConfig.NoDehydrateDC){
            Hydrate-DC -DCName $DCName -VhdPath $vhdpath -VmPath $VmPath -SwitchName $Switchname -TimeZone $TimeZone -DhcpScope $LabConfig.DHCPscope -AdminPassword $AdminPassword
            $DC=Get-VM -Name $DCName
            if ($DC -eq $null){
                WriteErrorAndExit "DC was not created successfully Press any key to continue ..."
            } else {
                WriteInfo "`t`t Virtual Machine $($DC.name) located in folder $($DC.Path) hydrated"
            }
        } else {
            WriteInfoHighlighted "Skipping creation of dehydrated Domain Controller"
        }
    }
#endregion

#region backup DC and cleanup
    #cleanup DC
    if (-not $DCFilesExists -and -not $LabConfig.NoDehydrateDC){
        WriteInfoHighlighted "Backup DC and cleanup"
        #shutdown DC 
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

    $options = [System.Management.Automation.Host.ChoiceDescription[]] @(
        <# 0 #> New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Cleanup .\Temp\ 1_Prereq.ps1 2_CreateParentDisks.ps1 and rename 3_deploy.ps1 to just deploy.ps1"
        <# 1 #> New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Keep files (in case DC was not created sucessfully)"
    )
    
    If (!$LabConfig.AutoCleanUp) {
        $response = $host.UI.PromptForChoice("Unnecessary files cleanup","Do you want to cleanup unnecessary files and folders?", $options, 0 <#default option#>)
    }
    else {
        $response = 0
    }

    If ($response -eq 1){
        $renamed = $false
        WriteInfo "Skipping cleanup"
    }else{
        $renamed = $true
        WriteInfo "`t `t Cleaning unnecessary items"
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse
        "$PSScriptRoot\Temp","$PSScriptRoot\1_Prereq.ps1","$PSScriptRoot\2_CreateParentDisks.ps1" | ForEach-Object {
            WriteInfo "`t `t `t Removing $_"
            Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
        } 
        WriteInfo "`t `t `t Renaming $PSScriptRoot\3_Deploy.ps1 to Deploy.ps1"
        Rename-Item -Path "$PSScriptRoot\3_Deploy.ps1" -NewName "Deploy.ps1" -ErrorAction SilentlyContinue
    }

    # Telemetry Event
    if($LabConfig.TelemetryLevel -in $TelemetryEnabledLevels) {
        WriteInfo "Sending telemetry info"
        $metrics = @{
            'script.duration' = ((Get-Date) - $StartDateTime).TotalSeconds
            'msu.count' = ($packages | Measure-Object).Count
        }
        if(-not $DCFilesExists) {
            $metrics['dc.duration'] = ($dcHydrationEndTime - $dcHydrationEndTime).TotalSeconds
        }

        $properties = @{
            'dc.exists' = [int]$DCFilesExists
            'dc.edition' = $LabConfig.DCEdition
            'dc.build' = $BuildNumber
            'dc.language' = $OSLanguage
            'lab.scriptsRenamed' = $renamed
            'lab.installScvmm' = $LabConfig.InstallSCVMM
            'os.windowsInstallationType' = $WindowsInstallationType
        }
        $events = @()

        # First for parent disks
        foreach($key in $vhdStatusInfo.Keys) {
            $status = $vhdStatusInfo[$key]
            $buildDuration = 0
            if(-not $status.AlreadyExists) {
                $buildDuration = ($status.BuildEndDate - $status.BuildStartDate).TotalSeconds
            }
            $key = $key.ToLower()

            $properties["vhd.$($key).exists"] = [int]$status.AlreadyExists
            $properties["vhd.$($key).name"] = $status.Name
            if($buildDuration -gt 0) {
                $metrics["vhd.$($key).duration"] = $buildDuration
            }

            if($status.AlreadyExists) {
               continue # verbose events are interesting only when creating a new vhds
            }

            $vhdMetrics = @{
                'vhd.duration' = $buildDuration
            }
            $vhdProperties = @{
                'vhd.name' = $status.Name
                'vhd.kind' = $status.Kind
            }
            if($status.Kind -ne "Tools") {
                $vhdProperties['vhd.os.build'] = $BuildNumber

                if($LabConfig.TelemetryLevel -eq "Full") {
                    $vhdProperties['vhd.os.language'] = $OSLanguage
                }
            }
            $events += Initialize-TelemetryEvent -Event "CreateParentDisks.Vhd" -Metrics $vhdMetrics -Properties $vhdProperties -NickName $LabConfig.TelemetryNickName
        }

        # and one overall
        $events += Initialize-TelemetryEvent -Event "CreateParentDisks.End" -Metrics $metrics -Properties $properties -NickName $LabConfig.TelemetryNickName

        Send-TelemetryEvents -Events $events | Out-Null
    }

Stop-Transcript

If (!$LabConfig.AutoClosePSWindows) {
    WriteSuccess "Job Done. Press enter to continue..."
    Read-Host | Out-Null
}

#endregion
