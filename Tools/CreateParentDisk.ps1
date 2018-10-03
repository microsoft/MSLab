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
        $ISO = Mount-DiskImage -ImagePath $openFile.FileName -PassThru

        $ISOMediaPath = (Get-Volume -DiskImage $ISO).DriveLetter+':'

    #endregion

    #region ask for MSU packages
        WriteInfoHighlighted "Please select msu packages you want to add to image. Click cancel if you don't want any."
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $msupackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Multiselect = $true;
            Title="Please select msu packages you want to add to image. Click cancel if you don't want any."
        }
        $msupackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
        If($msupackages.ShowDialog() -eq "OK"){
            WriteInfoHighlighted  "Following patches selected:"
            foreach ($filename in $msupackages.FileNames){
                WriteInfo "`t $filename"
            }
        }

        #Write info if nothing is selected
        if (!$msupackages.FileNames){
            WriteInfoHighlighted "No msu was selected..."
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
        $BuildNumber=(Get-ItemProperty -Path "$ISOMediaPath\setup.exe").versioninfo.FileBuildPart

        if ($BuildNumber -eq 14393){
            $NanoServer=(Read-Host -Prompt "Server 2016 ISO Selected. Do you want to build NanoServer? Y/N")
        }

        if ($Nanoserver -eq "Y"){
            $WindowsImage=Get-WindowsImage -ImagePath "$ISOMediaPath\NanoServer\NanoServer.wim"
            
            #ask for edition
            $Edition=($WindowsImage | Out-GridView -OutputMode Single).ImageName

            #ask for cab files
                WriteInfoHighlighted "Please select cab packages you want to add to image. Click cancel if you want default."
                $nanocabs=(Get-ChildItem -Path "$ISOMediaPath\NanoServer\Packages" -filter *.cab| select BaseName) | Out-GridView -OutputMode Multiple
                if (!$nanocabs){
                    $nanocabs="Microsoft-NanoServer-DSC-Package","Microsoft-NanoServer-FailoverCluster-Package","Microsoft-NanoServer-Guest-Package","Microsoft-NanoServer-Storage-Package","Microsoft-NanoServer-SCVMM-Package","Microsoft-NanoServer-Compute-Package","Microsoft-NanoServer-SCVMM-Compute-Package","Microsoft-NanoServer-SecureStartup-Package","Microsoft-NanoServer-DCB-Package","Microsoft-NanoServer-ShieldedVM-Package"
                }
           #grab Nano packages
                $NanoPackages=@()
                foreach ($NanoPackage in $nanocabs){
                    $NanoPackages+=(Get-ChildItem -Path "$ISOMediaPath\NanoServer\Packages" -Recurse | Where-Object Name -like $NanoPackage*).FullName
                }
                WriteInfoHighlighted  "Following patches selected:"
                $NanoPackages
           #create temp name
           $tempvhdname="Win2016NanoHV_G2.vhdx"
    
        }else{
            $WindowsImage=Get-WindowsImage -ImagePath "$ISOMediaPath\sources\install.wim"
            if ($BuildNumber -lt 7600){
                if ($ISO -ne $Null){
                    $ISO | Dismount-DiskImage
                }
                WriteErrorAndExit "`t Use Windows 7 or newer!"
            }
            #ask for edition
            $Edition=($WindowsImage | Out-GridView -OutputMode Single).ImageName

            #Generate vhdx name
            if ($Edition -like "*Server*Core*"){
                $tempvhdname = switch ($BuildNumber){
                    7600 {
                        "Win2008R2Core_G1.vhdx"
                    }
                    7601 {
                        "Win2008R2SP1Core_G1.vhdx"
                    }
                    9200 {
                        "Win2012Core_G2.vhdx"
                    }
                    9600 {
                        "Win2012R2Core_G2.vhdx"
                    }
                    14393 {
                        "Win2016Core_G2.vhdx"
                    }
                    14393 {
                        "Win2016Core_G2.vhdx"
                    }
                    16299 {
                        "WinServer1709_G2.vhdx"
                    }
                    17134 {
                        "WinServer1803_G2.vhdx"
                    }
                    17763 {
                        "Win2019Core_G2.vhdx"
                    }
                }
                if ($BuildNumber -GT 17763 -or $BuildNumber -eq 17744){
                    $tempvhdname="Win2019Core_$BuildNumber.vhdx"
                }
            }elseif($Edition -like "*Server*"){
                $tempvhdname = switch ($BuildNumber){
                    7600 {
                        "Win2008R2_G1.vhdx"
                    }
                    7601 {
                        "Win2008R2SP1_G1.vhdx"
                    }
                    9200 {
                        "Win2012_G2.vhdx"
                    }
                    9600 {
                        "Win2012R2_G2.vhdx"
                    }
                    14393 {
                        "Win2016_G2.vhdx"
                    }
                    17763 {
                        "Win2019_G2.vhdx"
                    }
                }
                if ($BuildNumber -GT 17763 -or $BuildNumber -eq 17744){
                    $tempvhdname="Win2019_$BuildNumber.vhdx"
                }
            }else{
                $tempvhdname = switch ($BuildNumber){
                    7600 {
                        "Win7_G1.vhdx"
                    }
                    7601 {
                        "Win7SP1_G1.vhdx"
                    }
                    9200 {
                        "Win8_G2.vhdx"
                    }
                    9600 {
                        "Win8.1_G2.vhdx"
                    }
                    10240 {
                        "Win10TH1_G2.vhdx"
                    }
                    10586 {
                        "Win10TH2_G2.vhdx"
                    }
                    14393 {
                        "Win10RS1_G2.vhdx"
                    }
                    14393 {
                        "Win10RS1_G2.vhdx"
                    }
                    15064 {
                        "Win10RS2_G2.vhdx"
                    }
                    16299 {
                        "Win10RS3_G2.vhdx"
                    }
                    17134 {
                        "Win10RS4_G2.vhdx"
                    }
                    17763 {
                        "Win10RS5_G2.vhdx"
                    }
                }
                if ($BuildNumber -GT 17763 -or $BuildNumber -eq 17744){
                    $tempvhdname="Win10Insider_$BuildNumber.vhdx"
                }
            }
        }

        #ask for imagename
        $vhdname=(Read-Host -Prompt "Please type VHD name (if nothing specified, $tempvhdname is used")
        if(!$vhdname){$vhdname=$tempvhdname}
        
        #ask for size
        [int64]$size=(Read-Host -Prompt "Please type size of the Image in GB. If nothing specified, 60 is used")
        $size=$size*1GB
        if (!$size){$size=60GB}
        
        #Create VHD
        if ($nanoserver -eq "y"){
             Convert-WindowsImage -SourcePath "$ISOMediaPath\NanoServer\NanoServer.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI -Package ($msupackages.FileNames+$NanoPackages)
        }else{
            if ($msupackages.FileNames -ne $null){
                if ($BuildNumber -le 7601){
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout BIOS -Package $msupackages.FileNames
                }else{
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI -Package $msupackages.FileNames
                }
            }else{
                if ($BuildNumber -le 7601){
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout BIOS
                }else{
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$PSScriptRoot\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI
                }
            }
        }

        WriteInfo "Dismounting ISO Image"
        if ($ISO -ne $Null){
        $ISO | Dismount-DiskImage
        }
        
        WriteSuccess "Job Done. Press enter to continue..."
        $exit=Read-Host
    #endregion