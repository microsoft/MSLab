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
        Write-Host "Press any key to continue ..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
        $HOST.UI.RawUI.Flushinputbuffer()
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
            $Path
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

    #create variables if not already in labconfig
        If (!$LabConfig.DomainNetbiosName){
            $LabConfig.DomainNetbiosName="Corp"
        }

        If (!$LabConfig.DomainName){
            $LabConfig.DomainName="Corp.contoso.com"
        }

        If (!$LabConfig.DefaultOUName){
            $LabConfig.DefaultOUName="Workshop"
        }

    #create some variables
        $DN=$null
        $LabConfig.DomainName.Split(".") | ForEach-Object {
            $DN+="DC=$_,"   
        }
        
        $LabConfig.DN=$DN.TrimEnd(",")

        $AdminPassword=$LabConfig.AdminPassword
        $Switchname='DC_HydrationSwitch'
        $DCName='DC'

    #create $serverVHDs variables if not already in $labconfig
        if (!$Labconfig.ServerVHDs){
            $Labconfig.ServerVHDs=@()
            $LABConfig.ServerVHDs += @{
                Edition="DataCenterCore" 
                VHDName="Win2016Core_G2.vhdx"
                Size=30GB
            }
            $LABConfig.ServerVHDs += @{ 
                Edition="DataCenterNano"
                VHDName="Win2016NanoHV_G2.vhdx"
                NanoPackages="Microsoft-NanoServer-DSC-Package","Microsoft-NanoServer-FailoverCluster-Package","Microsoft-NanoServer-Guest-Package","Microsoft-NanoServer-Storage-Package","Microsoft-NanoServer-SCVMM-Package","Microsoft-NanoServer-Compute-Package","Microsoft-NanoServer-SCVMM-Compute-Package","Microsoft-NanoServer-SecureStartup-Package","Microsoft-NanoServer-DCB-Package","Microsoft-NanoServer-ShieldedVM-Package"
                Size=30GB
            }
        }   
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

    #check if VMM prereqs files are present if InstallSCVMM or SCVMM prereq is requested
        if ($LabConfig.InstallSCVMM -eq "Yes"){
            "Tools\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Tools\ToolsVHD\SCVMM\SCVMM\setup.exe","Tools\ToolsVHD\SCVMM\SQL\setup.exe","Tools\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi","Tools\ToolsVHD\SCVMM\dotNET\microsoft-windows-netfx3-ondemand-package.cab" | ForEach-Object {
                if(!(Test-Path -Path "$PSScriptRoot\$_")){
                    WriteErrorAndExit "files $_ needed for SCVMM install not found. Exitting"
                }
            }    
        }

        if ($LabConfig.InstallSCVMM -eq "Prereqs"){
            "Tools\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Tools\ToolsVHD\SCVMM\SQL\setup.exe","Tools\ToolsVHD\SCVMM\ADK\Installers\Windows PE x86 x64-x86_en-us.msi","Tools\ToolsVHD\SCVMM\dotNET\microsoft-windows-netfx3-ondemand-package.cab" | ForEach-Object {
                if(!(Test-Path -Path "$PSScriptRoot\$_")){
                    WriteErrorAndExit "files $_ needed for SCVMM Prereqs install not found. Exitting"
                }
            } 
        }
    
        if ($LabConfig.InstallSCVMM -eq "SQL"){
            "Tools\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Tools\ToolsVHD\SCVMM\SQL\setup.exe","Tools\ToolsVHD\SCVMM\dotNET\microsoft-windows-netfx3-ondemand-package.cab" | ForEach-Object {
                if(!(Test-Path -Path "$PSScriptRoot\$_")){
                    WriteErrorAndExit "files $_ needed for SQL install not found. Exitting"
                }
            }
        }    

        if ($LabConfig.InstallSCVMM -eq "ADK"){
            "Tools\ToolsVHD\SCVMM\ADK\ADKsetup.exe","Tools\ToolsVHD\SCVMM\dotNET\microsoft-windows-netfx3-ondemand-package.cab" | ForEach-Object {
                if(!(Test-Path -Path "$PSScriptRoot\$_")){
                    WriteErrorAndExit "files $_ needed for ADK install not found. Exitting"
                }
            }
        }   

#endregion

#region Ask for ISO images and Cumulative updates
    #Grab Server ISO
        WriteInfoHighlighted "Please select ISO image with Windows Server 2016"
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select ISO image with Windows Server 2016"
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
        #Generate Media Path
        $ServerMediaPath = (Get-Volume -DiskImage $ISOServer).DriveLetter+':'

    #Ask for Client ISO
        If ($LabConfig.CreateClientParent){
            WriteInfoHighlighted "Please select ISO image with Windows 10. Please use 1507 and newer"
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                Title="Please select ISO image with Windows 10. Please use 1507 and newer"
            }
            $openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
            If($openFile.ShowDialog() -eq "OK"){
                WriteInfo  "File $($openfile.FileName) selected"
            } 
            if (!$openFile.FileName){
                WriteErrorAndExit  "Iso was not selected... Exitting"
            }
        #Mount ISO
        $ISOClient = Mount-DiskImage -ImagePath $openFile.FileName -PassThru
        #Generate Media Path		
            $ClientMediaPath = (Get-Volume -DiskImage $ISOClient).DriveLetter+':'
        }

    #Grab packages if not insider
        if (!$labconfig.Insider){
            #grab server packages
                #ask for MSU patches
                WriteInfoHighlighted "Please select latest Server Cumulative Update (.MSU)"
                [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
                $ServerPackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                    Multiselect = $true;
                    Title="Please select latest Windows Server 2016 Cumulative Update"
                }
                $ServerPackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
                If($ServerPackages.ShowDialog() -eq "OK"){
                    WriteInfoHighlighted  "Following patches selected:"
                    WriteInfo "`t $($ServerPackages.filenames)"
                } 

                #exit if nothing is selected
                if (!$ServerPackages.FileNames){
                    WriteErrorAndExit "no msu was selected... Exitting"
                }

                $serverpackages=$serverpackages.FileNames | Sort-Object

            #grab Client packages
            If ($LabConfig.CreateClientParent){
                #ask for MSU patches
                WriteInfoHighlighted "Please select latest Client Cumulative Update (MSU)"
                [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
                $ClientPackages = New-Object System.Windows.Forms.OpenFileDialog -Property @{
                    Multiselect = $true;
                    Title="Please select Windows 10 Cumulative Update"
                }
                $ClientPackages.Filter = "msu files (*.msu)|*.msu|All files (*.*)|*.*" 
                If($ClientPackages.ShowDialog() -eq "OK"){
                    WriteInfoHighlighted  "Following patches selected:"
                    WriteInfo "`t $($ClientPackages.filenames)"
                } 
                #exit if nothing is selected
                if (!$ClientPackages.FileNames){
                    WriteErrorAndExit "no msu was selected... Exitting"
                }
                $clientpackages=$clientpackages.FileNames | Sort-Object    
            }
    }
#endregion

#region Create parent disks
    #create some folders
        'ParentDisks','Temp','Temp\mountdir' | ForEach-Object {
            if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } 
        }

    #load convert-windowsimage to memory
        . "$PSScriptRoot\tools\convert-windowsimage.ps1"

    #Create client OS VHD
        If ($LabConfig.CreateClientParent -eq $true){
            if (!(Test-Path "$PSScriptRoot\ParentDisks\Win10_G2.vhdx")){
                WriteInfoHighlighted "Creating Client Parent"
                if ($ClientPackages){
                    Convert-WindowsImage -SourcePath "$ClientMediaPath\sources\install.wim" -Edition $LabConfig.ClientEdition -VHDPath "$PSScriptRoot\ParentDisks\Win10_G2.vhdx" -SizeBytes 30GB -VHDFormat VHDX -DiskLayout UEFI -package $ClientPackages
                }else{
                    Convert-WindowsImage -SourcePath "$ClientMediaPath\sources\install.wim" -Edition $LabConfig.ClientEdition -VHDPath "$PSScriptRoot\ParentDisks\Win10_G2.vhdx" -SizeBytes 30GB -VHDFormat VHDX -DiskLayout UEFI 
                }
            }else{
                WriteInfoHighlighted "Client Parent found, skipping creation"
            }
        }

    #Create Servers Parent VHDs
        foreach ($ServerVHD in $labconfig.ServerVHDs){
            if ($serverVHD.Edition -notlike "*nano"){
                if (!(Test-Path "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)")){
                    WriteInfoHighlighted "Creating Server Parent $($ServerVHD.VHDName)"
                    if ($serverpackages){     
                        Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package $serverpackages
                    }else{
                        Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI
                    }
                }else{
                    WriteInfoHighlighted "Server Parent $($ServerVHD.VHDName) found, skipping creation"
                }
            }
            if ($serverVHD.Edition -like "*nano"){
                $NanoPackages=@()
                foreach ($NanoPackage in $serverVHD.NanoPackages){
                    $NanoPackages+=(Get-ChildItem -Path "$ServerMediaPath\NanoServer\" -Recurse | Where-Object Name -like $NanoPackage*).FullName
                }
                if (!(Test-Path "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)")){
                    WriteInfoHighlighted "Creating Server Parent $($ServerVHD.VHDName)"
                    if ($serverpackages){
                        Convert-WindowsImage -SourcePath "$ServerMediaPath\NanoServer\NanoServer.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package ($NanoPackages+$serverpackages)
                    }else{
                        Convert-WindowsImage -SourcePath "$ServerMediaPath\NanoServer\NanoServer.wim" -Edition $serverVHD.Edition -VHDPath "$PSScriptRoot\ParentDisks\$($ServerVHD.VHDName)" -SizeBytes $serverVHD.Size -VHDFormat VHDX -DiskLayout UEFI -Package $NanoPackages
                    }
                }else{
                    WriteInfoHighlighted "Server Parent $($ServerVHD.VHDName) found, skipping creation"
                }
            }
        }

    #create Tools VHDX from .\tools\ToolsVHD
        if (!(Test-Path "$PSScriptRoot\ParentDisks\tools.vhdx")){
            WriteInfoHighlighted "Creating Tools.vhdx"
            $toolsVHD=New-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx" -SizeBytes 30GB -Dynamic
            #mount and format VHD
                $VHDMount = Mount-VHD $toolsVHD.Path -Passthru
                $vhddisk = $VHDMount| get-disk 
                $vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |Format-Volume -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel ToolsDisk 

            $VHDPathTest=Test-Path -Path "$PSScriptRoot\Tools\ToolsVHD\"
            if (!$VHDPathTest){
                New-Item -Type Directory -Path "$PSScriptRoot\Tools\ToolsVHD"
            }
            if ($VHDPathTest){
                WriteInfo "Found $PSScriptRoot\Tools\ToolsVHD\*, copying files into VHDX"
                Copy-Item -Path "$PSScriptRoot\Tools\ToolsVHD\*" -Destination "$($vhddiskpart.DriveLetter):\" -Recurse -Force
            }else{
                WriteInfo "Files not found" 
                WriteInfoHighlighted "Add required tools into $PSScriptRoot\Tools\toolsVHD and Press any key to continue..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
                Copy-Item -Path "$PSScriptRoot\Tools\ToolsVHD\*" -Destination ($vhddiskpart.DriveLetter+':\') -Recurse -Force
            }

            Dismount-VHD $vhddisk.Number
        }else{
            WriteInfoHighlighted "Tools.vhdx found, skipping creation"
        }
#endregion

#region Hydrate DC

    $vhdpath="$PSScriptRoot\LAB\$DCName\Virtual Hard Disks\$DCName.vhdx"
    $VMPath="$PSScriptRoot\LAB\"

    if ($LABConfig.DCEdition -like "*core" ){
        $DCVHDSource="$PSScriptRoot\ParentDisks\Win2016Core_G2.vhdx"
    }else{
        $DCVHDSource="$PSScriptRoot\ParentDisks\Win2016_G2.vhdx"
    }

    #reuse VHD if already created
     if (Test-Path $DCVHDSource){
         WriteInfoHighlighted "$DCVHDSource found, reusing copying to $vhdpath"
         New-Item -Path "$VMPath\$DCName" -Name "Virtual Hard Disks" -ItemType Directory
         Copy-Item -Path $DCVHDSource -Destination $vhdpath
     }else{
        #Create Parent VHD
        WriteInfoHighlighted "Creating VHD for DC"
        if ($serverpackages){
            Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $LABConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI -package $Serverpackages
        }else{
            Convert-WindowsImage -SourcePath "$ServerMediaPath\sources\install.wim" -Edition $LABConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI
        }
     }

    #If the switch does not already exist, then create a switch with the name $SwitchName
        if (-not [bool](Get-VMSwitch -Name $Switchname -ErrorAction SilentlyContinue)) {
            WriteInfoHighlighted "Creating temp hydration switch $Switchname"
            New-VMSwitch -SwitchType Private -Name $Switchname
        }

    #create VM DC
        WriteInfoHighlighted "Creating DC VM"
        $DC=New-VM -Name $DCName -VHDPath $vhdpath -MemoryStartupBytes 2GB -path $vmpath -SwitchName $Switchname -Generation 2
        $DC | Set-VMProcessor -Count 2
        $DC | Set-VMMemory -DynamicMemoryEnabled $true
        $DC | Set-VM -MemoryMinimumBytes 2GB
        if ($LabConfig.Secureboot -eq $False) {$DC | Set-VMFirmware -EnableSecureBoot Off}

    #Apply Unattend to VM
        WriteInfoHighlighted "Applying Unattend and copying Powershell DSC Modules"
        $unattendfile=CreateUnattendFileVHD -Computername $DCName -AdminPassword $AdminPassword -path "$PSScriptRoot\temp\"
        if (Test-Path "$PSScriptRoot\Temp\"){
            Remove-Item -Path "$PSScriptRoot\Temp\" -Recurse
        }
        New-item -type directory -Path $PSScriptRoot\Temp\mountdir -force
        Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
        Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
        #&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\mountdir
        #&"$PSScriptRoot\Tools\dism\dism" /image:$PSScriptRoot\Temp\mountdir /Apply-Unattend:$unattendfile
        New-item -type directory -Path "$PSScriptRoot\Temp\mountdir\Windows\Panther" -force
        Copy-Item -Path $unattendfile -Destination "$PSScriptRoot\Temp\mountdir\Windows\Panther\unattend.xml" -force
        Copy-Item -Path "$PSScriptRoot\tools\DSC\*" -Destination "$PSScriptRoot\Temp\mountdir\Program Files\WindowsPowerShell\Modules\" -Recurse -force

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
        
            Import-DscResource -ModuleName xActiveDirectory -ModuleVersion "2.14.0.0"
            Import-DSCResource -ModuleName xNetworking -ModuleVersion "3.0.0.0"
            Import-DSCResource -ModuleName xDHCPServer -ModuleVersion "1.5.0.0"
            Import-DSCResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion "5.0.0.0"
            Import-DscResource –ModuleName PSDesiredStateConfiguration

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

                xADUser AdministratorNeverExpires
                {
                    DomainName = $Node.DomainName
                    UserName = "Administrator"
                    Ensure = "Present"
                    DependsOn = "[xADDomain]FirstDS"
                    PasswordNeverExpires = $true
                }

                xIPaddress IP
                {
                    IPAddress = '10.0.0.1'
                    PrefixLength = 24
                    AddressFamily = 'IPv4'
                    InterfaceAlias = 'Ethernet'
                }
                WindowsFeature DHCPServer
                {
                    Ensure = "Present"
                    Name = "DHCP"
                    DependsOn = "[xADDomain]FirstDS"
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
                IPStartRange = '10.0.0.10'
                IPEndRange = '10.0.0.254'
                Name = 'ManagementScope'
                SubnetMask = '255.255.255.0'
                LeaseDuration = '00:08:00'
                State = 'Active'
                AddressFamily = 'IPv4'
                DependsOn = "[WindowsFeature]DHCPServerManagement"
                }

                xDhcpServerOption Option
                {
                Ensure = 'Present'
                ScopeID = '10.0.0.0'
                DnsDomain = $Node.DomainName
                DnsServerIPAddress = '10.0.0.1'
                AddressFamily = 'IPv4'
                Router = '10.0.0.1'
                DependsOn = "[xDHCPServerScope]ManagementScope"
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

        $ConfigData = @{ 
        
            AllNodes = @( 
                @{ 
                    Nodename = $DCName 
                    Role = "Parent DC" 
                    DomainAdminName=$labconfig.DomainAdminName
                    DomainName = $Labconfig.DomainName
                    DomainNetbiosName = $Labconfig.DomainNetbiosName
                    DomainDN = $Labconfig.DN
                    DefaultOUName=$Labconfig.DefaultOUName
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
        WriteInfo "Creating DSC Configs for DC"
        LCMConfig       -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData
        DCHydration     -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData -safemodeAdministratorCred $cred -domainCred $cred -NewADUserCred $cred
    
    #copy DSC MOF files to DC
        WriteInfo "Copying DSC configurations (pending.mof and metaconfig.mof)"
        New-item -type directory -Path "$PSScriptRoot\Temp\config" -ErrorAction Ignore
        Copy-Item -path "$PSScriptRoot\Temp\config\dc.mof"      -Destination "$PSScriptRoot\Temp\mountdir\Windows\system32\Configuration\pending.mof"
        Copy-Item -Path "$PSScriptRoot\Temp\config\dc.meta.mof" -Destination "$PSScriptRoot\Temp\mountdir\Windows\system32\Configuration\metaconfig.mof"

    #close VHD and apply changes
        WriteInfo "Applying changes to VHD"
        Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
        #&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\mountdir /Commit

    #Start DC VM and wait for configuration
        WriteInfo "Starting DC"
        $DC | Start-VM

        $VMStartupTime = 250 
        WriteInfoHighlighted "Configuring DC takes a while"
        WriteInfo "`t Initial configuration in progress. Sleeping $VMStartupTime seconds"
        Start-Sleep $VMStartupTime

        do{
            $test=Invoke-Command -VMGuid $DC.id -ScriptBlock {Get-DscConfigurationStatus} -Credential $cred -ErrorAction SilentlyContinue
            if ($test -eq $null) {
                WriteInfo "`t Configuration in Progress. Sleeping 10 seconds"
            }else{
                WriteInfo "`t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count). Sleeping 10 seconds" 
                WriteInfoHighlighted "`t Invoking DSC Configuration again" 
                Invoke-Command -VMGuid $DC.id -ScriptBlock {Start-DscConfiguration -UseExisting} -Credential $cred
            }
            Start-Sleep 10
        }until ($test.Status -eq 'Success' -and $test.rebootrequested -eq $false)
        $test

    #configure default OU where new Machines will be created using redircmp
        Invoke-Command -VMGuid $DC.id -Credential $cred -ErrorAction SilentlyContinue -ArgumentList $LabConfig -ScriptBlock {
            Param($labconfig);
            redircmp "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"
        } 
    #install SCVMM or its prereqs if specified so
        if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
            $DC | Add-VMHardDiskDrive -Path $toolsVHD.Path
        }

        if ($LabConfig.InstallSCVMM -eq "Yes"){
            WriteInfoHighlighted "Installing System Center Virtual Machine Manager and its prerequisites"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                d:\scvmm\1_SQL_Install.ps1
                d:\scvmm\2_ADK_Install.ps1  
                Restart-Computer    
            }
            Start-Sleep 10

            WriteInfoHighlighted "$($DC.name) was restarted, waiting for Active Directory on $($DC.name) to be started."
            do{
            $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
                param($labconfig);
                Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue}
                Start-Sleep 5
            }
            until ($test -ne $Null)
            WriteSuccess "Active Directory on $($DC.name) is up."

            Start-Sleep 30 #Wait as sometimes VMM failed to install without this.
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                d:\scvmm\3_SCVMM_Install.ps1    
            }
        }

        if ($LabConfig.InstallSCVMM -eq "SQL"){
            WriteInfoHighlighted "Installing SQL"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                d:\scvmm\1_SQL_Install.ps1  
            }
        }

        if ($LabConfig.InstallSCVMM -eq "ADK"){
            WriteInfoHighlighted "Installing ADK"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                d:\scvmm\2_ADK_Install.ps1
            }       
        }

        if ($LabConfig.InstallSCVMM -eq "Prereqs"){
            WriteInfoHighlighted "Installing System Center VMM Prereqs"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                d:\scvmm\1_SQL_Install.ps1
                d:\scvmm\2_ADK_Install.ps1
            }  
        }

        if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
            $DC | Get-VMHardDiskDrive | Where-Object path -eq $toolsVHD.Path | Remove-VMHardDiskDrive
        }
#endregion

#region backup DC and cleanup
    #shutdown DC 
        WriteInfo "Disconnecting VMNetwork Adapter from DC"
        $DC | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter
        WriteInfo "Shutting down DC"
        $DC | Stop-VM
        $DC | Set-VM -MemoryMinimumBytes 512MB

    #Backup DC config, remove from Hyper-V, return DC config
        WriteInfo "Creating backup of DC VM configuration"
        Copy-Item -Path "$vmpath\$DCName\Virtual Machines\" -Destination "$vmpath\$DCName\Virtual Machines_Bak\" -Recurse
        WriteInfo "Removing DC"
        $DC | Remove-VM -Force
        WriteInfo "Returning VM config and adding to Virtual Machines.zip"
        Remove-Item -Path "$vmpath\$DCName\Virtual Machines\" -Recurse
        Rename-Item -Path "$vmpath\$DCName\Virtual Machines_Bak\" -NewName 'Virtual Machines'
        Compress-Archive -Path "$vmpath\$DCName\Virtual Machines\" -DestinationPath "$vmpath\$DCName\Virtual Machines.zip"

    #Cleanup The rest ###
        WriteInfo "Removing switch $Switchname"
        Remove-VMSwitch -Name $Switchname -Force -ErrorAction SilentlyContinue

        WriteInfo "Removing ISO Images"
        if ($ISOServer -ne $Null){
            $ISOServer | Dismount-DiskImage
        }

        if ($ISOClient -ne $Null){
            $ISOClient | Dismount-DiskImage
        }

        WriteInfo "Deleting temp dir"
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse

#endregion

#region finishing

    WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

    WriteInfoHighlighted "Do you want to cleanup unnecessary files and folders?"
    WriteInfo "(.\Tools\ToolsVHD 1_Prereq.ps1 2_CreateParentDisks.ps1 and rename 3_deploy to just deploy)"
    If ((Read-host "Please type Y or N") -like "*Y"){
        WriteInfo "`t Cleaning unnecessary items" 
        "$PSScriptRoot\Tools\ToolsVHD","$PSScriptRoot\Tools\DSC","$PSScriptRoot\1_Prereq.ps1","$PSScriptRoot\2_CreateParentDisks.ps1" | ForEach-Object {
            WriteInfo "`t `t Removing $_"
            Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
        } 
        WriteInfo "`t `t Renaming $PSScriptRoot\3_Deploy.ps1 to Deploy.ps1"
        Rename-Item -Path "$PSScriptRoot\3_Deploy.ps1" -NewName "Deploy.ps1" -ErrorAction SilentlyContinue
        
    }else{
        WriteInfo "You did not type Y, skipping cleanup"
    }

    Stop-Transcript
    WriteSuccess "Job Done. Press any key to continue..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL

#endregion