#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Write-Verbose -Message "Loading Functions"
. .\functions.ps1

Write-Verbose -Message "Get workdirectory and Start Time"
$workdir       = Get-ScriptDirectory
Start-Transcript -Path $workdir\CreateParentDisks.log -Append
$StartDateTime = get-date
Write-Output "Script started at $StartDateTime"

Write-Verbose -Message "Load Variables Script"
. "$($workdir)\variables.ps1"

#region Variables
$AdminPassword=$LabConfig.AdminPassword
$Switchname='DC_HydrationSwitch'
$VMName='DC'
#endregion



Write-Information -MessageData "Checking if Hyper-V is installed" -InformationAction Continue
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'Enabled'){
	Write-Verbose -Message "Hyper-V is Installed"
}else{
	Write-Error "Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
	Exit
}


Write-Verbose -Message "Test for unpacked media - detect install.wim"
If (Test-Path -Path "$workdir\OSServer\Sources\install.wim"){
    $ServerMediaPath="$workdir\OSServer"
	Write-Information -MessageData "Server install.wim found under $ServerMediaPath " -InformationAction Continue
}else{
    Write-Verbose -Message "Test for Server ISO and mount if found"
    $ISOServer = Mount-ISO -Path "$workdir\OSServer"
	$ServerMediaPath = (Get-Volume -DiskImage $ISOServer).DriveLetter+':'
}

If ($LabConfig.CreateClientParent -eq "Yes"){
	If (Test-Path -Path "$workdir\OSClient\Sources\install.wim"){
        $ClientMediaPath="$workdir\OSClient"
		Write-Information -MessageData "Client install.wim found under $ClientMediaPath" -InformationAction Continue
	}else{
		Write-Verbose -Message "Test for Client ISO and mount if found"
		$ISOClient = Mount-ISO -Path "$workdir\OSClient"
		$ClientMediaPath = (Get-Volume -DiskImage $ISOClient).DriveLetter+':'
	}
}

Write-Verbose -Message "grab packages"
$ServerPackages=Get-ChildItem "$workdir\OSServer\Packages" -Recurse | where {$_.Extension -eq ".msu" -or $_.Extension -eq ".cab"}
if ($ServerPackages -ne $null){
    Write-Information -MessageData "Server Packages Found" -InformationAction Continue
    $ServerPackages | ForEach-Object {Write-Information -MessageData $_.Name -InformationAction Continue}
}
If ($LabConfig.CreateClientParent -eq "Yes"){
    $ClientPackages=Get-ChildItem "$workdir\OSClient\Packages" -Recurse | where {$_.Extension -eq ".msu" -or $_.Extension -eq ".cab"}
    if ($ClientPackages -ne $null){
        Write-Information -MessageData "Client Packages Found" -InformationAction Continue
        $ClientPackages | ForEach-Object {Write-Information -MessageData $_.Name -InformationAction Continue}
    }

}
("ParentDisks","Temp","Temp\mountdir","Temp\packages","Tools\dism")|ForEach-Object{
    If(!(Test-Path -Path $_)){
        Write-Verbose -Message "Creating $workdir\$_"
        New-Item -Type Directory -Path "$workdir\$_"
    }
}


. "$workdir\tools\convert-windowsimage.ps1"


Convert-WindowsImage -SourcePath $ServerMediaPath'\sources\install.wim' -Edition ServerDataCenterCore -VHDPath $workdir'\ParentDisks\Win2016Core_G2.vhdx' -SizeBytes 30GB -VHDFormat VHDX -DiskLayout UEFI


If ($LabConfig.CreateClientParent -eq "Yes"){
    Write-Verbose -Message "Create Client Parent disk"
    Convert-WindowsImage -SourcePath $ClientMediaPath'\sources\install.wim' -Edition $LabConfig.ClientEdition -VHDPath $workdir'\ParentDisks\Win10_G2.vhdx' -SizeBytes 30GB -VHDFormat VHDX -DiskLayout UEFI
}


#copy dism tools 
  
Copy-Item -Path $ServerMediaPath'\sources\api*downlevel*.dll' -Destination $workdir\Tools\dism
Copy-Item -Path $ServerMediaPath'\sources\*provider*' -Destination $workdir\Tools\dism
Copy-Item -Path $ServerMediaPath'\sources\*dism*' -Destination $workdir\Tools\dism
Copy-Item -Path $ServerMediaPath'\nanoserver\packages\*' -Destination $workdir\Temp\packages\ -Recurse 


#Old way
#Todo: use the tool for NanoServer
if (Test-Path -Path $ServerMediaPath'\nanoserver\Packages\en-us\*en-us*'){
	#vnext version
	Convert-WindowsImage -SourcePath $ServerMediaPath'\Nanoserver\NanoServer.wim' -edition 2 -VHDPath $workdir'\ParentDisks\Win2016Nano_G2.vhdx' -SizeBytes 30GB -VHDFormat VHDX -DiskLayout UEFI
	&"$workdir\Tools\dism\dism" /Mount-Image /ImageFile:$workdir\Parentdisks\Win2016Nano_G2.vhdx /Index:1 /MountDir:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-DSC-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-DSC-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-FailoverCluster-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-FailoverCluster-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-Guest-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-Guest-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-Storage-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-Storage-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-SCVMM-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-SCVMM-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\mountdir /Commit

	Copy-Item -Path "$workdir\Parentdisks\Win2016Nano_G2.vhdx" -Destination "$workdir\ParentDisks\Win2016NanoHV_G2.vhdx"
 
	&"$workdir\Tools\dism\dism" /Mount-Image /ImageFile:$workdir\Parentdisks\Win2016NanoHV_G2.vhdx /Index:1 /MountDir:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-Compute-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-Compute-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\Microsoft-NanoServer-SCVMM-Compute-Package.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$workdir\Temp\packages\en-us\Microsoft-NanoServer-SCVMM-Compute-Package_en-us.cab /Image:$workdir\Temp\mountdir
	&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\mountdir /Commit

	#do some servicing
	'Win2016Core_G2.vhdx','Win2016Nano_G2.vhdx','Win2016NanoHV_G2.vhdx' | ForEach-Object {
		&"$workdir\Tools\dism\dism" /Mount-Image /ImageFile:$workdir\Parentdisks\$_ /Index:1 /MountDir:$workdir\Temp\mountdir
		$ServerPackages | ForEach-Object {
			$packagepath=$_.FullName
			&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$packagepath /Image:$workdir\Temp\mountdir
		}
		&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\mountdir /Commit
	}

	If ($LabConfig.CreateClientParent -eq "Yes"){
		&"$workdir\Tools\dism\dism" /Mount-Image /ImageFile:$workdir\Parentdisks\Win10_G2.vhdx /Index:1 /MountDir:$workdir\Temp\mountdir
		$ClientPackages | ForEach-Object {
			$packagepath=$_.FullName
			&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$packagepath /Image:$workdir\Temp\mountdir
		}
		&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\mountdir /Commit
	}


}else{

	Write-Host "`t Please use Windows Server TP5 and newer. Exiting" -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}

#create Tools VHDX

$vhd=New-VHD -Path "$workdir\ParentDisks\tools.vhdx" -SizeBytes 30GB -Dynamic
$VHDMount = Mount-VHD $vhd.Path -Passthru

$vhddisk = $VHDMount| get-disk 
$vhddiskpart = $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |Format-Volume -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel ToolsDisk 

$VHDPathTest=Test-Path -Path "$workdir\Tools\ToolsVHD\"

if (!$VHDPathTest){
	New-Item -Type Directory -Path $workdir'\Tools\ToolsVHD'
}

if ($VHDPathTest){
    Write-Host "Found $workdir\Tools\ToolsVHD\*, copying files into VHDX"
    Copy-Item -Path "$workdir\Tools\ToolsVHD\*" -Destination ($vhddiskpart.DriveLetter+':\') -Recurse -Force
}else{
    write-host "Files not found" 
    Write-Host "Add required tools into $workdir\Tools\toolsVHD and Press any key to continue..." -ForegroundColor Green
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
    Copy-Item -Path "$workdir\Tools\ToolsVHD\*" -Destination ($vhddiskpart.DriveLetter+':\') -Recurse -Force
}

Dismount-VHD $vhddisk.Number

##############
# Hydrate DC #
##############

$workdir
$vhdpath=$workdir+'\LAB\'+$VMName+'\Virtual Hard Disks\'+$VMName+'.vhdx'
$VMPath=$Workdir+'\LAB\'


#Create Parent VHD
Convert-WindowsImage -SourcePath $ServerMediaPath'\sources\install.wim' -Edition $LABConfig.DCEdition -VHDPath $vhdpath -SizeBytes 60GB -VHDFormat VHDX -DiskLayout UEFI

#do some servicing
&"$workdir\Tools\dism\dism" /Mount-Image /ImageFile:$vhdpath /Index:1 /MountDir:$workdir\Temp\mountdir
$ServerPackages | ForEach-Object {
	$packagepath=$_.FullName
	&"$workdir\Tools\dism\dism" /Add-Package /PackagePath:$packagepath /Image:$workdir\Temp\mountdir
}
&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\mountdir /Commit



#If the switch does not already exist, then create a switch with the name $SwitchName
if (-not [bool](Get-VMSwitch -Name $Switchname -ErrorAction SilentlyContinue)) {New-VMSwitch -SwitchType Private -Name $Switchname}

$DC=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes 2GB -path $vmpath -SwitchName $Switchname -Generation 2 
$DC | Set-VMProcessor -Count 2
$DC | Set-VMMemory -DynamicMemoryEnabled $true
if ($LabConfig.Secureboot -eq 'Off') {$DC | Set-VMFirmware -EnableSecureBoot Off}

#Apply Unattend
$unattendfile=Create-UnattendFileVHD -Computername $VMName -AdminPassword $AdminPassword -path "$workdir\temp\"
New-item -type directory -Path $Workdir\Temp\mountdir -force
&"$workdir\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$Workdir\Temp\mountdir
&"$workdir\Tools\dism\dism" /image:$Workdir\Temp\mountdir /Apply-Unattend:$unattendfile
New-item -type directory -Path "$Workdir\Temp\mountdir\Windows\Panther" -force
Copy-Item -Path $unattendfile -Destination "$Workdir\Temp\mountdir\Windows\Panther\unattend.xml" -force
Copy-Item -Path "$workdir\tools\DSC\*" -Destination "$Workdir\Temp\mountdir\Program Files\WindowsPowerShell\Modules\" -Recurse -force


#####
#Here goes Configuration and creation of pending.mof

$username = "corp\Administrator"
$password = $AdminPassword
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

configuration DCHydration
{
     param 
    ( 
        [Parameter(Mandatory)] 
        [pscredential]$safemodeAdministratorCred, 
 
        [Parameter(Mandatory)] 
        [pscredential]$domainCred,

        [Parameter(Mandatory)]
        [pscredential]$NewADUserCred,

		[Parameter(Mandatory)]
        [string]$DomainAdminName

    )
 
    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion "2.10.0.0"
	Import-DSCResource -ModuleName xNetworking -ModuleVersion "2.8.0.0"
	Import-DSCResource -ModuleName xDHCPServer -ModuleVersion "1.3.0.0"
	Import-DSCResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion "3.9.0.0"
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
        
		xADOrganizationalUnit WorkshopOU
        {
			Name = 'Workshop'
			Path = 'dc=corp,dc=contoso,dc=com'
			ProtectedFromAccidentalDeletion = $true
			Description = 'Default OU for Workshop'
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
            DependsOn = "[xADOrganizationalUnit]WorkshopOU"
			Description = "SQL Service Account"
			Path = 'OU=workshop,dc=corp,dc=contoso,dc=com'
			PasswordNeverExpires = $true
        }

		xADUser SQL_Agent
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            UserName = "SQL_Agent"
            Password = $NewADUserCred
            Ensure = "Present"
            DependsOn = "[xADOrganizationalUnit]WorkshopOU"
			Description = "SQL Agent Account"
			Path = 'OU=workshop,dc=corp,dc=contoso,dc=com'
			PasswordNeverExpires = $true
        }

		xADUser Domain_Admin
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            UserName = $DomainAdminName
            Password = $NewADUserCred
            Ensure = "Present"
            DependsOn = "[xADOrganizationalUnit]WorkshopOU"
			Description = "DomainAdmin"
			Path = 'OU=workshop,dc=corp,dc=contoso,dc=com'
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
			Path = 'OU=workshop,dc=corp,dc=contoso,dc=com'
			PasswordNeverExpires = $true
        }

		xADGroup DomainAdmins
		{
			GroupName = "Domain Admins"
			DependsOn = "[xADUser]VMM_SA"
			MembersToInclude = "VMM_SA",$DomainAdminName
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
            SubnetMask = 24
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
        DnsDomain = 'corp.contoso.com'
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

        xDscWebService PSDSCComplianceServer
        {
            Ensure                  = "Present"
            EndpointName            = "PSDSCComplianceServer"
            Port                    = 9080
            PhysicalPath            = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
            CertificateThumbPrint   = "AllowUnencryptedTraffic"
            State                   = "Started"
            DependsOn               = ("[WindowsFeature]DSCServiceFeature","[xDSCWebService]PSDSCPullServer")
        }
		
    }
}

$ConfigData = @{ 
 
    AllNodes = @( 
        @{ 
            Nodename = "DC" 
            Role = "Parent DC" 
            DomainName = "corp.contoso.com"
            DomainNetbiosName = "corp"
            PSDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser= $true        
            RetryCount = 50  
            RetryIntervalSec = 30  
        }         
    ) 
} 

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

LCMConfig       -OutputPath "$workdir\Temp\config" -ConfigurationData $ConfigData
DCHydration     -OutputPath "$workdir\Temp\config" -ConfigurationData $ConfigData -safemodeAdministratorCred $cred -domainCred $cred -NewADUserCred $cred -DomainAdminName $LabConfig.DomainAdminName

New-item -type directory -Path "$Workdir\Temp\config" -ErrorAction Ignore
Copy-Item -path "$workdir\Temp\config\dc.mof"      -Destination "$workdir\Temp\mountdir\Windows\system32\Configuration\pending.mof"
Copy-Item -Path "$workdir\Temp\config\dc.meta.mof" -Destination "$workdir\Temp\mountdir\Windows\system32\Configuration\metaconfig.mof"


#####

&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$Workdir\Temp\mountdir /Commit


#Start and wait for configuration
try{
    $DC | Start-VM -ErrorAction Stop 

    $VMStartupTime = 250 
    Write-host "Configuring DC takes a while"
    Write-host "Initial configuration in progress. Sleeping $VMStartupTime seconds"
    Start-Sleep $VMStartupTime

    do{
        $test=Invoke-Command -VMGuid $DC.id -ScriptBlock {Get-DscConfigurationStatus} -Credential $cred -ErrorAction SilentlyContinue
        if ($test -eq $null) {
            Write-Host "Configuration in Progress. Sleeping 10 seconds"
        }else{
            Write-Host "Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count). Sleeping 10 seconds" 
            Write-Host "Invoking DSC Configuration again" 
            Invoke-Command -VMGuid $DC.id -ScriptBlock {Start-DscConfiguration -UseExisting} -Credential $cred
        }
        Start-Sleep 10
    }until ($test.Status -eq 'Success' -and $test.rebootrequested -eq $false)
    $test

    Invoke-Command -VMGuid $DC.id -ScriptBlock {redircmp 'OU=Workshop,DC=corp,DC=contoso,DC=com'} -Credential $cred -ErrorAction SilentlyContinue

    $DC | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter
    $DC | Stop-VM
}catch{
    $VMStartError = $true
    Write-Warning -Message "Unable to Start VM!! "
}

#cleanup

###Backup VM Configuration ###
If($VMStartError -eq $false){
    Copy-Item -Path "$vmpath\$VMNAME\Virtual Machines\" -Destination "$vmpath\$VMNAME\Virtual Machines_Bak\" -Recurse   
}
$DC | Remove-VM -Force
Remove-Item -Path "$vmpath\$VMNAME\Virtual Machines\" -Recurse
If($VMStartError -eq $false){
    Rename-Item -Path "$vmpath\$VMNAME\Virtual Machines_Bak\" -NewName 'Virtual Machines'
    Compress-Archive -Path "$vmpath\$VMNAME\Virtual Machines\" -DestinationPath "$vmpath\$VMNAME\Virtual Machines.zip"
}
###Cleanup The rest ###
Remove-VMSwitch -Name $Switchname -Force -ErrorAction SilentlyContinue
if ($ISOServer -ne $Null){
$ISOServer | Dismount-DiskImage
}

if ($ISOClient -ne $Null){
$ISOClient | Dismount-DiskImage
}

Remove-Item -Path "$workdir\temp" -Force -Recurse

Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

Stop-Transcript
Write-Host "Job Done. Press any key to continue..." -ForegroundColor Green
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL