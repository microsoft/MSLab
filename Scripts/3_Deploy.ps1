# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
	Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Sleep -Seconds 1
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
	exit
}

#############
# Functions #
#############

Function CreateUnattendFileBlob
    #Create Unattend (parameter is Blob)
    {
param (
    [parameter(Mandatory=$true)]
    [string]
    $Blob,
    [parameter(Mandatory=$true)]
    [string]
    $AdminPassword
)

    if ( Test-Path "Unattend.xml" ) {
      del .\Unattend.xml
    }
    $unattendFile = New-Item "Unattend.xml" -type File
    $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <OfflineIdentification>              
           <Provisioning>  
             <AccountData>$Blob</AccountData>
           </Provisioning>  
         </OfflineIdentification>  
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
	  <TimeZone>Pacific Standard Time</TimeZone>
    </component>
  </settings>

  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RegisteredOwner>PFE</RegisteredOwner>
      <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
  </settings>
</unattend>

"@

    Set-Content $unattendFile $fileContent

    #return the file object
    $unattendFile 
}

Function CreateUnattendFileNoDjoin
    #Create Unattend)
    {
param (
    [parameter(Mandatory=$true)]
    [string]
    $ComputerName,
    [parameter(Mandatory=$true)]
    [string]
    $AdminPassword
)

    if ( Test-Path "Unattend.xml" ) {
      del .\Unattend.xml
    }
    $unattendFile = New-Item "Unattend.xml" -type File
    $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
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

    Set-Content $unattendFile $fileContent

    #return the file object
    $unattendFile 
}

Function CreateUnattendFileWin2012
    #Create Unattend)
    {
param (
    [parameter(Mandatory=$true)]
    [string]
    $ComputerName,
    [parameter(Mandatory=$true)]
    [string]
    $AdminPassword
)

    if ( Test-Path "Unattend.xml" ) {
      del .\Unattend.xml
    }
    $unattendFile = New-Item "Unattend.xml" -type File
    $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
		<RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Identification>
                <Credentials>
                    <Domain>corp.contoso.com</Domain>
                    <Password>$AdminPassword</Password>
                    <Username>Administrator</Username>
                </Credentials>
				<JoinDomain>corp.contoso.com</JoinDomain>			
        </Identification>
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

    Set-Content $unattendFile $fileContent

    #return the file object
    $unattendFile 
}

##########################################################################################

Function Get-ScriptDirectory
    {
    Split-Path $script:MyInvocation.MyCommand.Path
    }

##########################################################################################

function  Get-WindowsBuildNumber { 
    $os = Get-WmiObject -Class Win32_OperatingSystem 
    return [int]($os.BuildNumber) 
} 

##########################################################################################
Function Set-VMNetworkConfiguration {

#source:http://www.ravichaganti.com/blog/?p=2766 with some changes
#example use: Get-VMNetworkAdapter -VMName Demo-VM-1 -Name iSCSINet | Set-VMNetworkConfiguration -IPAddress 192.168.100.1 00 -Subnet 255.255.0.0 -DNSServer 192.168.100.101 -DefaultGateway 192.168.100.1
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName='DHCP',
                   ValueFromPipeline=$true)]
        [Parameter(Mandatory=$true,
                   Position=0,
                   ParameterSetName='Static',
                   ValueFromPipeline=$true)]
        [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$NetworkAdapter,

        [Parameter(Mandatory=$true,
                   Position=1,
                   ParameterSetName='Static')]
        [String[]]$IPAddress=@(),

        [Parameter(Mandatory=$false,
                   Position=2,
                   ParameterSetName='Static')]
        [String[]]$Subnet=@(),

        [Parameter(Mandatory=$false,
                   Position=3,
                   ParameterSetName='Static')]
        [String[]]$DefaultGateway = @(),

        [Parameter(Mandatory=$false,
                   Position=4,
                   ParameterSetName='Static')]
        [String[]]$DNSServer = @(),

        [Parameter(Mandatory=$false,
                   Position=0,
                   ParameterSetName='DHCP')]
        [Switch]$Dhcp
    )

    $VM = Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $NetworkAdapter.VMName } 
    $VMSettings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }    
    $VMNetAdapters = $VMSettings.GetRelated('Msvm_SyntheticEthernetPortSettingData') 

    $NetworkSettings = @()
    foreach ($NetAdapter in $VMNetAdapters) {
        if ($NetAdapter.elementname -eq $NetworkAdapter.name) {
            $NetworkSettings = $NetworkSettings + $NetAdapter.GetRelated("Msvm_GuestNetworkAdapterConfiguration")
        }
    }

    $NetworkSettings[0].IPAddresses = $IPAddress
    $NetworkSettings[0].Subnets = $Subnet
    $NetworkSettings[0].DefaultGateways = $DefaultGateway
    $NetworkSettings[0].DNSServers = $DNSServer
    $NetworkSettings[0].ProtocolIFType = 4096

    if ($dhcp) {
        $NetworkSettings[0].DHCPEnabled = $true
    } else {
        $NetworkSettings[0].DHCPEnabled = $false
    }

    $Service = Get-WmiObject -Class "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
    $setIP = $Service.SetGuestNetworkAdapterConfiguration($VM, $NetworkSettings[0].GetText(1))

    if ($setip.ReturnValue -eq 4096) {
        $job=[WMI]$setip.job 

        while ($job.JobState -eq 3 -or $job.JobState -eq 4) {
            start-sleep 1
            $job=[WMI]$setip.job
        }

        if ($job.JobState -eq 7) {
            write-host "Success"
        }
        else {
            $job.GetError()
        }
    } elseif($setip.ReturnValue -eq 0) {
        Write-Host "Success"
    }
}

##########################################################################################
#Some necessary stuff
##########################################################################################
$Workdir=Get-ScriptDirectory

Start-Transcript -Path $workdir'\Deploy.log'

$StartDateTime = get-date
Write-host	"Script started at $StartDateTime"


##Load Variables....
. "$($workdir)\variables.ps1"

Write-Host "List of variables used" -ForegroundColor Cyan
Write-Host "`t Prefix used in lab is "$labconfig.prefix

$SwitchName=($labconfig.prefix+$Networkconfig.SwitchName)
Write-Host "`t Switchname is $SwitchName" 

Write-Host "`t Workdir is $Workdir"

$LABfolder="$Workdir\LAB"
Write-Host "`t LabFolder is $LabFolder"

$LABfolderDrivePath=$LABfolder.Substring(0,3)

$IP=1
##########################################################################################
# Some Additional checks and prereqs
##########################################################################################

	#checking if Prefix is not empty

if (!$LabConfig.Prefix){
    Write-Host "`t Prefix is empty. Exiting" -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}

	# Checking for Compatible OS
Write-Host "Checking if OS is Windows 10 TH2/Server 2016 TP4 or newer" -ForegroundColor Cyan

$BuildNumber=Get-WindowsBuildNumber
if ($BuildNumber -ge 10586){
	Write-Host "`t OS is Windows 10 TH2/Server 2016 TP4 or newer" -ForegroundColor Green
    }else{
    Write-Host "`t Windows 10/ Server 2016 not detected. Exiting" -ForegroundColor Red
    Write-Host "Press any key to continue ..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
    $HOST.UI.RawUI.Flushinputbuffer()
    Exit
}

#Check support for shared disks + enable if possible

if ($LabVMs.configuration -contains 'Shared' -or $LabVMs.configuration -contains 'Replica'){
	Write-Host "Configuration contains Shared or Replica scenario" -ForegroundColor Cyan
    Write-Host "Checking for support for shared disks" -ForegroundColor Cyan
    $OS=gwmi win32_operatingsystem
	if ((($OS.operatingsystemsku -eq 7) -or ($OS.operatingsystemsku -eq 8)) -and $OS.version -gt 10){
		Write-Host "`t Installing Failover Clustering Feature"
		$FC=Install-WindowsFeature Failover-Clustering
		If ($FC.Success -eq $True){
			Write-Host "`t`t Failover Clustering Feature installed with exit code: "$FC.ExitCode 
		}else{
			Write-Host "`t`t Failover Clustering Feature was not installed with exit code: "$FC.ExitCode
		}
	}else{
		if (((Get-WindowsOptionalFeature -Online -featurename FailoverCluster-FullServer).State -eq "Enabled") -or ((Get-WindowsOptionalFeature -Online -featurename FailoverCluster-NanoServer).State -eq "Enabled")){
			Write-Host "`t OS is Windows 10 and Failover clustering is present" -ForegroundColor Green
		}else{
			Write-Host "`t OS is Windows 10 and Failover clustering is not present. Please install it or choose simple lab without shared disks" -ForegroundColor Red
			Write-Host "Press any key to continue ..."
			$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
			$HOST.UI.RawUI.Flushinputbuffer()
			Exit
		}
	}

	Write-Host "Attaching svhdxflt filter driver to drive $LABfolderDrivePath" -ForegroundColor Cyan
	fltmc.exe attach svhdxflt $LABfolderDrivePath
	Write-Host "Adding svhdxflt to registry for autostart" -ForegroundColor Cyan
	
	if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters)){
		New-Item HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters
	}
    
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters -Name AutoAttachOnNonCSVVolumes -PropertyType DWORD -Value 1 -force
}

#Check if Hyper-V is installed

Write-Host "Checking if Hyper-V is installed" -ForegroundColor Cyan
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq 'Enabled'){
	Write-Host "`t Hyper-V is Installed" -ForegroundColor Green
}else{
	Write-Host "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting" -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}


#Create Switches

Write-Host "Creating Switch" -ForegroundColor Cyan
Write-Host "`t Checking if $SwitchName already exists..."

if ((Get-VMSwitch -Name $SwitchName -ErrorAction Ignore) -eq $Null){ 
    Write-Host "`t Creating $SwitchName..." -ForegroundColor Green
    New-VMSwitch -SwitchType Private -Name $SwitchName
    
}else{
    Write-Host "`t $SwitchName exists. Looks like lab with same prefix exists. Exiting" -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}


Write-Host "`t Creating Mountdir" -ForegroundColor Green
New-Item $workdir\Temp\MountDir -ItemType Directory -Force

Write-Host "`t Creating VMs dir" -ForegroundColor Green
New-Item $workdir\LAB\VMs -ItemType Directory -Force


######################
# Getting tools disk #
######################

#get path for Tools disk

Write-Host "`t Looking for Tools Parent Disks"
$toolsparent=Get-ChildItem $Workdir -Recurse | where name -eq tools.vhdx
if ($toolsparent -eq $null){
	Write-Host "`t`t Tools parent disk not found" -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}else{
Write-Host "`t`t Tools parent disk"$toolsparent.Name"found"
}

################
# Importing DC #
################

Write-Host "Looking for DC to be imported" -ForegroundColor Cyan
get-childitem $LABFolder -Recurse | where {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
	$DC=Import-VM -Path $_.FullName
	if ($DC -eq $null){
		Write-Host "DC was not imported successfully Press any key to continue ..." -ForegroundColor Red -BackgroundColor White
		$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
		$HOST.UI.RawUI.Flushinputbuffer()
		exit
	}
}

Write-Host "`t Virtual Machine"$DC.name"located in folder"$_.DirectoryName"imported"

$DC | Checkpoint-VM -SnapshotName Initial
Write-Host "`t Virtual Machine"$DC.name"checkpoint created"
	
Start-Sleep -Seconds 5

Write-Host "`t Configuring Network"

$DC | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

Write-Host "`t`t Adding network adapters"
$DC | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage1
$DC | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage2
$DC | Get-VMNetworkAdapter -Name Storage1 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet1+$IP.ToString()) -Subnet 255.255.255.0
$DC | Get-VMNetworkAdapter -Name Storage2 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet2+$IP.ToString()) -Subnet 255.255.255.0
$IP++

Write-Host "`t Adding Tools disk to DC machine"

$toolspath=$LABFolder+'\VMs\tools.vhdx'
$VHD=New-VHD -ParentPath $toolsparent.fullname -Path $toolspath

Write-Host "`t Adding Virtual Hard Disk" $VHD.Path
$DC | Add-VMHardDiskDrive -Path $vhd.Path

Write-Host "`t`t Starting Virtual Machine"$DC.name
$DC | Start-VM

Write-Host "`t`t Renaming"$DC.name"to"($labconfig.Prefix+$DC.name)
$DC | Rename-VM -NewName ($labconfig.Prefix+$DC.name)



############################
# Testing DC To come alive #
############################

#Credentials for Session
$username = "corp\Administrator"
$password = $LabConfig.AdminPassword
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

Write-Host "Testing if Active Directory is Started." -ForegroundColor Cyan 
do{
$test=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {Get-ADComputer -Filter * -SearchBase 'DC=Corp,DC=Contoso,DC=Com' -ErrorAction SilentlyContinue} -ErrorAction SilentlyContinue
Start-Sleep 5
}
until ($test -ne $Null)
Write-Host "Active Directory is up." -ForegroundColor Green 

#make tools disk online
Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | where operationalstatus -eq offline | Set-Disk -IsReadOnly $false}
Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | where operationalstatus -eq offline | Set-Disk -IsOffline $false}


#################
# Provision VMs  #
#################

#DCM Config
[DSCLocalConfigurationManager()]
Configuration LCM_HTTPPULL 
{
    param
        (
            [Parameter(Mandatory=$true)]
            [string[]]$ComputerName,

            [Parameter(Mandatory=$true)]
            [string]$guid
        )      	
	Node $ComputerName {
	
		Settings{
		
			AllowModuleOverwrite = $True
            ConfigurationMode = 'ApplyAndAutoCorrect'
			RefreshMode = 'Pull'
			RebootNodeIfNeeded = $True
			ActionAfterReboot = 'ContinueConfiguration'
			ConfigurationID = $guid
            }

            ConfigurationRepositoryWeb DSCHTTP { 
                ServerURL = 'http://dc.corp.contoso.com:8080/PSDSCPullServer.svc'
                AllowUnsecureConnection = $true
            }
		
	}
}
$LabVMs.GetEnumerator() | ForEach-Object {

    if ($_.configuration -eq 'Shared'){
        $VMSet=$_.VMSet
        if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
                $SSDSize=$_.SSDSize
            	$HDDSize=$_.HDDSize
                $SharedSSDs=$null
				$SharedHDDs=$null
				If (($_.SSDNumber -ge 1) -and ($_.SSDNumber -ne $null)){  
					$SharedSSDs= 1..$_.ssdnumber | % {New-vhd -Path "$LABfolder\VMs\SharedSSD-$VMSet-$_.VHDS" -Dynamic –Size $SSDSize}
					$SharedSSDs | % {Write-Host "`t`t Disk SSD"$_.path" size "($_.size /1GB)"GB created"}
				}
				If (($_.HDDNumber -ge 1) -and ($_.HDDNumber -ne $null)){  
					$SharedHDDs= 1..$_.hddnumber | % {New-VHD -Path "$LABfolder\VMs\SharedHDD-$VMSet-$_.VHDS" -Dynamic –Size $HDDSize}
					$SharedHDDs | % {Write-Host "`t`t Disk HDD"$_.path"size"($_.size /1GB)"GB created"}
				}
			}


#region Todo:convert this Block to function

        Write-Host "`t Looking for Parent Disk"
        $serverparent=Get-ChildItem $Workdir"\ParentDisks\" -Recurse | where Name -eq $_.ParentVHD
        
        if ($serverparent -eq $null){
            Write-Host "`t`t Server parent disk"$_.ParentVHD"not found" -ForegroundColor Red
            Write-Host "Press any key to continue ..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
            $HOST.UI.RawUI.Flushinputbuffer()
            Exit
        }else{
	        Write-Host "`t`t Server parent disk"$serverparent.Name"found"
        }
                
        $VMname=$Labconfig.Prefix+$_.VMName
		$folder="$LabFolder\VMs\$VMname"
		$vhdpath="$folder\$VMname.vhdx"
		Write-Host "Creating VM"$VMname -ForegroundColor Cyan
		New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
		$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
		$VMTemp | Set-VMProcessor -Count 2
		$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
		$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management
		$VMTemp | Add-VMNetworkAdapter -Name Management -SwitchName $SwitchName

		if ($LabConfig.Secureboot -eq 'Off') {$VMTemp | Set-VMFirmware -EnableSecureBoot Off}

		if ($_.StorageNetwork -eq 'Yes'){
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage1
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage2
			$VMTemp | Get-VMNetworkAdapter -Name Storage1 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet1+$IP.ToString()) -Subnet 255.255.255.0
			$VMTemp | Get-VMNetworkAdapter -Name Storage2 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet2+$IP.ToString()) -Subnet 255.255.255.0
			$IP++
		}

		#Generate DSC Config
		if ($_.DSCMode -eq 'Pull'){
			if ($_.GUID -eq $Null){$Guid=[guid]::NewGuid()}
			else{$Guid=$_.Guid}
			LCM_HTTPPULL -ComputerName $_.VMName -Guid $Guid -OutputPath $workdir\temp\dscconfig
		}
		
		#configure nested virt
		if ($_.NestedVirt -eq 'Yes'){
			$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
		}		

		$Name=$_.VMName
		
		if ($_.SkipDjoin -eq 'Yes'){
			$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
		}
		else{
			if ($_.Win2012Djoin -eq 'Yes'){
				$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
			}
			else{
				$path="c:\$vmname.txt"
				Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path); djoin.exe /provision /domain corp /machine $Name /savefile $path /machineou "OU=Workshop,DC=corp,DC=contoso,DC=com"} -ArgumentList $Name,$path
				$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
				Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); del $path} -ArgumentList $path
				$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
			}
		}

		&"$workdir\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$workdir\Temp\Mountdir
		&"$workdir\Tools\dism\dism" /image:$workdir\Temp\Mountdir /Apply-Unattend:$unattendfile
		New-item -type directory $workdir\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
		copy $unattendfile $workdir\Temp\Mountdir\Windows\Panther\unattend.xml
		
		if ($_.DSCMode -eq 'Pull'){
			copy "$workdir\temp\dscconfig\$name.meta.mof" -Destination "$workdir\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
		}
		
		&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\Mountdir /Commit

		#add toolsdisk
		if ($_.AddToolsVHD -eq 'Yes'){
			$VHD=New-VHD -ParentPath $toolsparent.fullname -Path "$folder\tools.vhdx"
			Write-Host "`t Adding Virtual Hard Disk" $VHD.Path " to $VMName"
			$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
		}

#endregion
	
		Write-Host "`t Attaching Shared Disks to $VMname" -ForegroundColor Cyan

		$SharedSSDs | % {
			Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
			Write-Host "`t`t SSD "$_.path"size"($_.size /1GB)"GB added to $VMname"
		}
		$SharedHDDs | % {
			Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
			Write-Host "`t`t HDD "$_.path"size"($_.size /1GB)"GB added to $VMname"
		}
		
	}
    
    if ($_.configuration -eq 'Simple'){
#region Todo:convert this Block to function

        Write-Host "`t Looking for Parent Disk"
        $serverparent=Get-ChildItem $Workdir"\ParentDisks\" -Recurse | where Name -eq $_.ParentVHD
        
        if ($serverparent -eq $null){
            Write-Host "`t`t Server parent disk"$_.ParentVHD"not found" -ForegroundColor Red
            Write-Host "Press any key to continue ..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
            $HOST.UI.RawUI.Flushinputbuffer()
            Exit
        }else{
	        Write-Host "`t`t Server parent disk"$serverparent.Name"found"
        }
                
        $VMname=$Labconfig.Prefix+$_.VMName
		$folder="$LabFolder\VMs\$VMname"
		$vhdpath="$folder\$VMname.vhdx"
		Write-Host "Creating VM"$VMname -ForegroundColor Cyan
		New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
		$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
		$VMTemp | Set-VMProcessor -Count 2
		$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
		$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management
		$VMTemp | Add-VMNetworkAdapter -Name Management -SwitchName $SwitchName

		if ($LabConfig.Secureboot -eq 'Off') {$VMTemp | Set-VMFirmware -EnableSecureBoot Off}

		if ($_.StorageNetwork -eq 'Yes'){
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage1
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage2
			$VMTemp | Get-VMNetworkAdapter -Name Storage1 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet1+$IP.ToString()) -Subnet 255.255.255.0
			$VMTemp | Get-VMNetworkAdapter -Name Storage2 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet2+$IP.ToString()) -Subnet 255.255.255.0
			$IP++
		}

		#Generate DSC Config
		if ($_.DSCMode -eq 'Pull'){
			if ($_.GUID -eq $Null){$Guid=[guid]::NewGuid()}
			else{$Guid=$_.Guid}
			LCM_HTTPPULL -ComputerName $_.VMName -Guid $Guid -OutputPath $workdir\temp\dscconfig
		}
		
		#configure nested virt
		if ($_.NestedVirt -eq 'Yes'){
			$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
		}		

		$Name=$_.VMName
		
		if ($_.SkipDjoin -eq 'Yes'){
			$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
		}
		else{
			if ($_.Win2012Djoin -eq 'Yes'){
				$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
			}
			else{
				$path="c:\$vmname.txt"
				Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path); djoin.exe /provision /domain corp /machine $Name /savefile $path /machineou "OU=Workshop,DC=corp,DC=contoso,DC=com"} -ArgumentList $Name,$path
				$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
				Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); del $path} -ArgumentList $path
				$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
			}
		}

		&"$workdir\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$workdir\Temp\Mountdir
		&"$workdir\Tools\dism\dism" /image:$workdir\Temp\Mountdir /Apply-Unattend:$unattendfile
		New-item -type directory $workdir\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
		copy $unattendfile $workdir\Temp\Mountdir\Windows\Panther\unattend.xml
		
		if ($_.DSCMode -eq 'Pull'){
			copy "$workdir\temp\dscconfig\$name.meta.mof" -Destination "$workdir\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
		}
		
		&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\Mountdir /Commit

		#add toolsdisk
		if ($_.AddToolsVHD -eq 'Yes'){
			$VHD=New-VHD -ParentPath $toolsparent.fullname -Path "$folder\tools.vhdx"
			Write-Host "`t Adding Virtual Hard Disk" $VHD.Path " to $VMName"
			$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
		}

#endregion
        
        }

    if ($_.configuration -eq 'S2D'){
#region Todo:convert this Block to function

        Write-Host "`t Looking for Parent Disk"
        $serverparent=Get-ChildItem $Workdir"\ParentDisks\" -Recurse | where Name -eq $_.ParentVHD
        
        if ($serverparent -eq $null){
            Write-Host "`t`t Server parent disk"$_.ParentVHD"not found" -ForegroundColor Red
            Write-Host "Press any key to continue ..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
            $HOST.UI.RawUI.Flushinputbuffer()
            Exit
        }else{
	        Write-Host "`t`t Server parent disk"$serverparent.Name"found"
        }
                
        $VMname=$Labconfig.Prefix+$_.VMName
		$folder="$LabFolder\VMs\$VMname"
		$vhdpath="$folder\$VMname.vhdx"
		Write-Host "Creating VM"$VMname -ForegroundColor Cyan
		New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
		$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
		$VMTemp | Set-VMProcessor -Count 2
		$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
		$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management
		$VMTemp | Add-VMNetworkAdapter -Name Management -SwitchName $SwitchName

		if ($LabConfig.Secureboot -eq 'Off') {$VMTemp | Set-VMFirmware -EnableSecureBoot Off}

		if ($_.StorageNetwork -eq 'Yes'){
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage1
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage2
			$VMTemp | Get-VMNetworkAdapter -Name Storage1 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet1+$IP.ToString()) -Subnet 255.255.255.0
			$VMTemp | Get-VMNetworkAdapter -Name Storage2 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet2+$IP.ToString()) -Subnet 255.255.255.0
			$IP++
		}

		#Generate DSC Config
		if ($_.DSCMode -eq 'Pull'){
			if ($_.GUID -eq $Null){$Guid=[guid]::NewGuid()}
			else{$Guid=$_.Guid}
			LCM_HTTPPULL -ComputerName $_.VMName -Guid $Guid -OutputPath $workdir\temp\dscconfig
		}
		
		#configure nested virt
		if ($_.NestedVirt -eq 'Yes'){
			$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
		}		

		$Name=$_.VMName
		
		if ($_.SkipDjoin -eq 'Yes'){
			$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
		}
		else{
			if ($_.Win2012Djoin -eq 'Yes'){
				$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
			}
			else{
				$path="c:\$vmname.txt"
				Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path); djoin.exe /provision /domain corp /machine $Name /savefile $path /machineou "OU=Workshop,DC=corp,DC=contoso,DC=com"} -ArgumentList $Name,$path
				$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
				Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); del $path} -ArgumentList $path
				$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
			}
		}

		&"$workdir\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$workdir\Temp\Mountdir
		&"$workdir\Tools\dism\dism" /image:$workdir\Temp\Mountdir /Apply-Unattend:$unattendfile
		New-item -type directory $workdir\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
		copy $unattendfile $workdir\Temp\Mountdir\Windows\Panther\unattend.xml
		
		if ($_.DSCMode -eq 'Pull'){
			copy "$workdir\temp\dscconfig\$name.meta.mof" -Destination "$workdir\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
		}
		
		&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\Mountdir /Commit

		#add toolsdisk
		if ($_.AddToolsVHD -eq 'Yes'){
			$VHD=New-VHD -ParentPath $toolsparent.fullname -Path "$folder\tools.vhdx"
			Write-Host "`t Adding Virtual Hard Disk" $VHD.Path " to $VMName"
			$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
		}

#endregion
        
        
        If (($_.SSDNumber -ge 1) -and ($_.SSDNumber -ne $null)){         
            $SSDSize=$_.SSDSize
            $SSDs= 1..$_.SSDNumber | % { New-vhd -Path "$folder\SSD-$_.VHDX" -Dynamic –Size $SSDSize}
		    Write-Host "`t`t Adding Virtual SSD Disks"
		    $SSDs | % {
			    Add-VMHardDiskDrive -Path $_.path -VMName $VMname
			    Write-Host "`t`t SSD "$_.path"size"($_.size /1GB)"GB added to $VMname"
		    }
	    }

	    If (($_.HDDNumber -ge 1) -and ($_.HDDNumber -ne $null)) {
		    $HDDSize=$_.HDDSize
            $HDDs= 1..$_.HDDNumber | % { New-VHD -Path "$folder\HDD-$_.VHDX" -Dynamic –Size $HDDSize}
		    Write-Host "`t Adding Virtual HDD Disks"
		    $HDDs | % {
			Add-VMHardDiskDrive -Path $_.path -VMName $VMname
			Write-Host "`t`t HDD "$_.path"size"($_.size /1GB)"GB added to $VMname"
		    }	
        }      
    }
        
    if ($_.configuration -eq 'Replica'){
        
        $VMSet=$_.VMSet
        if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
            $ReplicaHDD= New-vhd -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS" -Dynamic –Size $_.ReplicaHDDSize
	        $ReplicaHDD | % {Write-Host "`t`t ReplicaHDD"$_.path"size"($_.size /1GB)"GB created"}
	        $ReplicaLog= New-vhd -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS" -Dynamic –Size $_.ReplicaLogSize
	        $ReplicaLog | % {Write-Host "`t`t ReplicaHDD"$_.path"size"($_.size /1GB)"GB created"}
        }
#region Todo:convert this Block to function

        Write-Host "`t Looking for Parent Disk"
        $serverparent=Get-ChildItem $Workdir"\ParentDisks\" -Recurse | where Name -eq $_.ParentVHD
        
        if ($serverparent -eq $null){
            Write-Host "`t`t Server parent disk"$_.ParentVHD"not found" -ForegroundColor Red
            Write-Host "Press any key to continue ..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
            $HOST.UI.RawUI.Flushinputbuffer()
            Exit
        }else{
	        Write-Host "`t`t Server parent disk"$serverparent.Name"found"
        }
                
        $VMname=$Labconfig.Prefix+$_.VMName
		$folder="$LabFolder\VMs\$VMname"
		$vhdpath="$folder\$VMname.vhdx"
		Write-Host "Creating VM"$VMname -ForegroundColor Cyan
		New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
		$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
		$VMTemp | Set-VMProcessor -Count 2
		$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
		$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management
		$VMTemp | Add-VMNetworkAdapter -Name Management -SwitchName $SwitchName

		if ($LabConfig.Secureboot -eq 'Off') {$VMTemp | Set-VMFirmware -EnableSecureBoot Off}

		if ($_.StorageNetwork -eq 'Yes'){
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage1
			$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name Storage2
			$VMTemp | Get-VMNetworkAdapter -Name Storage1 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet1+$IP.ToString()) -Subnet 255.255.255.0
			$VMTemp | Get-VMNetworkAdapter -Name Storage2 | Set-VMNetworkConfiguration -IPAddress ($NetworkConfig.StorageNet2+$IP.ToString()) -Subnet 255.255.255.0
			$IP++
		}

		#Generate DSC Config
		if ($_.DSCMode -eq 'Pull'){
			if ($_.GUID -eq $Null){$Guid=[guid]::NewGuid()}
			else{$Guid=$_.Guid}
			LCM_HTTPPULL -ComputerName $_.VMName -Guid $Guid -OutputPath $workdir\temp\dscconfig
		}
		
		#configure nested virt
		if ($_.NestedVirt -eq 'Yes'){
			$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
		}		

		$Name=$_.VMName
		
		if ($_.SkipDjoin -eq 'Yes'){
			$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
		}
		else{
			if ($_.Win2012Djoin -eq 'Yes'){
				$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
			}
			else{
				$path="c:\$vmname.txt"
				Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path); djoin.exe /provision /domain corp /machine $Name /savefile $path /machineou "OU=Workshop,DC=corp,DC=contoso,DC=com"} -ArgumentList $Name,$path
				$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
				Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); del $path} -ArgumentList $path
				$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
			}
		}

		&"$workdir\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$workdir\Temp\Mountdir
		&"$workdir\Tools\dism\dism" /image:$workdir\Temp\Mountdir /Apply-Unattend:$unattendfile
		New-item -type directory $workdir\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
		copy $unattendfile $workdir\Temp\Mountdir\Windows\Panther\unattend.xml
		
		if ($_.DSCMode -eq 'Pull'){
			copy "$workdir\temp\dscconfig\$name.meta.mof" -Destination "$workdir\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
		}
		
		&"$workdir\Tools\dism\dism" /Unmount-Image /MountDir:$workdir\Temp\Mountdir /Commit

		#add toolsdisk
		if ($_.AddToolsVHD -eq 'Yes'){
			$VHD=New-VHD -ParentPath $toolsparent.fullname -Path "$folder\tools.vhdx"
			Write-Host "`t Adding Virtual Hard Disk" $VHD.Path " to $VMName"
			$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
		}

#endregion
        
        Write-Host "`t Attaching Shared Disks..."
		$ReplicaHdd | % {
			Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
			Write-Host "`t`t HDD "$_.path"size"($_.size /1GB)"GB added to $VMname"
		}

		$ReplicaLog | % {
			Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
			Write-Host "`t`t HDD "$_.path"size"($_.size /1GB)"GB added to $VMname"
		}

        
    }
}



################
# some Cleanup #
################

Remove-Item -Path "$workdir\temp" -Force -Recurse

#############
# Finishing #
#############

Write-Host "Finishing..." -ForegroundColor Cyan
#get-vm | where name -like $prefix* | Start-VM
$prefix=$labconfig.Prefix
Write-Host "Setting MacSpoofing On and AllowTeaming On" -ForegroundColor Cyan
Get-VMNetworkAdapter -VMName $prefix* | Set-VMNetworkAdapter -MacAddressSpoofing On -AllowTeaming On
Get-VM | where name -like $prefix*  | % { Write-Host "Machine "$_.VMName"provisioned" -ForegroundColor Green }

Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript

Write-Host "Press any key to continue ..." -ForegroundColor Green
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL