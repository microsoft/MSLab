# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
	Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
	exit
}

#############
# Functions #
#############

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

function WriteErrorAndExit($message)
{
	Write-Host $message -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}

Function CreateUnattendFileBlob
    #Create Unattend (parameter is Blob)
    {
param (
    [parameter(Mandatory=$true)]
    [string]
    $Blob,
    [parameter(Mandatory=$true)]
    [string]
    $AdminPassword,
	[parameter(Mandatory=$false)]
    [string]
    $Specialize
)

    if ( Test-Path "Unattend.xml" ) {
      Remove-Item .\Unattend.xml
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
      <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
	$Specialize
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
    $AdminPassword,
	[parameter(Mandatory=$false)]
    [string]
    $Specialize,
	[parameter(Mandatory=$false)]
    [string]
    $AdditionalAccount
)

    if ( Test-Path "Unattend.xml" ) {
      Remove-Item .\Unattend.xml
    }
    $unattendFile = New-Item "Unattend.xml" -type File
    $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
		<RegisteredOwner>PFE</RegisteredOwner>
      	<RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
	$Specialize
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
		$AdditionalAccount
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
    $AdminPassword,
	[parameter(Mandatory=$true)]
    [string]
    $DomainName
)

    if ( Test-Path "Unattend.xml" ) {
      Remove-Item .\Unattend.xml
    }
    $unattendFile = New-Item "Unattend.xml" -type File
    $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
		<RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Identification>
                <Credentials>
                    <Domain>$DomainName</Domain>
                    <Password>$AdminPassword</Password>
                    <Username>Administrator</Username>
                </Credentials>
				<JoinDomain>$DomainName</JoinDomain>			
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

Function AdditionalLocalAccountXML
#Creates Additional local account unattend piece
{
param (
    [parameter(Mandatory=$true)]
    [string]
    $AdminPassword,
	[parameter(Mandatory=$true)]
    [string]
    $AdditionalAdminName
)
@"
<LocalAccounts>
	<LocalAccount wcm:action="add">
		<Password>
			<Value>$AdminPassword</Value>
			<PlainText>true</PlainText>
		</Password>
		<Description>$AdditionalAdminName admin account</Description>
		<DisplayName>$AdditionalAdminName</DisplayName>
		<Group>Administrators</Group>
		<Name>$AdditionalAdminName</Name>
	</LocalAccount>
</LocalAccounts>
"@
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

<#
.Synopsis
   Function to wrap legacy programm
.DESCRIPTION
   Using this function you can run legacy program and search in output string 
.EXAMPLE
   WrapProcess -filename fltmc.exe -arguments "attach svhdxflt e:" -outputstring "Success"
.EXAMPLE
   Another example of how to use this cmdlet
#>
function WrapProcess
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([bool])]
    Param
    (
        # process name. For example fltmc.exe
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $filename,

        # arguments. for example "attach svhdxflt e:"
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        $arguments,

        # string to search. for example "attach svhdxflt e:"
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        $outputstring
    )
    Process
    {
    
        	$procinfo = New-Object System.Diagnostics.ProcessStartInfo
			$procinfo.FileName = $filename
			$procinfo.Arguments = $arguments
			$procinfo.UseShellExecute = $false
			$procinfo.CreateNoWindow = $true
			$procinfo.RedirectStandardOutput = $true
			$procinfo.RedirectStandardError = $true


			# Create a process object using the startup info
			$process = New-Object System.Diagnostics.Process
			$process.StartInfo = $procinfo
			# Start the process
			$process.Start() | Out-Null

			# test if process is still running
			if(!$process.HasExited){
                do
                {
                   Start-Sleep 1 
                }
                until ($process.HasExited -eq $true)
            }

			# get output 
			$out = $process.StandardOutput.ReadToEnd()

            if ($out.Contains($outputstring)) {
				$output=$true
			} else {
                $output=$false
			}
            return, $output
    }
}

##########################################################################################
#Some necessary stuff
##########################################################################################

Start-Transcript -Path "$PSScriptRoot\Deploy.log"

$StartDateTime = get-date
WriteInfoHighlighted "Script started at $StartDateTime"


##Load LabConfig....
. "$PSScriptRoot\LabConfig.ps1"


#####################
# Default variables #
#####################

If (!$LabConfig.DomainNetbiosName){
    $LabConfig.DomainNetbiosName="Corp"
}

If (!$LabConfig.DomainName){
    $LabConfig.DomainName="Corp.contoso.com"
}

If (!$LabConfig.DefaultOUName){
    $LabConfig.DefaultOUName="Workshop"
}

$DN=$null
$LabConfig.DomainName.Split(".") | ForEach-Object {
    $DN+="DC=$_,"   
}
$LabConfig.DN=$DN.TrimEnd(",")

$IP=1

WriteInfoHighlighted "List of variables used"
WriteInfo "`t Prefix used in lab is $($labconfig.prefix)"

$SwitchName=($labconfig.prefix+$LabConfig.SwitchName)
WriteInfo "`t Switchname is $SwitchName" 

WriteInfo "`t Workdir is $PSScriptRoot"

$LABfolder="$PSScriptRoot\LAB"
WriteInfo "`t LabFolder is $LabFolder"

$LABfolderDrivePath=$LABfolder.Substring(0,3)

$DisableWCF=@'
<component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<RunSynchronous>
		<RunSynchronousCommand wcm:action="add">
			<Path>reg add HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f</Path>
			<Description>disable consumer features</Description>
			<Order>5</Order>
		</RunSynchronousCommand>
	</RunSynchronous>
</component>
'@

$ExternalSwitchName="$($Labconfig.Prefix)$($LabConfig.Switchname)-External"

#####################


##########################################################################################
# Some Additional checks and prereqs
##########################################################################################

	#checking if Prefix is not empty

if (!$LabConfig.Prefix){
    WriteErrorAndExit "`t Prefix is empty. Exiting"
}

	# Checking for Compatible OS
WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"

$BuildNumber=Get-WindowsBuildNumber
if ($BuildNumber -ge 10586){
	WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
    }else{
    WriteErrorAndExit "`t Windows 10/ Server 2016 not detected. Exiting"
}

# Checking for NestedVirt
if ($LABConfig.VMs.NestedVirt -contains $True){
	$BuildNumber=Get-WindowsBuildNumber
	if ($BuildNumber -ge 14393){
		WriteSuccess "`t Windows is build greated than 14393. NestedVirt will work"
		}else{
		WriteErrorAndExit "`t Windows build older than 14393 detected. NestedVirt will not work. Exiting"
		}
}

# Checking for vTPM support
if ($LABConfig.VMs.vTPM -contains $true){
	$BuildNumber=Get-WindowsBuildNumber
	if ($BuildNumber -ge 14393){
		WriteSuccess "`t Windows is build greated than 14393. vTPM will work"
		}else{
		WriteErrorAndExit "`t Windows build older than 14393 detected. vTPM will not work Exiting"
	}
	if (((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus -ne 0) -and ((Get-Process "secure system") -ne $null )){
		WriteSuccess "`t Virtualization Based Security is running. vTPM can be enabled"
		}else{
		WriteErrorAndExit "`t Virtualization based security is not running. Enable VBS, or remove vTPM from configuration"
	}
	#load Guardian
	$guardian=Get-HgsGuardian | Select-Object -first 1
	if($guardian -eq $null){
		$guardian=New-HgsGuardian -Name LabGuardian -GenerateCertificates
		WriteInfo "`t HGS with name LabGuardian created"
	}	
}

#Check support for shared disks + enable if possible

if ($LABConfig.VMs.Configuration -contains "Shared" -or $LABConfig.VMs.Configuration -contains "Replica"){
	WriteInfoHighlighted "Configuration contains Shared or Replica scenario"
    WriteInfo "Checking support for shared disks"
    $OS=Get-WmiObject win32_operatingsystem
	if (($OS.caption -like "*Server*") -and $OS.version -gt 10){
		WriteInfo "`t Installing Failover Clustering Feature"
		$FC=Install-WindowsFeature Failover-Clustering
		If ($FC.Success -eq $True){
			WriteSuccess "`t`t Failover Clustering Feature installed with exit code: $($FC.ExitCode)" 
		}else{
			WriteError "`t`t Failover Clustering Feature was not installed with exit code: $($FC.ExitCode)"
		}
	}

	WriteInfoHighlighted "`t Attaching svhdxflt filter driver to drive $LABfolderDrivePath"


	if (WrapProcess -filename fltmc.exe -arguments "attach svhdxflt $LABfolderDrivePath" -outputstring "successful"){
		WriteSuccess "`t Svhdx filter driver was successfully attached"
	}else{
		if (WrapProcess -filename fltmc.exe -arguments "attach svhdxflt $LABfolderDrivePath" -outputstring "0x801f0012"){
		WriteSuccess "`t Svhdx filter driver was already attached"
		}else{
		WriteErrorAndExit "`t unable to load svhdx filter driver. Exiting Please use Server SKU or figure out how to install svhdx into the client SKU"
		}
	}

	WriteInfoHighlighted "Adding svhdxflt to registry for autostart"	
	if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters)){
		New-Item HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters
	}   
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters -Name AutoAttachOnNonCSVVolumes -PropertyType DWORD -Value 1 -force
}

#Check if Hyper-V is installed

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


#Create Switches

WriteInfoHighlighted "Creating Switch"
WriteInfo "`t Checking if $SwitchName already exists..."

if ((Get-VMSwitch -Name $SwitchName -ErrorAction Ignore) -eq $Null){ 
    WriteInfo "`t Creating $SwitchName..."
    New-VMSwitch -SwitchType Private -Name $SwitchName
    
}else{
	$SwitchNameExists=$True
    WriteInfoHighlighted "`t $SwitchName exists. Looks like lab with same prefix exists. "
}

if ($Labconfig.Internet){
	WriteInfoHighlighted "Internet connectivity requested"
	WriteInfo "`t Detecting external vSwitch $ExternalSwitchName"
	$ExternalSwitch=Get-VMSwitch -SwitchType External -Name $ExternalSwitchName -ErrorAction Ignore
	if ($ExternalSwitch){
		WriteSuccess "`t External vSwitch  $ExternalSwitchName detected"
	}else{
		WriteInfo "`t Detecting external VMSwitch"
		$ExtSwitch=Get-VMSwitch -SwitchType External
		if (!$ExtSwitch){
			WriteInfoHighlighted "`t No External Switch detected. Will create one "
			$TempNetAdapters=get-netadapter | Where-Object status -eq up
			if (!$TempNetAdapters){
				WriteErrorAndExit "No Adapters with Status -eq UP detected. Exitting"
			}
			if ($TempNetAdapters.name.count -eq 1){
				WriteInfo "`t Just one connected NIC detected ($($TempNetAdapters.name)). Will create vSwitch connected to it"
				$ExternalSwitch=New-VMSwitch -NetAdapterName $TempNetAdapters.name -Name $ExternalSwitchName -AllowManagementOS $true
			}
			if ($TempNetAdapters.name.count -gt 1){
				WriteInfo "`t More than 1 NIC detected"
				WriteInfoHighlighted "`t Please select NetAdapter you want to use for vSwitch"
				$tempNetAdapter=get-netadapter | Where-Object status -eq up | Out-GridView -OutputMode Single -Title "Please select adapter you want to use for External vSwitch" 
				if (!$tempNetAdapter){
					WriteErrorAndExit "You did not select any net adapter. Exitting."
				}
				$ExternalSwitch=New-VMSwitch -NetAdapterName $tempNetAdapter.name -Name $ExternalSwitchName -AllowManagementOS $true
			}
		}
		if ($ExtSwitch.count -eq 1){
			WriteSuccess "`t External vswitch $($ExtSwitch.name) found. Will be used for connecting lab to internet"
			$ExternalSwitch=$ExtSwitch
		}
		if ($ExtSwitch.count -gt 1){
			WriteInfoHighlighted "`t More than 1 External Switch found. Please chose what switch you want to use for internet connectivity"
			$ExternalSwitch=Get-VMSwitch -SwitchType External | Out-GridView -OutputMode Single -Title 'Please Select External Switch you want to use for Internet Connectivity'
		}
	}
}

WriteInfo "Testing if lab already exists."
#Testing if lab already exists.
if ($SwitchNameExists){
	if ((Get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue) -ne $null){
		$LABExists=$True
		WriteInfoHighlighted "`t Lab already exists. If labconfig contains additional VMs, they will be added."
	}
}

#If lab exists, correct starting IP will be calculated
if (($LABExists) -and ($labconfig.AdditionalNetworksInDC)) {
	$IP++
}

$Labconfig.VMs | ForEach-Object {
	if (((Get-VM -Name ($labconfig.prefix+$_.vmname) -ErrorAction SilentlyContinue) -ne $null) -and ($_.AdditionalNetworks -eq $True)){
		$IP++
	}
}

WriteInfo "Starting IP for AdditionalNetworks is $IP"

WriteInfoHighlighted "Creating Mountdir"
New-Item "$PSScriptRoot\Temp\MountDir" -ItemType Directory -Force

WriteInfoHighlighted "Creating VMs dir"
New-Item "$PSScriptRoot\LAB\VMs" -ItemType Directory -Force


######################
# Getting tools disk #
######################

#get path for Tools disk

WriteInfoHighlighted "Looking for Tools Parent Disks"
$toolsparent=Get-ChildItem "$PSScriptRoot\ParentDisks" -Recurse | Where-Object name -eq tools.vhdx
if ($toolsparent -eq $null){
	WriteErrorAndExit "`t Tools parent disk not found"
}else{
WriteInfo "`t Tools parent disk $($toolsparent.fullname) found"
}

################
# Importing DC #
################

if (!(get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue)){
	WriteInfoHighlighted "Looking for DC to be imported"
	get-childitem $LABFolder -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
		$DC=Import-VM -Path $_.FullName
		if ($DC -eq $null){
			WriteErrorAndExit "DC was not imported successfully Press any key to continue ..."
		}
	}

	WriteInfo "`t Virtual Machine $($DC.name) located in folder $($DC.Path) imported"

	$DC | Checkpoint-VM -SnapshotName Initial
	WriteInfo "`t Virtual Machine $($DC.name) checkpoint created"
		
	Start-Sleep -Seconds 5

	WriteInfo "`t Configuring Network"

	$DC | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
	If($labconfig.MGMTNICsInDC -gt 8){
		$labconfig.MGMTNICsInDC=8
	}

	If($labconfig.MGMTNICsInDC -ge 2){
		2..$labconfig.MGMTNICsInDC | ForEach-Object {
			WriteInfo "`t Adding Network Adapter Management$_"
			$DC | Add-VMNetworkAdapter -Name Management$_
		}
	}

	$DC | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

	if ($labconfig.AdditionalNetworksInDC -eq $True){
		WriteInfo "`t`t Adding network Additional networks"
		$Labconfig.AdditionalNetworksConfig | ForEach-Object {
			$DC | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $_.NetName
			$DC | Get-VMNetworkAdapter -Name $_.NetName | Set-VMNetworkConfiguration -IPAddress ($_.NetAddress+$IP.ToString()) -Subnet $_.Subnet
			if($_.NetVLAN -ne 0){ $DC | Get-VMNetworkAdapter -Name $_.NetName  | Set-VMNetworkAdapterVlan -VlanId $_.NetVLAN -Access }
		}
		$IP++
	}

	if ($labconfig.internet){
		WriteInfo "`t`t Adding Network Adapter Internet and connecting to $($ExternalSwitch.Name)"
		$DC | Add-VMNetworkAdapter -Name Internet -DeviceNaming On
		$DC | Get-VMNetworkAdapter -Name Internet | Connect-VMNetworkAdapter -SwitchName $ExternalSwitch.Name
	}

	WriteInfo "`t Adding Tools disk to DC machine"

	$VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$LABFolder\VMs\tools.vhdx"

	WriteInfo "`t `t Adding Virtual Hard Disk $($VHD.Path)"
	$DC | Add-VMHardDiskDrive -Path $vhd.Path

	WriteInfo  "`t Starting Virtual Machine $($DC.name)"
	$DC | Start-VM

	WriteInfo "`t Renaming $($DC.name) to $($labconfig.Prefix+$DC.name)"
	$DC | Rename-VM -NewName ($labconfig.Prefix+$DC.name)
}else{
	$DC=get-vm -Name ($labconfig.prefix+"DC")
}

#Start DC if it is not running
if ($DC.State -ne "Running"){
	WriteInfo "DC was not started. Starting now..."
	$DC | Start-VM
}

############################
# Testing DC To come alive #
############################

#Credentials for Session
$username = "$($Labconfig.DomainNetbiosName)\Administrator"
$password = $LabConfig.AdminPassword
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

WriteInfoHighlighted "Waiting for Active Directory on $($DC.name) to be Started."
do{
$test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
	param($labconfig);
	Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue}
	Start-Sleep 5
}
until ($test -ne $Null)
WriteSuccess "Active Directory on $($DC.name) is up."

if (!$LABExists){
	WriteInfoHighlighted "Performing some some actions against DC with powershell Direct"
	#make tools disk online
	WriteInfo "`t Making tools disk online"
	Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | Where-Object operationalstatus -eq offline | Set-Disk -IsReadOnly $false}
	Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | Where-Object operationalstatus -eq offline | Set-Disk -IsOffline $false}

	#authorize DHCP (if more networks added, then re-authorization is needed. Also if you add multiple networks once, it messes somehow even with parent VM for DC)
	WriteInfo "`t Authorizing DHCP"
	Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ScriptBlock {
		param($labconfig);
		Get-DhcpServerInDC | Remove-DHCPServerInDC
		Add-DhcpServerInDC -DnsName "DC.$($Labconfig.DomainName)" -IPAddress 10.0.0.1
	}
	If ($labconfig.internet){
		WriteInfoHighlighted "`t Configuring NAT"
		WriteInfo "`t `t Installing Routing and RSAT-RemoteAccess features"
		$cmd=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
			Install-WindowsFeature -Name Routing,RSAT-RemoteAccess -IncludeAllSubFeature -WarningAction Ignore
		}
		if ($cmd.restartneeded -eq "Yes"){
			WriteInfo "`t `t Restart of DC is requested"
			WriteInfo "`t `t Restarting DC"
			$DC | Restart-VM -Force
			Start-Sleep 10
			WriteInfoHighlighted "`t `t Waiting for Active Directory on $($DC.name) to be Started."
			do{
			$test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
				param($labconfig);
				Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue}
				Start-Sleep 5
			}
			until ($test -ne $Null)
			WriteSuccess "`t `t Active Directory on $($DC.name) is up."
		}
		WriteInfoHighlighted "`t Requesting DNS settings from Host"
		$vNICName=(Get-VMNetworkAdapter -ManagementOS -SwitchName $externalswitch.Name).name | select -First 1 #in case multiple adapters are in managementos
		$DNSServers=@()
		$DNSServers+=(Get-NetIPConfiguration -InterfaceAlias "vEthernet ($vNICName)").DNSServer.ServerAddresses #grab DNS IP from vNIC
		$DNSServers+="8.8.8.8","208.67.222.222" #Adding OpenDNS and Google DNS servers
		WriteInfoHighlighted "`t `t Configuring NAT with netSH and starting services"
		Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $DNSServers -ScriptBlock {	
			param($DNSServers);
			Set-Service -Name RemoteAccess -StartupType Automatic
			Start-Service -Name RemoteAccess
			netsh.exe routing ip nat install
			netsh.exe routing ip nat add interface (Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq "Internet").Name
			netsh.exe routing ip nat set interface (Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq "Internet").Name mode=full
			netsh.exe ras set conf confstate = enabled
			netsh.exe routing ip dnsproxy install
			Restart-Service -Name RemoteAccess -WarningAction SilentlyContinue
    		foreach ($DNSServer in $DNSServers){
        		Add-DnsServerForwarder $DNSServer
    		}
		}
	}
}
#################
# Provision VMs  #
#################

WriteInfoHighlighted "Creating DSC config to configure DC as pull server"

#DCM Config
[DSCLocalConfigurationManager()]
Configuration PullClientConfig 
{
    param
        (
            [Parameter(Mandatory=$true)]
            [string[]]$ComputerName,

            [Parameter(Mandatory=$true)]
			[string[]]$DSCConfig,

			[Parameter(Mandatory=$true)]
			[string[]]$DomainName
        )      	
	Node $ComputerName {
	
		Settings{
		
			AllowModuleOverwrite = $True
            ConfigurationMode = 'ApplyAndAutoCorrect'
			RefreshMode = 'Pull'
			RebootNodeIfNeeded = $True
			ActionAfterReboot = 'ContinueConfiguration'
            }

            ConfigurationRepositoryWeb PullServerWeb { 
        	ServerURL = "http://dc.$($DomainName):8080/PSDSCPullServer.svc"
            AllowUnsecureConnection = $true
			RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
			ConfigurationNames = $DSCConfig
            }

            ReportServerWeb PullServerReports {
            ServerURL = "http://dc.$($DomainName):8080/PSDSCPullServer.svc"
            RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
            }

			$DSCConfig | ForEach-Object {
				PartialConfiguration $_
                {
                RefreshMode = 'Pull'
            	ConfigurationSource = '[ConfigurationRepositoryWeb]PullServerWeb'
				}
			}
	}
}

WriteInfoHighlighted 'Processing $LabConfig.VMs, creating VMs'

$LABConfig.VMs.GetEnumerator() | ForEach-Object {

	if (!(Get-VM -Name ($labconfig.prefix+$_.vmname) -ErrorAction SilentlyContinue)){
		if ($_.configuration -eq 'Shared'){
			$VMSet=$_.VMSet
			if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
					$SSDSize=$_.SSDSize
					$HDDSize=$_.HDDSize
					$SharedSSDs=$null
					$SharedHDDs=$null
					If (($_.SSDNumber -ge 1) -and ($_.SSDNumber -ne $null)){  
						$SharedSSDs= 1..$_.ssdnumber | ForEach-Object {New-vhd -Path "$LABfolder\VMs\SharedSSD-$VMSet-$_.VHDS" -Dynamic –Size $SSDSize}
						$SharedSSDs | ForEach-Object {WriteInfo "`t Disk SSD $($_.path) size $($_.size /1GB)GB created"}
					}
					If (($_.HDDNumber -ge 1) -and ($_.HDDNumber -ne $null)){  
						$SharedHDDs= 1..$_.hddnumber | ForEach-Object {New-VHD -Path "$LABfolder\VMs\SharedHDD-$VMSet-$_.VHDS" -Dynamic –Size $HDDSize}
						$SharedHDDs | ForEach-Object {WriteInfo "`t Disk HDD $($_.path) size $($_.size /1GB)GB created"}
					}
			}else{
					$SharedSSDs=Get-VHD -Path "$LABfolder\VMs\SharedSSD*$VMSet*.VHDS"
					$SharedHDDs=Get-VHD -Path "$LABfolder\VMs\SharedHDD*$VMSet*.VHDS"
			}

#region Todo:convert this Block to function
			WriteInfoHighlighted "Creating VM $($_.VMName)"
			WriteInfo "`t Looking for Parent Disk"
			$serverparent=Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $_.ParentVHD
			
			if ($serverparent -eq $null){
				WriteErrorAndExit "Server parent disk $($_.ParentVHD) not found"
			}else{
				WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
			}
					
			$VMname=$Labconfig.Prefix+$_.VMName
			$folder="$LabFolder\VMs\$VMname"
			$vhdpath="$folder\$VMname.vhdx"
			WriteInfo "`t Creating OS VHD"
			New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
			WriteInfo "`t Creating VM"
			$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
			$VMTemp | Set-VMProcessor -Count 2
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
			$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1

			$MGMTNICs=$_.MGMTNICs
			If($MGMTNICs -eq $null){
				$MGMTNICs = 2
			}

			If($MGMTNICs -gt 8){
				$MGMTNICs=8
			}

			If($MGMTNICs -ge 2){
				2..$MGMTNICs | ForEach-Object {
					WriteInfo "`t Adding Network Adapter Management$_"
					$VMTemp | Add-VMNetworkAdapter -Name Management$_
				}
			}
			WriteInfo "`t Connecting vNIC to $switchname"
			$VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

			if ($LabConfig.Secureboot -eq $False) {
				WriteInfo "`t Disabling Secureboot"
				$VMTemp | Set-VMFirmware -EnableSecureBoot Off
			}

			if ($_.AdditionalNetworks -eq $True){
				$LabConfig.AdditionalNetworksConfig | ForEach-Object {
					$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $_.NetName
					$VMTemp | Get-VMNetworkAdapter -Name $_.NetName  | Set-VMNetworkConfiguration -IPAddress ($_.NetAddress+$IP.ToString()) -Subnet $_.Subnet
					if($_.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $_.NetName | Set-VMNetworkAdapterVlan -VlanId $_.NetVLAN -Access }
				}
				$IP++
			}

			#Generate DSC Config
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Setting DSC Mode to Pull"
				PullClientConfig -ComputerName $_.VMName -DSCConfig $_.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
			}
			
			#configure nested virt
			if ($_.NestedVirt -eq $True){
				WriteInfo "`t Enabling NestedVirt"
				$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			}		

			#configure vTPM
			if ($_.vTPM -eq $True){
				WriteInfo "`t Enabling vTPM"
				$keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
				Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
				Enable-VMTPM -VM $VMTemp 
			}

			#set MemoryMinimumBytes
			if ($_.MemoryMinimumBytes -ne $null){
				WriteInfo "`t Configuring MemoryMinimumBytes to $($_.MemoryMinimumBytes/1MB)MB"
				Set-VM -VM $VMTemp -MemoryMinimumBytes $_.MemoryMinimumBytes
			}
			
			#Set static Memory
			if ($_.StaticMemory -eq $true){
				WriteInfo "`t Configuring StaticMemory"
				$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
			}		

			$Name=$_.VMName
			
			if ($_.SkipDjoin -eq $True){
				WriteInfo "`t Skipping Djoin"				
				if ($_.DisableWCF -eq $True){
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t WCF will be disabled and Additional Local Admin $($_.AdditionalLocalAdmin) will be added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							WriteInfo "`t WCF will be disabled"
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
						}			
				}else{
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t Additional Local Admin $($_.AdditionalLocalAdmin) will added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
						}	
					}
			}else{
				if ($_.Win2012Djoin -eq $True){
					WriteInfo "`t Creating Unattend with win2012 domain join"
					$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -DomainName $Labconfig.DomainName
				}else{
					WriteInfo "`t Creating Unattend with djoin blob"
					$path="c:\$vmname.txt"
					Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $labconfig.DomainNetbiosName /machine $Name /savefile $path /machineou "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"} -ArgumentList $Name,$path,$Labconfig
					$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
					Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
					if ($_.DisableWCF -eq $True){
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
					}else{
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
					}
				}
			}

			WriteInfo "`t Adding unattend to VHD"
			Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
			Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
			#&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\Mountdir
			#&"$PSScriptRoot\Tools\dism\dism" /image:$PSScriptRoot\Temp\Mountdir /Apply-Unattend:$unattendfile
			New-item -type directory $PSScriptRoot\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
			Copy-Item $unattendfile $PSScriptRoot\Temp\Mountdir\Windows\Panther\unattend.xml
			
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Adding metaconfig.mof to VHD"
				Copy-Item "$PSScriptRoot\temp\dscconfig\$name.meta.mof" -Destination "$PSScriptRoot\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
			}
			
			Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
			#&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\Mountdir /Commit

			#add toolsdisk
			if ($_.AddToolsVHD -eq $True){
				$VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$folder\tools.vhdx"
				WriteInfoHighlighted "`t Adding Virtual Hard Disk $($VHD.Path)"
				$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
			}

#endregion
			
			WriteInfoHighlighted "`t Attaching Shared Disks to $VMname"

			$SharedSSDs | ForEach-Object {
				Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
				WriteInfo "`t`t SSD $($_.path) size $($_.size /1GB)GB added to $VMname"
			}
			$SharedHDDs | ForEach-Object {
				Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
				WriteInfo "`t`t HDD $($_.path) size $($_.size /1GB)GB added to $VMname"
			}
			
		}
		
		if ($_.configuration -eq 'Simple'){

#region Todo:convert this Block to function
			WriteInfoHighlighted "Creating VM $($_.VMName)"
			WriteInfo "`t Looking for Parent Disk"
			$serverparent=Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $_.ParentVHD
			
			if ($serverparent -eq $null){
				WriteErrorAndExit "Server parent disk $($_.ParentVHD) not found"
			}else{
				WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
			}
					
			$VMname=$Labconfig.Prefix+$_.VMName
			$folder="$LabFolder\VMs\$VMname"
			$vhdpath="$folder\$VMname.vhdx"
			WriteInfo "`t Creating OS VHD"
			New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
			WriteInfo "`t Creating VM"
			$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
			$VMTemp | Set-VMProcessor -Count 2
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
			$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1

			$MGMTNICs=$_.MGMTNICs
			If($MGMTNICs -eq $null){
				$MGMTNICs = 2
			}

			If($MGMTNICs -gt 8){
				$MGMTNICs=8
			}

			If($MGMTNICs -ge 2){
				2..$MGMTNICs | ForEach-Object {
					WriteInfo "`t Adding Network Adapter Management$_"
					$VMTemp | Add-VMNetworkAdapter -Name Management$_
				}
			}
			WriteInfo "`t Connecting vNIC to $switchname"
			$VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

			if ($LabConfig.Secureboot -eq $False) {
				WriteInfo "`t Disabling Secureboot"
				$VMTemp | Set-VMFirmware -EnableSecureBoot Off
			}

			if ($_.AdditionalNetworks -eq $True){
				$LabConfig.AdditionalNetworksConfig | ForEach-Object {
					$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $_.NetName
					$VMTemp | Get-VMNetworkAdapter -Name $_.NetName  | Set-VMNetworkConfiguration -IPAddress ($_.NetAddress+$IP.ToString()) -Subnet $_.Subnet
					if($_.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $_.NetName | Set-VMNetworkAdapterVlan -VlanId $_.NetVLAN -Access }
				}
				$IP++
			}

			#Generate DSC Config
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Setting DSC Mode to Pull"
				PullClientConfig -ComputerName $_.VMName -DSCConfig $_.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
			}
			
			#configure nested virt
			if ($_.NestedVirt -eq $True){
				WriteInfo "`t Enabling NestedVirt"
				$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			}		

			#configure vTPM
			if ($_.vTPM -eq $True){
				WriteInfo "`t Enabling vTPM"
				$keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
				Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
				Enable-VMTPM -VM $VMTemp 
			}

			#set MemoryMinimumBytes
			if ($_.MemoryMinimumBytes -ne $null){
				WriteInfo "`t Configuring MemoryMinimumBytes to $($_.MemoryMinimumBytes/1MB)MB"
				Set-VM -VM $VMTemp -MemoryMinimumBytes $_.MemoryMinimumBytes
			}
			
			#Set static Memory
			if ($_.StaticMemory -eq $true){
				WriteInfo "`t Configuring StaticMemory"
				$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
			}		

			$Name=$_.VMName
			
			if ($_.SkipDjoin -eq $True){
				WriteInfo "`t Skipping Djoin"				
				if ($_.DisableWCF -eq $True){
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t WCF will be disabled and Additional Local Admin $($_.AdditionalLocalAdmin) will be added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							WriteInfo "`t WCF will be disabled"
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
						}			
				}else{
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t Additional Local Admin $($_.AdditionalLocalAdmin) will added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
						}	
					}
			}else{
				if ($_.Win2012Djoin -eq $True){
					WriteInfo "`t Creating Unattend with win2012 domain join"
					$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -DomainName $Labconfig.DomainName
				}else{
					WriteInfo "`t Creating Unattend with djoin blob"
					$path="c:\$vmname.txt"
					Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $labconfig.DomainNetbiosName /machine $Name /savefile $path /machineou "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"} -ArgumentList $Name,$path,$Labconfig
					$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
					Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
					if ($_.DisableWCF -eq $True){
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
					}else{
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
					}
				}
			}

			WriteInfo "`t Adding unattend to VHD"
			Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
			Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
			#&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\Mountdir
			#&"$PSScriptRoot\Tools\dism\dism" /image:$PSScriptRoot\Temp\Mountdir /Apply-Unattend:$unattendfile
			New-item -type directory $PSScriptRoot\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
			Copy-Item $unattendfile $PSScriptRoot\Temp\Mountdir\Windows\Panther\unattend.xml
			
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Adding metaconfig.mof to VHD"
				Copy-Item "$PSScriptRoot\temp\dscconfig\$name.meta.mof" -Destination "$PSScriptRoot\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
			}
			
			Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
			#&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\Mountdir /Commit

			#add toolsdisk
			if ($_.AddToolsVHD -eq $True){
				$VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$folder\tools.vhdx"
				WriteInfoHighlighted "`t Adding Virtual Hard Disk $($VHD.Path)"
				$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
			}

#endregion
		}

		if ($_.configuration -eq 'S2D'){

#region Todo:convert this Block to function
			WriteInfoHighlighted "Creating VM $($_.VMName)"
			WriteInfo "`t Looking for Parent Disk"
			$serverparent=Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $_.ParentVHD
			
			if ($serverparent -eq $null){
				WriteErrorAndExit "Server parent disk $($_.ParentVHD) not found"
			}else{
				WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
			}
					
			$VMname=$Labconfig.Prefix+$_.VMName
			$folder="$LabFolder\VMs\$VMname"
			$vhdpath="$folder\$VMname.vhdx"
			WriteInfo "`t Creating OS VHD"
			New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
			WriteInfo "`t Creating VM"
			$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
			$VMTemp | Set-VMProcessor -Count 2
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
			$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1

			$MGMTNICs=$_.MGMTNICs
			If($MGMTNICs -eq $null){
				$MGMTNICs = 2
			}

			If($MGMTNICs -gt 8){
				$MGMTNICs=8
			}

			If($MGMTNICs -ge 2){
				2..$MGMTNICs | ForEach-Object {
					WriteInfo "`t Adding Network Adapter Management$_"
					$VMTemp | Add-VMNetworkAdapter -Name Management$_
				}
			}
			WriteInfo "`t Connecting vNIC to $switchname"
			$VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

			if ($LabConfig.Secureboot -eq $False) {
				WriteInfo "`t Disabling Secureboot"
				$VMTemp | Set-VMFirmware -EnableSecureBoot Off
			}

			if ($_.AdditionalNetworks -eq $True){
				$LabConfig.AdditionalNetworksConfig | ForEach-Object {
					$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $_.NetName
					$VMTemp | Get-VMNetworkAdapter -Name $_.NetName  | Set-VMNetworkConfiguration -IPAddress ($_.NetAddress+$IP.ToString()) -Subnet $_.Subnet
					if($_.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $_.NetName | Set-VMNetworkAdapterVlan -VlanId $_.NetVLAN -Access }
				}
				$IP++
			}

			#Generate DSC Config
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Setting DSC Mode to Pull"
				PullClientConfig -ComputerName $_.VMName -DSCConfig $_.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
			}
			
			#configure nested virt
			if ($_.NestedVirt -eq $True){
				WriteInfo "`t Enabling NestedVirt"
				$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			}		

			#configure vTPM
			if ($_.vTPM -eq $True){
				WriteInfo "`t Enabling vTPM"
				$keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
				Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
				Enable-VMTPM -VM $VMTemp 
			}

			#set MemoryMinimumBytes
			if ($_.MemoryMinimumBytes -ne $null){
				WriteInfo "`t Configuring MemoryMinimumBytes to $($_.MemoryMinimumBytes/1MB)MB"
				Set-VM -VM $VMTemp -MemoryMinimumBytes $_.MemoryMinimumBytes
			}
			
			#Set static Memory
			if ($_.StaticMemory -eq $true){
				WriteInfo "`t Configuring StaticMemory"
				$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
			}		

			$Name=$_.VMName
			
			if ($_.SkipDjoin -eq $True){
				WriteInfo "`t Skipping Djoin"				
				if ($_.DisableWCF -eq $True){
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t WCF will be disabled and Additional Local Admin $($_.AdditionalLocalAdmin) will be added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							WriteInfo "`t WCF will be disabled"
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
						}			
				}else{
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t Additional Local Admin $($_.AdditionalLocalAdmin) will added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
						}	
					}
			}else{
				if ($_.Win2012Djoin -eq $True){
					WriteInfo "`t Creating Unattend with win2012 domain join"
					$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -DomainName $Labconfig.DomainName
				}else{
					WriteInfo "`t Creating Unattend with djoin blob"
					$path="c:\$vmname.txt"
					Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $labconfig.DomainNetbiosName /machine $Name /savefile $path /machineou "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"} -ArgumentList $Name,$path,$Labconfig
					$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
					Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
					if ($_.DisableWCF -eq $True){
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
					}else{
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
					}
				}
			}

			WriteInfo "`t Adding unattend to VHD"
			Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
			Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
			#&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\Mountdir
			#&"$PSScriptRoot\Tools\dism\dism" /image:$PSScriptRoot\Temp\Mountdir /Apply-Unattend:$unattendfile
			New-item -type directory $PSScriptRoot\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
			Copy-Item $unattendfile $PSScriptRoot\Temp\Mountdir\Windows\Panther\unattend.xml
			
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Adding metaconfig.mof to VHD"
				Copy-Item "$PSScriptRoot\temp\dscconfig\$name.meta.mof" -Destination "$PSScriptRoot\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
			}
			
			Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
			#&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\Mountdir /Commit

			#add toolsdisk
			if ($_.AddToolsVHD -eq $True){
				$VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$folder\tools.vhdx"
				WriteInfoHighlighted "`t Adding Virtual Hard Disk $($VHD.Path)"
				$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
			}

#endregion
						
			If (($_.SSDNumber -ge 1) -and ($_.SSDNumber -ne $null)){         
				$SSDSize=$_.SSDSize
				$SSDs= 1..$_.SSDNumber | ForEach-Object { New-vhd -Path "$folder\SSD-$_.VHDX" -Dynamic –Size $SSDSize}
				WriteInfoHighlighted "`t Adding Virtual SSD Disks"
				$SSDs | ForEach-Object {
					Add-VMHardDiskDrive -Path $_.path -VMName $VMname
					WriteInfo "`t`t SSD $($_.path) size $($_.size /1GB)GB added to $VMname"
				}
			}

			If (($_.HDDNumber -ge 1) -and ($_.HDDNumber -ne $null)) {
				$HDDSize=$_.HDDSize
				$HDDs= 1..$_.HDDNumber | ForEach-Object { New-VHD -Path "$folder\HDD-$_.VHDX" -Dynamic –Size $HDDSize}
				WriteInfoHighlighted "`t Adding Virtual HDD Disks"
				$HDDs | ForEach-Object {
				Add-VMHardDiskDrive -Path $_.path -VMName $VMname
				WriteInfo "`t`t HDD $($_.path) size $($_.size /1GB)GB added to $VMname"
				}	
			}      
		}
			
		if ($_.configuration -eq 'Replica'){
			
			$VMSet=$_.VMSet
			if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
				$ReplicaHDD= New-vhd -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS" -Dynamic –Size $_.ReplicaHDDSize
				$ReplicaHDD | ForEach-Object {WriteInfo "`t`t ReplicaHDD $($_.path) size $($_.size /1GB)GB created"}
				$ReplicaLog= New-vhd -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS" -Dynamic –Size $_.ReplicaLogSize
				$ReplicaLog | ForEach-Object {WriteInfo "`t`t ReplicaLog $($_.path) size $($_.size /1GB)GB created"}
			}else{
				$ReplicaHDD=Get-VHD -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS"
				$ReplicaLog=Get-VHD -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS"
			}
			
#region Todo:convert this Block to function
			WriteInfoHighlighted "Creating VM $($_.VMName)"
			WriteInfo "`t Looking for Parent Disk"
			$serverparent=Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $_.ParentVHD
			
			if ($serverparent -eq $null){
				WriteErrorAndExit "Server parent disk $($_.ParentVHD) not found"
			}else{
				WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
			}
					
			$VMname=$Labconfig.Prefix+$_.VMName
			$folder="$LabFolder\VMs\$VMname"
			$vhdpath="$folder\$VMname.vhdx"
			WriteInfo "`t Creating OS VHD"
			New-VHD -ParentPath $serverparent.fullname -Path $vhdpath
			WriteInfo "`t Creating VM"
			$VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $_.MemoryStartupBytes -path $folder -SwitchName $SwitchName -Generation 2
			$VMTemp | Set-VMProcessor -Count 2
			$VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
			$VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1

			$MGMTNICs=$_.MGMTNICs
			If($MGMTNICs -eq $null){
				$MGMTNICs = 2
			}

			If($MGMTNICs -gt 8){
				$MGMTNICs=8
			}

			If($MGMTNICs -ge 2){
				2..$MGMTNICs | ForEach-Object {
					WriteInfo "`t Adding Network Adapter Management$_"
					$VMTemp | Add-VMNetworkAdapter -Name Management$_
				}
			}
			WriteInfo "`t Connecting vNIC to $switchname"
			$VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

			if ($LabConfig.Secureboot -eq $False) {
				WriteInfo "`t Disabling Secureboot"
				$VMTemp | Set-VMFirmware -EnableSecureBoot Off
			}

			if ($_.AdditionalNetworks -eq $True){
				$LabConfig.AdditionalNetworksConfig | ForEach-Object {
					$VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $_.NetName
					$VMTemp | Get-VMNetworkAdapter -Name $_.NetName  | Set-VMNetworkConfiguration -IPAddress ($_.NetAddress+$IP.ToString()) -Subnet $_.Subnet
					if($_.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $_.NetName | Set-VMNetworkAdapterVlan -VlanId $_.NetVLAN -Access }
				}
				$IP++
			}

			#Generate DSC Config
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Setting DSC Mode to Pull"
				PullClientConfig -ComputerName $_.VMName -DSCConfig $_.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
			}
			
			#configure nested virt
			if ($_.NestedVirt -eq $True){
				WriteInfo "`t Enabling NestedVirt"
				$VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
			}		

			#configure vTPM
			if ($_.vTPM -eq $True){
				WriteInfo "`t Enabling vTPM"
				$keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
				Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
				Enable-VMTPM -VM $VMTemp 
			}

			#set MemoryMinimumBytes
			if ($_.MemoryMinimumBytes -ne $null){
				WriteInfo "`t Configuring MemoryMinimumBytes to $($_.MemoryMinimumBytes/1MB)MB"
				Set-VM -VM $VMTemp -MemoryMinimumBytes $_.MemoryMinimumBytes
			}
			
			#Set static Memory
			if ($_.StaticMemory -eq $true){
				WriteInfo "`t Configuring StaticMemory"
				$VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
			}		

			$Name=$_.VMName
			
			if ($_.SkipDjoin -eq $True){
				WriteInfo "`t Skipping Djoin"				
				if ($_.DisableWCF -eq $True){
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t WCF will be disabled and Additional Local Admin $($_.AdditionalLocalAdmin) will be added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							WriteInfo "`t WCF will be disabled"
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
						}			
				}else{
						if ($_.AdditionalLocalAdmin -ne $null){
							WriteInfo "`t Additional Local Admin $($_.AdditionalLocalAdmin) will added"
							$AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdminPassword $Labconfig.AdminPassword -AdditionalAdminName $_.AdditionalLocalAdmin
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -AdditionalAccount $AdditionalLocalAccountXML
						}else{
							$unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword
						}	
					}
			}else{
				if ($_.Win2012Djoin -eq $True){
					WriteInfo "`t Creating Unattend with win2012 domain join"
					$unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -DomainName $Labconfig.DomainName
				}else{
					WriteInfo "`t Creating Unattend with djoin blob"
					$path="c:\$vmname.txt"
					Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $labconfig.DomainNetbiosName /machine $Name /savefile $path /machineou "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"} -ArgumentList $Name,$path,$Labconfig
					$blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
					Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
					if ($_.DisableWCF -eq $True){
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -Specialize $DisableWCF
					}else{
						$unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword
					}
				}
			}

			WriteInfo "`t Adding unattend to VHD"
			Mount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -ImagePath $VHDPath -Index 1
			Use-WindowsUnattend -Path "$PSScriptRoot\Temp\mountdir" -UnattendPath $unattendFile 
			#&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$PSScriptRoot\Temp\Mountdir
			#&"$PSScriptRoot\Tools\dism\dism" /image:$PSScriptRoot\Temp\Mountdir /Apply-Unattend:$unattendfile
			New-item -type directory $PSScriptRoot\Temp\Mountdir\Windows\Panther -ErrorAction Ignore
			Copy-Item $unattendfile $PSScriptRoot\Temp\Mountdir\Windows\Panther\unattend.xml
			
			if ($_.DSCMode -eq 'Pull'){
				WriteInfo "`t Adding metaconfig.mof to VHD"
				Copy-Item "$PSScriptRoot\temp\dscconfig\$name.meta.mof" -Destination "$PSScriptRoot\Temp\Mountdir\Windows\system32\Configuration\metaconfig.mof"
			}
			
			Dismount-WindowsImage -Path "$PSScriptRoot\Temp\mountdir" -Save
			#&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\Temp\Mountdir /Commit

			#add toolsdisk
			if ($_.AddToolsVHD -eq $True){
				$VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$folder\tools.vhdx"
				WriteInfoHighlighted "`t Adding Virtual Hard Disk $($VHD.Path)"
				$VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
			}

#endregion
			
			WriteInfoHighlighted "`t Attaching Shared Disks..."
			$ReplicaHdd | ForEach-Object {
				Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
				WriteInfo "`t`t ReplicaHDD $($_.path) size $($_.size /1GB)GB added to $VMname"
			}

			$ReplicaLog | ForEach-Object {
				Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
				WriteInfo "`t`t ReplicaLog $($_.path) size $($_.size /1GB)GB added to $VMname"
			}

			
		}
	}
}

################
# some Cleanup #
################

Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse
if (Test-Path "$PSScriptRoot\unattend.xml") {remove-item "$PSScriptRoot\unattend.xml"}

#############
# Finishing #
#############

WriteInfoHighlighted "Finishing..." 
#get-vm | Where-Object name -like $($labconfig.Prefix) | Start-VM
WriteInfo "`t Setting MacSpoofing On and AllowTeaming On"
Set-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -MacAddressSpoofing On -AllowTeaming On
Get-VM | Where-Object name -like "$($labconfig.Prefix)*"  | ForEach-Object { WriteSuccess "Machine $($_.VMName) provisioned" }

if ($labconfig.AllowedVLans){
	WriteInfo "`t Configuring AllowedVlanIdList for Management NICs to $($LabConfig.AllowedVlans)"
	Get-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -Name Management* | Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList $LabConfig.AllowedVlans
}else{
	WriteInfo "`t Configuring AllowedVlanIdList for Management NICs to 1-10"
	Get-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -Name Management* | Set-VMNetworkAdapterVlan -Trunk -NativeVlanId 0 -AllowedVlanIdList "1-10"
}

WriteInfo "`t Configuring EnableHostResourceProtection on all VM processors"
Set-VMProcessor -EnableHostResourceProtection $true -VMName "$($labconfig.Prefix)*" 

WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
Stop-Transcript

WriteSuccess "Press any key to continue ..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL