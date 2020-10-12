#run all from DC

#region download and install binaries

#download folder location
$downloadfolder="$env:USERPROFILE\Downloads"

#Download files
$ProgressPreference="SilentlyContinue"
$files=@()
$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2026036" ; FileName="adksetup.exe" ; Description="Windows 10 ADK 1809"}
$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2022233" ; FileName="adkwinpesetup.exe" ; Description="WindowsPE 1809"}
$Files+=@{Uri="https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi" ; FileName="MicrosoftDeploymentToolkit_x64.msi" ; Description="Microsoft Deployment Toolkit"}
$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=866658" ; FileName="SQL2019-SSEI-Expr.exe" ; Description="Microsoft Deployment Toolkit"}
$Files+=@{Uri="https://software-download.microsoft.com/download/pr/AzureStackHCI_17784.1068_EN-US.iso" ; FileName="AzureStackHCI_17784.1068_EN-US.iso" ; Description="Azure Stack HCI ISO"}
#$Files+=@{Uri="https://aka.ms/ssmsfullsetup" ; FileName="SSMS-Setup-ENU" ; Description="SQL Management Studio"}

foreach ($file in $files){
    if (-not (Test-Path "$downloadfolder\$($file.filename)")){
        Write-Output "Downloading $($file.Description)"
        Invoke-WebRequest -UseBasicParsing -Uri $file.uri -OutFile "$downloadfolder\$($file.filename)"
    }
}
$ProgressPreference="Continue"
#install ADK
Start-Process -Wait -FilePath "$downloadfolder\adksetup.exe" -ArgumentList "/features OptionId.DeploymentTools OptionId.UserStateMigrationTool /quiet"
#install ADK WinPE
Start-Process -Wait -FilePath "$downloadfolder\adkwinpesetup.exe" -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /Quiet"
#install MDT
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $downloadfolder\MicrosoftDeploymentToolkit_x64.msi /q"
#install SQL Express
$exec="$downloadfolder\SQL2019-SSEI-Expr.exe"
$params="/Action=Install /MediaPath=$downloadfolder\SQLMedia /IAcceptSqlServerLicenseTerms /quiet"
Start-Process -FilePath $exec -ArgumentList $params -NoNewWindow -Wait

#endregion

#region configure MDT

#import MDT Module
Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
#list commands
Get-Command -Module MicrosoftDeploymentToolkit

#Create new Deployment Share
New-Item -Path c:\ -Name DeploymentShare -ItemType Directory
New-SmbShare -Name "DeploymentShare$" -Path "C:\DeploymentShare" -FullAccess Administrators

#map MDT deployment share as PSDrive
New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "C:\DeploymentShare" -Description "MDT Deployment Share" -NetworkPath "\\DC\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose

#Enable Named Pipes for SQLServer
Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Np\" -Name Enabled -Value 1
#Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\" -Name Enabled -Value 1
#Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name TcpPort -Value 1433
Restart-Service 'MSSQL$SQLEXPRESS'
Set-Service -Name SQLBrowser -StartupType Automatic
Start-Service -Name SQLBrowser

#create DB in MDT
new-MDTDatabase -path "DS001:" -SQLServer "$env:COMPUTERNAME" -Instance "SQLExpress" -Netlib "DBNMPNTW" -Database "MDTDB" -SQLShare "DeploymentShare$" -Verbose
#New-MDTDatabase -path "DS001:" -SQLServer "$env:COMPUTERNAME" -Port "1433" -Netlib "DBMSSOCN" -Database "MDTDB" -Verbose

#Import Operating System
$ISO = Mount-DiskImage -ImagePath "$downloadfolder\AzureStackHCI_17784.1068_EN-US.iso" -PassThru
$ISOMediaPath = (Get-Volume -DiskImage $ISO).DriveLetter+':\'
Import-mdtoperatingsystem -path "DS001:\Operating Systems" -SourcePath $ISOMediaPath -DestinationFolder "Azure Stack HCI SERVERAZURESTACKHCICORE x64" -Verbose

$ISO | Dismount-DiskImage

#configure Deployment Share properties
Set-ItemProperty DS001:\ -name SupportX86 -value False
Set-ItemProperty DS001:\ -name Boot.x86.GenerateLiteTouchISO -value False
Set-ItemProperty DS001:\ -name Boot.x64.SelectionProfile -value "Nothing"
Set-ItemProperty DS001:\ -name Boot.x64.IncludeNetworkDrivers -value True
Set-ItemProperty DS001:\ -name Boot.x64.IncludeMassStorageDrivers -value True
Set-ItemProperty DS001:\ -name Boot.x64.IncludeAllDrivers -value False
Set-ItemProperty DS001:\ -name Boot.x64.GenerateGenericWIM -value True

#add Task Sequence
import-mdttasksequence -path "DS001:\Task Sequences" -Name "Azure Stack HCI Deploy" -Template "Server.xml" -Comments "" -ID "AzSHCI" -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Azure Stack HCI SERVERAZURESTACKHCICORE in Azure Stack HCI SERVERAZURESTACKHCICORE x64 install.wim" -FullName "PFE" -OrgName "Contoso" -HomePage "about:blank" -AdminPassword "LS1setup!" -Verbose

#endregion

#region configure MDT run-as account

#create identity for MDT
New-ADUser -Name MDTUser -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"

#add FileShare permissions for MDT Account
Grant-SmbShareAccess -Name DeploymentShare$ -AccessRight Read -AccountName MDTUser -Confirm:$false

#endregion

#region configure Bootstrap ini and generate WinPE
#populate bootstrap.ini
$content=@'
[Settings]
Priority=Default

[Default]
DeployRoot=\\DC\DeploymentShare$
UserDomain=corp
UserID=MDTUser
UserPassword=LS1setup!
SkipBDDWelcome=YES
'@
$content | Set-Content -Path C:\DeploymentShare\Control\Bootstrap.ini

#update deployment share
update-mdtdeploymentshare -path "DS001:" -verbose -force

#endregion

#region Install and configure WDS

#install WDS
Install-WindowsFeature WDS -IncludeManagementTools -IncludeAllSubFeature
wdsutil /initialize-server /reminst:"C:\RemoteInstall"
wdsutil /start-server
wdsutil.exe /Set-Server /AnswerClients:Known
#WDSUTIL /Set-Server /AnswerClients:Known /ResponseDelay:4
WDSUTIL /Set-Server /PxePromptPolicy /known:Noprompt /new:abort
#WDSUTIL /Set-Server /PxePromptPolicy /known:Noprompt /new:Noprompt

#import the boot media to WDS
Get-WdsBootImage |Remove-WdsBootImage
Import-wdsbootimage -path C:\DeploymentShare\Boot\LiteTouchPE_x64.wim -Verbose

#endregion

#region configure MDT Monitoring
if (-not(Get-PSDrive -Name ds001)){
    New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "C:\DeploymentShare" -Description "MDT Deployment Share" -NetworkPath "\\DC\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
}
#configure ports in MDT
Set-ItemProperty DS001:\ -name MonitorHost -value DC
#enable service
Enable-MDTMonitorService -EventPort 9800 -DataPort 9801
#add firewall rule
New-NetFirewallRule `
-Action Allow `
-Name "MDT-Monitoring-In-TCP" `
-DisplayName "MDT (Monitoring-In-TCP)" `
-Description "Inbound rule for MDT Monitoring. [TCP-9800,9801]" `
-Enabled True `
-Direction Inbound `
-Program "System" `
-Protocol UDP `
-LocalPort 9800,9801 `
-Profile Any `
-Group "MDT" `
-RemoteAddress Any
#endregion

#####################################
#       Run from Hyper-V Host       #
#                                   #
# ! Adjust LabPrefix and VMs Path ! #
#####################################

#region Run from Hyper-V Host to create new, empty VMs
    #some variables
    $LabPrefix="WSLab17763.1339-"
    $vSwitchName="$($LabPrefix)LabSwitch"
    $VMsPath="E:\WSLab17763.1339\LAB\VMs"
    $VMNames="AzHCI1","AzHCI2","AzHCI3","AzHCI4"
    $NumberOfHDDs=4
    $SizeOfHDD=4TB
    $MemoryStartupBytes=4GB
    #create some blank VMs
    foreach ($VMName in $VMNames){
            $VMName="$LabPrefix$VMName"
            New-VM -Name $VMName -NewVHDPath "$VMsPath\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 128GB -SwitchName $vSwitchName -Generation 2 -Path "$VMsPath" -MemoryStartupBytes $MemoryStartupBytes
            1..$NumberOfHDDs | ForEach-Object {
                $VHD=New-VHD -Path "$VMsPath\$VMName\Virtual Hard Disks\HDD$_.vhdx" -SizeBytes $SizeOfHDD
                Add-VMHardDiskDrive -VMName $VMName -Path "$VMsPath\$VMName\Virtual Hard Disks\HDD$_.vhdx"
            }
            #Add Adapter
            Add-VMNetworkAdapter -VMName $VMName -SwitchName $vSwitchName
            #configure Nested Virt and 2 cores
            Set-VMProcessor -ExposeVirtualizationExtensions $true -VMName $VMName -Count 2
            #configure Memory
            Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false
            #configure network adapters
            Set-VMNetworkAdapter -VMName $VMName -AllowTeaming On -MacAddressSpoofing On
            Set-VMNetworkAdapterVlan -VMName $VMName -Trunk -NativeVlanId 0 -AllowedVlanIdList "1-10"
            #disable automatic checkpoints
            if ((get-vm -VMName $VMName).AutomaticCheckpointsEnabled -eq $True){
                Set-VM -Name $VMName -AutomaticCheckpointsEnabled $False
            }
            #Start VM
            Start-VM -Name $VMName
    }

#endregion

###############
# Run from DC #
###############

#region Create hash table out of machines that attempted boot last 5 minutes

#in real world scenairos you can have hash table like this:
<#
$HVHosts = @()
$HVHosts+=@{ComputerName="AzSHCI1"  ;IPAddress="10.0.0.101" ; MACAddress="00:15:5D:01:20:3B" ; GUID="FFB429BB-1521-47C6-88BF-F5F2D1BA17F5"}
$HVHosts+=@{ComputerName="AzSHCI2"  ;IPAddress="10.0.0.102" ; MACAddress="00:15:5D:01:20:3E" ; GUID="056423D7-6BAC-460F-AD0D-78AF6D26E151"}
$HVHosts+=@{ComputerName="AzSHCI3"  ;IPAddress="10.0.0.103" ; MACAddress="00:15:5D:01:20:40" ; GUID="D1DF2157-8EE0-4C7A-A0FD-6E7779C62FCE"}
$HVHosts+=@{ComputerName="AzSHCI4"  ;IPAddress="10.0.0.104" ; MACAddress="00:15:5D:01:20:42" ; GUID="7392BBB5-99D7-4EEE-9C22-4CA6EB6058FB"}
#>

#grab machines that attempted to boot and create hash table of 
$IpaddressScope="10.0.0."
$IPAddressStart=101 #starting this number IPs will be asigned
$ServersNamePrefix="AzSHCI"

$events=Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Deployment-Services-Diagnostics/Operational";Id=4132;StartTime=(get-date).AddMinutes(-5)} | Where-Object Message -like "*it is not recognized*" | Sort-Object TimeCreated

$HVHosts = @()
$GUIDS=@()
$i=1
foreach ($event in $events){
    if (!($guids).Contains($event.properties.value[2])){
        $HVHosts+= @{ ComputerName="$ServersNamePrefix$i";GUID = $event.properties.value[2] -replace '[{}]' ; MACAddress = $event.properties.value[0] -replace "-",":" ; IPAddress="$IpaddressScope$($IPAddressStart.tostring())"}
        $i++
        $IPAddressStart++
        $GUIDS+=$event.properties.value[2]
    }
}

#endregion

#region add deploy info to AD Object and MDT Database

#download and unzip mdtdb
Invoke-WebRequest -Uri https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/5209/00/00/03/24/15/04/MDTDB.zip -OutFile $env:USERPROFILE\Downloads\MDTDB.zip
Expand-Archive -Path $env:USERPROFILE\Downloads\MDTDB.zip -DestinationPath $env:USERPROFILE\Downloads\MDTDB\
Import-Module $env:USERPROFILE\Downloads\MDTDB\MDTDB.psm1
#Connect to DB
Connect-MDTDatabase -database mdtdb -sqlServer dc -instance SQLExpress

#add hosts to MDT DB
foreach ($HVHost in $HVHosts){
    if (-not(Get-AdComputer  -Filter "Name -eq `"$($HVHost.ComputerName)`"")){
        New-ADComputer -Name $hvhost.ComputerName
    }
    #add to MDT DB
    if (-not (Get-MDTComputer -macAddress $HVHost.MACAddress)){
        New-MDTComputer -macAddress $HVHost.MACAddress -description $HVHost.ComputerName -uuid $HVHost.GUID -settings @{ 
            ComputerName        = $HVHost.ComputerName 
            OSDComputerName     = $HVHost.ComputerName 
            #SkipBDDWelcome      = 'Yes' 
        }
    }
    Get-MDTComputer -macAddress $HVHost.MACAddress | Set-MDTComputerRole -roles JoinDomain,AZSHCI
}

#Configure MDT DB Roles
if (-not (Get-MDTRole -name azshci)){
    New-MDTRole -name AZSHCI -settings @{ 
        SkipTaskSequence    = 'YES' 
        SkipWizard          = 'YES' 
        SkipSummary         = 'YES' 
        SkipApplications    = 'YES' 
        TaskSequenceID      = 'AZSHCI' 
    }
}

if (-not (Get-MDTRole -name JoinDomain)){
    New-MDTRole -name JoinDomain -settings @{ 
        SkipComputerName    ='YES' 
        SkipDomainMembership='YES' 
        JoinDomain          ='corp.contoso.COM' 
        DomainAdmin         ='MDTUser' 
        DomainAdminDomain   ='corp' 
        DomainAdminPassword ='LS1setup!' 
    }
}

#allow machines to boot from PXE from DC by adding info into AD Object
foreach ($HVHost in $HVHosts){
    [guid]$guid=$HVHost.GUID
    Set-ADComputer -identity $hvhost.ComputerName -replace @{netbootGUID = $guid}
    #Set-ADComputer -identity $hvhost.ComputerName -replace @{netbootMachineFilePath = "DC"}
}
#endregion

#region replace customsettings.ini with all DB data to query (wizard output)
$content=@'
[Settings]
Priority=CSettings, CPackages, CApps, CAdmins, CRoles, Locations, LSettings, LPackages, LApps, LAdmins, LRoles, MMSettings, MMPackages, MMApps, MMAdmins, MMRoles, RSettings, RPackages, RApps, RAdmins, Default
Properties=MyCustomProperty

[Default]
OSInstall=Y
SkipCapture=YES
SkipAdminPassword=NO
SkipProductKey=YES
EventService=http://DC:9800

[CSettings]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=ComputerSettings
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[CPackages]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=ComputerPackages
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR
Order=Sequence

[CApps]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=ComputerApplications
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR
Order=Sequence

[CAdmins]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=ComputerAdministrators
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[CRoles]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=ComputerRoles
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[Locations]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=Locations
Parameters=DefaultGateway

[LSettings]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=LocationSettings
Parameters=DefaultGateway

[LPackages]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=LocationPackages
Parameters=DefaultGateway
Order=Sequence

[LApps]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=LocationApplications
Parameters=DefaultGateway
Order=Sequence

[LAdmins]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=LocationAdministrators
Parameters=DefaultGateway

[LRoles]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=LocationRoles
Parameters=DefaultGateway

[MMSettings]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=MakeModelSettings
Parameters=Make, Model

[MMPackages]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=MakeModelPackages
Parameters=Make, Model
Order=Sequence

[MMApps]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=MakeModelApplications
Parameters=Make, Model
Order=Sequence

[MMAdmins]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=MakeModelAdministrators
Parameters=Make, Model

[MMRoles]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=MakeModelRoles
Parameters=Make, Model

[RSettings]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=RoleSettings
Parameters=Role

[RPackages]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=RolePackages
Parameters=Role
Order=Sequence

[RApps]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=RoleApplications
Parameters=Role
Order=Sequence

[RAdmins]
SQLServer=dc
Instance=SQLExpress
Database=MDTDB
Netlib=DBNMPNTW
SQLShare=DeploymentShare$
Table=RoleAdministrators
Parameters=Role

[Settings]
Priority=CSettings, CPackages, CApps, CAdmins, CRoles, Locations, LSettings, LPackages, LApps, LAdmins, LRoles, MMSettings, MMPackages, MMApps, MMAdmins, MMRoles, RSettings, RPackages, RApps, RAdmins, 

'@
$content | Set-Content C:\DeploymentShare\Control\CustomSettings.ini

#endregion

#region configure SQL to be able to access it remotely using MDTUser account

#create Firewall rule for SQL Server, so client can access settings
<#
New-NetFirewallRule `
-Action Allow `
-Name "SQLExpress-In-TCP" `
-DisplayName "SQLExpress (SQL-In)" `
-Description "Inbound rule for SQL. [TCP-1433]" `
-Enabled True `
-Direction Inbound `
-Program "%ProgramFiles%\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\Binn\sqlservr.exe" `
-Protocol TCP `
-LocalPort 1433 `
-Profile Any `
-Group "SQL Express" `
-RemoteAddress Any
#>

New-NetFirewallRule `
-Action Allow `
-Name "SQLBrowser-In-UDP" `
-DisplayName "SQLBrowser (SQL-In-UDP)" `
-Description "Inbound rule for SQLBrowser. [UDP-1434]" `
-Enabled True `
-Direction Inbound `
-Program "%ProgramFiles% (x86)\Microsoft SQL Server\90\Shared\sqlbrowser.exe" `
-Protocol UDP `
-LocalPort 1434 `
-Profile Any `
-Group "SQL Express" `
-RemoteAddress Any

#Add permissions for MDT account to sql database
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name sqlserver -AllowClobber -Force
$sqlscript=@'
USE [master]
GO
CREATE LOGIN [CORP\MDTUser] FROM WINDOWS WITH DEFAULT_DATABASE=[MDTDB]
GO
USE [MDTDB]
GO
CREATE USER [corp\mdtuser] FOR LOGIN [corp\mdtuser]
GO
USE [MDTDB]
GO
ALTER ROLE [db_datareader] ADD MEMBER [corp\mdtuser]
GO
'@
Invoke-Sqlcmd -ServerInstance dc\sqlexpress -Database MDTDB -Query $sqlscript

#endregion

################################################
# restart hyper-v machines to let them install #
################################################

#remove pxe boot
foreach ($HVHost in $HVHosts){
    [guid]$guid=$HVHost.GUID
    Set-ADComputer -identity $hvhost.ComputerName -remove @{netbootGUID = $guid}
    Set-ADComputer -identity $hvhost.ComputerName -remove @{netbootMachineFilePath = "DC"}
}

#TBD: 
#remove from pxe boot as package in MDT
#enable MDT monitoring with posh
#add real servers drivers
#...
