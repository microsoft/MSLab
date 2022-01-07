#run all from DC or management machine (Windows 11 or Windows Server 2022)

#region variables
    $MDTServer="MDT"
    $DeploymentShareLocation="D:\DeploymentShare"
    $Connection="TCPIP" #or "NamedPipes"
    $downloadfolder="$env:USERPROFILE\Downloads"
    $WDSRoot="D:\RemoteInstall"
    $DHCPServer="DC"
    $ScopeID="10.0.0.0"

    $CredSSPUserName="CORP\LabAdmin"
    $CredSSPPassword="LS1setup!"
#endregion

#region prereqs
    #install management features (ADDS, DHCP,...)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    If ($WindowsInstallationType -like "Server*"){
        Install-WindowsFeature -Name "RSAT-AD-PowerShell","RSAT-ADDS","RSAT-DHCP","RSAT-DNS-Server","WDS-AdminPack"
    }else{
        $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.DHCP.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0","Rsat.Dns.Tools~~~~0.0.1.0"
        foreach ($Capability in $Capabilities){
            Add-WindowsCapability -Name $Capability -Online
        }
    }

    #download and install binaries
        #Download files
        $files=@()
        #$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2026036" ; FileName="adksetup.exe" ; Description="Windows 10 ADK 1809"}
        #$Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2022233" ; FileName="adkwinpesetup.exe" ; Description="WindowsPE 1809"}
        $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2165884" ; FileName="adksetup.exe" ; Description="Windows 11 21H2 ADK"}
        $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=2166133" ; FileName="adkwinpesetup.exe" ; Description="WindowsPE for Windows 11 21H2"}
        $Files+=@{Uri="https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi" ; FileName="MicrosoftDeploymentToolkit_x64.msi" ; Description="Microsoft Deployment Toolkit"}
        #$Files+=@{Uri="https://software-download.microsoft.com/download/pr/AzureStackHCI_17784.1408_EN-US.iso" ; FileName="AzureStackHCI_17784.1408_EN-US.iso" ; Description="Azure Stack HCI ISO"}
        $Files+=@{Uri="https://software-download.microsoft.com/download/sg/AzureStackHCI_20348.288_en-us.iso" ; FileName="AzureStackHCI_20348.288_en-us.iso" ; Description="Azure Stack HCI ISO"}
        $Files+=@{Uri="https://go.microsoft.com/fwlink/?linkid=866658" ; FileName="SQL2019-SSEI-Expr.exe" ; Description="SQL Express 2019"}
        #$Files+=@{Uri="https://aka.ms/ssmsfullsetup" ; FileName="SSMS-Setup-ENU.exe" ; Description="SQL Management Studio"}
        foreach ($file in $files){
            if (-not (Test-Path "$downloadfolder\$($file.filename)")){
                Start-BitsTransfer -Source $file.uri -Destination "$downloadfolder\$($file.filename)" -DisplayName "Downloading: $($file.filename)"
            }
        }

        #install ADK
        Start-Process -Wait -FilePath "$downloadfolder\adksetup.exe" -ArgumentList "/features OptionId.DeploymentTools OptionId.UserStateMigrationTool /quiet"
        #install ADK WinPE
        Start-Process -Wait -FilePath "$downloadfolder\adkwinpesetup.exe" -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /Quiet"
        #install MDT locally
        Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $downloadfolder\MicrosoftDeploymentToolkit_x64.msi /q"

        #prepare MDT Server
            #format and prepare "D" drive on MDT Server
            Get-Disk -CimSession $MDTServer | Where-Object PartitionStyle -eq RAW | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -Filesystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel "Storage"
            #enable SMB FIrewall rule
            Enable-NetFirewallRUle -CimSession $MDTServer -Name FPS-SMB-In-TCP
            #copy binaries
            New-Item -Path "\\$MDTServer\d$\" -Name INstall -ItemType Directory
            Copy-Item -Path "$env:UserProfile\Downloads\*" -Destination "\\$MDTServer\d$\Install" -Recurse

            #Install MDT and Prereqs to MDT Server
            Invoke-Command -ComputerName $MDTServer -ScriptBlock {
                $downloadfolder="d:\Install"
                #install ADK
                Start-Process -Wait -FilePath "$downloadfolder\adksetup.exe" -ArgumentList "/features OptionId.DeploymentTools OptionId.UserStateMigrationTool /quiet"
                #install ADK WinPE
                Start-Process -Wait -FilePath "$downloadfolder\adkwinpesetup.exe" -ArgumentList "/features OptionID.WindowsPreinstallationEnvironment /Quiet"
                #install MDT
                Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $downloadfolder\MicrosoftDeploymentToolkit_x64.msi /q"
            }

        #install SQL Express to MDT Machine (using credssp)
            # Temporarily enable CredSSP delegation to avoid double-hop issue
            $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
            If ($WindowsInstallationType -eq "Client"){
                winrm quickconfig -force #on client is winrm not configured
            }
            Enable-WSManCredSSP -Role "Client" -DelegateComputer $MDTServer -Force
            Invoke-Command -ComputerName $MDTServer -ScriptBlock { Enable-WSManCredSSP Server -Force }

            $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
            $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

            Invoke-Command -ComputerName $MDTServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
                $downloadfolder="D:\Install"
                #install
                $exec="$downloadfolder\SQL2019-SSEI-Expr.exe"
                $params="/Action=Install /MediaPath=$downloadfolder\SQLMedia /IAcceptSqlServerLicenseTerms /quiet"
                Start-Process -FilePath $exec -ArgumentList $params -NoNewWindow -Wait
            }

            # Disable CredSSP
            Disable-WSManCredSSP -Role Client
            Invoke-Command -ComputerName $MDTServer -ScriptBlock {Disable-WSManCredSSP Server}
#endregion

#region configure MDT
    #import MDT Module
    Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    #list commands
    Get-Command -Module MicrosoftDeploymentToolkit

    #Create new Deployment Share
       #Create Deployment Share
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        New-Item -Path $using:DeploymentShareLocation -ItemType Directory -ErrorAction Ignore
        New-SmbShare -Name "DeploymentShare$" -Path "$using:DeploymentShareLocation" -FullAccess Administrators
    }
    #map MDT deployment share as PSDrive
    #sometimes happens that script to complains: The process cannot access the file '\\MDT\DeploymentShare$\Control\Settings.xml' because it is being used by another process.
    do{
        New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        if (-not (get-psdrive -Name DS001)){
            Write-Output "Failed adding PSDrive - trying again"
        }
    }until (get-psdrive -Name DS001)
    #Configure SQL Services

    Invoke-Command -ComputerName $MDTServer -scriptblock {
        if ($using:Connection -eq "NamedPipes"){
            #Named Pipes
            Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Np\" -Name Enabled -Value 1
        }

        if ($using:Connection -eq "TCPIP"){
            #TCP
            Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\" -Name Enabled -Value 1
            Set-ItemProperty -Path "hklm:\\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name TcpPort -Value 1433
        }

        Restart-Service 'MSSQL$SQLEXPRESS'
        Set-Service -Name SQLBrowser -StartupType Automatic
        Start-Service -Name SQLBrowser
    }

    #create Firewall rule for SQL Server

        if ($Connection -eq "TCPIP"){
            New-NetFirewallRule `
            -CimSession $MDTServer `
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
        }

        New-NetFirewallRule `
        -CimSession $MDTServer `
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

    #create DB in MDT
    if ($Connection -eq "NamedPipes"){
        New-MDTDatabase -path "DS001:" -SQLServer $MDTServer -Instance "SQLExpress" -Netlib "DBNMPNTW" -Database "MDTDB" -SQLShare "DeploymentShare$" -Verbose
    }elseif ($Connection -eq "TCPIP"){
        New-MDTDatabase -path "DS001:" -SQLServer $MDTServer  -Port "1433" -Netlib "DBMSSOCN" -Database "MDTDB" -Verbose
    }

    #Import Operating System
    $ISO = Mount-DiskImage -ImagePath "$downloadfolder\AzureStackHCI_20348.288_en-us.iso" -PassThru
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
    #add PowerShell
    $Properties=@()
    $Properties+=(Get-ItemPropertyValue DS001:\ -Name Boot.x64.FeaturePacks) -split (",")
    $FeaturesToAdd="winpe-netfx","winpe-powershell"
    foreach ($FeatureToAdd in $FeaturesToAdd){
        if ($properties -notcontains $FeatureToAdd){
            $Properties+=$FeatureToAdd
        }
    }
    Set-ItemProperty DS001:\ -name Boot.x64.FeaturePacks -value ($Properties -Join (","))

    #add Task Sequence
    import-mdttasksequence -path "DS001:\Task Sequences" -Name "Azure Stack HCI Deploy" -Template "Server.xml" -Comments "" -ID "AzSHCI" -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Azure Stack HCI SERVERAZURESTACKHCICORE in Azure Stack HCI SERVERAZURESTACKHCICORE x64 install.wim" -FullName "PFE" -OrgName "Contoso" -HomePage "about:blank" -AdminPassword "LS1setup!" -Verbose

#endregion

#region configure MDT run-as account
    #create identity for MDT
    $DefaultOUPath=(Get-ADDomain).UsersContainer
    New-ADUser -Name MDTUser -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path $DefaultOUPath

    #add FileShare permissions for MDT Account
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        Grant-SmbShareAccess -Name DeploymentShare$ -AccessRight Read -AccountName MDTUser -Confirm:$false
    }
    #delegate djoin permissions https://www.sevecek.com/EnglishPages/Lists/Posts/Post.aspx?ID=48
    $user = "$env:userdomain\MDTUser"
    $ou = (Get-ADDomain).ComputersContainer

    DSACLS $ou /R $user

    DSACLS $ou /I:S /G "$($user):GR;;computer"
    DSACLS $ou /I:S /G "$($user):CA;Reset Password;computer"
    DSACLS $ou /I:S /G "$($user):WP;pwdLastSet;computer"
    DSACLS $ou /I:S /G "$($user):WP;Logon Information;computer"
    DSACLS $ou /I:S /G "$($user):WP;description;computer"
    DSACLS $ou /I:S /G "$($user):WP;displayName;computer"
    DSACLS $ou /I:S /G "$($user):WP;sAMAccountName;computer"
    DSACLS $ou /I:S /G "$($user):WP;DNS Host Name Attributes;computer"
    DSACLS $ou /I:S /G "$($user):WP;Account Restrictions;computer"
    DSACLS $ou /I:S /G "$($user):WP;servicePrincipalName;computer"
    DSACLS $ou /I:S /G "$($user):CC;computer;organizationalUnit"

#endregion

#region configure Bootstrap ini and generate WinPE
    #populate bootstrap.ini
    $content=@"
[Settings]
Priority=Default

[Default]
DeployRoot=\\$MDTServer\DeploymentShare$
UserDomain=$env:userdomain
UserID=MDTUser
UserPassword=LS1setup!
SkipBDDWelcome=YES
"@
    #remove bootstrap.ini first (sometimes there is an error if just populating content)
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Remove-Item -Path "$using:DeploymentShareLocation\Control\Bootstrap.ini" -Force}
    #populate content
    Set-Content -Path "\\$MDTServer\DeploymentShare$\Control\Bootstrap.ini" -Value $content


    #update deployment share to generate new WIM for WDS
    if (-not(get-module MicrosoftDeploymentToolkit)){
        Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    }
    if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
        New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
    }
    update-mdtdeploymentshare -path "DS001:" -verbose -force

#endregion

#region Install and configure WDS
    #install WDS
    Install-WindowsFeature -Name WDS -ComputerName $MDTServer -IncludeManagementTools -IncludeAllSubFeature

    # Temporarily enable CredSSP delegation to avoid double-hop issue
    winrm quickconfig -force #on client is winrm not configured
    Enable-WSManCredSSP -Role "Client" -DelegateComputer $MDTServer -Force
    Invoke-Command -ComputerName $MDTServer -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

    #Configure WDS
    Invoke-Command -ComputerName $MDTServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
        $MDTServer=$using:MDTServer
        wdsutil /initialize-server /reminst:$using:WDSRoot
        wdsutil /start-server
        wdsutil.exe /Set-Server /AnswerClients:Known
        #WDSUTIL /Set-Server /AnswerClients:Known /ResponseDelay:4
        WDSUTIL /Set-Server /PxePromptPolicy /known:Noprompt /new:abort
        #WDSUTIL /Set-Server /PxePromptPolicy /known:Noprompt /new:Noprompt
    }

   #import the boot media to WDS
   Invoke-Command -ComputerName $MDTServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Get-WdsBootImage | Remove-WdsBootImage
        Import-wdsbootimage -path "$($using:DeploymentShareLocation)\Boot\LiteTouchPE_x64.wim" -Verbose
    }


    #Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Disable-WSManCredSSP Server}

    
    #Mitigate issue with Variable Window Extension
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        Wdsutil /Set-TransportServer /EnableTftpVariableWindowExtension:No
    }
#endregion

#region configure MDT Monitoring
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        if (-not(get-module MicrosoftDeploymentToolkit)){
            Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
        }
        if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
            New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "$using:DeploymentShareLocation" -Description "MDT Deployment Share" -NetworkPath "\\$using:MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        }
        #configure ports in MDT
        Set-ItemProperty DS001:\ -name MonitorHost -value $using:MDTServer
        #enable service
        Enable-MDTMonitorService -EventPort 9800 -DataPort 9801
    }

    #add firewall rule
    New-NetFirewallRule `
        -CimSession $MDTServer `
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

#region replace customsettings.ini with all DB data to query (wizard output)
    if ($Connection -eq "NamedPipes"){
        $Netlib="DBNMPNTW"
    }elseif($Connection -eq "TCPIP"){
        $Netlib="DBMSSOCN"
        $Creds=@"
DBID=MDTSQLUser
DBPwd=LS1setup!
"@
}

    $content=@"
[Settings]
Priority=CSettings, CPackages, CApps, CAdmins, CRoles, Locations, LSettings, LPackages, LApps, LAdmins, LRoles, MMSettings, MMPackages, MMApps, MMAdmins, MMRoles, RSettings, RPackages, RApps, RAdmins, Default
Properties=MyCustomProperty

[Default]
OSInstall=Y
SkipCapture=YES
SkipAdminPassword=NO
SkipProductKey=YES
EventService=http://$($MDTServer):9800

[CSettings]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerSettings
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[CPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerPackages
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR
Order=Sequence

[CApps]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerApplications
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR
Order=Sequence

[CAdmins]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerAdministrators
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[CRoles]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=ComputerRoles
Parameters=UUID, AssetTag, SerialNumber, MacAddress
ParameterCondition=OR

[Locations]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=Locations
Parameters=DefaultGateway

[LSettings]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationSettings
Parameters=DefaultGateway

[LPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationPackages
Parameters=DefaultGateway
Order=Sequence

[LApps]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationApplications
Parameters=DefaultGateway
Order=Sequence

[LAdmins]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationAdministrators
Parameters=DefaultGateway

[LRoles]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=LocationRoles
Parameters=DefaultGateway

[MMSettings]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelSettings
Parameters=Make, Model

[MMPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelPackages
Parameters=Make, Model
Order=Sequence

[MMApps]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelApplications
Parameters=Make, Model
Order=Sequence

[MMAdmins]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelAdministrators
Parameters=Make, Model

[MMRoles]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=MakeModelRoles
Parameters=Make, Model

[RSettings]
$creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RoleSettings
Parameters=Role

[RPackages]
$Creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RolePackages
Parameters=Role
Order=Sequence

[RApps]
$creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RoleApplications
Parameters=Role
Order=Sequence

[RAdmins]
$creds
SQLServer=$MDTServer
Instance=SQLExpress
Database=MDTDB
Netlib=$Netlib
SQLShare=DeploymentShare$
Table=RoleAdministrators
Parameters=Role
"@


$CustomSettingsFile="\\$MDTServer\DeploymentShare$\Control\CustomSettings.ini"
Set-Content -Path $CustomSettingsFile -Value $Content -NoNewline #if NoNewLine not specified, scipt will add crlf at and of the file
#replace LF with CRLF as text will be displayed correctly in Deployment Workbench
$text = [IO.File]::ReadAllText($CustomSettingsFile) -replace "`n", "`r`n"
[IO.File]::WriteAllText($CustomSettingsFile, $text)

#endregion

#region configure SQL to be able to access it remotely using MDTUser account(NamedPipes) or create dedicated SQL user (TCPIP)
    #Add permissions for MDT account to sql database
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name sqlserver -AllowClobber -Force
    if ((Get-ExecutionPolicy) -eq "Restricted"){
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
    }
    if ($Connection -eq "NamedPipes"){
            #Named Pipes
    $sqlscript=@"
USE [master]
GO
CREATE LOGIN [$env:userdomain\MDTUser] FROM WINDOWS WITH DEFAULT_DATABASE=[MDTDB]
GO
USE [MDTDB]
GO
CREATE USER [$env:userdomain\mdtuser] FOR LOGIN [$env:userdomain\mdtuser]
GO
USE [MDTDB]
GO
ALTER ROLE [db_datareader] ADD MEMBER [$env:userdomain\mdtuser]
GO

"@
    Invoke-Sqlcmd -ServerInstance $MDTServer\sqlexpress -Database MDTDB -Query $sqlscript

}elseif($Connection -eq "TCPIP"){
    #TCP (add user and change authentication mode to be able to use both SQL and Windows Auth
    $sqlscript=@"
USE [master]
GO
CREATE LOGIN [MDTSQLUser] WITH PASSWORD='LS1setup!', DEFAULT_DATABASE=[MDTDB]
GO
USE [MDTDB]
GO
CREATE USER [MDTSQLUser] FOR LOGIN [MDTSQLUser]
GO
ALTER ROLE [db_datareader] ADD MEMBER [MDTSQLUser]
GO
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2
GO

"@
    #TCP
    Invoke-Sqlcmd -ServerInstance "tcp:$MDTServer" -Database MDTDB -Query $sqlscript
    #restart service to apply mixed auth mode
    Invoke-Command -ComputerName $MDTServer -scriptblock {
        Restart-Service 'MSSQL$SQLEXPRESS'
    }
}
#endregion

#####################################
#       Run from Hyper-V Host       #
#                                   #
# ! Adjust LabPrefix and VMs Path ! #
#####################################

#region Run from Hyper-V Host to create new, empty VMs
    #some variables
    $LabPrefix="MSLab20348.169-"
    $vSwitchName="$($LabPrefix)LabSwitch"
    $VMsPath="D:\MSLab20348.169\LAB\VMs"
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

########################################
# Run from Management VM (Win11) or DC #
########################################

#region Create hash table out of machines that attempted boot last 5 minutes
    #in real world scenairos you can have hash table like this:
    <#
    $HVHosts = @()
    $HVHosts+=@{ComputerName="AzSHCI1"  ;IPAddress="10.0.0.101" ; MACAddress="00:15:5D:01:20:3B" ; GUID="FFB429BB-1521-47C6-88BF-F5F2D1BA17F5"}
    $HVHosts+=@{ComputerName="AzSHCI2"  ;IPAddress="10.0.0.102" ; MACAddress="00:15:5D:01:20:3E" ; GUID="056423D7-6BAC-460F-AD0D-78AF6D26E151"}
    $HVHosts+=@{ComputerName="AzSHCI3"  ;IPAddress="10.0.0.103" ; MACAddress="00:15:5D:01:20:40" ; GUID="D1DF2157-8EE0-4C7A-A0FD-6E7779C62FCE"}
    $HVHosts+=@{ComputerName="AzSHCI4"  ;IPAddress="10.0.0.104" ; MACAddress="00:15:5D:01:20:42" ; GUID="7392BBB5-99D7-4EEE-9C22-4CA6EB6058FB"}
    #>

    #grab machines that attempted to boot in last 5 minutes and create hash table.
    $HVHosts=Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        $IpaddressScope="10.0.0."
        $IPAddressStart=101 #starting this number IPs will be asigned
        $ServersNamePrefix="AzSHCI"
        $events=Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Deployment-Services-Diagnostics/Operational";Id=4132;StartTime=(get-date).AddMinutes(-5)} | Where-Object Message -like "*it is not recognized*" | Sort-Object TimeCreated
        $HVHosts = @()
        $GUIDS=@()
        $i=1
        foreach ($event in $events){
            [System.Diagnostics.Eventing.Reader.EventLogRecord]$event=$event
            if (!($guids).Contains($event.properties.value[2])){
                $HVHosts+= @{ ComputerName="$ServersNamePrefix$i";GUID = $event.properties.value[2] -replace '[{}]' ; MACAddress = $event.properties.value[0] -replace "-",":" ; IPAddress="$IpaddressScope$($IPAddressStart.tostring())"}
                $i++
                $IPAddressStart++
                $GUIDS+=$event.properties.value[2]
            }
        }
        Return $HVHosts
    }
$HVHosts

#endregion

#region create DHCP reservation for machines
    #Create DHCP reservations for Hyper-V hosts
        #Add DHCP Reservations
        foreach ($HVHost in $HVHosts){
            if (!(Get-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $DHCPServer -ScopeId $ScopeID -ClientId ($HVHost.MACAddress).Replace(":","") | Where-Object IPAddress -eq $HVHost.IPAddress)){
                Add-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $ScopeID -IPAddress $HVHost.IPAddress -ClientId ($HVHost.MACAddress).Replace(":","")
            }
        }

    #configure NTP server in DHCP (might be useful if Servers have issues with time)
        if (!(get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -ErrorAction SilentlyContinue)){
            Set-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -Value "10.0.0.1"
        }
#endregion

#region add deploy info to AD Object and MDT Database
    #download and unzip mdtdb (blog available in web.archive only https://web.archive.org/web/20190421025144/https://blogs.technet.microsoft.com/mniehaus/2009/05/14/manipulating-the-microsoft-deployment-toolkit-database-using-powershell/)
    #Start-BitsTransfer -Source https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/5209/00/00/03/24/15/04/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip
    Start-BitsTransfer -Source https://github.com/microsoft/MSLab/raw/master/Scenarios/AzSHCI%20and%20MDT/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip

    Expand-Archive -Path $env:USERPROFILE\Downloads\MDTDB.zip -DestinationPath $env:USERPROFILE\Downloads\MDTDB\
    if ((Get-ExecutionPolicy) -eq "Restricted"){
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
    }
    Import-Module $env:USERPROFILE\Downloads\MDTDB\MDTDB.psm1
    #make sure DS is connected
        if (-not(get-module MicrosoftDeploymentToolkit)){
            Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
        }
        if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
            New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        }
    #Connect to DB
        #Connect-MDTDatabase -database mdtdb -sqlServer $MDTServer -instance SQLExpress
        Connect-MDTDatabase -drivePath "DS001:\"


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
                SkipFinalSummary    = 'YES'
                FinishAction        = 'LOGOFF'
            }
        }

        if (-not (Get-MDTRole -name JoinDomain)){
            New-MDTRole -name JoinDomain -settings @{
                SkipComputerName    ='YES'
                SkipDomainMembership='YES'
                JoinDomain          = $env:USERDNSDomain 
                DomainAdmin         ='MDTUser'
                DomainAdminDomain   = $env:userdomain
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

################################################
# restart hyper-v machines to let them install #
################################################

#region remove pxe boot after install is done
    foreach ($HVHost in $HVHosts){
        [guid]$guid=$HVHost.GUID
        Set-ADComputer -identity $hvhost.ComputerName -remove @{netbootGUID = $guid}
        Set-ADComputer -identity $hvhost.ComputerName -remove @{netbootMachineFilePath = "DC"}
    }
#endregion

############################################################################################################################################

#######################################################
#               Fun with Dell AX nodes                #
#                                                     #
#       Run from machine that can talk to iDRAC       #
#######################################################

#region Restart AX Nodes
#$Credentials=Get-Credential
$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("LabAdmin", $password)
$idrac_ips="192.168.100.130","192.168.100.131"
$Headers=@{"Accept"="application/json"}
$ContentType='application/json'
function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}
#ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck
Ignore-SSLCertificates

#reboot machines
foreach ($idrac_ip in $idrac_ips){
    #Configure PXE for next reboot
    $JsonBody = @{ Boot = @{
        "BootSourceOverrideTarget"="Pxe"
        }} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"
    Invoke-RestMethod -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    
    #Validate
    $uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    $Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    $Result.Boot.BootSourceOverrideTarget

    #check reboot options
    #$uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    #$Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    #$Result.Actions.'#ComputerSystem.Reset'.'ResetType@Redfish.AllowableValues'

    #reboot
    #possible values: On,ForceOff,ForceRestart,GracefulShutdown,PushPowerButton,Nmi,PowerCycle
    $JsonBody = @{ "ResetType" = "ForceRestart"} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"
    Invoke-RestMethod -Body $JsonBody -Method Post -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials

    Start-Sleep 10
}
#endregion

#######################################################
#               Fun with Dell AX nodes                #
#                                                     #
#             Run from management machine             #
#######################################################

#region Create hash table out of machines that attempted boot last 5 minutes
    #in real world scenairos you can have hash table like this:
    <#
    $HVHosts = @()
    $HVHosts+=@{ComputerName="AxNode1"  ;IPAddress="10.0.0.120" ; MACAddress="0C:42:A1:DD:57:DC" ; GUID="4C4C4544-004D-5410-8031-B4C04F373733"}
    $HVHosts+=@{ComputerName="AxNode2"  ;IPAddress="10.0.0.121" ; MACAddress="0C:42:A1:DD:57:C8" ; GUID="4C4C4544-004D-5410-8033-B4C04F373733"}
    #>

    #grab machines that attempted to boot in last 5 minutes and create hash table.
    $HVHosts=Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        $IpaddressScope="10.0.0."
        $IPAddressStart=120 #starting this number IPs will be asigned
        $ServersNamePrefix="AxNode"
        $events=Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Deployment-Services-Diagnostics/Operational";Id=4132;StartTime=(get-date).AddMinutes(-5)} | Where-Object Message -like "*it is not recognized*" | Sort-Object TimeCreated
        $HVHosts = @()
        $GUIDS=@()
        $i=1
        foreach ($event in $events){
            [System.Diagnostics.Eventing.Reader.EventLogRecord]$event=$event
            if (!($guids).Contains($event.properties.value[2])){
                $HVHosts+= @{ ComputerName="$ServersNamePrefix$i";GUID = $event.properties.value[2] -replace '[{}]' ; MACAddress = $event.properties.value[0] -replace "-",":" ; IPAddress="$IpaddressScope$($IPAddressStart.tostring())"}
                $i++
                $IPAddressStart++
                $GUIDS+=$event.properties.value[2]
            }
        }
        Return $HVHosts
    }


#endregion

#region create DHCP reservation for machines
    #Create DHCP reservations for Hyper-V hosts
        #Add DHCP Reservations
        foreach ($HVHost in $HVHosts){
            if (!(Get-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $DHCPServer -ScopeId $ScopeID -ClientId ($HVHost.MACAddress).Replace(":","") | Where-Object IPAddress -eq $HVHost.IPAddress)){
                Add-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $ScopeID -IPAddress $HVHost.IPAddress -ClientId ($HVHost.MACAddress).Replace(":","")
            }
        }

    #configure NTP server in DHCP (might be useful if Servers have issues with time)
        if (!(get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -ErrorAction SilentlyContinue)){
            Set-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -Value "10.0.0.1"
        }
#endregion

#region add deploy info to AD Object and MDT Database
    #download and unzip mdtdb (blog available in web.archive only https://web.archive.org/web/20190421025144/https://blogs.technet.microsoft.com/mniehaus/2009/05/14/manipulating-the-microsoft-deployment-toolkit-database-using-powershell/)
    #Start-BitsTransfer -Source https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/5209/00/00/03/24/15/04/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip
    Start-BitsTransfer -Source https://github.com/microsoft/MSLab/raw/master/Scenarios/AzSHCI%20and%20MDT/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip

    Expand-Archive -Path $env:USERPROFILE\Downloads\MDTDB.zip -DestinationPath $env:USERPROFILE\Downloads\MDTDB\
    if ((Get-ExecutionPolicy) -eq "Restricted"){
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
    }
    Import-Module $env:USERPROFILE\Downloads\MDTDB\MDTDB.psm1
    #make sure DS is connected
        if (-not(get-module MicrosoftDeploymentToolkit)){
            Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
        }
        if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
            New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        }
    #Connect to DB
        #Connect-MDTDatabase -database mdtdb -sqlServer $MDTServer -instance SQLExpress
        Connect-MDTDatabase -drivePath "DS001:\"


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
                SkipFinalSummary    = 'YES'
                FinishAction        = 'LOGOFF'
            }
        }

        if (-not (Get-MDTRole -name JoinDomain)){
            New-MDTRole -name JoinDomain -settings @{
                SkipComputerName    ='YES'
                SkipDomainMembership='YES'
                JoinDomain          = $env:USERDNSDomain
                DomainAdmin         ='MDTUser'
                DomainAdminDomain   = $env:userdomain
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

#region update task sequence with powershell script to install OS to smallest disk right before "New Computer only" group
$TaskSequenceID="AzSHCI"
$PSScriptName="OSDDiskIndex.ps1"
$PSScriptContent=@'
$Disks=Get-CimInstance win32_DiskDrive
if ($Disks.model -contains "DELLBOSS VD"){
    #exact model for Dell AX node (DELLBOSS VD)
    $TSenv:OSDDiskIndex=($Disks | Where-Object Model -eq "DELLBOSS VD").Index
}else{
    #or just smallest disk
    $TSenv:OSDDiskIndex=($Disks | Where-Object MediaType -eq "Fixed hard disk media" | Sort-Object Size | Select-Object -First 1).Index
}
<# In case you need PowerShell and pause Task Sequence you can use this code:
#source: http://wiki.wladik.net/windows/mdt/powershell-scripting
#run posh
Start PowerShell
#pause TS
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.MessageBox]::Show("Click to continue...")
#>
'@

    #update Tasksequence
    $TS=Invoke-Command -ComputerName $MDTServer -ScriptBlock {Get-Content -Path $using:DeploymentShareLocation\Control\$using:TaskSequenceID\ts.xml}
    $TextToSearch='    <group name="New Computer only" disable="false" continueOnError="false" description="" expand="false">'
    $PoshScript=@"
    <step type="BDD_RunPowerShellAction" name="Run PowerShell Script" description="" disable="false" continueOnError="false" successCodeList="0 3010">
      <defaultVarList>
        <variable name="ScriptName" property="ScriptName">$PSScriptName</variable>
        <variable name="Parameters" property="Parameters"></variable>
        <variable name="PackageID" property="PackageID"></variable>
      </defaultVarList>
      <action>cscript.exe "%SCRIPTROOT%\ZTIPowerShell.wsf</action>
    </step>
$TextToSearch
"@
    $NewTS=$TS.replace($TextToSearch,$PoshScript)
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Set-Content -Path $using:DeploymentShareLocation\Control\$using:TaskSequenceID\ts.xml -Value $using:NewTS}
    #insert script
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Set-Content -Path $using:DeploymentShareLocation\Scripts\$using:PSScriptName -Value $using:PSScriptContent}

#endregion

#region update task sequence with drivers

#Download DSU
#https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1

    #grab DSU links from Dell website
    $URL="https://dl.dell.com/omimswac/dsu/"
    $Results=Invoke-WebRequest $URL -UseDefaultCredentials
    $Links=$results.Links.href | Select-Object -Skip 1
    #create PSObject from results
    $DSUs=@()
    foreach ($Link in $Links){
        $DSUs+=[PSCustomObject]@{
            Link = "https://dl.dell.com$Link"
            Version = $link -split "_" | Select-Object -Last 2 | Select-Object -First 1
        }
    }
    #download latest to separate folder
    $LatestDSU=$DSUs | Sort-Object Version | Select-Object -Last 1
    $Folder="$env:USERPROFILE\Downloads\DSU"
    if (-not (Test-Path $Folder)){New-Item -Path $Folder -ItemType Directory}
    Start-BitsTransfer -Source $LatestDSU.Link -Destination $Folder\DSU.exe

    #add DSU as application to MDT
    Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
        New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
    }
    $AppName="Dell DSU $($LatestDSU.Version)"
    Import-MDTApplication -path "DS001:\Applications" -enable "True" -Name $AppName -ShortName "DSU" -Version $LatestDSU.Version -Publisher "Dell" -Language "" -CommandLine "DSU.exe /silent" -WorkingDirectory ".\Applications\$AppName" -ApplicationSourcePath $Folder -DestinationFolder $AppName -Verbose
    #grap package ID for role config
    $DSUID=(Get-ChildItem -Path DS001:\Applications | Where-Object Name -eq $AppName).GUID

#download catalog and create answer file to run DSU
    #Dell Azure Stack HCI driver catalog https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz
    #Download catalog
    Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
    #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
    $Folder="$env:USERPROFILE\Downloads\DSUPackage"
    if (-not (Test-Path $Folder)){New-Item -Path $Folder -ItemType Directory}
    Function Expand-GZipArchive{
        Param(
            $infile,
            $outfile = ($infile -replace '\.gz$','')
            )
        $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
        $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
        $buffer = New-Object byte[](1024)
        while($true){
            $read = $gzipstream.Read($buffer, 0, 1024)
            if ($read -le 0){break}
            $output.Write($buffer, 0, $read)
            }
        $gzipStream.Close()
        $output.Close()
        $input.Close()
    }
    Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$folder\ASHCI-Catalog.xml"
    #create answerfile for DU
    $content='@
    a
    c
    @'
    Set-Content -Path "$folder\answer.txt" -Value $content -NoNewline
    $content='"C:\Program Files\Dell\DELL EMC System Update\DSU.exe" --catalog-location=ASHCI-Catalog.xml --apply-upgrades <answer.txt'
    Set-Content -Path "$folder\install.cmd" -Value $content -NoNewline

    #add package to MDT
    [xml]$xml=Get-Content "$folder\ASHCI-Catalog.xml"
    $version=$xml.Manifest.version
    $AppName="Dell DSU AzSHCI Package $Version"
    $Commandline="install.cmd"
    Import-MDTApplication -path "DS001:\Applications" -enable "True" -Name $AppName -ShortName "DSUAzSHCIPackage" -Version $Version -Publisher "Dell" -Language "" -CommandLine $Commandline -WorkingDirectory ".\Applications\$AppName" -ApplicationSourcePath $Folder -DestinationFolder $AppName -Verbose
    #configure app to reboot after run
    Set-ItemProperty -Path DS001:\Applications\$AppName -Name Reboot -Value "True"
    #configure dependency on DSU
    $guids=@()
    $guids+=$DSUID
    Set-ItemProperty -Path DS001:\Applications\$AppName -Name Dependency -Value $guids
    #grap package ID for role config
    $DSUPackageID=(Get-ChildItem -Path DS001:\Applications | Where-Object Name -eq $AppName).GUID

    #Create Role
    $RoleName="AXNodeDrivers"
    if (-not (Get-MDTRole -name $RoleName)){
        New-MDTRole -name $RoleName -settings @{
            OSInstall    ='YES'
        }
    }
    #Add apps to role
    $ID=(get-mdtrole -name $RoleName).ID
    Set-MDTRoleApplication -id $ID -applications $DSUID,$DSUPackageID

    #add role that will install drivers to AX computers
        foreach ($HVHost in $HVHosts){
            $MDTComputer=Get-MDTComputer -macAddress $HVHost.MACAddress
            $Roles=($MDTComputer | Get-MDTComputerRole).Role
            $Roles+=$RoleName
            #Get-MDTComputer -macAddress $HVHost.MACAddress | Set-MDTComputerRole -roles JoinDomain,AZSHCI
            $MDTComputer | Set-MDTComputerRole -roles $Roles
        }
#download catalog drivers <TBD>
<#
    #Create output folder
    $FolderName=$xml.manifest.version
    New-Item -ItemType Directory -Name $FolderName -Path "$env:UserProfile\Downloads" -ErrorAction Ignore
    New-Item -ItemType Directory -Name "RebootRequired" -Path "$env:UserProfile\Downloads\$FolderName" -ErrorAction Ignore
    New-Item -ItemType Directory -Name "RebootNotRequired" -Path "$env:UserProfile\Downloads\$FolderName" -ErrorAction Ignore
    #download files
    foreach ($item in $xml.manifest.softwarecomponent){
        $filename=$($item.path.split("/")|Select-Object -Last 1)
        if ($item.RebootRequired -eq "True"){
            Start-BitsTransfer -Source "https://downloads.dell.com/$($item.path)" -Destination "$env:UserProfile\Downloads\$FolderName\RebootRequired\$filename" -DisplayName "Downloading $filename releasedate $($item.releaseDate)"
        }else{
            Start-BitsTransfer -Source "https://downloads.dell.com/$($item.path)" -Destination "$env:UserProfile\Downloads\$FolderName\RebootNotRequired\$filename" -DisplayName "Downloading $filename releasedate $($item.releaseDate)"
        }
    }
#>
#endregion

#######################################################
#               Fun with Dell AX nodes                #
#                                                     #
#             Run from management machine             #
#######################################################

#region Restart AX Nodes again to deploy OS
#$Credentials=Get-Credential
$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("LabAdmin", $password)
$idrac_ips="192.168.100.130","192.168.100.131"
$Headers=@{"Accept"="application/json"}
$ContentType='application/json'
function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}
#ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck
Ignore-SSLCertificates

#reboot machines
foreach ($idrac_ip in $idrac_ips){
    #Configure PXE for next reboot
    $JsonBody = @{ Boot = @{
        "BootSourceOverrideTarget"="Pxe"
        }} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"
    Invoke-RestMethod -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    
    #Validate
    $uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    $Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    $Result.Boot.BootSourceOverrideTarget

    #check reboot options
    #$uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    #$Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    #$Result.Actions.'#ComputerSystem.Reset'.'ResetType@Redfish.AllowableValues'

    #reboot
    #possible values: On,ForceOff,ForceRestart,GracefulShutdown,PushPowerButton,Nmi,PowerCycle
    $JsonBody = @{ "ResetType" = "ForceRestart"} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"
    Invoke-RestMethod -Body $JsonBody -Method Post -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
}
#endregion

#######################################################
#               Fun with Dell AX nodes                #
#                                                     #
#             Run from management machine             #
#######################################################

#region remove pxe boot after install is done
foreach ($HVHost in $HVHosts){
    [guid]$guid=$HVHost.GUID
    Set-ADComputer -identity $hvhost.ComputerName -remove @{netbootGUID = $guid}
    Set-ADComputer -identity $hvhost.ComputerName -remove @{netbootMachineFilePath = "DC"}
}
#endregion

############################################################################################################################################

############################################################
#     Expanding lab with Another TS for Windows Server     #
############################################################

#region Add Windows Server Task Sequence
    $MDTServer="MDT"
    if (-not(get-module MicrosoftDeploymentToolkit)){
        Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    }
    Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
    if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
        New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
    }

    #Grab Server ISO
        Write-Output "Please select ISO image with Windows Server 2022"
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select ISO image with Windows Server 2022"
        }
        $openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK"){
            Write-Output  "File $($openfile.FileName) selected"
        } 
        if (!$openFile.FileName){
            Write-Error "Iso was not selected..."
        }
        $ISOServerPath=$openFile.FileName

    #Import Operating System
    $ISO = Mount-DiskImage -ImagePath $ISOServerPath -PassThru
    $ISOMediaPath = (Get-Volume -DiskImage $ISO).DriveLetter+':\'
    Import-mdtoperatingsystem -path "DS001:\Operating Systems" -SourcePath $ISOMediaPath -DestinationFolder "Windows Server 2022 x64" -Verbose
    $ISO | Dismount-DiskImage

    #add Task Sequence
    import-mdttasksequence -path "DS001:\Task Sequences" -Name "Windows Server Deploy" -Template "Server.xml" -Comments "" -ID "WinSRV" -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Windows Server 2022 SERVERDATACENTERCORE in Windows Server 2022 x64 install.wim" -FullName "PFE" -OrgName "Contoso" -HomePage "about:blank" -AdminPassword "LS1setup!" -Verbose

#endregion

#######################################################
#               Fun with Dell R440 nodes               #
#                                                     #
#       Run from machine that can talk to iDRAC       #
#######################################################

#region Restart R440 Nodes
#$Credentials=Get-Credential
$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("LabAdmin", $password)
$idrac_ips="192.168.100.128","192.168.100.129"
$Headers=@{"Accept"="application/json"}
$ContentType='application/json'
function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}
#ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck
Ignore-SSLCertificates

#reboot machines
foreach ($idrac_ip in $idrac_ips){
    #Configure PXE for next reboot
    $JsonBody = @{ Boot = @{
        "BootSourceOverrideTarget"="Pxe"
        }} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"
    Invoke-RestMethod -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    
    #Validate
    $uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    $Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    $Result.Boot.BootSourceOverrideTarget

    #check reboot options
    #$uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    #$Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    #$Result.Actions.'#ComputerSystem.Reset'.'ResetType@Redfish.AllowableValues'

    #reboot
    #possible values: On,ForceOff,ForceRestart,GracefulShutdown,PushPowerButton,Nmi,PowerCycle
    $JsonBody = @{ "ResetType" = "ForceRestart"} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"
    Invoke-RestMethod -Body $JsonBody -Method Post -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials

    Start-Sleep 10
}
#endregion

#######################################################
#               Fun with Dell R440 nodes              #
#                                                     #
#             Run from management machine             #
#######################################################

#region Create hash table out of machines that attempted boot last 5 minutes
    #in real world scenairos you can have hash table like this:
    <#
    $HVHosts = @()
    $HVHosts+=@{ComputerName="R440Node1"  ;IPAddress="10.0.0.122" ; MACAddress="34:80:0D:91:0B:66" ; GUID="4C4C4544-0051-5610-8056-B8C04F323333"}
    $HVHosts+=@{ComputerName="R440Node2"  ;IPAddress="10.0.0.123" ; MACAddress="34:80:0D:91:0B:54" ; GUID="4C4C4544-0051-5610-8054-B8C04F323333"}
    #>

    #grab machines that attempted to boot in last 5 minutes and create hash table.
    $HVHosts=Invoke-Command -ComputerName $MDTServer -ScriptBlock {
        $IpaddressScope="10.0.0."
        $IPAddressStart=122 #starting this number IPs will be asigned
        $ServersNamePrefix="R440Node"
        $events=Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Deployment-Services-Diagnostics/Operational";Id=4132;StartTime=(get-date).AddMinutes(-5)} | Where-Object Message -like "*it is not recognized*" | Sort-Object TimeCreated
        $HVHosts = @()
        $GUIDS=@()
        $i=1
        foreach ($event in $events){
            [System.Diagnostics.Eventing.Reader.EventLogRecord]$event=$event
            if (!($guids).Contains($event.properties.value[2])){
                $HVHosts+= @{ ComputerName="$ServersNamePrefix$i";GUID = $event.properties.value[2] -replace '[{}]' ; MACAddress = $event.properties.value[0] -replace "-",":" ; IPAddress="$IpaddressScope$($IPAddressStart.tostring())"}
                $i++
                $IPAddressStart++
                $GUIDS+=$event.properties.value[2]
            }
        }
        Return $HVHosts
    }


#endregion

#region create DHCP reservation for machines
    #Create DHCP reservations for Hyper-V hosts
        #Add DHCP Reservations
        foreach ($HVHost in $HVHosts){
            if (!(Get-DhcpServerv4Reservation -ErrorAction SilentlyContinue -ComputerName $DHCPServer -ScopeId $ScopeID -ClientId ($HVHost.MACAddress).Replace(":","") | Where-Object IPAddress -eq $HVHost.IPAddress)){
                Add-DhcpServerv4Reservation -ComputerName $DHCPServer -ScopeId $ScopeID -IPAddress $HVHost.IPAddress -ClientId ($HVHost.MACAddress).Replace(":","")
            }
        }

    #configure NTP server in DHCP (might be useful if Servers have issues with time)
        if (!(get-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -ErrorAction SilentlyContinue)){
            Set-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeID -OptionId 042 -Value "10.0.0.1"
        }
#endregion

#region add deploy info to AD Object and MDT Database
    #download and unzip mdtdb (blog available in web.archive only https://web.archive.org/web/20190421025144/https://blogs.technet.microsoft.com/mniehaus/2009/05/14/manipulating-the-microsoft-deployment-toolkit-database-using-powershell/)
    #Start-BitsTransfer -Source https://msdnshared.blob.core.windows.net/media/TNBlogsFS/prod.evol.blogs.technet.com/telligent.evolution.components.attachments/01/5209/00/00/03/24/15/04/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip
    Start-BitsTransfer -Source https://github.com/microsoft/MSLab/raw/master/Scenarios/AzSHCI%20and%20MDT/MDTDB.zip -Destination $env:USERPROFILE\Downloads\MDTDB.zip

    Expand-Archive -Path $env:USERPROFILE\Downloads\MDTDB.zip -DestinationPath $env:USERPROFILE\Downloads\MDTDB\ -Force
    if ((Get-ExecutionPolicy) -eq "Restricted"){
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
    }
    Import-Module $env:USERPROFILE\Downloads\MDTDB\MDTDB.psm1
    #make sure DS is connected
        if (-not(get-module MicrosoftDeploymentToolkit)){
            Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
        }
        if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
            New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        }
    #Connect to DB
        #Connect-MDTDatabase -database mdtdb -sqlServer $MDTServer -instance SQLExpress
        Connect-MDTDatabase -drivePath "DS001:\"


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
        Get-MDTComputer -macAddress $HVHost.MACAddress | Set-MDTComputerRole -roles JoinDomain,WinSRV
    }

    #Configure MDT DB Roles
        if (-not (Get-MDTRole -name WinSRV)){
            New-MDTRole -name WinSRV -settings @{
                SkipTaskSequence    = 'YES'
                SkipWizard          = 'YES'
                SkipSummary         = 'YES'
                SkipApplications    = 'YES'
                TaskSequenceID      = 'WinSRV'
                SkipFinalSummary    = 'YES'
                FinishAction        = 'LOGOFF'
            }
        }

        if (-not (Get-MDTRole -name JoinDomain)){
            New-MDTRole -name JoinDomain -settings @{
                SkipComputerName    ='YES'
                SkipDomainMembership='YES'
                JoinDomain          = $env:USERDNSDomain
                DomainAdmin         ='MDTUser'
                DomainAdminDomain   = $env:userdomain
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

#region update task sequence with powershell script to install OS to smallest disk right before "New Computer only" group
$TaskSequenceID="WinSRV"
$PSScriptName="OSDDiskIndex.ps1"
$PSScriptContent=@'
$Disks=Get-CimInstance win32_DiskDrive
if ($Disks.model -contains "DELLBOSS VD"){
    #exact model for Dell AX node (DELLBOSS VD)
    $TSenv:OSDDiskIndex=($Disks | Where-Object Model -eq "DELLBOSS VD").Index
}else{
    #or just smallest disk
    $TSenv:OSDDiskIndex=($Disks | Where-Object MediaType -eq "Fixed hard disk media" | Sort-Object Size | Select-Object -First 1).Index
}
<# In case you need PowerShell and pause Task Sequence you can use this code:
#source: http://wiki.wladik.net/windows/mdt/powershell-scripting
#run posh
Start PowerShell
#pause TS
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.MessageBox]::Show("Click to continue...")
#>
'@

    #update Tasksequence
    $TS=Invoke-Command -ComputerName $MDTServer -ScriptBlock {Get-Content -Path $using:DeploymentShareLocation\Control\$using:TaskSequenceID\ts.xml}
    $TextToSearch='    <group name="New Computer only" disable="false" continueOnError="false" description="" expand="false">'
    $PoshScript=@"
    <step type="BDD_RunPowerShellAction" name="Run PowerShell Script" description="" disable="false" continueOnError="false" successCodeList="0 3010">
      <defaultVarList>
        <variable name="ScriptName" property="ScriptName">$PSScriptName</variable>
        <variable name="Parameters" property="Parameters"></variable>
        <variable name="PackageID" property="PackageID"></variable>
      </defaultVarList>
      <action>cscript.exe "%SCRIPTROOT%\ZTIPowerShell.wsf</action>
    </step>
$TextToSearch
"@
    $NewTS=$TS.replace($TextToSearch,$PoshScript)
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Set-Content -Path $using:DeploymentShareLocation\Control\$using:TaskSequenceID\ts.xml -Value $using:NewTS}
    #insert script
    Invoke-Command -ComputerName $MDTServer -ScriptBlock {Set-Content -Path $using:DeploymentShareLocation\Scripts\$using:PSScriptName -Value $using:PSScriptContent}

#endregion

#region update task sequence with drivers
$RoleName="AXNodeDrivers"
if (-not (Get-MDTRole -name $RoleName)){
    #Download DSU
    #https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1

        #grab DSU links from Dell website
        $URL="https://dl.dell.com/omimswac/dsu/"
        $Results=Invoke-WebRequest $URL -UseDefaultCredentials
        $Links=$results.Links.href | Select-Object -Skip 1
        #create PSObject from results
        $DSUs=@()
        foreach ($Link in $Links){
            $DSUs+=[PSCustomObject]@{
                Link = "https://dl.dell.com$Link"
                Version = $link -split "_" | Select-Object -Last 2 | Select-Object -First 1
            }
        }
        #download latest to separate folder
        $LatestDSU=$DSUs | Sort-Object Version | Select-Object -Last 1
        $Folder="$env:USERPROFILE\Downloads\DSU"
        if (-not (Test-Path $Folder)){New-Item -Path $Folder -ItemType Directory}
        Start-BitsTransfer -Source $LatestDSU.Link -Destination $Folder\DSU.exe

        #add DSU as application to MDT
        Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
        if (-not(Get-PSDrive -Name ds001 -ErrorAction Ignore)){
            New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "\\$MDTServer\DeploymentShare$" -Description "MDT Deployment Share" -NetworkPath "\\$MDTServer\DeploymentShare$" -Verbose | add-MDTPersistentDrive -Verbose
        }
        $AppName="Dell DSU $($LatestDSU.Version)"
        Import-MDTApplication -path "DS001:\Applications" -enable "True" -Name $AppName -ShortName "DSU" -Version $LatestDSU.Version -Publisher "Dell" -Language "" -CommandLine "DSU.exe /silent" -WorkingDirectory ".\Applications\$AppName" -ApplicationSourcePath $Folder -DestinationFolder $AppName -Verbose
        #grap package ID for role config
        $DSUID=(Get-ChildItem -Path DS001:\Applications | Where-Object Name -eq $AppName).GUID

    #download catalog and create answer file to run DSU
        #Dell Azure Stack HCI driver catalog https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz
        #Download catalog
        Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
        #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
        $Folder="$env:USERPROFILE\Downloads\DSUPackage"
        if (-not (Test-Path $Folder)){New-Item -Path $Folder -ItemType Directory}
        Function Expand-GZipArchive{
            Param(
                $infile,
                $outfile = ($infile -replace '\.gz$','')
                )
            $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
            $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
            $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
            $buffer = New-Object byte[](1024)
            while($true){
                $read = $gzipstream.Read($buffer, 0, 1024)
                if ($read -le 0){break}
                $output.Write($buffer, 0, $read)
                }
            $gzipStream.Close()
            $output.Close()
            $input.Close()
        }
        Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$folder\ASHCI-Catalog.xml"
        #create answerfile for DU
        $content='@
        a
        c
        @'
        Set-Content -Path "$folder\answer.txt" -Value $content -NoNewline
        $content='"C:\Program Files\Dell\DELL EMC System Update\DSU.exe" --catalog-location=ASHCI-Catalog.xml --apply-upgrades <answer.txt'
        Set-Content -Path "$folder\install.cmd" -Value $content -NoNewline

        #add package to MDT
        [xml]$xml=Get-Content "$folder\ASHCI-Catalog.xml"
        $version=$xml.Manifest.version
        $AppName="Dell DSU AzSHCI Package $Version"
        $Commandline="install.cmd"
        Import-MDTApplication -path "DS001:\Applications" -enable "True" -Name $AppName -ShortName "DSUAzSHCIPackage" -Version $Version -Publisher "Dell" -Language "" -CommandLine $Commandline -WorkingDirectory ".\Applications\$AppName" -ApplicationSourcePath $Folder -DestinationFolder $AppName -Verbose
        #configure app to reboot after run
        Set-ItemProperty -Path DS001:\Applications\$AppName -Name Reboot -Value "True"
        #configure dependency on DSU
        $guids=@()
        $guids+=$DSUID
        Set-ItemProperty -Path DS001:\Applications\$AppName -Name Dependency -Value $guids
        #grap package ID for role config
        $DSUPackageID=(Get-ChildItem -Path DS001:\Applications | Where-Object Name -eq $AppName).GUID

        #Create Role
        New-MDTRole -name $RoleName -settings @{
            OSInstall    ='YES'
        }

        #Add apps to role
        $ID=(get-mdtrole -name $RoleName).ID
        Set-MDTRoleApplication -id $ID -applications $DSUID,$DSUPackageID
}

#add role that will install drivers to R440 computers
foreach ($HVHost in $HVHosts){
    $MDTComputer=Get-MDTComputer -macAddress $HVHost.MACAddress
    $Roles=($MDTComputer | Get-MDTComputerRole).Role
    $Roles+=$RoleName
    #Get-MDTComputer -macAddress $HVHost.MACAddress | Set-MDTComputerRole -roles JoinDomain,AZSHCI
    $MDTComputer | Set-MDTComputerRole -roles $Roles
}

#endregion

#######################################################
#               Fun with Dell R440 nodes               #
#                                                     #
#       Run from machine that can talk to iDRAC       #
#######################################################

#region Restart R440 Nodes to deploy OS
#$Credentials=Get-Credential
$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("LabAdmin", $password)
$idrac_ips="192.168.100.128","192.168.100.129"
$Headers=@{"Accept"="application/json"}
$ContentType='application/json'
function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}
#ignoring cert is needed for posh5. In 6 and newer you can just add -SkipCertificateCheck
Ignore-SSLCertificates

#reboot machines
foreach ($idrac_ip in $idrac_ips){
    #Configure PXE for next reboot
    $JsonBody = @{ Boot = @{
        "BootSourceOverrideTarget"="Pxe"
        }} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"
    Invoke-RestMethod -Body $JsonBody -Method Patch -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    
    #Validate
    $uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    $Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    $Result.Boot.BootSourceOverrideTarget

    #check reboot options
    #$uri="https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/"
    #$Result=Invoke-RestMethod -Method Get -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials
    #$Result.Actions.'#ComputerSystem.Reset'.'ResetType@Redfish.AllowableValues'

    #reboot
    #possible values: On,ForceOff,ForceRestart,GracefulShutdown,PushPowerButton,Nmi,PowerCycle
    $JsonBody = @{ "ResetType" = "ForceRestart"} | ConvertTo-Json -Compress
    $uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"
    Invoke-RestMethod -Body $JsonBody -Method Post -ContentType $ContentType -Headers $Headers -Uri $uri -Credential $Credentials

}
#endregion

