#region variables
    #global variables
    $GrafanaServerName="Grafana"
    $InfluxDBServerName="InfluxDB"
    $InfluxDBPath="E:\InfluxDB\" #path for DB and config. In lab is D drive drive that is not initialized and will be formatted
    $InfluxDBConfigPath=$InfluxDBPath+"influxdb.conf"

    #grafana variables
    $LDAP_servers = "10.0.0.1" #for multiple "10.0.0.2 10.0.0.3"
    $OU_For_User_And_Group = "OU=Workshop,DC=Corp,DC=contoso,DC=com"
    $Grafana_LDAPuser = "GrafanaUser" #account to query LDAP
    $Grafana_LDAPuserpwd = "LS1setup!"
    $Grafana_AdminsGroupName = "GrafanaAdmins" #Grafana Admins Group
    $Grafana_Admins_To_Add = "LabAdmin"

    #firewall vars
    $IPSecServers="DC",$GrafanaServerName,$InfluxDBServerName,"S2D1","S2D2","S2D3","S2D4"
    $InfluxDBAuthorizedServers="DC",$GrafanaServerName,"S2D1","S2D2","S2D3","S2D4"

    #telegraf - monitored servers
    $clusters=@("S2D-Cluster")
    #$clusters=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1).Name

#endregion

#region install management tools
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    $CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-AD-PowerShell
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-AD-PowerShell
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
        #Validate RSAT Installed
            if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                Write-Host "Please install RSAT, Exitting in 5s"
                Start-Sleep 5
                Exit
            }
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
        #Install RSAT tools
            $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            foreach ($Capability in $Capabilities){
                Add-WindowsCapability -Name $Capability -Online
            }
    }
#endregion

#region download required files to downloads folder
    $ProgressPreference='SilentlyContinue' #for faster download
    #influxDB and telegraph
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/influxdb/releases/influxdb-1.7.8_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\influxdb.zip"
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/telegraf/releases/telegraf-1.12.2_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\telegraf.zip"
    #Grafana
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.grafana.com/oss/release/grafana-6.4.1.windows-amd64.zip -OutFile "$env:USERPROFILE\Downloads\grafana.zip"
    #NSSM - the Non-Sucking Service Manager
    Invoke-WebRequest -UseBasicParsing -Uri https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip -OutFile "$env:USERPROFILE\Downloads\NSSM.zip"
#endregion

#region Copy NSSM, InfluxDB and Grafana to servers
    #increase MaxEnvelopeSize to transfer files
    Invoke-Command -ComputerName $GrafanaServerName,$InfluxDBServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}

    $GrafanaSession=New-PSSession -ComputerName $GrafanaServerName
    $InfluxDBSession=New-PSSession -ComputerName $InfluxDBServerName

    Copy-Item -Path "$env:USERPROFILE\Downloads\influxdb.zip" -Destination "$env:temp\influxdb.zip" -tosession $InfluxDBSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\grafana.zip" -Destination "$env:temp\grafana.zip" -tosession $GrafanaSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\NSSM.zip" -Destination "$env:temp\NSSM.zip" -tosession $GrafanaSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\NSSM.zip" -Destination "$env:temp\NSSM.zip" -tosession $InfluxDBSession

    #extract zip files and copy to destination folder
    invoke-command -Session $InfluxDBSession -scriptblock {
        Expand-Archive -Path "$env:temp\influxdb.zip" -DestinationPath "$env:temp" -Force
        Expand-Archive -Path "$env:temp\NSSM.zip" -DestinationPath "$env:temp" -Force
        #rename folder to remove version
        Get-ChildItem -Path $env:temp  | Where-Object name -like influxdb-* | Rename-Item -NewName InfluxDB
        Get-ChildItem -Path $env:temp  | Where-Object name -like nssm-* | Rename-Item -NewName NSSM
        #move to program files
        Move-Item -Path $env:temp\InfluxDB -Destination $env:ProgramFiles -Force
        #copy nssm to system32
        get-childitem -Path "$env:temp\NSSM" -recurse | Where-Object FullName -like "*win64*nssm.exe" | copy-item -destination "$env:SystemRoot\system32"
        #remove nssm folder
        Remove-Item -Path "$env:temp\NSSM" -Recurse -Force
        #remove zips
        Remove-Item -Path "$env:temp\*.zip" -Force
    }

    invoke-command -Session $GrafanaSession -scriptblock {
        Expand-Archive -Path "$env:temp\grafana.zip" -DestinationPath "$env:temp" -Force
        Expand-Archive -Path "$env:temp\NSSM.zip" -DestinationPath "$env:temp" -Force
        #rename folder to remove version
        Get-ChildItem -Path $env:temp  | Where-Object name -like grafana-* | Rename-Item -NewName Grafana
        Get-ChildItem -Path $env:temp  | Where-Object name -like nssm-* | Rename-Item -NewName NSSM
        #move to program files
        Move-Item -Path $env:temp\Grafana -Destination $env:ProgramFiles -Force
        #copy nssm to system32
        get-childitem -Path "$env:temp\NSSM" -recurse | Where-Object FullName -like "*win64*nssm.exe" | copy-item -destination "$env:SystemRoot\system32"
        #remove nssm folder
        Remove-Item -Path "$env:temp\NSSM" -Recurse -Force
        #remove zips
        Remove-Item -Path "$env:temp\*.zip" -Force
    }
#endregion

#region Configure InfluxDB to exist in different folder
    #Format raw Disk on InfluxDB Server
    Get-Disk -CimSession $InfluxDBServerName | Where-Object partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter E -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false

    #Create folders for DB
    Invoke-command -computername $InfluxDBServerName -scriptblock {   
        if (-not(Test-Path -Path $using:InfluxDBPath)){New-Item -Path $using:InfluxDBPath -ItemType Directory}
        "data","meta","wal" | Foreach-Object {
            New-Item -Type Directory -Path $using:InfluxDBPath -Name $_
        }
    }

    #replace path for database and copy config to DB folder
    $InfluxDBPathForeSlash=$InfluxDBPath.Replace("\","/")
    Invoke-command -computername $InfluxDBServerName -scriptblock {
        $content=Get-Content -Path $env:ProgramFiles\InfluxDB\InfluxDB.conf
        $content=$content.Replace("/var/lib/influxdb/",$using:InfluxDBPathForeSlash)
        Set-Content -Value $Content -Path $using:InfluxDBConfigPath -Encoding UTF8
    }
 
#endregion

#region Configure Grafana and Influx DB services
    Invoke-command -computername $GrafanaServerName -scriptblock {
        #install as service
        Start-Process -FilePath nssm.exe -ArgumentList "install Grafana ""$env:ProgramFiles\Grafana\bin\grafana-server.exe""" -Wait
        Start-Service Grafana
    }
    Invoke-command -computername $InfluxDBServerName -scriptblock {
        Start-Process -FilePath nssm.exe -ArgumentList "install InfluxDB ""$env:ProgramFiles\InfluxDB\influxd.exe""" -Wait
        Start-Process -FilePath nssm.exe -ArgumentList "set InfluxDB AppParameters -config $('"""""""')$using:InfluxDBConfigPath$('"""""""')" -Wait
        Start-Service InfluxDB
    }
    #remove
    #Start-Process -FilePath nssm.exe -ArgumentList "remove Grafana confirm" -Wait
    #Start-Process -FilePath nssm.exe -ArgumentList "remove InfluxDB confirm" -Wait
#endregion

#region Configure LDAP for Grafana
    #validate if AD Posh is installed (or install it)
        $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
        $CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
        if ($WindowsInstallationType -like "Server*"){
            Install-WindowsFeature -Name "RSAT-AD-PowerShell"
        }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
            #Validate RSAT Installed
                if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                    Write-Host "Please install RSAT, Exitting in 5s"
                    Start-Sleep 5
                    Exit
                }
        }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
            #install AD RSAT
            Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online
        }

    #Create Users and Groups
        #create Grafana LDAP User
        New-ADUser -Name $Grafana_LDAPuser -UserPrincipalName $Grafana_LDAPuser -Path $OU_For_User_And_Group -Enabled $true -AccountPassword (ConvertTo-SecureString $Grafana_LDAPuserpwd -AsPlainText -Force)

        #create group for Grafana Admins
        New-ADGroup -Name $Grafana_AdminsGroupName -GroupScope Global -Path $OU_For_User_And_Group

        #Add members to AD Group
        Add-ADGroupMember -Identity $Grafana_AdminsGroupName -Members $Grafana_Admins_To_Add

    ### setup LDAP Authentication - https://grafana.com/docs/auth/ldap/
    ### Source: Grafana, InfluxDB und Windows PowerShell - https://www.zueschen.eu/grafana-influxdb-und-windows-powershell-teil-7/
    Write-Host -ForegroundColor Cyan "Configuring Grafana for LDAP Authentication ..." 
    $GrafanaLDAPuser = (Get-ADUser $Grafana_LDAPuser).DistinguishedName
    $GrafanaLDAPuserpwd = $Grafana_LDAPuserpwd
    $GrafanaBaseDomain = (Get-ADDomain).DistinguishedName
    $GrafanaAdmins = (Get-ADGroup $Grafana_AdminsGroupName).DistinguishedName
    Invoke-command -computername $GrafanaServerName -scriptblock {
        Stop-Service -Name Grafana
            #region Configure LDAP authentication in Grafane server config file
                #Load Grafana Server config file - LDAP to be anabled there
                $configfile = "$($env:ProgramFiles)\Grafana\conf\defaults.ini"
                $GrafanaServerConfigLDAPstring = Select-String -Path $configfile -Pattern 'Auth LDAP'
                $GrafanaServerConfig = Get-Content -Path $configfile
 
                #Replace the default values with the new ones
                $GrafanaServerConfig[$GrafanaServerConfigLDAPstring.LineNumber + 1] = 'enabled = true'
                $GrafanaServerConfig[$GrafanaServerConfigLDAPstring.LineNumber + 2] = 'config_file = C:\Program Files\Grafana\conf\ldap.toml'
                $GrafanaServerConfig[$GrafanaServerConfigLDAPstring.LineNumber + 3] = 'allow_sign_up = true'
 
                # Set the new content
                $GrafanaServerConfig | Set-Content -Path "$($env:ProgramFiles)\Grafana\conf\defaults.ini"
            #endregion
            #region Configure LDAP authentication in Grafane LDAP config file
                #Load Grafana LDAP config file
                    $LDAPconfigfile = "C:\Program Files\Grafana\conf\ldap.toml"
                    $GrafanaLDAPConfig = Get-Content -Path $LDAPconfigfile
                #Define config file lines to be changed
                    $GrafanaLDAP_host = Select-String -Path $LDAPconfigfile -Pattern "Ldap server host"
                    $GrafanaLDAP_SearchUserBind = Select-String -Path $LDAPconfigfile -Pattern "Search user bind dn"
                    $GrafanaLDAP_UserSearchFilter = Select-String -Path $LDAPconfigfile -Pattern "User search filter, for example"
                    $GrafanaLDAP_BaseDNSSearch = Select-String -Path $LDAPconfigfile -Pattern "An array of base dns to search through"
                    $GrafanaLDAP_Attributes = Select-String -Path $LDAPconfigfile -Pattern "Specify names of the ldap attributes your ldap uses"
                    $GrafanaLDAP_AdminMapping = Select-String -Path $LDAPconfigfile -Pattern "Map ldap groups to grafana org roles"
                #Set LDAP servers
                    $GrafanaLDAPConfig[$GrafanaLDAP_host.LineNumber] = "host = $('"')$($using:LDAP_servers)$('"')"
                #Set Grafana search bind account
                    $GrafanaLDAPConfig[$GrafanaLDAP_SearchUserBind.LineNumber] = "bind_dn = $('"')$($using:GrafanaLDAPuser)$('"')"
                    $GrafanaLDAPConfig[$GrafanaLDAP_SearchUserBind.LineNumber + 3] = "bind_password = '$using:GrafanaLDAPuserpwd'"
                #Set user search filter
                    $GrafanaLDAPConfig[$GrafanaLDAP_UserSearchFilter.LineNumber] = 'search_filter = "(|(sAMAccountName=%s)(userPrincipalName=%s))"'
                #Set base dns search
                    $GrafanaLDAPConfig[$GrafanaLDAP_BaseDNSSearch.LineNumber] = "search_base_dns = [$('"')$($using:GrafanaBaseDomain)$('"')]"
                #Set LDAP attributes
                    $GrafanaLDAPConfig[$GrafanaLDAP_Attributes.LineNumber + 3] = 'username = "sAMAccountName"'
                #Set Admin role mapping
                    $GrafanaLDAPConfig[$GrafanaLDAP_AdminMapping.LineNumber + 1] = "group_dn = $('"')$($using:GrafanaAdmins)$('"')"
 
                # Set the new content
                    $GrafanaLDAPConfig | Set-Content -Path "C:\Program Files\Grafana\conf\ldap.toml"
            #endregion
            Set-Service -Name Grafana -StartupType Automatic  
            Start-Service -Name Grafana
    }
 
#endregion

#region Secure communication with IPSec

    #Create IPSec rule locally and on machines to secure traffic between endpoints
    Invoke-Command -ComputerName $IPSecServers -ScriptBlock {
        if (-not (Get-NetIPsecRule -DisplayName "Default Request Rule" -ErrorAction SilentlyContinue)){
            New-NetIPsecRule -DisplayName "Default Request Rule" -InboundSecurity Request -OutboundSecurity Request
        }
    }
    #enable firewall rules for Grafana
    New-NetFirewallRule -CimSession $GrafanaServerName `
        -Action Allow `
        -Name "Grafana-HTTP-In-TCP" `
        -DisplayName "Grafana (HTTP-In)" `
        -Description "Inbound rule for Grafana web. [TCP-3000]" `
        -Enabled True `
        -Direction Inbound `
        -Program "%ProgramFiles%\Grafana\bin\grafana-server.exe" `
        -Protocol TCP `
        -LocalPort 3000 `
        -Profile Any `
        -Group "Grafana" `
        -RemoteAddress Any `
        -Authentication Required `
        -Encryption Dynamic

    New-NetFirewallRule -CimSession $InfluxDBServerName `
        -Action Allow `
        -Name "InfluxDB-HTTP-In-TCP" `
        -DisplayName "InfluxDB (HTTP-In)" `
        -Description "Inbound rule for Grafana DB. [TCP-8086]" `
        -Enabled True `
        -Direction Inbound `
        -Program "%ProgramFiles%\InfluxDB\influxd.exe" `
        -Protocol TCP `
        -LocalPort 8086 `
        -Profile Any `
        -Group "InfluxDB" `
        -RemoteAddress Any `
        -Authentication Required `
        -Encryption Dynamic


    New-NetFirewallRule -CimSession $InfluxDBServerName `
        -Action Allow `
        -Name "InfluxDBBackup-HTTP-In-TCP" `
        -DisplayName "InfluxDBBackup (HTTP-In)" `
        -Description "Inbound rule for Grafana DB. [TCP-8088]" `
        -Enabled True `
        -Direction Inbound `
        -Program "%ProgramFiles%\InfluxDB\influxd.exe" `
        -Protocol TCP `
        -LocalPort 8088 `
        -Profile Any `
        -Group "InfluxDB" `
        -RemoteAddress Any `
        -Authentication Required `
        -Encryption Dynamic
 
#endregion

#region Add Computer to InfluxDB rule, to authorize access to Influx Database
    foreach ($server in $InfluxDBAuthorizedServers){
        #grab SID
        $SID=(Get-ADComputer -Identity $server).SID.Value
        #add SID to Firewall rule
        $FWRules=Get-NetFirewallrule -CimSession $InfluxDBServerName -Name InfluxDB*
        #grab current ACLs and add new ones
        foreach ($fwrule in $fwrules){
            $CurrentACL=($fwrule | Get-NetFirewallSecurityFilter).RemoteMachines
            if (-not($CurrentACL -like "*$SID*")){
                if ($CurrentACL){
                    $SDDL=$CurrentACL+"(A;;CC;;;$SID)"
                }else{
                    $SDDL="O:LSD:(A;;CC;;;$SID)"
                }
                $fwrule | Set-NetFirewallRule -RemoteMachine $SDDL
            }
        }
    }

#endregion

#region push telegraf agent to nodes

    #expand telegraf
    Expand-Archive -Path "$env:USERPROFILE\Downloads\Telegraf.zip" -DestinationPath "$env:temp" -Force

    #download telegraf configuration from WSLab Github and configure grafana URL
    $InfluxDBServerURL="http://InfluxDB.corp.contoso.com:8086"
    $config=invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.conf
    $posh=invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.ps1
    $config=$config.content.replace("PlaceInfluxDBUrlHere",$InfluxDBServerURL) #| Out-File -FilePath "$env:temp\telegraf\telegraf.conf" -Encoding UTF8 -Force
    <#
    #reuse default telegraf config and replace server name in config
    $config=get-content -path "$env:temp\telegraf\telegraf.conf"
    $config=$config.replace("127.0.0.1","grafana.corp.contoso.com")
    $config | Set-Content -Path "$env:temp\telegraf\telegraf.conf" -Encoding UTF8
    #>

    foreach ($Cluster in $Clusters){
        $servers=(Get-ClusterNode -Cluster $Cluster).Name
        #increase MaxEnvelopeSize to transfer foles
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
        #create sessions
        $sessions=New-PSSession -ComputerName $servers
        #copy telegraf
        foreach ($session in $sessions){
            Copy-Item -Path "$env:temp\Telegraf" -Destination "$env:ProgramFiles" -tosession $session -recurse -force
        }
        #replace telegraf conf and drop posh script
        Invoke-command -Session $sessions -ScriptBlock {
            $config=$using:config
            $config.replace("# clustername = ","clustername = $('"')$using:Cluster$('"')") | Out-File -FilePath "$env:ProgramFiles\telegraf\telegraf.conf" -Encoding UTF8 -Force
            $using:posh | Out-File -FilePath "$env:ProgramFiles\telegraf\telegraf.ps1" -Encoding UTF8 -Force
        }
        #install telegraf
        invoke-command -session $sessions -scriptblock {
            Start-Process -FilePath "$env:ProgramFiles\telegraf\telegraf.exe" -ArgumentList "--service install" -Wait
            Start-Service Telegraf
        }
    }
 
#endregion

#region Download Edge Dev
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2069324&Channel=Dev&language=en-us&Consent=1" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe"
#Install Edge Dev
Start-Process -FilePath "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe" -Wait

#endregion

#region check if traffic is encrypted
    #list main mode connections
    Get-NetIPsecMainModeSA | Out-GridView
    #list quick mode connections
    Get-NetIPsecQuickModeSA | Out-GridView
#endregion


#region TBD...
$multiinstancecounters=get-counter -ListSet * | Where-Object countersettype -eq multiinstance | Select-Object -ExpandProperty paths
$singleinstancecounters=get-counter -ListSet * | Where-Object countersettype -eq singleinstance | Select-Object -ExpandProperty paths

#create counters object
$counters=@()
foreach ($counter in $multiinstancecounters){
    $counter=$counter.Replace("(*)","").TrimStart("\").Split("\")
    $counters+= [PSCustomObject]@{ObjectName=$counter[0];Countername=$counter[1];InstanceType="Multi"}
}
foreach ($counter in $singleinstancecounters){
    $counter=$counter.Replace("(*)","").TrimStart("\").Split("\")
    $counters+= [PSCustomObject]@{ObjectName=$counter[0];Countername=$counter[1];InstanceType="Single"}
}
#endregion