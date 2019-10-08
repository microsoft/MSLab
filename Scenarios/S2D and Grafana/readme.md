<!-- TOC -->

- [S2D and Grafana](#s2d-and-grafana)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [The lab](#the-lab)

<!-- /TOC -->

# S2D and Grafana

## About the lab

In following lab you will install [Grafana](http://grafana.com), [influxDB and Telegraf](https://www.influxdata.com/time-series-platform/) on remote Windows Server. To be able to run it as service, [NSSM tool](https://nssm.cc/) is used.

As prerequisite, deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged/) with $realVMs=$true parameter in scenario.ps1 and NestedVirt=$true in LabConfig. This will enable real nested VMs. You will be asked during scenario for vhdx. You can provide nanoserver as it's really small.

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$true}}
$LabConfig.VMs += @{ VMName = 'Grafana' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes= 1GB }

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## The lab

First we will download install files to downloads folder. You can run all code from DC or from Management machine. 

```PowerShell
#download files to downloads folder
    $ProgressPreference='SilentlyContinue' #for faster download
    #influxDB and telegraph
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/influxdb/releases/influxdb-1.7.8_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\influxdb.zip"
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/telegraf/releases/telegraf-1.12.2_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\telegraf.zip"
    #Grafana
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.grafana.com/oss/release/grafana-6.4.1.windows-amd64.zip -OutFile "$env:USERPROFILE\Downloads\grafana.zip"
    #NSSM - the Non-Sucking Service Manager
    Invoke-WebRequest -UseBasicParsing -Uri https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip -OutFile "$env:USERPROFILE\Downloads\NSSM.zip"
 
```

Next step would be to copy zip files to Grafana server temp directory. I decided to copy whole zip as if you have a lot files, zips are more effective. Script will also extract zip files and copy to program files. NSSM x64 will be copied to system32 to be able to use it systemwide.

```PowerShell
$GrafanaServerName="Grafana"

#increase MaxEnvelopeSize to transfer foles
Invoke-Command -ComputerName $GrafanaServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
#Copy influxDB and Grafana to Grafana server
$session=New-PSSession -ComputerName $GrafanaServerName

Copy-Item -Path "$env:USERPROFILE\Downloads\influxdb.zip" -Destination "$env:temp\influxdb.zip" -tosession $session
Copy-Item -Path "$env:USERPROFILE\Downloads\grafana.zip" -Destination "$env:temp\grafana.zip" -tosession $session
Copy-Item -Path "$env:USERPROFILE\Downloads\NSSM.zip" -Destination "$env:temp\NSSM.zip" -tosession $session

#extract zip files and copy to destination folder
invoke-command -Session $session -scriptblock {
    Expand-Archive -Path "$env:temp\influxdb.zip" -DestinationPath "$env:temp" -Force
    Expand-Archive -Path "$env:temp\grafana.zip" -DestinationPath "$env:temp" -Force
    Expand-Archive -Path "$env:temp\NSSM.zip" -DestinationPath "$env:temp" -Force
    #rename folder to remove version
    Get-ChildItem -Path $env:temp  | where name -like influxdb-* | Rename-Item -NewName InfluxDB
    Get-ChildItem -Path $env:temp  | where name -like grafana-* | Rename-Item -NewName Grafana
    Get-ChildItem -Path $env:temp  | where name -like nssm-* | Rename-Item -NewName NSSM
    #move to program files
    Move-Item -Path $env:temp\InfluxDB -Destination $env:ProgramFiles -Force
    Move-Item -Path $env:temp\Grafana -Destination $env:ProgramFiles -Force
    #copy nssm to system32
    get-childitem -Path "$env:temp\NSSM" -recurse | Where FullName -like "*win64*nssm.exe" | copy-item -destination "$env:SystemRoot\system32"
    #remove nssm folder
    Remove-Item -Path "$env:temp\NSSM" -Recurse -Force
    #remove zips
    Remove-Item -Path "$env:temp\*.zip" -Force
}
 
```

The next code will configure InfluxDB have database in ProgramFiles folder (or anywhere else you specify)

```PowerShell
$GrafanaServerName="Grafana"
$GrafanaDBPath="C:\InfluxDB\" #path for DB and conf. But consider separate Tier1 disk (like "D:\InfluxDB\")
$GrafanaDBPathForeSlash=$GrafanaDBPath.Replace("\","/")

#replace path for database
Invoke-command -computername $GrafanaServerName -scriptblock {
    $content=Get-Content -Path $env:ProgramFiles\InfluxDB\InfluxDB.conf
    $content=$content.Replace("/var/lib/influxdb/",$using:GrafanaDBPathForeSlash)
    Set-Content -Value $Content -Path $using:GrafanaDBPath\InfluxDB.conf -Encoding UTF8
}

#Create folders for DB
Invoke-command -computername $GrafanaServerName -scriptblock {   
    if (-not(Test-Path -Path $using:GrafanaDBPath)){New-Item -Path $using:GrafanaDBPath -ItemType Directory}
    "data","meta","wal" | Foreach-Object {
        New-Item -Type Directory -Path $using:GrafanaDBPath -Name $_
    }
}
 
```

And now it's about a time to configure LDAP authentication for Grafana

```PowerShell
#some variables
    $GrafanaServerName="Grafana"
    $LDAP_servers = "10.0.0.1" #for multiple "10.0.0.2 10.0.0.3"
    $OU_For_User_And_Group = "OU=Workshop,DC=Corp,DC=contoso,DC=com"
    $Grafana_LDAPuser = "GrafanaUser" #account to query LDAP
    $Grafana_LDAPuserpwd = "LS1setup!"
    $Grafana_AdminsGroupName = "GrafanaAdmins" #Grafana Admins Group
    $Grafana_Admins_To_Add = "LabAdmin"

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

    ### LDAP Authentication - https://grafana.com/docs/auth/ldap/
    ### Grafana, InfluxDB und Windows PowerShell - https://www.zueschen.eu/grafana-influxdb-und-windows-powershell-teil-7/
    Write-Host -ForegroundColor Cyan "Configuring Grafana for LDAP Authentication ..." 
    $GrafanaLDAPuser = (Get-ADUser $Grafana_LDAPuser).DistinguishedName
    $GrafanaLDAPuserpwd = $Grafana_LDAPuserpwd
    $GrafanaBaseDomain = (Get-ADDomain).DistinguishedName
    $GrafanaAdmins = (Get-ADGroup $Grafana_AdminsGroupName).DistinguishedName
    Invoke-command -computername $grafanaServer -scriptblock {
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
 
```

Following script will run Grafana and InfluxDB as a service

```PowerShell
$GrafanaServerName="Grafana"
$GrafanaConfigPath="C:\InfluxDB\influxdb.conf"
#Run Grafana and InfluxDB as system service
Invoke-command -computername $GrafanaServerName -scriptblock {
    #install as service
    Start-Process -FilePath nssm.exe -ArgumentList "install Grafana ""$env:ProgramFiles\Grafana\bin\grafana-server.exe""" -Wait
    Start-Service Grafana
    Start-Process -FilePath nssm.exe -ArgumentList "install InfluxDB ""$env:ProgramFiles\InfluxDB\influxd.exe""" -Wait
    Start-Process -FilePath nssm.exe -ArgumentList "set InfluxDB AppParameters -config $('"""""""')$using:GrafanaConfigPath$('"""""""')" -Wait
    Start-Service InfluxDB

    #remove
    #Start-Process -FilePath nssm.exe -ArgumentList "remove Grafana confirm" -Wait
    #Start-Process -FilePath nssm.exe -ArgumentList "remove InfluxDB confirm" -Wait
}
 
```

Next PowerShell block will create firewall rules for Grafana and incoming data from telegraf agents.

```PowerShell
$GrafanaServerName="Grafana"
#enable firewall rules
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
        -RemoteAddress Any

    New-NetFirewallRule -CimSession $GrafanaServerName `
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
        -RemoteAddress Any

    New-NetFirewallRule -CimSession $GrafanaServerName `
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
        -RemoteAddress Any
 
```

Following script will push telegraf agent to nodes s2d1,s2d2,s2d3 and s2d4. It will dowload sample telegraf config from GitHub. Feel free to pull it, and add more.

```PowerShell
#install agents
$servers=1..4 | % {"s2d$_"}

#increase MaxEnvelopeSize to transfer foles
Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}

#create sessions
$sessions=New-PSSession -ComputerName $servers

#expand telegraf
Expand-Archive -Path "$env:USERPROFILE\Downloads\Telegraf.zip" -DestinationPath "$env:temp" -Force

<#
#reuse default telegraf config and replace server name in config
$config=get-content -path "$env:temp\telegraf\telegraf.conf"
$config=$config.replace("127.0.0.1","grafana.corp.contoso.com")
$config | Set-Content -Path "$env:temp\telegraf\telegraf.conf" -Encoding UTF8
#>

#download telegraf configuration from WSLab Github and configure grafana URL
$GrafanaServerURL="http://grafana.corp.contoso.com:8086"
$config=invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.conf
$config.content.replace("PlaceGrafanaURLHere",$GrafanaServerURL) | Out-File -FilePath "$env:temp\telegraf\telegraf.conf" -Encoding UTF8 -Force

#copy telegraf
foreach ($session in $sessions){
    Copy-Item -Path "$env:temp\Telegraf" -Destination "$env:ProgramFiles" -tosession $session -recurse -force
}

#install telegraf
invoke-command -session $sessions -scriptblock {
    Start-Process -FilePath "$env:ProgramFiles\telegraf\telegraf.exe" -ArgumentList "--service install" -Wait
    Start-Service Telegraf
}
 
```

Once all is set, you can navigate to http://grafana:3000 and login with admin/admin credentials. Optionally install Edge Dev

```PowerShell
#Download Edge Dev
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2069324&Channel=Dev&language=en-us&Consent=1" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe"
#Install Edge Dev
Start-Process -FilePath "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe" -Wait
 
```
![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaLogin.png)

In Add data source, add Telegraf DB

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaDB.png)

As you can see, all counters are now available for adding to graph.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaGraph.png)
