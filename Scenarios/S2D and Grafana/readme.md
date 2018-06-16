<!-- TOC -->

- [S2D and Grafana WORK IN PROGRESS](#s2d-and-grafana-work-in-progress)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [The lab](#the-lab)

<!-- /TOC -->

# S2D and Grafana WORK IN PROGRESS

## About the lab

In following lab you will install [Grafana](http://grafana.com), [influxDB and Telegraf](https://www.influxdata.com/time-series-platform/) on remote Windows Server. To be able to run it as service, [NSSM tool](https://nssm.cc/) is used.

As prerequisite, deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged/) with $realVMs=$true parameter in scenario.ps1 and NestedVirt=$true in LabConfig. This will enable real nested VMs. You will be asked during scenario for vhdx. You can provide nanoserver as it's really small.

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$true}}
$LabConfig.VMs += @{ VMName = 'Grafana' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes= 1GB }

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## The lab

First we will download install files to downloads folder. You can run all code from DC or from Management machine. 

```PowerShell
#download files to downloads folder
    #influxDB and telegraph
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/influxdb/releases/influxdb-1.5.3_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\influxdb.zip"
    Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/telegraf/releases/telegraf-1.6.4_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\telegraf.zip"
    #Grafana
    Invoke-WebRequest -UseBasicParsing -Uri https://s3-us-west-2.amazonaws.com/grafana-releases/release/grafana-5.1.3.windows-x64.zip -OutFile "$env:USERPROFILE\Downloads\grafana.zip"
    #NSSM - the Non-Sucking Service Manager
    Invoke-WebRequest -UseBasicParsing -Uri https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip -OutFile "$env:USERPROFILE\Downloads\NSSM.zip"
 
```

Next step would be to copy zip files to Grafana server temp directory. I decided to copy whole zip as if you have a lot files, zips are more effective. Script will also extract zip files and copy to program files. NSSM x64 will be copied to system32 to be able to use it systemwide.

```PowerShell
#Copy influxDB and Grafana to Grafana server
$session=New-PSSession -ComputerName Grafana

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

Following script will run Grafana and InfluxDB as a service

```PowerShell
#Run Grafana and InfluxDB as system service
Invoke-command -computername Grafana -scriptblock {
    #install as service
    Start-Process -FilePath nssm.exe -ArgumentList "install Grafana ""$env:ProgramFiles\Grafana\bin\grafana-server.exe""" -Wait
    Start-Service Grafana
    Start-Process -FilePath nssm.exe -ArgumentList "install InfluxDB ""$env:ProgramFiles\InfluxDB\influxd.exe""" -Wait
    Start-Service InfluxDB

    #remove
    #Start-Process -FilePath nssm.exe -ArgumentList "remove Grafana confirm" -Wait
    #Start-Process -FilePath nssm.exe -ArgumentList "remove InfluxDB confirm" -Wait
}
 
```
Next PowerShell block will create firewall rules for Grafana and incoming data from telegraf agents.

```PowerShell
#enable firewall rules
    New-NetFirewallRule -CimSession Grafana `
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

    New-NetFirewallRule -CimSession Grafana `
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

    New-NetFirewallRule -CimSession Grafana `
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

```PowerShell
#install agents
$servers=1..4 | % {"s2d$_"}

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

#download telegraf configuration from Github
$config=invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.conf
$config.content | Out-File -FilePath "$env:temp\telegraf\telegraf.conf" -Encoding UTF8 -Force

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
