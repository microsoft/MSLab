<!-- TOC -->

- [S2D and Grafana](#s2d-and-grafana)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [The lab](#the-lab)
        - [Region Variables](#region-variables)
        - [Region Install Management Tools](#region-install-management-tools)
        - [Region Download required files to downloads folder](#region-download-required-files-to-downloads-folder)
        - [Region Copy NSSM, InfluxDB and Grafana to servers](#region-copy-nssm-influxdb-and-grafana-to-servers)
        - [Region Configure InfluxDB to exist in different folder](#region-configure-influxdb-to-exist-in-different-folder)
        - [Region Configure Grafana and Influx DB Services](#region-configure-grafana-and-influx-db-services)
        - [Region Configure LDAP for Grafana](#region-configure-ldap-for-grafana)
        - [Region Secure communication with IPSec](#region-secure-communication-with-ipsec)
        - [Region Add computer to InfluxDB rule to authorize access to Influx DB Database](#region-add-computer-to-influxdb-rule-to-authorize-access-to-influx-db-database)
        - [Region push telegraf agent to nodes](#region-push-telegraf-agent-to-nodes)
        - [Region Download Edge Dev](#region-download-edge-dev)
    - [Manual actions needed](#manual-actions-needed)

<!-- /TOC -->

# S2D and Grafana

## About the lab

In following lab you will install [Grafana](http://grafana.com), [influxDB and Telegraf](https://www.influxdata.com/time-series-platform/) on remote Windows Servers. To be able to run it as service, [NSSM tool](https://nssm.cc/) is used.

Since Grafana and Influx DB uses certificates, instead of creating Certification authority (as demonstrated in [Certification Authority scenario](/Scenarios/Certification%20Authority)) is used Windows Firewall with IPSec. Also InfluxDB access is restricted (and encrypted) using firewall rules from nodes and management server only.

As prerequisite, deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged) just to have some data to play with. $realVMs=$true in Labconfig to have real virtual machines that provide workload. You can also consider loading some workload using [S2D and Diskspd scenario](/Scenarios/S2D%20and%20Diskspd)

## LabConfig

![](/Scenarios/S2D%20and%20Grafana/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Grafana' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 1GB }
$LabConfig.VMs += @{ VMName = 'InfluxDB' ; Configuration = 's2d' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 0; HDDSize= 4TB ; MemoryStartupBytes= 1GB }

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true}} 

# or without nested virt and just 512MB of memory
#1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## The lab

Follow the Scenario.ps1. Run all code from DC (or Management machine).

![](/Scenarios/S2D%20and%20Grafana/Screenshots/Scenario.png)

### Region Variables

Here you can decide where you want to host Grafana and InfluxDB. Servers can be the same. Also account that is used for querying LDAP is created.

### Region Install Management Tools

This region just makes sure that you have proper RSAT tools installed - Failover Clustering and AD PowerShell (to be able to query cluster and group)

### Region Download required files to downloads folder

It worth checking if the links are the latest one (since I did not find a way to just download latest packages). So links may download some older version. NSSM does not change much (the latest version is more than 2 years old)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/DownloadedFiles.png)

### Region Copy NSSM, InfluxDB and Grafana to servers

This region just copies downloaded files (ZIP) into temp folder on servers (GrafanaServer and InfluxDB). It will invoke unzipping and renaming to trim version (for easier upgrade later) into c:\Program Files.

NSSM is also copied into system32 folder to be able to run it anytime, anywhere.

First we will download install files to downloads folder. You can run all code from DC or from Management machine.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/FoldersInProgramFiles.png)

### Region Configure InfluxDB to exist in different folder

In this region will script first format disks that is RAW (in lab there is one more disk added into InfluxDB machine) as usually you want to have database on faster tier and somewhere else than OS.

It will be moved into location specified in variables (by default e:\InfluxDB\ ) and respective folders will be created. All this is specified in config that's located in the same location.

InfluxD service is then started with parameter that points it to config.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/InfluxDBFolders.png)

### Region Configure Grafana and Influx DB Services

Services are configured to start using NSSM. Influx DB has parameter of the config. Notice that after starting InfluxDB, files containing database are created.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/InfluxDBService.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/InfluxDBServiceNSSM.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaService.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaServiceNSSM.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/InfluxDBFiles.png)

### Region Configure LDAP for Grafana

Account specified in variables is created together with group GrafanaAdmins and added to C:\Program Files\Grafana\conf\ldap.toml. 

![](/Scenarios/S2D%20and%20Grafana/Screenshots/LDAPtoml.png)

### Region Secure communication with IPSec

This code will add default connection security rule to computers specified in $IPSecServers. It is necessary to understand kerberos traffic to create this default rule. You will find it under connection security rules in wf.msc

![](/Scenarios/S2D%20and%20Grafana/Screenshots/ConnectionSecurityRule.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/FWRuleInfluxDB.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/FWRuleGrafana.png)

```PowerShell
#to be able to remotely query firewall rules with wf.msc
Enable-NetFirewallRule -CimSession Grafana,Influxdb -Name RemoteFwAdmin*
 
```

### Region Add computer to InfluxDB rule to authorize access to Influx DB Database

Computers in $InfluxDBAuthorizedServers variable are added to FW rule.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/FWRuleInfluxDBAuthorizedComputers.png)

### Region push telegraf agent to nodes

In this region telegraf.conf is downloaded from GitHub S2D and Grafana scenario page. String "# clusters =" is replaced with cluster name for each cluster that's specified in variables and telegraf.conf is transferred. Script also copies telegraf to every node of specified cluster.

### Region Download Edge Dev

This part just downloads and installs Edge Dev, so you can navigate to Grafana:3000 from Windows Server (as it's html5 browser)

## Manual actions needed

After you finish scenario, open Edge Dev and navigate to http://grafana:3000 . Once you'll be here, you can check, if traffic is encrypted (tbd is to set IPSec to Elyptic Curves, SHA384...)

```PowerShell
#check traffic if it's encrypted
Get-NetIPsecQuickModeSA | select *endpoint*,*first*,*second* |ft
 
```

![](/Scenarios/S2D%20and%20Grafana/Screenshots/EncryptedTrafficPosh.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/EncryptedTrafficWFmsc.png)


You can log in with LabAdmin\LS1setup! as LDAP authorization is enabled

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaWeb.png)

You might want to cleanup default admin (Settings->Users)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/Users.png)

Add Datasource

![](/Scenarios/S2D%20and%20Grafana/Screenshots/AddDatasource01.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/AddDatasource02.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/AddDatasource03.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/AddDatasource04.png)

After that just import JSON by pasting query from [here](/Scenarios/S2D%20and%20Grafana/dashboard.json)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaImportDatabase.png)

Unfortunately IOPS are not collected as for some reason CSVFS counter does not provide anything (further investigation needed)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaDashboard.png)
