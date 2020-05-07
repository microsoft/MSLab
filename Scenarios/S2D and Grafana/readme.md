<!-- TOC -->

- [S2D and Grafana](#s2d-and-grafana)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [The lab](#the-lab)
        - [Region Variables](#region-variables)
        - [Region Download required files to downloads folder](#region-download-required-files-to-downloads-folder)
        - [Region Download and Install Edge Dev](#region-download-and-install-edge-dev)
        - [Region Install Management Tools](#region-install-management-tools)
        - [Region setup Certification Authority](#region-setup-certification-authority)
        - [Add certificate templates for Computers (to secure LDAP) and Exportable for Grafana](#add-certificate-templates-for-computers-to-secure-ldap-and-exportable-for-grafana)
        - [Region distribute certificates to Domain Controller and Grafana](#region-distribute-certificates-to-domain-controller-and-grafana)
        - [Region Reload AD SSL Certificate](#region-reload-ad-ssl-certificate)
        - [Region Copy NSSM, InfluxDB and Grafana to servers](#region-copy-nssm-influxdb-and-grafana-to-servers)
        - [Region Configure InfluxDB to exist in different folder](#region-configure-influxdb-to-exist-in-different-folder)
        - [Region Configure Grafana and Influx DB Services](#region-configure-grafana-and-influx-db-services)
        - [Region Secure communication with IPSec](#region-secure-communication-with-ipsec)
        - [Region Add computer to InfluxDB rule to authorize access to Influx DB Database](#region-add-computer-to-influxdb-rule-to-authorize-access-to-influx-db-database)
        - [Region Configure LDAP for Grafana](#region-configure-ldap-for-grafana)
        - [Region Secure LDAP to use SSL and Configure Grafana Certificate](#region-secure-ldap-to-use-ssl-and-configure-grafana-certificate)
        - [Region Add Firewall Rule for Grafana](#region-add-firewall-rule-for-grafana)
        - [Region push telegraf agent to nodes](#region-push-telegraf-agent-to-nodes)
    - [Manual actions needed](#manual-actions-needed)

<!-- /TOC -->

# S2D and Grafana

## About the lab

In following lab you will install [Grafana](http://grafana.com), [influxDB and Telegraf](https://www.influxdata.com/time-series-platform/) on remote Windows Servers. To be able to run it as service, [NSSM tool](https://nssm.cc/) is used.

The scenario demonstrates how to configure Grafana to use SSL and also to use LDAP over SSL. Scenario shares the code with [Certification Authority scenario](/Scenarios/Certification%20Authority)). To secure InfluxDB is IPSec used. Also InfluxDB access is restricted (and encrypted) using firewall rules to nodes and grafana server (and management server, in this case DC).

As prerequisite, deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged) just to have some data to play with. $realVMs=$true in Labconfig to have real virtual machines that provide workload. You can also consider loading some workload using [S2D and Diskspd scenario](/Scenarios/S2D%20and%20Diskspd)

Big thanks to https://twitter.com/Vecteurinfo who provided telegraf.conf and telegraf.ps1 together with his [dashboard](https://twitter.com/Vecteurinfo/status/1116386589389856770?s=20) that was later modified by Martin Rasendorfer to be universal and to be able to switch between clusters. Also big help comes from https://twitter.com/vladimirmach and his insight into Linux world and certs.

Note: if used in production, more things has to be tightened (like certs are exposed in program files - consider moving config to programdata..., telegraf blindly runs powershell code provided - consider signing...)

Further improvements welcomed - feel free to pull request!

## LabConfig

![](/Scenarios/S2D%20and%20Grafana/Screenshots/VMs.png)

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!';<# Prefix = 'WSLab-';#> SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true}}

# or without nested virt and just 512MB of memory
#1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB}}

$LabConfig.VMs += @{ VMName = 'CA' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 1GB }
$LabConfig.VMs += @{ VMName = 'Grafana' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes= 1GB }
$LabConfig.VMs += @{ VMName = 'InfluxDB' ; Configuration = 's2d' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 0; HDDSize= 4TB ; MemoryStartupBytes= 1GB }

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## The lab

Follow the code in [Scenario.ps1](/Scenarios/S2D%20and%20Grafana/Scenario.ps1). Run all code from DC (or Management machine).

![](/Scenarios/S2D%20and%20Grafana/Screenshots/Scenario.png)

### Region Variables

Here you can decide where you want to host Grafana and InfluxDB. Servers can be the same. Also account that is used for querying LDAP is created.

### Region Download required files to downloads folder

It worth checking if the links are the latest one (since I did not find a way to just download latest packages). So links may download some older version. NSSM does not change much (the latest version is more than 2 years old)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/DownloadedFiles.png)

### Region Download and Install Edge Dev

Edge dev is installed to have HTML5 enabled browser to work with Grafana from Windows Server.

### Region Install Management Tools

This region just makes sure that you have proper RSAT tools installed - Failover Clustering and AD PowerShell (to be able to query cluster and group)

### Region setup Certification Authority

The steps are identical to [Certification Authority scenario](/Scenarios/Certification%20Authority))

### Add certificate templates for Computers (to secure LDAP) and Exportable for Grafana

First certificate is for Domain Computer(s). It's there to secure LDAP on port 636. As template name suggest, it's Legacy CSP (just copy of Domain Controller template configured with Windows Server 2016 level)

Second certificate is for Grafana and it is exportable - since it's needed later in PEM format (separate private and public key)

Both certs are RSA. Same functions are used as in [Certification Authority scenario](/Scenarios/Certification%20Authority))

![](/Scenarios/S2D%20and%20Grafana/Screenshots/CATemplates01.png)

### Region distribute certificates to Domain Controller and Grafana

Firt of all ACLs are set on templates to be able to autoenroll from DC and Grafana server

![](/Scenarios/S2D%20and%20Grafana/Screenshots/CATemplates02.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/CATemplates03.png)

Then Autoenrollment policy is configured and certutil pulse is ran to refresh certs.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/AutoEnrolledCerts.png)

### Region Reload AD SSL Certificate

This piece of code just makes sure LDAPs is running on port 636 and is using certificate from local store (automatically picked). https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4cf26e43-ae0b-4823-b00c-18205ab78065?redirectedfrom=MSDN

You can use LDP.exe to validate. On my computer it asked for pin when succeeded.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/LDP.png)

### Region Copy NSSM, InfluxDB and Grafana to servers

This region just copies downloaded files (zip) into temp folder on servers (GrafanaServer and InfluxDB). It will invoke unzipping and renaming to trim version (for easier upgrade later) into c:\Program Files.

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

### Region Secure communication with IPSec

This code will add default connection security rule to computers specified in $IPSecServers. It is necessary to understand kerberos traffic to create this default rule. You will find it under connection security rules in wf.msc

![](/Scenarios/S2D%20and%20Grafana/Screenshots/ConnectionSecurityRule.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/FWRuleInfluxDB.png)

```PowerShell
#to be able to remotely query firewall rules with wf.msc
Enable-NetFirewallRule -CimSession Grafana,Influxdb -Name RemoteFwAdmin*
 
```

### Region Add computer to InfluxDB rule to authorize access to Influx DB Database

Computers in $InfluxDBAuthorizedServers variable are added to FW rule.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/FWRuleInfluxDBAuthorizedComputers.png)


### Region Configure LDAP for Grafana

Account specified in variables is created together with group GrafanaAdmins and added to C:\Program Files\Grafana\conf\ldap.toml. 

![](/Scenarios/S2D%20and%20Grafana/Screenshots/LDAPtoml.png)

### Region Secure LDAP to use SSL and Configure Grafana Certificate

This code will modify toml and config file to use LDAP over SSL (TLS). It will also configure Grafana to use port 443 with HTTPS protocol.

### Region Add Firewall Rule for Grafana

Just a simple firewall rule to enable Grafana to accept HTTPs connections.

### Region push telegraf agent to nodes

In this region telegraf.conf is downloaded from GitHub S2D and Grafana scenario page. String "# clusters =" is replaced with cluster name for each cluster that's specified in variables and telegraf.conf is transferred. Script also copies telegraf to every node of specified cluster.

## Manual actions needed

After you finish scenario, open Edge Dev and navigate to https://grafana.corp.contoso.com . Notice that traffic is now secured with HTTPs.ciorp

```PowerShell
#check traffic if it's encrypted
Get-NetIPsecQuickModeSA | select *endpoint*,*first*,*second* |ft
 
```

![](/Scenarios/S2D%20and%20Grafana/Screenshots/EncryptedTrafficPosh.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/EncryptedTrafficWFmsc.png)


You can log in with LabAdmin\LS1setup! as LDAP authorization is enabled

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaWeb.png)

You might want to cleanup default admin (Settings->Users)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaUsers.png)

Add Datasource

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaAddDatasource01.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaAddDatasource02.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaAddDatasource03.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaAddDatasource04.png)

After that just import JSON by pasting query from [here](/Scenarios/S2D%20and%20Grafana/dashboard.json)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaImportDashboard01.png)

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaImportDashboard02.png)

As you can see, virtualized system is not performing much. But for validating counters in Grafana it's more than enough.

![](/Scenarios/S2D%20and%20Grafana/Screenshots/GrafanaDashboard.png)
