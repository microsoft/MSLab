<!-- TOC -->

- [Windows Event Forwarding](#windows-event-forwarding)
    - [About lab](#about-lab)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [LabConfig Windows Server 2019](#labconfig-windows-server-2019)
    - [Configure event WEF collector and import NSA recommended events](#configure-event-wef-collector-and-import-nsa-recommended-events)
        - [Download zip with NSA Samples](#download-zip-with-nsa-samples)
        - [Create groups for each sample rule](#create-groups-for-each-sample-rule)
        - [Configure Collector](#configure-collector)
        - [Validate subscriptions on collector server](#validate-subscriptions-on-collector-server)
        - [Configure remote servers](#configure-remote-servers)
        - [Connect to Collector and view logs](#connect-to-collector-and-view-logs)
        - [Increase Forwarded Events log size](#increase-forwarded-events-log-size)
    - [Install Sysmon with sysmonconfig and enable WEF for Sysmon events](#install-sysmon-with-sysmonconfig-and-enable-wef-for-sysmon-events)
        - [Download sysmon and sysmon config](#download-sysmon-and-sysmon-config)
        - [Install sysmon to Server1 and Server2](#install-sysmon-to-server1-and-server2)
        - [Create sysmon subscription](#create-sysmon-subscription)
        - [Add servers to Sysmon AD Group](#add-servers-to-sysmon-ad-group)
        - [Create sysmon view](#create-sysmon-view)
    - [Install Weffles to explore events](#install-weffles-to-explore-events)
        - [Download and expand weffles repo](#download-and-expand-weffles-repo)
        - [Follow guide](#follow-guide)

<!-- /TOC -->

# Windows Event Forwarding

## About lab

This lab demonstrates how to collect events with Windows Event Forwarding using [NSA samples](https://github.com/nsacyber/Event-Forwarding-Guidance), how to install Sysmon and monitor Sysmon events using WEF

## LabConfig Windows Server 2016

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = 'Server1'   ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Server2'   ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

#$LabConfig.VMs += @{ VMName = 'Client1' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true }
#$LabConfig.VMs += @{ VMName = 'Client2' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true}

```

## LabConfig Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider17744-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = 'Server1'   ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Server2'   ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

#$LabConfig.VMs += @{ VMName = 'Client1' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true }
#$LabConfig.VMs += @{ VMName = 'Client2' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true}

$LabConfig.ServerVHDs += @{
    Edition="4"
    VHDName="Win2019_17744.vhdx"
    Size=60GB
}
$LabConfig.ServerVHDs += @{
    Edition="3"
    VHDName="Win2019Core_17744.vhdx"
    Size=30GB
}
 
```

## Configure event WEF collector and import NSA recommended events

### Download zip with NSA Samples

Fist step would be to download Event Forwarding Guidance github project into Downloads and will unzip it. It contains XML samples and list of logs and events recommendations (in JSON and CSV). It also contains some helper functions, for creating custom views.

Run all code from DC (or Win10 management machine, but make sure you install RSAT).

```PowerShell
#download zip with all NSA samples
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){ #there is no need to set Tls12 in 1809 releases, therefore for insider it does not apply
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Invoke-WebRequest -Uri https://github.com/nsacyber/Event-Forwarding-Guidance/archive/master.zip -OutFile $env:USERPROFILE\Downloads\NSASamples.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\NSASamples.zip -DestinationPath $env:USERPROFILE\Downloads
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Screenshots/NSAfiles.png)

### Create groups for each sample rule

Let's create AD Group for each sample rule. This will enable us to control what to collect on each computer

```PowerShell
#Create AD Groups for NSA Rules
$SampleRuleNames=(Get-ChildItem -Path "$env:USERPROFILE\Downloads\Event-Forwarding-Guidance-master\Subscriptions\NT6").BaseName
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$OUName="WEF Rules"

New-ADOrganizationalUnit -Name $OUName -Path $OUPath

foreach ($sampleRuleName in $sampleRuleNames){
    New-ADGroup -Name $sampleRuleName -Path "ou=$OUName,$OUPath" -GroupScope Global
}
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Screenshots/NSAGroups.png)

### Configure Collector

Now it's needed to configure collector server

```PowerShell
#create session for managed computer (Computername is Collector in this case)
$CollectorSession=New-PSSession -ComputerName Collector

#configure Event Forwarding on collector server
Invoke-Command -Session $CollectorSession -ScriptBlock {
    WECUtil qc /q
}

#Import XML files for rules, that will be configured on collector
$XMLFiles=Get-ChildItem "$env:USERPROFILE\downloads\Event-Forwarding-Guidance-master\Subscriptions\NT6\"

#modify target domain name in AccountLogons.xml
$Path="$env:USERPROFILE\Downloads\Event-Forwarding-Guidance-master\Subscriptions\NT6\AccountLogons.xml"
$AccountLogonsXML=Get-Content -Path $Path
$AccountLogonsXML[45]=$AccountLogonsXML[45].replace("TEST","$env:userdomain")
$AccountLogonsXML[59]=$AccountLogonsXML[59].replace("TEST","$env:userdomain")
$AccountLogonsXML | Out-File -FilePath $Path

#process Templates, add AD group to each template and create subscription
foreach ($XMLFile in $XMLFiles){
    #Generate AllowedSourceDomainComputers parameter
    $SID=(Get-ADGroup -Identity $XMLFile.Basename).SID.Value
    $AllowedSourceDomainComputers="O:NSG:BAD:P(A;;GA;;;$SID)S:"
    [xml]$XML=get-content $XMLFile.FullName
    invoke-command -Session $CollectorSession -ScriptBlock {
        $xml=$using:xml
        $xml.subscription.AllowedSourceDomainComputers=$using:AllowedSourceDomainComputers
        $xml.Save("$env:TEMP\temp.xml")
        wecutil cs "$env:TEMP\temp.xml"
    }
}

$CollectorSession | Remove-PSSession
 
```

### Validate subscriptions on collector server

Following script will help display all subscriptions and it's ACLs

```PowerShell
$CollectorName="Collector"

$subscriptions=Invoke-Command -ComputerName $CollectorName -ScriptBlock {
    #enumerate subscriptions
    $subs=wecutil es
    $subscriptionXMLs= foreach ($sub in $subs){
        [xml]$xml=wecutil gs $sub /f:xml
        $xml.subscription
    }
    $Subscriptions = foreach ($subXML in $subscriptionXMLs) {
        New-Object PSObject -Property @{
            SubscriptionId = $subXML.SubscriptionId
            SubscriptionType = $subXML.SubscriptionType
            Description = $subXML.Description
            Enabled = $subXML.Enabled
            Uri = $subXML.Uri
            ConfigurationMode = $subXML.ConfigurationMode
            Delivery = $subXML.Delivery
            Query = $subXML.Query."#cdata-section"
            ReadExistingEvents = $subXML.ReadExistingEvents
            TransportName = $subXML.TransportName
            ContentFormat = $subXML.ContentFormat
            Locale = $subXML.Locale
            LogFile = $subXML.LogFile
            AllowedSourceNonDomainComputers = $subXML.AllowedSourceNonDomainComputers
            AllowedSourceDomainComputers = $subXML.AllowedSourceDomainComputers
            AllowedSourceDomainComputersFriendly = (ConvertFrom-SddlString $subXML.AllowedSourceDomainComputers).DiscretionaryAcl
        }
    }
    return $subscriptions
}

$subscriptions | ft SubscriptionId,AllowedSourceDomainComputersFriendly
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Screenshots/SubscriptionACL.png)

### Configure remote servers

The next step is to configure remote server to send out logs. To do it, you need to configure Collector Server registry entry (or GPO), add Network Service for each monitored log as reader (with wevtutil sl $logname "/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)") Or add it to Event log readers group and also add server to AD Group (so Collector will accept logs from the server).

```PowerShell
$servers="Server1","Server2"
$CollectorServerName="Collector"

#configure servers
Invoke-Command -ComputerName $servers -ScriptBlock {
    Add-LocalGroupMember -Group "Event Log Readers" -Member "Network Service"
    $Path="hklm:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    if(!(Test-Path $Path)){
        New-Item $Path -Force
    }
    New-ItemProperty -Path $Path -Name 1 -Value "Server=http://$($using:CollectorServerName):5985/wsman/SubscriptionManager/WEC,Refresh=30" -PropertyType String -force
}

#add servers to AD Group
$ADGroups=(Get-ADGroup -SearchBase "OU=WEF Rules,OU=Workshop,DC=Corp,DC=contoso,DC=com" -Filter *).Name | Out-GridView -OutputMode Multiple -Title "Select AD Groups"
foreach ($Server in $servers){
    foreach ($ADGroup in $ADGroups){
        Add-ADGroupMember -Members "$($server)$" -Identity $ADGroup
    }
}
 
```

Restart servers to initiate sending logs (I did not figure out yet how to kick in event forwarder)

```PowerShell
$servers="Server1","Server2"
Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
 
```

### Connect to Collector and view logs

To enable firewall rule to be able to connect to remote server with eventvwr.msc run following command

```PowerShell
$CollectorName="Collector"
Enable-NetFirewallRule -CimSession $CollectorName -DisplayGroup "Remote Event Log Management"
 
```

NSA also provides Custom views generator. It will create custom view xmls out of wecutil xmls. So let's create it and copy to custom views...

```PowerShell
$WEFFolder="$env:USERPROFILE\Downloads\Event-Forwarding-Guidance-master"
cd "$WEFFolder\Scripts"

#Create custom view xmls
.\creatCV.ps1 -dir ..\subscriptions\nt6 -odir ..\customviews\nt6

#copy it to C:\ProgramData\Microsoft\Event Viewer\Views
copy-item -path "$WEFFolder\customviews\nt6\*" -destination "$env:ProgramData\Microsoft\Event Viewer\Views"

#run event viewer
eventvwr.msc
 
```

### Increase Forwarded Events log size

Lastly you may want to increase ForwardedEvents log size. You can do it with following command

```PowerShell
$CollectorName="Collector"
$LogSize=10GB
Invoke-Command -computername $CollectorName -scriptblock {
     wevtutil sl ForwardedEvents /ms:$using:Logsize
}
 
```

So if everything works well, and you will use RDP for connecting to for example Server1, you will see this event in collector

![](/Scenarios/Windows%20Event%20Forwarding/Screenshots/EventViewer.png)

## Install Sysmon with sysmonconfig and enable WEF for Sysmon events

### Download sysmon and sysmon config

```PowerShell
#Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:USERPROFILE\Downloads\Sysmon.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\Sysmon.zip -DestinationPath $env:USERPROFILE\Downloads\Sysmon\

#download sysmon config
$XML=Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
$xml.Save("$env:USERPROFILE\Downloads\Sysmon\Sysmonconfig-export.xml")
 
```

### Install sysmon to Server1 and Server2

```PowerShell
$servers="Server1","Server2"
$sessions=New-PSSession -ComputerName $servers

#copy sysmon to servers
foreach ($session in $sessions){
    Copy-Item -Path $env:USERPROFILE\Downloads\Sysmon -Destination $env:TEMP -ToSession $session -Recurse -Force
}

#install sysmon to servers
Invoke-Command -Session $sessions -ScriptBlock {
    Start-Process -Wait -FilePath sysmon.exe -ArgumentList "-accepteula -i sysmonconfig-export.xml" -WorkingDirectory "$env:Temp\Sysmon"
}

#validate if sysmon is running
Invoke-Command -Session $sessions -ScriptBlock {
    Get-Service Sysmon
}
 
```

### Create sysmon subscription

```Powershell
$CollectorName="Collector"
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$OUName="WEF Rules"
$GroupName="Sysmon"


#Create AD Group for sysmon rule
New-ADGroup -Name $GroupName -Path "ou=$OUName,$OUPath" -GroupScope Global

#Generate AllowedSourceDomainComputers parameter
$SID=(Get-ADGroup -Identity $GroupName).SID.Value
$AllowedSourceDomainComputers="O:NSG:BAD:P(A;;GA;;;$SID)S:"

#Create XML
[xml]$xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>Sysmon</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Sysmon. Targets: Vista+</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>

    <!-- Use Normal (default), Custom, MinLatency, MinBandwidth -->
    <ConfigurationMode>Custom</ConfigurationMode>

    <Delivery Mode="Push">
        <Batching>
            <MaxItems>1</MaxItems>
            <MaxLatencyTime>1000</MaxLatencyTime>
        </Batching>
        <PushSettings>
            <Heartbeat Interval="40000"/>
        </PushSettings>
    </Delivery>

    <Query>
        <![CDATA[

<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
  </Query>
</QueryList>

        ]]>
    </Query>

    <ReadExistingEvents>true</ReadExistingEvents>
    <TransportName>http</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
    <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
    <AllowedSourceDomainComputers>$AllowedSourceDomainComputers</AllowedSourceDomainComputers>
</Subscription>
"@

Invoke-Command -ComputerName $CollectorName -ScriptBlock {
    $($using:xml).Save("$env:TEMP\temp.xml")
    wecutil cs "$env:TEMP\temp.xml"
}

```

### Add servers to Sysmon AD Group

the downside of using AD Group different than Domain computers is that it applies after computer restart. However this way you can target just portion of computers.

```PowerShell
$servers="Server1","Server2"
foreach ($server in $servers){
    Add-ADGroupMember -Members "$($server)$" -Identity Sysmon
}

#restart to grab AD group membership
Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
 
```

### Create sysmon view

```PowerShell
[xml]$xml=@"
<ViewerConfig>
    <QueryConfig>
        <QueryParams>
            <UserQuery/>
        </QueryParams>
        <QueryNode>
            <Name>Sysmon</Name>
            <QueryList>
                <Query Id="0">
                    <Select Path="ForwardedEvents">
                        *[System[Provider[@Name='Microsoft-Windows-Sysmon']]]
                    </Select>
                </Query>
            </QueryList>
        </QueryNode>
    </QueryConfig>
</ViewerConfig>
"@
$xml.save("$env:ProgramData\Microsoft\Event Viewer\Views\sysmonview.xml")
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Screenshots/EventViewerSysmon.png)

## Install Weffles to explore events

Jessica Payne wrote nice solution for hunting malware called WEFFLES (Windows Event Logging Forensic Logging Enhancement Services). All info is located at http://aka.ms/weffles

### Download and expand weffles repo

```PowerShell
#configure TLS if needed
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){ #there is no need to set Tls12 in 1809 releases, therefore for insider it does not apply
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

#download zip with Weffles
Invoke-WebRequest -Uri https://github.com/jepayneMSFT/WEFFLES/archive/master.zip -OutFile $env:USERPROFILE\Downloads\WEFFLES.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\WEFFLES.zip -DestinationPath $env:USERPROFILE\Downloads
 
```

### Follow guide

Guide can be found here https://blogs.technet.microsoft.com/jepayne/2017/12/08/weffles/