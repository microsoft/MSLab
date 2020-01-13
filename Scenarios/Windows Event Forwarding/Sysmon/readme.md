<!-- TOC -->

- [Windows Event Forwarding and Sysmon](#windows-event-forwarding-and-sysmon)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [LabConfig Windows Server 2019](#labconfig-windows-server-2019)
    - [Install Sysmon on servers](#install-sysmon-on-servers)
        - [Download sysmon and sysmon config](#download-sysmon-and-sysmon-config)
        - [Install sysmon to Server1 and Server2](#install-sysmon-to-server1-and-server2)
    - [Configure event collector](#configure-event-collector)
        - [Validate subscriptions on collector server](#validate-subscriptions-on-collector-server)
    - [Configure Collector server address on member servers](#configure-collector-server-address-on-member-servers)
    - [Check if servers are registered with Collector](#check-if-servers-are-registered-with-collector)
    - [Generate views for EventViewer and connect to Collector](#generate-views-for-eventviewer-and-connect-to-collector)
        - [All events view](#all-events-view)
        - [Generate Views for each event](#generate-views-for-each-event)
        - [Allow firewall rule for Event logs, connect to Collector and enjoy](#allow-firewall-rule-for-event-logs-connect-to-collector-and-enjoy)

<!-- /TOC -->

# Windows Event Forwarding and Sysmon

In this scenario I'll demonstrate installing Sysmon with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config/) and then I'll demonstrate how to centrally collect logs with WEF. You can find nice info regarding WEF [here](https://blogs.msdn.microsoft.com/canberrapfe/2015/09/21/diy-client-monitoring-setting-up-tiered-event-forwarding/)

This scenario is introduction to Windows Event Forwarding.

## LabConfig Windows Server 2016

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Server1'   ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Server2'   ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true ; AddToolsVHD=$True }
#$LabConfig.VMs += @{ VMName = 'Client1' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true }
#$LabConfig.VMs += @{ VMName = 'Client2' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true}

```

## LabConfig Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'Server1'   ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Server2'   ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true ; AddToolsVHD=$True }
#$LabConfig.VMs += @{ VMName = 'Client1' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true }
#$LabConfig.VMs += @{ VMName = 'Client2' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true}
 
```

## Install Sysmon on servers

### Download sysmon and sysmon config

```PowerShell
#Download Sysmon
Invoke-WebRequest -UseBasicParsing -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:USERPROFILE\Downloads\Sysmon.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\Sysmon.zip -DestinationPath $env:USERPROFILE\Downloads\Sysmon\

#download sysmon config
[xml]$XML=Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
$xml.Save("$env:USERPROFILE\Downloads\Sysmon\Sysmonconfig-export.xml")
 
```

### Install sysmon to Server1 and Server2

```PowerShell
$servers="Server1","Server2"

#Increase MaxEvenlope and create session to copy files to
Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}

#create PSSessions
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

$sessions | Remove-PSSession
 
```

## Configure event collector

```PowerShell
$CollectorServerName="Collector"

#configure Event Forwarding on collector server
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    WECUtil qc /q
}

#Create XML Parameters
$Name="Sysmon"
$Description="Subscription for Sysmon"
$Query=@"
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
  </Query>
</QueryList>
"@

#Generate AllowedSourceDomainComputers parameter
$SID=(Get-ADGroup -Identity "Domain Computers").SID.Value
$AllowedSourceDomainComputers="O:NSG:BAD:P(A;;GA;;;$SID)S:"


#Create XML
[xml]$xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>$Name</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>$Description</Description>
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

$Query

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

#Configure subscription on Collector Server
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    $($using:xml).Save("$env:TEMP\temp.xml")
    wecutil cs "$env:TEMP\temp.xml"
}
 
```

### Validate subscriptions on collector server

Following script will help display all subscriptions and it's ACLs

```PowerShell
$CollectorServerName="Collector"

Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
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
 
```

## Configure Collector server address on member servers

```PowerShell
$servers="Server1","Server2"
$CollectorServerName="Collector"

#configure servers
Invoke-Command -ComputerName $servers -ScriptBlock {
    #add network service toEvent Log Readers
    Add-LocalGroupMember -Group "Event Log Readers" -Member "Network Service"
    
    #configure registry
    $Path="hklm:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    if(!(Test-Path $Path)){
        New-Item $Path -Force
    }
    New-ItemProperty -Path $Path -Name 1 -Value "Server=http://$($using:CollectorServerName):5985/wsman/SubscriptionManager/WEC,Refresh=30" -PropertyType String -force
    #refresh GPO to kick in event subscription
    gpupdate /force
}

#apply network service permissions to be able to read logs
Invoke-Command -ComputerName $servers -ScriptBlock {
    #create new svchost process
    Sc.exe config WinRM type= own
    restart-service WinRM
}
 
```

## Check if servers are registered with Collector

Since we allowed domain computers on collector to send sysmon data, you will see registred servers

```PowerShell
$CollectorServerName="Collector"
$SubscriptionName="Sysmon"
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    wecutil gs $Using:SubscriptionName
}
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Sysmon/Screenshots/RegisteredServers.png)

## Generate views for EventViewer and connect to Collector

### All events view

```PowerShell
[xml]$xml=@"
    <ViewerConfig>
        <QueryConfig>
            <QueryParams>
                <UserQuery/>
            </QueryParams>
            <QueryNode>
                <Name>Sysmon All Events</Name>
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
$xml.save("$env:ProgramData\Microsoft\Event Viewer\Views\Sysmon All Events.xml")
 
```

### Generate Views for each event

```PowerShell
$Queries=@()
$Queries += @{ Name="Sysmon ProcessCreate"  ; ID="1" }
$Queries += @{ Name="Sysmon FileCreateTime" ; ID="2" }
$Queries += @{ Name="Sysmon NetworkConnect" ; ID="3" }
$Queries += @{ Name="Sysmon SysmonServiceStateChange" ; ID="4" }
$Queries += @{ Name="Sysmon ProcessTerminate" ; ID="5" }
$Queries += @{ Name="Sysmon DriverLoad" ; ID="6" }
$Queries += @{ Name="Sysmon ImageLoad" ; ID="7" }
$Queries += @{ Name="Sysmon CreateRemoteThread" ; ID="8" }

$Queries += @{ Name="Sysmon RawAccessRead" ; ID="9" }
$Queries += @{ Name="Sysmon ProcessAccess" ; ID="10" }
$Queries += @{ Name="Sysmon FileCreate" ; ID="11" }
$Queries += @{ Name="Sysmon RegistryObjectAddDelete" ; ID="12" }
$Queries += @{ Name="Sysmon RegistryValueSet" ; ID="13" }
$Queries += @{ Name="Sysmon RegistryObjectRename" ; ID="14" }
$Queries += @{ Name="Sysmon FileCreateStreamHash" ; ID="15" }
$Queries += @{ Name="Sysmon SysmonConfigChange" ; ID="16" }
$Queries += @{ Name="Sysmon NamedPipeCreated" ; ID="17" }
$Queries += @{ Name="Sysmon NamedPipeConnected" ; ID="18" }

foreach ($Query in $Queries){
    [xml]$xml=@"
    <ViewerConfig>
        <QueryConfig>
            <QueryParams>
                <UserQuery/>
            </QueryParams>
            <QueryNode>
                <Name>$($Query.Name)</Name>
                <QueryList>
                    <Query Id="0">
                        <Select Path="ForwardedEvents">
                            *[System[Provider[@Name='Microsoft-Windows-Sysmon'] and EventID=$($Query.ID)]]
                        </Select>
                    </Query>
                </QueryList>
            </QueryNode>
        </QueryConfig>
    </ViewerConfig>
"@
    $xml.save("$env:ProgramData\Microsoft\Event Viewer\Views\$($Query.Name).xml")
}
 
```

### Allow firewall rule for Event logs, connect to Collector and enjoy

```PowerShell
$CollectorServerName="Collector"
Enable-NetFirewallRule -CimSession $CollectorServerName -DisplayGroup "Remote Event Log Management"
eventvwr
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Sysmon/Screenshots/EventViewer.png)