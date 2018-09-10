<!-- TOC -->

- [Palantir Event Forwarding Guidance](#palantir-event-forwarding-guidance)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [LabConfig Windows Server 2019](#labconfig-windows-server-2019)
    - [Configure WEF collector and import Palantir subscription templates](#configure-wef-collector-and-import-palantir-subscription-templates)
        - [Download Palantir GitHub project](#download-palantir-github-project)
        - [Create group for each sample subscription](#create-group-for-each-sample-subscription)
        - [Configure Collector](#configure-collector)
        - [Validate subscriptions on collector server](#validate-subscriptions-on-collector-server)
    - [Configure and validate subscription on remote servers](#configure-and-validate-subscription-on-remote-servers)
        - [Configure subscription on remote servers](#configure-subscription-on-remote-servers)
        - [Check if servers are registered with Collector](#check-if-servers-are-registered-with-collector)
    - [Configure log files](#configure-log-files)
        - [Move log files somewhere else and increase size](#move-log-files-somewhere-else-and-increase-size)
    - [Connect to Collector](#connect-to-collector)
        - [Allow firewall rule for Event logs, connect to Collector and enjoy](#allow-firewall-rule-for-event-logs-connect-to-collector-and-enjoy)

<!-- /TOC -->

# Palantir Event Forwarding Guidance

Scenario inspired by [Palantir Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding). It will demonstrate most complex WEF scenario with separate logs for each subscription.

Other resources: [Creating custom windows event forwarding logs](https://blogs.technet.microsoft.com/russellt/2016/05/18/creating-custom-windows-event-forwarding-logs/)
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

## Configure WEF collector and import Palantir subscription templates

### Download Palantir GitHub project

Run all code from DC (or Win10 management machine, but make sure you install RSAT)

```PowerShell
#download zip with all Palantir samples
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){ #there is no need to set Tls12 in 1809 releases, therefore for insider it does not apply
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Invoke-WebRequest -UseBasicParsing -Uri https://github.com/palantir/windows-event-forwarding/archive/master.zip -OutFile $env:USERPROFILE\Downloads\PalantirWEF.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\PalantirWEF.zip -DestinationPath $env:USERPROFILE\Downloads
 
```

### Create group for each sample subscription

```PowerShell
#Create AD Groups for Palantir subscriptions
$SampleRuleNames=(Get-ChildItem -Path "$env:USERPROFILE\Downloads\windows-event-forwarding-master\wef-subscriptions").BaseName
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$OUName="WEF Rules"

New-ADOrganizationalUnit -Name $OUName -Path $OUPath

foreach ($sampleRuleName in $sampleRuleNames){
    New-ADGroup -Name $sampleRuleName -Path "ou=$OUName,$OUPath" -GroupScope Global
}
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Palantir%20Event%20Forwarding%20Guidance/Screenshots/PalantirGroups.png)

### Configure Collector

```PowerShell
#create session for managed computer (ComputerName is Collector in this case)
$CollectorSession=New-PSSession -ComputerName Collector

#configure Event Forwarding on collector server
Invoke-Command -Session $CollectorSession -ScriptBlock {
    WECUtil qc /q
}

#Create custom event forwarding logs
Invoke-Command -Session $CollectorSession -ScriptBlock {
    Stop-Service Wecsvc
    #unload current event channnel (commented as there is no custom manifest)
    #wevtutil um C:\windows\system32\CustomEventChannels.man
}
#copy new man and dll
$files="CustomEventChannels.dll","CustomEventChannels.man"
$Path="$env:USERPROFILE\Downloads\windows-event-forwarding-master\windows-event-channels"
foreach ($file in $files){
    Copy-Item -Path "$path\$file" -Destination C:\Windows\system32 -ToSession $CollectorSession
}
#load new event channel file and start Wecsvc service
Invoke-Command -Session $CollectorSession -ScriptBlock {
    wevtutil im C:\windows\system32\CustomEventChannels.man
    Start-Service Wecsvc
}

#Import XML files for rules, that will be configured on collector
$XMLFiles=Get-ChildItem "$env:USERPROFILE\Downloads\windows-event-forwarding-master\wef-subscriptions" | Where Extension -eq ".xml"

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

$subscriptions | ft SubscriptionId,AllowedSourceDomainComputersFriendly,LogFile -AutoSize
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Palantir%20Event%20Forwarding%20Guidance/Screenshots/Subscriptions.png)

## Configure and validate subscription on remote servers

### Configure subscription on remote servers

```PowerShell
$CollectorServerName="Collector"

#ask for remote servers
$servers=(Get-ADComputer -Filter *).Name | Out-GridView -OutputMode Multiple

#configure servers
Invoke-Command -ComputerName $servers -ScriptBlock {
    Add-LocalGroupMember -Group "Event Log Readers" -Member "Network Service"
    $Path="hklm:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    if(!(Test-Path $Path)){
        New-Item $Path -Force
    }
    New-ItemProperty -Path $Path -Name 1 -Value "Server=http://$($using:CollectorServerName):5985/wsman/SubscriptionManager/WEC,Refresh=30" -PropertyType String -force
}

#add servers to AD Group and ask what ADGroups to use
$ADGroups=(Get-ADGroup -SearchBase "OU=WEF Rules,OU=Workshop,DC=Corp,DC=contoso,DC=com" -Filter *).Name | Out-GridView -OutputMode Multiple -Title "Select AD Groups"
foreach ($Server in $servers){
    foreach ($ADGroup in $ADGroups){
        Add-ADGroupMember -Members "$($server)$" -Identity $ADGroup
    }
}

<# unfortunately following does not work. Therefore I'll just restart destinatin servers. If you figure out how to kick in event collection without restart, pull change, thx!

#clear kerb tickets
Invoke-Command -ComputerName $servers -ScriptBlock {
    klist purge -li 0x3e7
}

#apply network service permissions to be able to read logs
Invoke-Command -ComputerName $servers -ScriptBlock {
    #create new svchost process
    Sc.exe config WinRM type= own
    restart-service WinRM
}

Invoke-Command -ComputerName $servers -ScriptBlock {
    #refresh GPO to kick in event subscription
    gpupdate /force
}

#>

#restart computers to kick in event forwarding
Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
 
```

### Check if servers are registered with Collector

```PowerShell
$CollectorServerName="Collector"
#Grab Subscriptions to enumerate
$SubscriptionNames=Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    wecutil es
} | Out-GridView -OutputMode Multiple
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    foreach ($SubscriptionName in $Using:SubscriptionNames){
        wecutil gs $SubscriptionName
    }
}
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Palantir%20Event%20Forwarding%20Guidance/Screenshots/RegisteredServers.png)

## Configure log files

### Move log files somewhere else and increase size

By default are all logs stored at %SystemRoot%\System32\Winevt\Logs\ ... For performance you may want to move it somewhere else (like dedicated SSD). Let's demonstrate it by moving into C:\Logs

```PowerShell
$CollectorServerName="Collector"
$Path="C:\Logs"
$MaxSize=1GB

Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    #Create log folder if not exist
    If (-not (Test-Path $using:Path)){
        New-Item -Path $Path -Type Directory
    }
    $xml = wevtutil el | select-string -pattern "WEC"
    foreach ($subscription in $xml) {
        #set max size
        wevtutil set-log $subscription /MaxSize:$($Using:MaxSize)
        #set location
        wevtutil set-log $subscription /LogFileName:"$($Using:Path)\$Subscription.evtx"
    }
}
 
```

## Connect to Collector

### Allow firewall rule for Event logs, connect to Collector and enjoy

```PowerShell
$CollectorServerName="Collector"
Enable-NetFirewallRule -CimSession $CollectorServerName -DisplayGroup "Remote Event Log Management"
eventvwr
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Palantir%20Event%20Forwarding%20Guidance/Screenshots/EventViewer.png)