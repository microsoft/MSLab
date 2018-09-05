<!-- TOC -->

- [Windows Event Forwarding WORK IN PROGRESS](#windows-event-forwarding-work-in-progress)
    - [About lab](#about-lab)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [LabConfig Windows Server 2019](#labconfig-windows-server-2019)
    - [Configure event WEF collector and import NSA recommended events](#configure-event-wef-collector-and-import-nsa-recommended-events)

<!-- /TOC -->

# Windows Event Forwarding WORK IN PROGRESS

## About lab

This lab demonstrates how to collect events with Windows Event Forwarding using [NSA samples](https://github.com/nsacyber/Event-Forwarding-Guidance)

Todo: how to create custom XML for Sysmon, how to deploy sysmon and how to visualize sysmon events with Weffles

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

Following script will help you validate results

```PowerShell
$CollectorName="Collector"

#grab subscriptions
$subscriptions=Invoke-Command -ComputerName $CollectorName -ScriptBlock {
    wecutil es #es = enumerate subscriptions = alias for enum-subscription. See wecutil /? for help
}

#elect what subscription you would like to see
$SubscriptionToQuery=$subscriptions | Out-GridView -OutputMode Multiple
$result=Invoke-Command -ComputerName $CollectorName -ScriptBlock {
    foreach ($subscription in $using:SubscriptionToQuery){
        wecutil gs $subscription
    }
}
$result

#You also may notice SDDL To translate it back to readable code you can run following PowerShell (todo: create customobject for all results - feel free to pull :) 

foreach ($line in $result){
    if ($line -like "Subscription Id: *"){
        write-host "SubscriptionName:" -ForegroundColor Cyan
        $($line.TrimStart("Subscription Id: "))
    }
    if ($line -like "AllowedSourceDomainComputers: *"){
        $SDDL=$line.TrimStart("AllowedSourceDomainComputers: *")
        write-host "SubscriptionACLs:" -ForegroundColor Cyan
        $(ConvertFrom-SDDLString $SDDL)
    }
}
 
```

![](/Scenarios/Windows%20Event%20Forwarding/Screenshots/SubscriptionACL.png)

The NEXT would be to configure remote server to send out logs. To do it, you need to configure Collector Server registry entry (or GPO), add Network Service for each monitored log as reader (with wevtutil sl $logname "/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)") Or add it to Event log readers group and also add server to AD Group (so Collector will accept logs from the server)

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
$ADGroups=(Get-ADGroup -SearchBase "OU=WEF Rules,OU=Workshop,DC=Corp,DC=contoso,DC=com" -Filter *).Name | Out-GridView -OutputMode Multiple
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

