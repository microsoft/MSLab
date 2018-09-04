
## About lab WORK IN PROGRESS

This lab demonstrates how to collect events with Windows Event Forwarding using [NSA samples](https://github.com/nsacyber/Event-Forwarding-Guidance)

## LabConfig Windows Server 2016

```PowerShell

```

## LabConfig Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider17744-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

$LabConfig.VMs += @{ VMName = 'Server1' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Server2' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

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

## Scenario

```PowerShell
#download zip with all NSA samples
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Invoke-WebRequest -Uri https://github.com/nsacyber/Event-Forwarding-Guidance/archive/master.zip -OutFile $env:USERPROFILE\Downloads\NSASamples.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\NSASamples.zip -DestinationPath $env:USERPROFILE\Downloads

#Create Group for monitored servers and add servers there
New-ADGroup -Name "WEF Member Servers" -Path "ou=workshop,dc=corp,dc=contoso,dc=com" -GroupScope Global
Add-ADGroupMember -Identity "WEF Member Servers" -Members "Server1$","Server2$"

#Generate Allowed source computers string
$SID=(Get-ADGroup -Identity "WEF Member Servers").SID.Value
$AllowedSourceDomainComputers="O:NSG:BAD:P(A;;GA;;;$SID)S:"

#Create PSSession to Collector server
$session=New-PSSession -computername Collector

#start WEF service
invoke-command -session $session -ScriptBlock {WECUtil qc /q}

#import XMLs to remote collector
$XMLFiles=Get-ChildItem "$env:USERPROFILE\downloads\Event-Forwarding-Guidance-master\Subscriptions\samples\"

foreach ($XMLFile in $XMLFiles){
    [xml]$XML=get-content $XMLFile.FullName
    invoke-command -session $session -scriptblock {
        $xml=$using:xml
        $xml.subscription.AllowedSourceDomainComputers=$using:AllowedSourceDomainComputers
        $xml.Save("$env:TEMP\temp.xml")
        wecutil cs "$env:TEMP\temp.xml"
    }
}

#configure servers
$servers="Server1","Server2"
Invoke-command -computername $servers -scriptblock {
    $Path="hklm:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    if(!(Test-Path $Path)){
        New-Item $Path -Force
    }
    New-ItemProperty -Path $Path -Name 1 -Value "Server=http://Collector:5985/wsman/SubscriptionManager/WEC,Refresh=30" -PropertyType String -force
}

#configure network service to be able to read all logs on servers
$events=ConvertFrom-csv -InputObject (get-content $env:USERPROFILE\Downloads\Event-Forwarding-Guidance-master\Events\RecommendedEvents.csv)
$lognames=$events | select "Event Log" -Unique

Invoke-command -computername $servers -scriptblock {
    foreach ($logname in $using:lognames){
        if (Get-WinEvent -ListLog $logname -ErrorAction SilentlyContinue){
            wevtutil sl $logname "/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)"
        }
    }
}

#enable firewall to collector so you are able to connect with event viewer
Enable-NetFirewallRule -CimSession Collector -DisplayGroup "Remote Event Log Management"


#todo... increase size... 
wevtutil sl $logname /ms:209715200


```