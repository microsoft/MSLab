<!-- TOC -->

- [S2D and Health Sevice logging](#s2d-and-health-sevice-logging)
    - [Sample LabConfig for Windows Server 2019](#sample-labconfig-for-windows-server-2019)
    - [About the lab](#about-the-lab)
    - [Prerequisites](#prerequisites)
    - [The Lab](#the-lab)
        - [Create custom log on Collector Server](#create-custom-log-on-collector-server)
        - [Enable Health Service Logging](#enable-health-service-logging)
        - [Configure event subscription](#configure-event-subscription)
        - [Validate subscription on collector server](#validate-subscription-on-collector-server)
        - [Configure Collector server address on member servers](#configure-collector-server-address-on-member-servers)
        - [Check if servers are registered with Collector](#check-if-servers-are-registered-with-collector)
        - [Resize/Move log if needed](#resizemove-log-if-needed)
        - [Enjoy logs redirected to collector](#enjoy-logs-redirected-to-collector)
        - [Grab logs with PowerShell](#grab-logs-with-powershell)

<!-- /TOC -->

# S2D and Health Sevice logging

## Sample LabConfig for Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4'; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

#collector server
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }

#3 HyperConverged Clusters
1..2 | ForEach-Object {$VMNames="1-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$True}}
1..2 | ForEach-Object {$VMNames="2-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$True}}
1..2 | ForEach-Object {$VMNames="3-S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 2GB ; NestedVirt=$True}}
 
```

## About the lab

It's inspired by [Health Service feature](https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/configure-azure-monitor#configuring-health-service) that writes events to event channel if configured.

Run all code from DC

## Prerequisites

Run following code to create 3 HyperConverged clusters with some VMs to play with. Script will ask you for VHD. You can use NanoServer as it's really small and will not have any footprint (created with createparentdisk.ps1 in ParentDisks folder). You can hit cancel when asked for VHD and VMs will not be created.

```PowerShell
#Variables
    #clusterconfig
    $Clusters=@()
    $Clusters+=@{Nodes="1-S2D1","1-S2D2" ; Name="Cluster1" ; IP="10.0.0.211" ; Volumenames="CL1Mirror1","CL1Mirror2" ; VolumeSize=2TB}
    $Clusters+=@{Nodes="2-S2D1","2-S2D2" ; Name="Cluster2" ; IP="10.0.0.212" ; Volumenames="CL2Mirror1","CL2Mirror2" ; VolumeSize=2TB}
    $Clusters+=@{Nodes="3-S2D1","3-S2D2" ; Name="Cluster3" ; IP="10.0.0.213" ; Volumenames="CL3Mirror1","CL3Mirror2" ; VolumeSize=2TB}

    #ask for parent vhdx (choose nanoserver preferably - it's small)
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
        }
        $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx"
        If($openFile.ShowDialog() -eq "OK"){
            Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
        }
        if (!$openFile.FileName){
            Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
        }
        $VHDPath = $openFile.FileName

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica,RSAT-AD-PowerShell
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica,RSAT-AD-PowerShell
    }

# Install features on servers
    Invoke-Command -computername $clusters.nodes -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell","Hyper-V"
    }

#reboot servers to finish Hyper-V install
    Restart-Computer $clusters.nodes -Protocol WSMan -Wait -For PowerShell
    start-sleep 20 #failsafe

#create clusters
    foreach ($Cluster in $clusters){
        New-Cluster -Name $Cluster.Name -Node $Cluster.Nodes -StaticAddress $Cluster.IP
    }

#add file share witnesses
    foreach ($Cluster in $clusters){
        #Create new directory
            $WitnessName=$Cluster.name+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$($Cluster.Name)$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $Cluster.name -FileShareWitness "\\DC\$WitnessName"
    }


#enable s2d
    foreach ($Cluster in $clusters){
        Enable-ClusterS2D -CimSession $Cluster.Name -confirm:0 -Verbose
    }

#create volumes
    Foreach ($Cluster in $clusters){
        New-Volume -StoragePoolFriendlyName "S2D on $($Cluster.Name)" -FriendlyName $Cluster.VolumeNames[0] -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes $Cluster.VolumeSize -CimSession $Cluster.Name
        New-Volume -StoragePoolFriendlyName "S2D on $($Cluster.Name)" -FriendlyName $Cluster.VolumeNames[1]  -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes $Cluster.VolumeSize -CimSession $Cluster.Name
    }

#Create 1 VM on each Volume
    if ($VHDPath){
        Foreach ($Cluster in $clusters){
            $VMName="$($Cluster.Name)_VM1"
            $VolumeName=$Cluster.VolumeNames[0]
            New-Item -Path "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks" -ItemType Directory
            Copy-Item -Path $VHDPath -Destination "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx"
            New-VM -Name $VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\$VolumeName" -VHDPath "c:\ClusterStorage\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx" -ComputerName $Cluster.Nodes[0]
            Start-VM -name $VMName -ComputerName $Cluster.Nodes[0]
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $Cluster.Name

            $VMName="$($Cluster.Name)_VM2"
            $VolumeName=$Cluster.VolumeNames[1]
            New-Item -Path "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks" -ItemType Directory
            Copy-Item -Path $VHDPath -Destination "\\$($Cluster.Name)\ClusterStorage$\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx"
            New-VM -Name $VMName -MemoryStartupBytes 256MB -Generation 2 -Path "c:\ClusterStorage\$VolumeName" -VHDPath "c:\ClusterStorage\$VolumeName\$VMName\Virtual Hard Disks\$($VMName)_Disk1.vhdx" -ComputerName $Cluster.Nodes[1]
            Start-VM -name $VMName -ComputerName $Cluster.Nodes[1]
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $Cluster.Name
        }
    }
 
```

## The Lab

### Create custom log on Collector Server

This part will configure Collector as demonstrated in [Creating Custom WEF Logs scenario](/Scenarios/Windows%20Event%20Forwarding/Creating%20Custom%20WEF%20logs)

```PowerShell
#Variables
$CustomEventChannelsFileName="S2DEventChannels"
$OutputFolder="$env:UserProfile\Downloads\ECMan"
$ToolsPath="C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64"
$dotNetPath="C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
$CollectorServerName="Collector"
$CustomEventsFilesLocation=$OutputFolder

#some more variables
$ManifestFileName = '{0}.man' -f $CustomEventChannelsFileName
$ResourceFileName = 'C:\Windows\system32\{0}.dll' -f $CustomEventChannelsFileName
$message = '$(string.Custom Forwarded Events.event.100.message)' 

#Events definition
$EventsArray = @(
    @{
        EventProviderName = 'S2DClusters'
        EventGuid = New-Guid
        EventSymbol = 'S2DClusters_EVENTS'
        EventResourceFileName = $ResourceFileName
        ImportChannelID='C1'
        Channels = @(
            @{
                ChannelName = 'S2D-HealthServiceLog'
                ChannelchID = 'S2D-HealthServiceLog'
                ChannelSymbol = 'S2D_HealthServiceLog'
            }
        )
    }
)

#Download SDK
$ProgressPreference='SilentlyContinue' #for faster download
#Download Windows 10 RS5 SDK
Invoke-WebRequest -UseBasicParsing -Uri https://go.microsoft.com/fwlink/p/?LinkID=2033908 -OutFile "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe"
#Install SDK RS5
Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe" -ArgumentList "/features OptionId.DesktopCPPx64 /quiet"
 
#Generate XML
$EventsArrayFinal = foreach ($Event in $EventsArray) {
    $channels = foreach ($channel in $Event.Channels) {
    @"

                    <channel name="$($Channel.ChannelName)" chid="$($Channel.ChannelchID)" symbol="$($Channel.ChannelSymbol)" type="Operational" enabled="true"></channel>
"@
    }
    @"

            <provider name="$($Event.EventProviderName)" guid="{$($Event.EventGUID)}" symbol="$($Event.EventSymbol)" resourceFileName="$($Event.EventResourceFileName)" messageFileName="$($Event.EventResourceFileName)">
                <events>
                    <event symbol="DUMMY_EVENT" value="100" version="0" template="DUMMY_TEMPLATE" message="$message"></event>
                </events>
                <channels>
                    <importChannel name="System" chid="$($Event.ImportChannelID)"></importChannel>$channels
                </channels>
                <templates>
                    <template tid="DUMMY_TEMPLATE">
                        <data name="Prop_UnicodeString" inType="win:UnicodeString" outType="xs:string"></data>
                        <data name="PropUInt32" inType="win:UInt32" outType="xs:unsignedInt"></data>
                    </template>
                </templates>
            </provider>
"@
}
$Content=@"
<?xml version="1.0"?>
<instrumentationManifest xsi:schemaLocation="http://schemas.microsoft.com/win/2004/08/events eventman.xsd" xmlns="http://schemas.microsoft.com/win/2004/08/events" xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:trace="http://schemas.microsoft.com/win/2004/08/events/trace">
    <instrumentation>
        <events>$EventsArrayFinal
        </events>
    </instrumentation>
    <localization>
        <resources culture="en-US">
            <stringTable>
                <string id="level.Informational" value="Information"></string>
                <string id="channel.System" value="System"></string>
                <string id="Publisher.EventMessage" value="Prop_UnicodeString=%1;%n&#xA;                  Prop_UInt32=%2;%n"></string>
                <string id="Custom Forwarded Events.event.100.message" value="Prop_UnicodeString=%1;%n&#xA;                  Prop_UInt32=%2;%n"></string>
            </stringTable>
        </resources>
    </localization>
</instrumentationManifest>
"@

#Create output folder if does not exist
if(-not (Test-Path $OutputFolder)) { 
    New-Item -Path $OutputFolder -ItemType Directory
}

#write XML
Set-Content -Value $content -Path (Join-Path -Path $OutputFolder -ChildPath $ManifestFileName) -Encoding ASCII

#Compile manifest https://docs.microsoft.com/en-us/windows/desktop/WES/compiling-an-instrumentation-manifest

Start-Process -Wait -FilePath "$ToolsPath\mc.exe" -ArgumentList "$OutputFolder\$CustomEventChannelsFileName.man" -WorkingDirectory $OutputFolder
Start-Process -Wait -FilePath "$ToolsPath\mc.exe" -ArgumentList "-css CustomEventChannels.DummyEvent  $OutputFolder\$CustomEventChannelsFileName.man" -WorkingDirectory $OutputFolder
Start-Process -Wait -FilePath "$ToolsPath\rc.exe" -ArgumentList "$OutputFolder\$CustomEventChannelsFileName.rc"
Start-Process -Wait -FilePath "$dotNetPath\csc.exe" -ArgumentList "/win32res:$OutputFolder\$CustomEventChannelsFileName.res /unsafe /target:library /out:$OutputFolder\$CustomEventChannelsFileName.dll"

#Configure collector server

#create session for managed computer (ComputerName is Collector in this case)
$CollectorSession=New-PSSession -ComputerName $CollectorServerName
 
#configure Event Forwarding on collector server
Invoke-Command -Session $CollectorSession -ScriptBlock {
    WECUtil qc /q
}
 
#Create custom event forwarding logs
Invoke-Command -Session $CollectorSession -ScriptBlock {
    Stop-Service Wecsvc
    #unload current event channnel (commented as there is no custom manifest)
    #wevtutil um "C:\windows\system32\$using:CustomEventChannelsFileName.man"
}
 
#copy new man and dll
$files="$CustomEventChannelsFileName.dll","$CustomEventChannelsFileName.man"
$Path="$CustomEventsFilesLocation"
foreach ($file in $files){
    Copy-Item -Path "$path\$file" -Destination C:\Windows\system32 -ToSession $CollectorSession
}
#load new event channel file and start Wecsvc service
Invoke-Command -Session $CollectorSession -ScriptBlock {
    wevtutil im "C:\windows\system32\$using:CustomEventChannelsFileName.man"
    Start-Service Wecsvc
}

#Enable Firewall rule
Enable-NetFirewallRule -CimSession $CollectorServerName -DisplayGroup "Remote Event Log Management"
eventvwr
 
```
 
![](/Scenarios/S2D%20and%20Health%20Service%20logging/Screenshots/HealthServiceLog.png)

### Enable Health Service Logging

```PowerShell
#grab all s2d clusters
$S2DClusters=(Get-Cluster -Domain $env:USERDOMAIN | where S2DEnabled -eq 1).Name
#enable health service logging
Invoke-Command -ComputerName $S2DClusters -ScriptBlock {get-storagesubsystem clus* | Set-StorageHealthSetting -Name "Platform.ETW.MasTypes" -Value "Microsoft.Health.EntityType.Subsystem,Microsoft.Health.EntityType.Server,Microsoft.Health.EntityType.PhysicalDisk,Microsoft.Health.EntityType.StoragePool,Microsoft.Health.EntityType.Volume,Microsoft.Health.EntityType.Cluster"}
 
```

### Configure event subscription

```PowerShell
$CollectorServerName="Collector"
#XML Parameters
$Name="S2D-HealthServiceLog"
$Description="Subscription for S2D Health Service"
$LogFile="S2D-HealthServiceLog"

#configure Event Forwarding on collector server
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    WECUtil qc /q
}

$Query=@"
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-Health/Operational">*</Select>
    <Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Health'] and (EventID=8465)]]</Select>
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
    <LogFile>$LogFile</LogFile>
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

### Validate subscription on collector server

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

![](/Scenarios/S2D%20and%20Health%20Service%20logging/Screenshots/ConfiguredSubscription.png)


### Configure Collector server address on member servers

```PowerShell
$S2DClusters=(Get-Cluster -Domain $env:UserDomain | where S2DEnabled -eq 1).Name
$servers=foreach ($S2DCluster in $S2DClusters){(Get-ClusterNode -Cluster $S2DCluster).Name}
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
#you will see some errors as winrm restarts (session will be disconnected)
Invoke-Command -ComputerName $servers -ScriptBlock {
    #create new svchost process
    Sc.exe config WinRM type= own
    restart-service WinRM
}
 
```

### Check if servers are registered with Collector

Since we allowed domain computers on collector to send sysmon data, you will see registred servers

```PowerShell
$CollectorServerName="Collector"
$SubscriptionName="S2D-HealthServiceLog"
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    wecutil gs $Using:SubscriptionName
}
 
```

![](/Scenarios/S2D%20and%20Health%20Service%20logging/Screenshots/SubscribedServers.png)

### Resize/Move log if needed

In case you want to increase log size or move it somewhere else, you can do it with wewutil

```PowerShell
$CollectorServerName="Collector"
$Path="C:\Logs"
$MaxSize=1GB
$LogName="S2D-HealthServiceLog"

Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    #Create log folder if not exist
    If (-not (Test-Path $using:Path)){
        New-Item -Path $using:Path -Type Directory
    }
    #set max size
    wevtutil set-log $using:LogName /MaxSize:$($Using:MaxSize)
    #set location
    wevtutil set-log $using:LogName /LogFileName:"$($Using:Path)\$using:LogName.evtx"
}
 
```

![](/Scenarios/S2D%20and%20Health%20Service%20logging/Screenshots/ConfiguredLog.png)

### Enjoy logs redirected to collector

Shutdown some server and wait for at least 5 minutes for health service to kick in. You should see logs on collector server

![](/Scenarios/S2D%20and%20Health%20Service%20logging/Screenshots/RedirectedLogs.png)

### Grab logs with PowerShell

```PowerShell
$CollectorServerName="Collector"
$LogName="S2D-HealthServiceLog"

$events=Get-WinEvent -ComputerName $CollectorServerName -LogName $LogName
ForEach ($Event in $Events) {
    # Convert the event to XML
    $eventXML = [xml]$Event.ToXml()
    # create custom object for all values
    for ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
        # Append these as object properties            
        Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'
                        
    }
}
$events | Select-Object * | Out-GridView
 
```

![](/Scenarios/S2D%20and%20Health%20Service%20logging/Screenshots/Events.png)