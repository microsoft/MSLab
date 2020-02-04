# Creating Custom WEF logs
 
## About lab
 
This lab demonstrates how to create custom logs for event forwarding. This is very useful if you need to collect events to multiple logs, not just forwarded events. This scenario was inspired by [Palantir guidance](https://github.com/palantir/windows-event-forwarding/tree/master/windows-event-channels). Special thanks to [Mateusz Czerniawski](https://twitter.com/Arcontar) for helping with XML!

For more info about developing custom event log see this [document](http://download.microsoft.com/download/7/E/7/7E7662CF-CBEA-470B-A97E-CE7CE0D98DC2/eventing-guide.docx)
 
## LabConfig Windows Server 2019
 
```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}
 
$LabConfig.VMs += @{ VMName = 'Collector' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }
 
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; AddToolsVHD=$True }
```
 
## The lab

Run all code from DC or Management machine

### Download and Install SDK
 
```PowerShell
#Download SDK
$ProgressPreference='SilentlyContinue' #for faster download
#Download Windows 8.1 SDK - only needed for ecmangen.exe (Last SDK where ecmangen was present is Windows 10 SDK ver. 10.0.15063. 8.1 can coexist with 10)
#Invoke-WebRequest -UseBasicParsing -Uri https://go.microsoft.com/fwlink/p/?LinkId=323507 -OutFile "$env:USERPROFILE\Downloads\SDK81_Setup.exe"
#Install SDK 8.1
#Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\SDK81_Setup.exe" -ArgumentList "/features OptionID.WindowsDesktopSoftwareDevelopmentKit /quiet"
 
#Download Windows 10 RS5 SDK
Invoke-WebRequest -UseBasicParsing -Uri https://go.microsoft.com/fwlink/p/?LinkID=2033908 -OutFile "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe"
#Install SDK RS5
Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe" -ArgumentList "/features OptionId.DesktopCPPx64 /quiet"
 
```
 
### Generate manifest file
 
```PowerShell
#Create Man file or run setup
 
#Manifest Generator GUI Tool - only in SDK 8.1
#Start-Process -FilePath "C:\Program Files (x86)\Windows Kits\8.1\bin\x64\ecmangen.exe"
 
#or create file
#Variables
$CustomEventChannelsFileName="CustomEventChannels"
$OutputFolder="$env:UserProfile\Downloads\ECMan"

#some neccessaries
$ManifestFileName = '{0}.man' -f $CustomEventChannelsFileName
$ResourceFileName = 'C:\Windows\system32\{0}.dll' -f $CustomEventChannelsFileName
$message = '$(string.Custom Forwarded Events.event.100.message)' 

#Events definition
$EventsArray = @(
    @{
        EventProviderName = 'WSLAB1'
        EventGuid = New-Guid
        EventSymbol = 'WSLAB1_EVENTS'
        EventResourceFileName = $ResourceFileName
        ImportChannelID='C1'
        Channels = @(
            @{
                ChannelName = 'LogForSomething01'
                ChannelchID = 'LogForSomething01'
                ChannelSymbol = 'LogForSomething01'
            },
            @{
                ChannelName = 'LogForSomething02'
                ChannelchID = 'LogForSomething02'
                ChannelSymbol = 'LogForSomething02'
            }
        )
    },
    @{
        EventProviderName = 'WSLAB2'
        EventGuid = New-Guid
        EventSymbol = 'WSLAB2_EVENTS'
        EventResourceFileName = $ResourceFileName
        ImportChannelID='C2'
        Channels = @(
            @{
                ChannelName = 'LogForSomething03'
                ChannelchID = 'LogForSomething03'
                ChannelSymbol = 'LogForSomething03'
            },
            @{
                ChannelName = 'LogForSomething04'
                ChannelchID = 'LogForSomething04'
                ChannelSymbol = 'LogForSomething04'
            }
        )
    }
)

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
 
```
 
![](/Scenarios/Windows%20Event%20Forwarding/Creating%20Custom%20WEF%20logs/Screenshots/ManifestGenerator.png)
 
### Compile Manifest
 
```PowerShell
#Compile manifest https://docs.microsoft.com/en-us/windows/desktop/WES/compiling-an-instrumentation-manifest
$CustomEventChannelsFileName="CustomEventChannels"
$OutputFolder="$env:UserProfile\Downloads\ECMan"
$ToolsPath="C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64"
$dotNetPath="C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
 
Start-Process -Wait -FilePath "$ToolsPath\mc.exe" -ArgumentList "$OutputFolder\$CustomEventChannelsFileName.man" -WorkingDirectory $OutputFolder
Start-Process -Wait -FilePath "$ToolsPath\mc.exe" -ArgumentList "-css CustomEventChannels.DummyEvent  $OutputFolder\$CustomEventChannelsFileName.man" -WorkingDirectory $OutputFolder
Start-Process -Wait -FilePath "$ToolsPath\rc.exe" -ArgumentList "$OutputFolder\$CustomEventChannelsFileName.rc"
Start-Process -Wait -FilePath "$dotNetPath\csc.exe" -ArgumentList "/win32res:$OutputFolder\$CustomEventChannelsFileName.res /unsafe /target:library /out:$OutputFolder\$CustomEventChannelsFileName.dll"
 
```
 
![](/Scenarios/Windows%20Event%20Forwarding/Creating%20Custom%20WEF%20logs/Screenshots/CompiledFiles.png)
 
### Configure Collector server
 
```PowerShell
#Some variables
$CollectorServerName="Collector"
$CustomEventChannelsFileName="CustomEventChannels"
$CustomEventsFilesLocation="$env:UserProfile\Downloads\ECMan"
 
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
    #wevtutil um C:\windows\system32\CustomEventChannels.man
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
 
```
 
### Allow firewall rule for Event logs, connect to Collector server and enjoy
 
```PowerShell
$CollectorServerName="Collector"
Enable-NetFirewallRule -CimSession $CollectorServerName -DisplayGroup "Remote Event Log Management"
eventvwr
 
```
 
![](/Scenarios/Windows%20Event%20Forwarding/Creating%20Custom%20WEF%20logs/Screenshots/EventViewer.png)