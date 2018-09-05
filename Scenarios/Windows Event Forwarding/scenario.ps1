#download zip with all NSA samples
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){ #there is no need to set Tls12 in 1809 releases, therefore for insider it does not apply
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Invoke-WebRequest -Uri https://github.com/nsacyber/Event-Forwarding-Guidance/archive/master.zip -OutFile $env:USERPROFILE\Downloads\NSASamples.zip

#unzip
Expand-Archive -Path $env:USERPROFILE\Downloads\NSASamples.zip -DestinationPath $env:USERPROFILE\Downloads

#Create AD Groups for NSA Rules
$SampleRuleNames=(Get-ChildItem -Path "$env:USERPROFILE\Downloads\Event-Forwarding-Guidance-master\Subscriptions\samples").BaseName
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
$OUName="WEF Rules"

New-ADOrganizationalUnit -Name $OUName -Path $OUPath

foreach ($sampleRuleName in $sampleRuleNames){
    New-ADGroup -Name $sampleRuleName -Path "ou=$OUName,$OUPath" -GroupScope Global
}

#create session for managed computer
$CollectorSession=New-PSSession -ComputerName Collector

#configure Event Forwarding on collector server
Invoke-Command -Session $CollectorSession -ScriptBlock {
    WECUtil qc /q
}

#Import XML files for rules, that will be configured on collector
$XMLFiles=Get-ChildItem "$env:USERPROFILE\downloads\Event-Forwarding-Guidance-master\Subscriptions\samples\"

#process Templates and and add AD group to each template. 
foreach ($XMLFile in $XMLFiles){
    #Generate AllowedSourceDomainComputers parameter
    $SID=(Get-ADGroup -Identity $XMLFile.Basename).SID.Value
    $AllowedSourceDomainComputers="O:NSG:BAD:P(A;;GA;;;$SID)S:"
    [xml]$XML=get-content $XMLFile.FullName
    invoke-command -Session $CollectorSession -scriptblock {
        $xml=$using:xml
        $xml.subscription.AllowedSourceDomainComputers=$using:AllowedSourceDomainComputers
        $xml.Save("$env:TEMP\temp.xml")
        wecutil cs "$env:TEMP\temp.xml"
    }
}

$CollectorSession | Remove-PSSession
 