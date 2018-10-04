<!-- TOC -->

- [S2D and Pester](#s2d-and-pester)
    - [LabConfig Windows Server 2016](#labconfig-windows-server-2016)
    - [LabConfig Windows Server 2019](#labconfig-windows-server-2019)
    - [The lab](#the-lab)
        - [Download pester and Polish PowerShell user group files](#download-pester-and-polish-powershell-user-group-files)
        - [Create a baseline](#create-a-baseline)
        - [Compare baseline to server with some misconfiguration](#compare-baseline-to-server-with-some-misconfiguration)

<!-- /TOC -->

# S2D and Pester

## LabConfig Windows Server 2016

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2016Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true ; AddToolsVHD=$True }
 
```

## LabConfig Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider17744-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'WinSrvInsiderCore_17744.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS4_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; DisableWCF=$True ; WinRM=$true ; AddToolsVHD=$True }
 
```

## The lab

Following scenario is based on [Mateusz Czerniawski](https://twitter.com/Arcontar) awesome work. [Here](https://www.youtube.com/watch?v=SoBFCEiIps8) you can find presentation where he shared his work in detail. All scripts demoed in video are available at [this link](https://github.com/psconfeu/2018/raw/master/Mateusz%20Czerniawski/OVF%20-%20Getting%20fun%20from%20boring%20tasks/Mateusz_Czerniawski_OVF.zip
)

This scenario greatly helps to monitor unwanted changes to your cluster (imagine firmware update changes something in the networking) or some colleague clicks on some wrong button. Following scenario will help you setup a way to monitor unwanted changes. Optionally you can run it as schedule task and write an event into event log (see demos link in above)

Windows 10 management machine is optional as you may want to use Edge to display reports (If you dont like iexplore). Windows 10 image can be created with createparentdisks.ps1 script in tools folder (inside WSLab folder)

First you need to deploy [S2D Hyperconverged Scenario](/Scenarios/S2D%20Hyperconverged/) as prerequisite. Notice internet=$true in labconfig lab downloads files from internet.

You can extend your lab with Internet=$true and managmenet machine just by rewriting labconfig and running deploy again (lab will be expanded and internet connection added)

### Download pester and Polish PowerShell user group files


```PowerShell
#update pester
Install-PackageProvider -Name NuGet -Force
Install-Module Pester -SkipPublisherCheck -Force

#configure TLS1.2 if needed
if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){ #there is no need to set Tls12 in 1809 releases, therefore for insider it does not apply
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

#download repos from Polish PowerShell User Group
$Repos="PPoShTools","PPoShOVF","PPoShOVFDiagnostics"
foreach ($repo in $repos){
    Invoke-WebRequest -UseBasicParsing -Uri https://github.com/PPOSHGROUP/$repo/archive/master.zip -OutFile $env:USERPROFILE\Downloads\$repo.zip
    Expand-Archive -Path $env:USERPROFILE\Downloads\$repo.zip -DestinationPath $env:USERPROFILE\Downloads
}

#import repos
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force #this is needed only for client SKU
foreach ($repo in $repos){
    Import-Module $env:USERPROFILE\Downloads\$repo-master\$repo -Force
}
 
```

### Create a baseline

```PowerShell
#create a baseline
$ClusterName="S2D-Cluster"
$BaselineFolder="$env:USERPROFILE\Downloads\$ClusterName-Baseline"
New-POVFBaselineS2DCluster -ClusterName $ClusterName -POVFConfigurationFolder $BaselineFolder
 
```

```PowerShell
#validate if config is still same
$ClusterName="S2D-Cluster"
$BaselineFolder="$env:USERPROFILE\Downloads\$ClusterName-Baseline"
$ComparisonOutputFolder="$env:USERPROFILE\Downloads\$ClusterName-Compare"
$ReportFolder="$env:USERPROFILE\Downloads\$ClusterName-Report"
$creds=Get-Credential -Credential corp\LabAdmin

#Compare
Invoke-POVFDiagnostics -ServiceConfiguration $BaselineFolder -POVFServiceName S2D -Show All -Tag "Configuration" -ReportFilePrefix 'objectivity' -OutputFolder $ComparisonOutputFolder -Credential $creds

#Build comparison report
new-item -type Directory -Path $ReportFolder -ErrorAction SilentlyContinue
Invoke-POVFReportUnit -InputFolder $ComparisonOutputFolder -OutputFolder $ReportFolder

#display report
Invoke-Item -Path $ReportFolder\index.html
 
```

![](/Scenarios/S2D%20and%20Pester/Screenshots/ValidationInProcess.png)

![](/Scenarios/S2D%20and%20Pester/Screenshots/Report1.png)

### Compare baseline to server with some misconfiguration

For simplicity let's change VLAN on SMB1 adapter on machine S2D1 to 2 (s2d hyperconverged uses 1)

```PowerShell
#introduce misconfiguration on S2D1
Invoke-Command -computername S2D1 -ScriptBlock {
    Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB_1 -VlanId 2 -Access -ManagementOS
}
 
```

```PowerShell
#generate a new configuration and compare

$ClusterName="S2D-Cluster"
$BaselineFolder="$env:USERPROFILE\Downloads\$ClusterName-Baseline"
$ComparisonOutputFolder="$env:USERPROFILE\Downloads\$ClusterName-Compare"
$ReportFolder="$env:USERPROFILE\Downloads\$ClusterName-Report"
$creds=Get-Credential -Credential corp\LabAdmin

#remove old comparison and report folders
Remove-Item $ComparisonOutputFolder -Recurse
Remove-Item $ReportFolder -Recurse

#Compare
Invoke-POVFDiagnostics -ServiceConfiguration $BaselineFolder -POVFServiceName S2D -Show All -Tag "Configuration" -ReportFilePrefix 'objectivity' -OutputFolder $ComparisonOutputFolder -Credential $creds

#Build comparison report
new-item -type Directory -Path $ReportFolder -ErrorAction SilentlyContinue
Invoke-POVFReportUnit -InputFolder $ComparisonOutputFolder -OutputFolder $ReportFolder

#display report
Invoke-Item -Path $ReportFolder\index.html
 
```

I also included [OK](/Scenarios/S2D%20and%20Pester/ReportsOK.zip) and [Fail](/Scenarios/S2D%20and%20Pester/ReportsFail.zip) reports as zip file.

![](/Scenarios/S2D%20and%20Pester/Screenshots/ValidationInProcess-failure.png)

![](/Scenarios/S2D%20and%20Pester/Screenshots/Report2.png)

![](/Scenarios/S2D%20and%20Pester/Screenshots/Report3.png)

![](/Scenarios/S2D%20and%20Pester/Screenshots/Report4.png)