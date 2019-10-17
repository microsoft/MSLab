# S2D and Validate-DCB

## About the lab

http://aka.ms/Validate-DCB can be used to build and validate DCB configuration. Following scenario will demonstrate how to run Validate-DCB in enterprise environment to detect misconfigurations. Guide for DCB Deployment is located at http://aka.ms/ConvergedRDMA

You can learn about Validate-DCB on real systems from these videos

* Part 1: https://youtu.be/NXK_amScDDE
* Part 2: https://youtu.be/PgtZvVPQ05E
* Part 3: https://youtu.be/Llnaw4KgOt8 
* Part 4: https://youtu.be/NFpQh9TOfXI
 
## Labconfig

Labconfig is the same as default

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}
1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 

#Optional management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win1019H1_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## The lab

### Prereq

To have networking on some servers, deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged) with $DCB=$true in Variables.

There is also one cosmetic detail, that if VMNetworkAdapter does not have the same name as NetAdapter, validate-DCB will complain. You can remove "vEthernet" from NetAdapter name with following script

```PowerShell
$servers="S2D1","S2D2","S2D3","S2D4"
$adapters=Get-NetAdapter -CimSession $servers | where name -like "vEthernet (*"
foreach ($adapter in $adapters){
    $newname=$adapter.name.Replace("vEthernet (","").Replace(")","")
    $adapter | Rename-NetAdapter -NewName $newname
}
 
```

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/NetAdaptersRenamed.png)

### Install Validate-DCB PowerShell module on online Windows System

```PowerShell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module Pester -Force -SkipPublisherCheck
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
if ($WindowsInstallationType -eq "Client"){
    Add-WindowsCapability -Name Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0 -Online
}else{
    Install-WindowsFeature -Name RSAT-Clustering-PowerShell
}
Install-Module Validate-DCB -Force
Get-Command -Module Validate-DCB
 
```

#### WSLab DC specific

Since DC is hydrated using DSC, having older and newer Networking DSC module does not play well. (yeah, I don't update script regularly and I download specific version as DSC versions are different from each other and it might break build process). Following script is needed just to keep latest NetworkinDSC module.

```PowerShell
#cleanup NetworkingDSC modules
$dirs=Get-ChildItem  -Path 'C:\Program Files\WindowsPowerShell\Modules\NetworkingDsc\'
if ($dirs.Count -gt 1){
    $dirs |Sort-Object -Property Name |select -First ($dirs.Count-1) | Remove-Item -Recurse -Force
}
 
```

#### Some notes for script above: 

If you just install Validate-DCB, you will receive notification about Nuget - that it needs to be installed. That's why in script above is NuGet as first.

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/NuGetPrompt.png)

Since there is also warning about untrusted repo (as PSGallery is not in PSRepository), you will receive following message if you don't specify "-force"

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UntrustedRepo.png)

Validate-DCB will end with red error about Pester module if pester is not updated before

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/PesterError01.png)

Just Installing Pester (with "-force") will return error, therefore "-SkipPublisherCheck" is required.

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/PesterError02.png)

If Pester and NuGet are installed, Install-Module Validate-DCB will endup with error complaining about missing FailoverClusters. Therefore it's also needed to run it before Install-Module Validate-DCB

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_FailoverClustersWarning.png)

### Running Validate-DCB - prerequisites

Just running Validate-DCB will check prereqs and after that, wizard will pop up.

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI01.png)!

If you fill all data and click Export, you will see several errors indicating, that you miss prerequisites.

![](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_MissingPrereqs.png)

To install required features run following code (note that Client needs just Microsoft-Hyper-V-Management-PowerShell but it cannot be installed separately with script in client SKU). Consider just installing it in OptionalFeatures.exe

```PowerShell
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
if ($WindowsInstallationType -eq "Client"){
    Enable-WindowsOptionalFeature -Online -FeatureName "DataCenterBridging","Microsoft-Hyper-V-All" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V"
}else{
    Install-WindowsFeature -Name "Data-Center-Bridging","RSAT-Hyper-V-Tools"
}
 
```

### Running Validate-DCB - GUI

```PowerShell
Validate-DCB
 
```

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI01.png)

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI02.png)

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI03.png)

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI04.png)

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI05.png)

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_UI06.png)

[](/Scenarios/S2D%20and%20Validate-DCB/Screenshots/Validate-DCB_TestResult.png)

### Running Validate-DCB - PowerShell

```PowerShell
Validate-DCB 
#Download example config that fits WSLab
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Validate-DCB/Config.ps1 -OutFile $env:USERPROFILE\Downloads\Config.ps1

Validate-DCB -ConfigFilePath $env:USERPROFILE\Downloads\Config.ps1
 
```

