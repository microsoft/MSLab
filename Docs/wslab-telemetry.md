# WSLab Telemetry

## Introduction

We started to collect telemetry to better understand impact of WSLab scripts as currently we cannot determine number of VMs deployed and where is WSLab being used. Data are hosted in Azure Application Insights and it is absolutely transparent what information is being collected, since all is visible in PowerShell Scripts.

Currently there is no public facing interface, however we plan to create PowerBI dashboards, where we will present Leader Boards and some nice statistics - such as how many VMs were deployed and we will be able to create statistics that will show in what countries is WSLab running and many more

## Verbosity level

Currently there are 3 different levels: **None**, **Basic** and **Full**. If nothing is configured in LabConfig, you will be asked to provide preferred option.

### None

If you don't want to send anything, or if you are in offline environment.

### Basic

Sends information about deployed lab, that is vital for us to understand impact of WSLab scripts.

### Full

Provides enhanced information such as computer model, amount of RAM and number of cores. This information is not essential, however i will provide interesting insight.

## LabConfig examples

Basic telemetry level

```powershell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-' ; DCEdition='4'; Internet=$true ; TelemetryLevel='Basic' ; AdditionalNetworksConfig=@(); VMs=@()}
 
```

Full telemetry including NickName that will be included in LeaderBoards once we will publish PowerBI statistics.

```powershell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-' ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='Jaromirk' ; AdditionalNetworksConfig=@(); VMs=@()}
 
```

## Collected information

|                   |Basic|Full|Description|
|--------------------|:---:|:--:|-----------|

|Application Version |x    |x   |Version of WSLab Scripts |
|Product type        |x    |x   |Workstation or Server|
|TelemetrySessionID  |x    |x   |Calculated based on MachineGUID, PSScriptRoot and ComputerName hash|
|Device Manufacturer |     |x   |Manufacturer (for example Lenovo, Dell, HP...)|
|Device model        |     |x   |Device model based on win32_ComputerSystem|
|Operating System    |     |x   |OS SKU and build (for example Windows 10 Enterprise (10.0.19041.388)|
|Amount of RAM       |     |x   |   |
|Number of Cores     |     |x   |   |
|Disk Manufacturer   |     |x   |   |
|Disk Model          |     |x   |   |
|Disk MedyaType      |     |x   |   |
|Disk Bustype        |     |x   |   |
|TotalDuration       |x    |x   |Duration of script run|
|PowerShell Edition  |x    |x   |Desktop or core|
|PowerShell Version  |x    |x   |   |


### Specific to Deploy.ps1

|                             |Basic|Full|Description|
|-----------------------------|:---:|:--:|-----------|
|VMDeploymentDuration         |x    |x   |Duration of Deploy.ps1 script|
|Deployed VM OSBuild          |x    |x   |For example 19041|
|Deployed VM InstallationType |x    |x   |For example Server Core|
|Deployed VM OsVersion        |x    |x   |For example 10.0.17763.1282|
|Deployed VM EditionID        |x    |x   |For example ServerDatacenter|

### Specific to Cleanup.ps1

|           |Basic|Full|Description|
|-----------|:---:|:--:|-----------|
|VmsRemoved	|x    |x   |Number of removed VMs|



