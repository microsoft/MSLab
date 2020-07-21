# WSLab Telemetry

## Introduction

We started to collect telemetry to better understand impact of WSLab scripts as currently we cannot determine number of VMs deployed and where is WSLab being used. Data are hosted in Azure Application Insights and it is absolutely transparent what information is being collected, since all is visible in PowerShell Scripts.

Currently there is no public facing interface, however we plan to create PowerBI dashboards, where we will present Leader Boards and some nice statistics - such as how many VMs were deployed and we will be able to create statistics that will show in what countries is WSLab running and many more

## Verbosity level

Currently there are 3 different levels: **None**, **Basic** and **Full**. If nothing is configured in LabConfig, you will be asked to provide your preferred option.

### None

If you don't want to send anything, or if you are in offline environment.

### Basic

Sends information about deployed lab, that is vital for us to understand impact of WSLab scripts.

### Full

Provides enhanced information such as computer model, amount of RAM and number of cores. This information is not essential, however i will provide interesting insight.

## LabConfig examples

Basic telemetry level

```powershell
$LabConfig = @{ 
      DomainAdminName = 'LabAdmin'
      AdminPassword = 'LS1setup!'
      Prefix = 'WSLab-'
      DCEdition = '4'
      Internet = $true
      TelemetryLevel = 'Basic'
      AdditionalNetworksConfig = @()
      VMs = @()
}
 
```

Full telemetry including NickName that will be included in LeaderBoards once we will publish PowerBI statistics.

```powershell
$LabConfig = @{
	DomainAdminName = 'LabAdmin'
	AdminPassword = 'LS1setup!'
	Prefix = 'WSLab-'
	DCEdition = '4'
	Internet = $true
	TelemetryLevel = 'Full'
	TelemetryNickname = 'Jaromirk'
	AdditionalNetworksConfig = @()
	VMs = @()
}
 
```

## Collected information

These properties are attached to every telemetry event that is sent to the Application Insights workspace.

|                     | Basic | Full |Description| Sample Value | Application Insights property |
|---------------------|:-----:|:----:|-----------| --- | ---- |
| Application Version | x     | x    | Version of WSLab Scripts | v20.07.1 | `ai.application.ver` |
| Telemetry Level     | x     | x    | Which level of telemetry has been set | Full | `telemetry.level` |
| Product type        | x     | x    | Workstation or Server| Workstation | `os.type` |
| Session ID          | x     | x    | One-way hash (`SHA1`) of `MachineGUID`, `PSScriptRoot` and `ComputerName`. Purpose of this session ID is only to link execution of separate scripts within the same lab folder. | 482e33a99e6fb41e5f739d9294ac1b339c7c3c60 | `ai.session.id` |
| Device Locale       | x     | x    | Locale of Host OS | en-US | `ai.device.locale` |
| PowerShell Edition  | x     | x    | Desktop or Core | Core | `powershell.edition` |
| PowerShell Version  | x     | x    | version  | 7.0.2 | `powershell.version` | 
| TotalDuration       | x     | x    | Duration of script run in seconds | 23,62 | `TotalDuration` | 
| Device Manufacturer |       | x    | Device Manufacturer | LENOVO | `ai.device.oemName` |
| Device model        |       | x    | Device model based on `Win32_ComputerSystem` | ThinkPad P52 | `ai.device.model` |
| Operating System    |       | x    | OS SKU and build | Windows 10 Enterprise (10.0.19041.388)| `ai.device.os` |
| OS Build            |       | x    | OS Build Number | 19041 | `os.build` |
| Amount of RAM       |       | x    | Total amount of RAM in MB | 65311 | `memory.total` |
| Number of Sockets   |       | x    | How many sockets system have | 1 | `cpu.sockets.count` |
| Number of Cores     |       | x    | Total number of CPU cores available | 12 | `cpu.logical.count` |
| Volume Capacity     |       | x    | Capacity of a volume where WSLab was run (in GB) | 954 | `volume.size` | 
| Disk Model          |       | x    | Friendly name of a disk where volume with WSLab was run | Samsung SSD 970 PRO 1TB | `disk.model` |
| Disk Media Type     |       | x    | Type of the disk where WSLab was run  | SSD | `disk.type` |
| Disk Bus type       |       | x    | Bus connection of the disk where WSLab was run  | NVMe | `disk.busType` |

### Specific Events for 2_CreateParentDisks.ps1 script

#### CreateParentDisks.Start
When script is started.
#### CreateParentDisks.Vhd
For each hydrated VHD parent disk.
#### CreateParentDisks.End
When script finished.

### Specific Events to Deploy.ps1 script

#### Deploy.Start
When script is started.

#### Deploy.VM
For each provisioned VM.

#### Deploy.End
When script finished.

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
| lab.removed.count	|x    |x   |Number of removed VMs|



