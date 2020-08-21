# WSLab Telemetry

## Introduction

WSLab introduced opt-in telemetry collection to better understand impact of WSLab scripts as currently we cannot determine number of VMs deployed or where is WSLab being used. Data sent from scripts are hosted in Azure Application Insights service and it is absolutely transparent what information is being collected, since all code is visible in PowerShell Scripts on Github repository.

Currently there is no public facing interface to read collected information, however in the future plan is to create a public Power BI dashboard, where we will present Leader Boards and usage statistics - such as how many VMs were deployed and we will be able to create statistics that will show in what countries is WSLab running etc.

We are not collecting any PII, whole purpose of this telemetry is to get overall usage statistics of WSLab.

## Verbosity level

Currently there are 3 different verbosity levels for telemetry: **None**, **Basic** and **Full**. If nothing is configured in LabConfig, you will be asked to provide your preferred option. If you would like to skip this interactive prompt completely, configure desired telemetry level in your LabConfig file on per lab basis. You can also configure telemetry behaviour globally using environment variable `WSLAB_TELEMETRY_LEVEL` set to one of three options. If you configure both, LabConfig and Environment variable, LabConfig value take precedence.

### None

If you don't want to send anything, or if you are in an offline environment.

### Basic

Sends information about deployed lab, that is vital for us to understand impact of WSLab scripts.

### Full

Provides enhanced information such as amount of RAM and number of CPU cores of host environment. This information is not essential, however it will provide interesting insight to correlate script performance.

## Tag

If you would like to participate in leaderboard and show how many lab VMs you've deployed, you can also include `TelemetryNickname` variable in LabConfig configuration and this value would be then appended to every telemetry event sent.

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

## Telemetry Events

If WSLab telemetry is enabled, multiple events are sent. All events are listed in the table below. In general when script is started `.Start` type of event is sent and after script sucessfully finished respective `.End` event is sent. Two separate events are used to measure success rate of the scripts.

| Event                     | Script                    | Description |
|---------------------------|---------------------------|-------------|
| `Prereq.Start`            | `1_Prereq.ps1`            | When script it started. |
| `Prereq.End`              | `1_Prereq.ps1`            | When all prerequisities are downloaded. |
| `CreateParentDisks.Start` | `2_CreateParentDisks.ps1` | When script it started. |
| `CreateParentDisks.Vhd`   | `2_CreateParentDisks.ps1` | One event per each parent disk. Includes information how long the disk took to hydrate. |
| `CreateParentDisks.End`   | `2_CreateParentDisks.ps1` | When all parent disks are created. |
| `Deploy.Start`            | `3_Deploy.ps1`            | When script it started. |
| `Deploy.VM`               | `3_Deploy.ps1`            | One event per each provisioned lab VM. Includes information about that VM. |
| `Deploy.End`              | `3_Deploy.ps1`            | When lab has been deployed. Includes details about lab (e. g. incremental or new deploy). |
| `Cleanup`                 | `Cleanup.ps1`             | When lab has been deprovisioned. Includes count of actually removed VMs. |

## Collected information

These properties are sent with every telemetry event to the Application Insights workspace.

|                          | Basic | Full |Description| Sample Value | Application Insights property |
|--------------------------|:-----:|:----:|-----------| --- | ---- |
| Application Version      | x     | x    | Version of WSLab Scripts | v20.07.1 | `ai.application.ver` |
| Script name              | x     | x    | Name of the executed script | Deploy.ps1 | `i.cloud.role` |
| Telemetry Level          | x     | x    | Which level of telemetry has been set | Full | `telemetry.level` |
| Product type             | x     | x    | Workstation or Server| Workstation | `os.type` |
| Session ID               | x     | x    | One-way hash (`SHA1`) of `MachineGUID`, `PSScriptRoot` and `ComputerName`. Purpose of this ID is only to sync execution of separate WSLab scripts to the same lab instance. | 482e33a99e6fb41e5f739d9294ac1b339c7c3c60 | `ai.session.id` |
| User ID                  | x     | x    | One-way hash (`SHA1`) of `MachineGUID`. This provide option to differentiate multiple lab instances between multiple machines. | 0f3e4472845a50445883666b6f9efe55982bc1d0 | `ai.user.id` |
| Device ID                | x     | x    | Same value as User ID. | 0f3e4472845a50445883666b6f9efe55982bc1d0 | `ai.device.id` |
| Device Type              | x     | x    | PC System Type | Laptop | `ai.device.type` |
| PowerShell Edition       | x     | x    | Desktop or Core | Core | `powershell.edition` |
| PowerShell Version       | x     | x    | version  | 7.0.2 | `powershell.version` | 
| TotalDuration            | x     | x    | Duration of script run in seconds | 23,62 | `script.duration` | 
| OS Build                 | x     | x    | OS Build Number | 19041 | `os.build` |
| Device Locale            |       | x    | Locale of Host OS | en-US | `device.locale` |
| Operating System Name    |       | x    | OS SKU and build | Windows 10 Enterprise (10.0.19041.388 | `ai.device.os` |
| Operating System Version |       | x    | OS Build with patch level | 10.0.19041.388 | `ai.device.osVersion` |
| Amount of RAM            |       | x    | Total amount of RAM in MB of host OS. | 65311 | `memory.total` |
| CPU Model                |       | x    | What CPU model is used to execute WSLab. | Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz | `cpu.sockets.count` |
| Number of Sockets        |       | x    | How many sockets system have. | 1 | `cpu.sockets.count` |
| Number of Cores          |       | x    | Total number of CPU cores available. | 12 | `cpu.logical.count` |
| Volume Capacity          |       | x    | Capacity of a volume where WSLab was run (in GB). | 954 | `volume.size` | 
| Volume File system       |       | x    | What file system is on a volume where WSLab was executed. | ReFS | `volume.size` | 
| Disk Media Type          |       | x    | Type of the disk where WSLab was run.  | SSD | `disk.type` |
| Disk Bus type            |       | x    | Bus connection of the disk where WSLab was run.  | NVMe | `disk.busType` |

### Event-specific information 

In addition to general properties in the table above, these events include additional information to the telemetry event.

#### CreateParentDisks.Vhd

This event is sent for every newly created VHD file. If any of the VHD files in WSLab folder already exists, it would be skipped.

|                             | Basic | Full | Description | Sample Value | Application Insights property |
| --------------------------- |:-----:|:----:| ----------- | ------------ | ----------------------------- |
| VHD hydration duration      | x     | x    | How many seconds took to create specific VHD file. | 95,5  | `vhd.duration` |
| VHD name                    | x     | x    | Well-known name of the generated VHD file based on the dictionary in WSLab scripts. | Win2019Core_G2.vhdx | `vhd.name` |
| VHD kind                    | x     | x    | Type of VHD (Tools disk, Server Core or Full Desktop Experience). | Core | `vhd.kind` |
| Guest OS Build number       | x     | x    | Build number of OS in the generated VHD File. | 17763 | `vhd.os.build` |
| Guest OS Language           |       | x    | Language code of the OS in the generated VHD file. | en-US | `vhd.os.language` |


#### CreateParentDisks.End

This event is sent after Create Parent Disks script finishes and contains summary information about the lab itself.

|                             | Basic | Full | Description | Sample Value | Application Insights property |
| --------------------------- |:-----:|:----:| ----------- | ------------ | ----------------------------- |
| Server Core VHD - Exists    | x     | x    | True if VHD was already present, otherwise false.                                   | false               | `vhd.core.exists`   |
| Server Core VHD - Name      | x     | x    | Well-known name of the generated VHD file based on the dictionary in WSLab scripts. | Win2019Core_G2.vhdx | `vhd.core.name`     |
| Server Core VHD - Duration  | x     | x    | How many seconds took to create specific VHD file.                                  | 95.5                | `vhd.core.duration` |
| Server Desktop Experience VHD - Exists    | x     | x    | True if VHD was already present, otherwise false.                                   | false           | `vhd.full.exists`   |
| Server Desktop Experience VHD - Name      | x     | x    | Well-known name of the generated VHD file based on the dictionary in WSLab scripts. | Win2019_G2.vhdx | `vhd.full.name`     |
| Server Desktop Experience VHD - Duration  | x     | x    | How many seconds took to create specific VHD file.                                  | 195.5           | `vhd.full.duration` |
| Tools VHD - Exists    | x     | x    | True if VHD was already present, otherwise false.                                   | false       | `vhd.tools.exists`   |
| Tools VHD - Name      | x     | x    | Well-known name of the generated VHD file based on the dictionary in WSLab scripts. | Tools.vhdx  | `vhd.tools.name`     |
| Tools VHD - Duration  | x     | x    | How many seconds took to create specific VHD file.                                  | 25.5        | `vhd.tools.duration` |


#### Deploy.Start

This event is sent for every provisioned lab VM.

|                                    | Basic | Full | Description | Sample Value | Application Insights property |
| ---------------------------------- |:-----:|:----:| ----------- | ------------ | ----------------------------- |
| VM Configuration type in LabConfig | x     | x    | What configuration mode is used in LabConfig                           | S2D              | `vm.configuration`       |
| VM Unattend type in LabConfig      | x     | x    | What type of domain join is used for the VM in LabConfig               |  DjoinBlob       | `vm.os.installationType` |
| Installation type of OS VM         | x     | x    | What installation type is this VM (Server Core or Desktop Experience)  | Server Core      | `vm.os.editionId`        |
| Edition ID of VM                   | x     | x    | What OS Edition                                                        | ServerDatacenter | `vm.os.version`          |
| VM Provisioning time               | x     | x    | How much time was needed to create a VM instance                       | 34,7             | `vm.deploymentDuration`  |


#### Deploy.End

This event is sent when lab deploment is complete. Provide overall information about the lab instance.

|                       | Basic | Full | Description                         | Sample Value | Application Insights property |
| --------------------- |:-----:|:----:| ----------------------------------- | ------------ | ----------------------------- |
| Total VM count        | x     | x    | Total number of VMs in lab.                                                             | 8    | `lab.vmsCount.active`        |
| New VM count          | x     | x    | How many virtual machines were created by script instance.                              | 5    | `lab.vmsCount.provisioned`   |
| Lab Internet mode     | x     | x    | True if internet is enabled in LabConfig.                                               | true | `lab.internet`               |
| Is Incremental deploy | x     | x    | True if Deploy script was run before and is only adding additional VMs to existing lab. | true | `lab.isncrementalDeployment` |
| Lab Auto Start mode   | x     | x    | What auto-start mode is enabled for the lab.                                            | 2    | `lab.autostartmode`          |


#### Cleanup

This event is sent when Cleanup script removes lab virtual machines and contain number of affected virtual machines.

|                   | Basic | Full | Description                         | Sample Value | Application Insights property |
| ----------------- |:-----:|:----:| ----------------------------------- | ------------ | ----------------------------- |
| Removed VMs count | x     | x    | How many VMs were actually removed. | 8            | `lab.removed.count`           |



