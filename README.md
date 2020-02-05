# WSLab Introduction

<!-- TOC -->

- [WSLab Introduction](#wslab-introduction)
    - [Requirements](#requirements)
    - [Scripts](#scripts)
    - [Use cases](#use-cases)
        - [Prototyping](#prototyping)
        - [Hands on Labs](#hands-on-labs)
        - [Issue reproduction](#issue-reproduction)
        - [Sessions](#sessions)

<!-- /TOC -->

WSLab is a GitHub project that aims to provide virtual environments in Hyper-V, that can be built in consistent way. It comes at no additional cost, it's free and available under the [MIT License](License).

Unlike other solutions, WSLab focuses on simplicity (all actions can be done without typing complex scripts) and low profile (all disks are differencing, minimum requirements are 8GB RAM and 40GB free space). There is no special hardware requirement. WSLab can run on almost any machine that has SSD and decent amount of memory.

![](Docs/media/Hyper-V_Manager01.png)

## Requirements

* Windows 10 Pro/Enterprise (as Hyper-V is required) or Windows Server 2016/2019
* 8GB RAM
* CPU with Virtualization support
* SSD
* 40GB free space

## Scripts

The main part of WSLab are the [Scripts](https://aka.ms/wslabzip) that will help you preparing lab files ([Hydration Phase](Docs/wslab-hydration.md)). This phase is the most time consuming (1-2hours), but needs to be done only once. It will create virtual hard disks from of provided ISO and will create Domain Controller. [WSLab Deployment](Docs/wslab-deployment.md) takes only few minutes as it will just import Domain Controller and will add other Virtual Machines as specified in LabConfig.ps1

![](Docs/media/Explorer01.png)

## Use cases

### Prototyping

WSLab is ideal for prototyping. It will quickly spin Windows Server/Client environments that are connected to Internet and ready to be played with. If something goes wrong, there is nothing easier than just run Cleanup and then Deploy again

### Hands on Labs

WSLab virtual machines are defined in LabConfig.ps1 as simple hash table. This way you can share your configurations and create consistent, complex environments. Labs are easy to distribute. Once you are done with Hydration Phase, you can just copy result folder to multiple computers and deliver entire classes.

### Issue reproduction

Many times happened, that there was an issue that was hard to reproduce. And even if you could reproduce it, another person did not have the same environment, so even with the same steps, the issue might not occur again. WSLab changes this as all WSLab environments with the same LabConfig are the same. So only thing you need to share to other person to reproduce issue are steps and LabConfig.ps1.

### Sessions

For more session slides navigate to [Slides](https://1drv.ms/u/s!AjTsLJdE37DwtrsnIehxKx7N7XgoBg?e=r1sszn) OneDrive

[![WSLab in MVPDays](/Docs/media/S2DSimulations_presentation_thumb.png)](https://youtu.be/u7d6Go8weBc)
1
[![WSLab in CDCGermany](/Docs/media/WSLab_Datacenter_Simulation_presentation_thumb.png)](https://youtu.be/5IX9OLEk50Q)

### Run in PowerShell Core 7
WSLab scripts work also in PowerShell 7, if you want to test it just install latest version of PowerShell 7.

If you also would like to have context menu integration like this:
![](Docs/media/Explorer02pwsh.png) 

You can use this script to register PowerShell Core integration in Explorer.

```powershell
# Set context menu option
$pwshPath = "c:\Program Files\PowerShell\7-preview\pwsh.exe"

if(-not (Get-PSDrive -PSProvider Registry | Where-Object Root -EQ "HKEY_CLASSES_ROOT")) {
    New-PSDrive -PSProvider Registry -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
}

New-Item -Path "HKCR:\Microsoft.PowerShellScript.1\Shell" -Name "1"
New-ItemProperty -Path "HKCR:\Microsoft.PowerShellScript.1\Shell\1" -PropertyType String -Name "MUIVerb" -Value "Run with PowerShell &Core"
New-ItemProperty -Path "HKCR:\Microsoft.PowerShellScript.1\Shell\1" -PropertyType String -Name "Icon" -Value $pwshPath

New-Item -Path "HKCR:\Microsoft.PowerShellScript.1\Shell\1" -Name "Command"
Set-ItemProperty -Path "HKCR:\Microsoft.PowerShellScript.1\Shell\1\Command" -Name "(Default)" -Value ('"{0}" "-Command" "if((Get-ExecutionPolicy ) -ne ''AllSigned'') {{ Set-ExecutionPolicy -Scope Process Bypass }}; & ''%1''"' -f $pwshPath)

```
