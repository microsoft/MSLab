# Project Description
 * Deployment Automation of Windows Server 2016 labs on WS2016/Windows10 Hyper-V
 * Simply deploy your lab just with these scripts and ISO file.
 * Major differentiator is that once hydrated (first 2 scripts), deploy takes ~5 minutes. Cleanup is ~10s.
 * Options for setting up a Windows Server 2016-based lab are simpler than with some of the other available lab automation systems as the project is based on well-crafted Powershell scripts and, rather than XML or DSC configuration files.
 * Scripts are not intentionally doing everything. You can spend nice time studying scenarios.
 * This solution is used in Microsoft Premier Workshop for Software Defined Storage, Hyper-V and System Center VMM. If you have Premier Contract, contact your TAM and our trainers can deliver this workshop for you.

 * Check [this](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios) page for end to end scenarios! It's just a small portion I wrote for internally for consultants and PFEs in Microsoft

 * Want to try Windows Server insider builds? Check [this](https://github.com/Microsoft/ws2016lab/tree/master/Insider) page

 * Want to try Windows Server 1709? Check [this](https://github.com/Microsoft/ws2016lab/tree/master/1709) page

# Videos

Videos are bit outdated as subtle changes are in scripts.

* [1 Lab Hydration](https://youtu.be/xDrMYdSCIpM)
* [2 Lab Deployment](https://youtu.be/SzewA7C9lzI)
* [3 S2D Scenario](https://youtu.be/CX3ny0ON9X0)
* [4 Bonus-S2D to S2D Storage Replica Scenario](https://youtu.be/JRzBIOMEUO8)

# HowTo

## Step 1 Download required files (prerequisities):
* [Scripts](https://github.com/Microsoft/ws2016lab/blob/master/scripts.zip?raw=true)
* [Windows Server 2016](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016) 
* [Latest Cumulative Update](http://catalog.update.microsoft.com/v7/site/Search.aspx?q=Cumulative%20Update%20for%20Windows%20Server%202016%20for%20x64-based%20Systems%20) for Windows Server 2016 and [Servicing Stack Update](https://www.catalog.update.microsoft.com/Search.aspx?q=2017-11%20Update%20for%20Windows%20Server%202016%20for%20x64-based%20Systems%20(KB4049065)%20)

## Step 2 Create folder and Unzip scripts there

![](/Screenshots/ScriptsExtracted.png)

## Step3 (Optional) Check the LabConfig.p1 
* Edit it to specify the lab setup that you require (such as different domain name, Domain Admin name..) This script file documents the detailed configuration options that are available. (The default script will generate a lab with a Windows Server 2016 DataCenter Domain Controller and 4 Windows Server 2016 Core servers ready to be set up with Storage Spaces Direct.)

**Default Labconfig**

![](/Screenshots/LabConfig.png)

**Default Labconfig with collapsed sections (ctrl+M)**

![](/Screenshots/LabConfigCollapsed.png)

**Advanced LabConfig (deleted lines 1-11)**

![](/Screenshots/LabConfigAdvanced.png)

##Step 4 Right-click and run with PowerShell 1_Prereq.ps1
 * 1_Prereq.ps1 will create folder structure and downloads some additional necessary files from internet
 * If you don't have an internet connection on your server, run this on internet connected machine, copy created files over and run 1_prereq.ps1 again

![](/Screenshots/1_Prereq.png)

**Result**

![](/Screenshots/1_PrereqResult1.png)
![](/Screenshots/1_PrereqResult2.png)

**CreateParentDisk tool**

![](/Screenshots/ToolsCreateParentDisk.png)

## Step 5 (optional) Copy SCVMM files (or your tools) to toolsVHD folder
 * If you modified labconfig.ps1 in Step 3 to also deploy SCVMM, populate the Tools\SCVMM folder. If you downloaded SCVMM trial, run the exe file to extract it. Also extract SCVMM Update Rollups (extract MSP files from cabs)

You can also copy your favorite tools you would like to have in ToolsVHD, thats always mounted to DC, or optionally to any machine in lab.

**ToolsVHD folder**

![](/Screenshots/ToolsVHDFolder.png)

**ToolsVHD SCVMM Folders**

![](/Screenshots/ToolsVHDSCVMM1.png)

![](/Screenshots/ToolsVHDSCVMM2.png)

## Step 6 Right-click and run with PowerShell 2_CreateParentDisks.ps1
 * 2_CreateParentDisks.ps1 will check if you have Hyper-V installed, it will prompt you for Windows Server 2016 ISO file, nd the it will ask for packages (provide Cumulative Update and Servicing Stack Update). After that it will hydrate parent disks and Domain Controller.
 * Domain controller is provisioned using DSC. Takes some time, but after that you do not need to run this step anymore as DC is saved, used for deploy and then returned to previous state before deploy step.

![](/Screenshots/2_CreateParentDisks.png)

**ISO Prompt**

![](/Screenshots/2_CreateParentDisksISOPrompt.png)

**MSU Prompt**

![](/Screenshots/2_CreateParentDisksMSUPrompt.png)

**Result: Script finished**

![](/Screenshots/2_CreateParentDisksResultCleanup3.png)

**Result: Script cleanup unneccessary folders - before**

![](/Screenshots/2_CreateParentDisksResultCleanup2.png)

**Result: Script cleanup unneccessary folders - after**

![](/Screenshots/2_CreateParentDisksResultCleanup4.png)

**Result: Parent disks are created**

![](/Screenshots/2_CreateParentDisksResultParentDisks.png)

**Result: DC, thats imported during deploy is Created**

![](/Screenshots/2_CreateParentDisksResultDC.png)

## Step 7 Right-click and run with PowerShell Deploy.ps1
 * Deploy.ps1 will deploy servers as specified in Labconfig.ps1 By default, it will deploy servers for S2D Hyperconverged [scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios)

![](/Screenshots/Deploy.png)

**Result**

![](/Screenshots/DeployResultOverview.png)
 
## Step 8 Continue with [S2D Hyperconverged Scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged) 

* will guide you to deploy 4 Node Storage Spaces Direct cluster.
* Note: scenario is completely separate script. You use it when logged into DC. Take your time and look what it does as you can easily learn from it. If you are not in rush, run it line by line in PowerShell or PowerShell ISE and look with GUI what has changed to fully understand what's happening.

## Step 9 Cleanup lab with Cleanup.ps1

![](/Screenshots/Cleanup.png)

![](/Screenshots/Cleanup1.png)

![](/Screenshots/Cleanup2.png)

## Step 10 Try different [scenarios](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/)

* Just replace LabConfig and Deploy again (takes 5-10 minutes to spin up new VMs)

# Tips and tricks

* In tools folder is CreateParentDisk.ps1 script created. You can use this anytime to create additional parent disks (such as Server with GUI or Windows 10). Just right-click and run with PowerShell

![](/Screenshots/ToolsCreateParentDisk.png)

* If you want to run scripts on Server Core, modify labconfig and use ServerISOFolder and ClientISOFolder variables (MSUs are optional)
* disable Defender during CreateParentDisks as AMSI is scanning scripts and it utilizes CPU. (Takes twice more time to create parent disks)
* every script is creating transcript file. You can look for issues there.
* if you want internet connection, just specify Internet=$true in Labconfig.

# Known issues

* DISM does not work on Cluster Shared Volumes
* When waiting on DC to come online, the script throws some red errors. It's by design, nothing to worry about.
* DISM sometimes throws errors on NTFS volumes also. Just build the lab again in different folder.
* sometimes if all machines are started at once, some are not domain joined. Just cleanup and deploy again.

# So what is it good for?

Simulations such as
* how to script against servers
* how to automate configuration
* what will happen when I run this and that command
* how change drive in S2D cluster
* what will happen when one node goes down
* testing new features before pushing to production
* ...
