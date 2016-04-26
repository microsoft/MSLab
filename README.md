#Project Description
 Deployment Automation of Windows Server 2016 labs on WS2016/Windows10 Hyper-V

 Simply deploy your lab just with these scripts and ISO file.

 This solution is used in Microsoft Premier Workshop for Software Defined Storage.

#Usage (more info in wiki)

 [Download](https://github.com/Microsoft/ws2016lab/blob/master/scripts.zip?raw=true) scripts
 
 Unzip in some folder
 
 Right-click and run with PowerShell. (1_Prereq.ps1 -> 2_CreateParentDisks.ps1 -> 3_Deploy.ps1 -> Cleanup.ps1 (if needed) -> modify variables.ps1 -> 3_Deploy.ps1 again)

 You will be prompted for Windows Server 2016 ISO (TP5 and newer only) when running 2_CreateParentDisks.ps1. 

 You can create [multiple scenarios](https://github.com/Microsoft/ws2016lab/wiki/variables.ps1-examples) if you modify variables.ps1 - **Simple**, **S2D** works on Windows 10
 **Replica**, **Shared** requires Failover Clustering (svhdx filter driver)

#What's in the lab

Automatically hydrated Domain Controller with DHCP and one scope. There are several accounts automatically provisioned - SQL Run As Account, SQL Agent Account,  VMM Service Account and one additional Domain Admin with name you can specify, so you can install SQL + SC VMM easily.

![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/dhcp01.png)
![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/ActiveDirectory01.PNG)

You can then modify variables.ps1 to hydrate whatever you want. Like this 4 node nano s2d cluster with 200TB capacity - all running on ultrabook.

![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/HVConsole01.png)
![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/ServerManager01.png)
![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/FCConsole01.png)
![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/FCConsole02.png)
![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/FCConsole03.png)

#So what is it good for?

Simulations such as
* how to script against nano servers
* how to automate configuration
* what will happen when I run this and that command
* how change drive in S2D cluster
* what will happen when one node goes down
* testing new features before pushing to production
* ...

