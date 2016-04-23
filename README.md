#Project Description
 Deployment Automation of Windows Server 2016 labs on WS2016/Windows10 Hyper-V

Simply deploy your lab just with these scripts and ISO file.

 This solution is used in Microsoft Premier Workshop for Software Defined Storage.

#Usage (more info in wiki)

 [Download](https://github.com/Microsoft/ws2016lab/blob/master/ws2016lab.zip?raw=true) scripts
 
 Unzip in some folder
 
 Right-click and run with PowerShell. (1-Prereq -> 2-CreateParentDisks -> 3-Deploy -> Cleanup (if needed) -> modify variables.ps1 -> 3-Deploy again)

 You will be prompted for Windows Server 2016 ISO (TP5 and newer only) when running 2-CreateParentDisks. 

 You can now create multiple scenarios if you modify variables.ps1.

 Simple, S2D works on Windows 10
 Replica, Shared requires Failover Clustering (svhdx filter driver)
