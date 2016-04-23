#Project Description
 Deployment Automation of Windows Server 2016 labs on WS2016/Windows10 Hyper-V

 This project focuses on Deployment Automation of Windows Server 2016 labs on WS2016/Windows10 Hyper-V. Simply deploy your lab just with these scripts and ISO file.

 This solution is used in Microsoft Premier Workshop for Software Defined Storage.

#Usage (more info in wiki)

 Download scripts
 
 Unzip in some folder
 
 Right-click and run with PowerShell. (1-Prereq -> 2-CreateParentDisks -> 3-Deploy -> Cleanup (if needed) -> modify variables.ps1 -> 3-Deploy again)

 You will be prompted for Windows Server 2016 ISO (TP4 and newer only) when running 2-CreateParentDisks. 

 You can now create multiple scenarios if you modify variables.ps1.

 Simple, S2D works on Windows 10
 Replica, Shared requires Failover Clustering (svhdx filter driver)

#Tips
 You can copy W2016 iso into OS folder and you will not be prompted when running 2-CreateParentDisks. 
 You can copy files in \tools\toolsVHD\. Files will be added into tools.vhdx, that is mounted into the DC during deployment (3-Deploy).
 If your server is offline, run 1-Prereq somewhere else - it will generate all folders and copy it over. Then run 1-Prereq on server again.
