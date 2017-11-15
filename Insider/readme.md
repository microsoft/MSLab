# Server Insider lab

## Howto
To create Insider lab, just replace LabConfig.ps1 with the insider labconfig from this page. It will hydrate DC, S2D servers with core edition and Windows 10 for management. 

### Download following

[Scripts](https://github.com/Microsoft/ws2016lab/blob/master/scripts.zip)

[Windows Server Insider and RSAT 64-bit](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver)

[Windows 10 Insider Enterprise 64-bit](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewadvanced)

[Project Honolulu](http://aka.ms/honoluludownload)

### Hydrate labs
Hydrate labs as [usual](https://github.com/Microsoft/ws2016lab#howto), just replace labconfig with [Insider Labconfig.ps1](https://github.com/Microsoft/ws2016lab/blob/master/Insider/LabConfig.ps1)
. During 2_CreateParentDisks click cancel, when asked for Server Cumulative Update for Server and choose RSAT for Windows 10.

Continue with [S2D scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged). You can then install Honolulu to manage HyperConverged cluster.

## Issues

* creating Volumes may not succeed. It may throw errors as RHS sometimes crashes.
* DSC Pull server is not configured on DC as there is a bug that prevents setting up Pull server using DSC. It is specified in LabConfig to skip Pull server configuration.
* RRAS configuration on DC fails, so you will not have internet connection in the lab (bug in server)
* Setting performance power plan fails

### Server Manager in Windows 10 management machine (default LabConfig)
![](/Insider/Screenshots/ServerManager.png)

### Cluadmin in Windows 10 management machine (default LabConfig)
![](/Insider/Screenshots/cluadmin.png)

### PowerPlan fails to set
![](/Insider/Screenshots/powerplan.png)