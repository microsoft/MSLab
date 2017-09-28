# Server Insider lab

## Howto
To create Insider lab, just replace LabConfig.ps1 with the insider labconfig from this page. It will hydrate DC, S2D servers with core edition and Windows 10 for management. 

Download bits [here](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver)

Hydrate labs as [usual](https://github.com/Microsoft/ws2016lab#howto), just click cancel when asked for Server Cumulative Update. 

If you hydrate lab with Windows 10 (default), you will be asked for Windows 10 media. Use English Enterprise 64-bit version (to match RSAT) [RS3 Insider Preview ISO](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewadvanced)

[download RSAT](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver) to manage the environment. Provide it when asked for Cumulative Update.

Continue with [S2D scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged)

Give a try to [Project Honolulu](http://aka.ms/honoluludownload). Just download honolulu bits, copy over to Management machine and install.

## Issues

* creating Volumes may not succeed. It may throw errors as RHS sometimes crashes. To mitigate the issue, configure CSV Cache to 0 and create cluster with static IP Address
````PowerShell
    New-Cluster –Name $ClusterName –Node $servers -StaticAddress "10.0.0.111"
    Start-Sleep 5
    Clear-DnsClientCache
    (get-cluster -Name $clustername).BlockCacheSize=0
````
* DSC Pull server is not configured on DC as there is a bug that prevents setting up Pull server using DSC. It is specified in LabConfig to skip Pull server configuration.
* RRAS configuration on DC fails, so you will not have internet connection in the lab (bug in server)
* Setting witness on DC will fail
* Setting performance power plan fails

### Server Manager in Windows 10 management machine (default LabConfig)
![](/Insider/Screenshots/ServerManager.png)

### Cluadmin in Windows 10 management machine (default LabConfig)
![](/Insider/Screenshots/cluadmin.png)

### PowerPlan fails to set
![](/Insider/Screenshots/powerplan.png)