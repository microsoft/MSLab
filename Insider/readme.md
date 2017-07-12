# Server Insider lab

## Howto
To create Insider lab, just replace LabConfig.ps1 with the insider from this page. It will hydrate DC and S2D servers with core edition, Windows 10 for management and connects lab to your connected physical NIC to get internet connectivity. Optionally (commented section in LabConfig) you can have just DC and S2D servers without internet connectivity.

Download bits [here](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver)

Hydrate labs as usual. Just click cancel when asked for Server Cumulative Update. 

If you hydrate lab with Windows 10 (default), you will be asked for Windows 10 media. You can use [RS2 evaluation version](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise) or [RS3 Insider Preview ISO](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewadvanced)

If using Windows 10, [download RSAT](https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS2016-x64.msu) to manage the environment. You can provide it when asked for Cumulative Update.

Continue with [S2D scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged)

## Issues

* RSAT is RS1, therefore you cannot run scenario scripts from Windows 10. Cluadmin seems fine, but RS1 PowerShell Modules does not work well with RS3.

* creating Virtual Disk will not succeed. It will throw errors, node might even bluescreen. This is known issue with 16237 build. See screenshot below

* Power Plan activation fails. See screenshot below

* DSC Pull server is not configured on DC as there is a bug in 16273 that prevents setting up Pull server using DSC. It is specified in LabConfig to skip Pull server configuration.

![Script setting S2D cluster from Host using PowerShell Direct (simple LabConfig)](/Insider/Screenshots/2017-07-11-01-19-42.png)
![Errors creating Volume](/Insider/Screenshots/2017-07-11-02-14-04.png)
![Errors during Power Plan setting](/Insider/Screenshots/2017-07-11-02-19-34.png)
![Server Manager in Windows 10 management machine (default LabConfig)](/Insider/Screenshots/2017-07-11-02-07-23.png)
![Cluadmin in Windows 10 management machine (default LabConfig)](/Insider/Screenshots/2017-07-11-02-12-39.png)