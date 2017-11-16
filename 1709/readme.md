# Server 1709 lab

## Howto
To create Windows Server 1709 lab, just replace LabConfig.ps1 with the 1709 labconfig from [this](https://github.com/Microsoft/ws2016lab/tree/master/1709/LabConfig.ps1) page.

Download Windows Server 1709 bits [from eval center](https://www.microsoft.com/en-us/evalcenter/) once its available there, or from your [Visual Studio subscription](https://my.visualstudio.com/Downloads?q=Windows%20Server,%20version%201709) 


Download Windows 10 bits [from eval center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise), or from your [Visual Studio subscription](https://my.visualstudio.com/Downloads?q=Windows%2010%20(multi-edition),%20Version%201709%20(Updated%20Sept%202017)) 

Download latest Server Cumulative update (it's the same file as for 1709 Windows 10) [here](https://www.catalog.update.microsoft.com/Search.aspx?q=Cumulative%20Update%20for%20Windows%20Server%202016%20(1709)%20for%20x64-based%20Systems)

Download latest [RSAT](http://aka.ms/RSAT) for Windows 10.

(Optional) Download [Project Honolulu](http://aka.ms/honoluludownload) and add it into toolsVHD folder before running 2_CreateParentDisks.ps1 as it will be added into tools.vhdx automagically

Hydrate labs as [usual](https://github.com/Microsoft/ws2016lab#howto)

Continue with [Hyper-V with SAN scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/Hyper-V%201709%20with%20SAN) (add servers in labconfig as per scenario)

Give a try to [Project Honolulu](http://aka.ms/honoluludownload). Just download honolulu bits, copy over to Management machine and install.