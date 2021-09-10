#Creating Parent Disk

If you need additional VHD (like Windows 11, or Azure Stack HCI OS), you can create it by simply navigating to ParentDisks folder and running PowerShell

![](Docs/media/MSLAB-Advanced_CreateParentDisk_Explorer01.png)

You will be asked for ISO file and latest cumulative update that you can download using "DownloadLatestCUs.ps1" script.

![](Docs/media/MSLAB-Advanced_CreateParentDisk_PowerShell01.png)

ISO file can be downloaded from various locations such as:

* [Visual Studio Suubscription Downloads](https://my.visualstudio.com/Downloads)
* [Evaluation Center](https://www.microsoft.com/en-us/evalcenter/)
* [Windows Insider Preview](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewiso)
* [UUP Dump](https://uupdump.net/) - unofficial to, not supported, but good enough for labs if ISO is not (yet) available

Script will also ask what edition you would like to use

![](Docs/media/MSLAB-Advanced_CreateParentDisk_PowerShell02.png)

Name of VHD and size (you can just hit enter to leave it blank)

![](Docs/media/MSLAB-Advanced_CreateParentDisk_PowerShell03.png)

In few minutes, the VHD will be created

![](Docs/media/MSLAB-Advanced_CreateParentDisk_PowerShell04.png)
