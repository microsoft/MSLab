#Project Description
 Deployment Automation of Windows Server 2016 labs on WS2016/Windows10 Hyper-V

 Simply deploy your lab just with these scripts and ISO file.

 This solution is used in Microsoft Premier Workshop for Software Defined Storage.
 
 Check [this](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios) page for end to end scenarios!

 You can try [dev branch scripts](https://github.com/Microsoft/ws2016lab/blob/dev/scripts.zip) to test new labconfig, vTPM, new nested virtualization, number of Management adapters...


#Usage (more info in [wiki](https://github.com/Microsoft/ws2016lab/wiki) )

**Step 1** Download required files (prerequisities):
* [Scripts](https://github.com/Microsoft/ws2016lab/raw/master/scripts.zip) or [Dev Scripts](https://github.com/Microsoft/ws2016lab/blob/dev/scripts.zip?raw=true) (recommended)
* [Windows Server 2016 TP5](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-technical-preview) 
* [Cumulative Update](http://catalog.update.microsoft.com/v7/site/search.aspx?q=kb3172989)  for Windows Server 2016 Technical Preview 5 kb3172989

**Step 2** Create folder and Unzip scripts there

**Step 3** Right-click and run with PowerShell 1_Prereq.ps1
 * 1_Prereq.ps1 will create folder structure and download neccessary files from internet
 * If you don't have an internet connection on your server, run this on internet connected machine, copy created files over and run 1_prereq.ps1 again
 
**Step 4** Copy Cumulative Update into the OSServer\Packages folder.

**Step 5** Right-click and run with PowerShell 2_CreateParentDisks.ps1
 * 2_CreateParentDisks.ps1 will check if you have Hyper-V installed, it will prompt you for Windows Server 2016 TP5 ISO file, hydrate parent disks and hydrate Domain Controller.
 * note: if you have Windows 10 Anniversary Update, DC will fail to start. You need to switch Secure Boot to Microsoft UEFI CA and then disable Secure Boot. This problem is only in TP5 guests. RTM is OK.
 
````PowerShell
Stop-VM -VMName DC -TurnOff
Set-VMFirmware -SecureBootTemplate MicrosoftUEFICertificateAuthority -VMName DC
Set-VMFirmware -EnableSecureBoot Off -VMName DC
Start-VM -VMName DC
````

**Step 6** Right-click and run with PowerShell 3_Deploy.ps1
 * 3_Deploy.ps1 will deploy S2D Hyperconverged [scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios) defined in variables.ps1 [different examples](https://github.com/Microsoft/ws2016lab/wiki/variables.ps1-examples)
 
**Step 7** Continue with [S2D Hyperconverged Scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged%20TP5)

* This scenario will help you understand new Windows Server 2016 feature called Storage Spaces Direct.

* It will deploy 4 nanoservers simulating 200TB Storage

* note: if you run Win10 Anniversary, you will need to disable SB for TP5 machines

````PowerShell
$VMs=Get-VM -VMName *-S2D*
$VMs | Set-VMFirmware -SecureBootTemplate MicrosoftUEFICertificateAuthority
$VMs | Set-VMFirmware -EnableSecureBoot Off
````


**Step 8** Cleanup lab with Cleanup.ps1

**Step 9** Try different scenarios
* [Local Admin Password solution for NanoServer](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/LAPS%20on%20Nano)
* [Testing Nano first boot performance](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/Testing%20Nano%20performance)

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


#Changelog

* 10.6.2016 - Changed DSC to use Configuration name to be able to play with LAPS https://blogs.msdn.microsoft.com/laps/2016/06/10/testing-laps-for-nano-server-with-ws2016lab/
* 17.5.2016 - Added SCVMM automation - if you specify labconfig parameter to install SCVMM and put all install files into toolsVHD folder, SCVMM will be automatically installed during 2_CreateParentDisks
* 15.5.2016 - Simplified variables.ps1, SCVMM install scripts added
* 3.5.2016 - Scripts will exit if prefix is empty. Also will exit if iso was not selected in prompt.
* 1.5.2016 - Added win2012R2 support, optimized answer files, moved dism to tools, all scripts use dism from tools (copied from iso)
