# fun with VMFleet

Ws2016lab now downloads VMFleet into ToolsVHD during 1_Prereq.ps1. (the VHD with Windows Server is copied manually from ParentDisks folder)

![](/Scenarios/VMFleet/Screenshots/ToolsVHD.png)

Deploy [S2D Hyperconverged scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged) and then right-click SetupVMFleet.ps1 and select run with PowerShell

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step1.png)

Script will run, asks you to select your S2D cluster

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step2.png)

Script will also ask you for Password, that will be injected in answer file into VHD for VMFleet.

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step3.png)

Will also ask you for VHD with windows server (it will inject answer file and create users\administrator folder, so vmfleet will be able to use it). I recommend copying VHD there before deployment - just mount toolsVHD, copy and eject.
**Make sure you use different VHD than for cluster nodes. See known issues in the bottom** You can create another VHD with CreateParentDisk.ps1 located in tools folder.

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step4.png)

And after it will create Volumes, copy VHD into collect volume, and install failover clustering PowerShell, it will provide you commands, you will run in first node (s2d1 in this case)

![](/Scenarios/VMFleet/Screenshots/VMFleet_Step5.png)

Provisioning VMs will take some time, I usually dedup volumes during this process, as it quickly fills all available space. But after this, you will be able to play with VMFleet

![](/Scenarios/VMFleet/Screenshots/VMfleetInAction.png)

For additional commands take a look here https://blogs.technet.microsoft.com/larryexchange/2016/08/17/leverage-vm-fleet-testing-the-performance-of-storage-space-direct/

# Known isues

Make sure you use different VHD than for s2d cluster node. Following screenshot shows disk, that fails to go online as there is same GUID/UniqueID as OS Disk.

![](/Scenarios/VMFleet/Screenshots/Error_wrongVHD.png)

Therefore you use the same as OS, OS wil fail to online volume and vmfleet will fail to add drive letter. You will also see following errors.

![](/Scenarios/VMFleet/Screenshots/Error_wrongVHD1.png)