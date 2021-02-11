# Deploying VMs

Depending on scale, you might consider using PowerShell to deploy Virtual Machines and join these machines to domain in one iteration. The process is two part. In first part you create a VM on one cluster node (preferably random) and second part adds this VM as clustered resource

## Simple example

```powershell
$VMName="MyVM"
$VolumeName="MirrorDisk1"
$ClusterName="AzSHCI-Cluster"
$ClusterNode="AzSHCI1"
$SwitchName="SETSwitch"
$DiskSize=128GB
$MemoryStartupBytes=1GB

New-VM -Name $VMName `
-NewVHDPath "c:\ClusterStorage\$VolumeName\$VMName\Virtual Hard Disks\$VMName.vhdx" `
-NewVHDSizeBytes $DiskSize `
-SwitchName $SwitchName `
-Generation 2 `
-Path "c:\ClusterStorage\$VolumeName\" `
-MemoryStartupBytes $MemoryStartupBytes `
-CimSession $ClusterNode  

Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName 
 
```

Since above example just creates blank VM, let's experiment with creating Windows Server Virtual Machine.

## Creating Windows Server/Windows 10 VHD

To create Windows vhd/vhdx can be tool convert-windowsimage used. https://github.com/MicrosoftDocs/Virtualization-Documentation/blob/master/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1

To simplify conversion process you will find **CreateParentDisk.ps1** tool in wslab. It is available [WSLab GitHub](https://github.com/microsoft/WSLab/blob/master/Tools/CreateParentDisk.ps1) and the only thing needed is to right-click and select "run with PowerShell". The script will download convert-windowsimage and will ask for ISO and MSU (Cumulative Update and Servicing Stack Update). To Download CU and SSU you can use another tool - [DownloadLatestCUs.ps1](https://github.com/microsoft/WSLab/blob/master/Tools/DownloadLatestCUs.ps1).

![](07-Deploying-VMs/media/Explorer01.png)

Once parent VHD is created, we can proceed with VM creation. The end-to-end process on how to create domain-joined VMs with various parameters is documented [here](https://github.com/microsoft/WSLab/tree/master/Scenarios/S2D%20and%20Bulk%20VM%20creation)