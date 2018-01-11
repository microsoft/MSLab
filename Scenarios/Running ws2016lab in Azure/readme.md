<!-- TOC -->

- [Overview](#overview)
- [Creating VM with PowerShell](#creating-vm-with-powershell)
- [Create VM with JSON in UI](#create-vm-with-json-in-ui)
- [Cleanup the VM and resources](#cleanup-the-vm-and-resources)
- [Creating VM Manually](#creating-vm-manually)
    - [Adding premium disk (bit pricey)](#adding-premium-disk-bit-pricey)
- [Overall experience](#overall-experience)

<!-- /TOC -->

# Overview

I was always wondering how fast will be Azure VM to host ws2016lab since we [announced](https://azure.microsoft.com/en-us/blog/nested-virtualization-in-azure/) availability of nested virtualization in Azure. Thanks to @DaveKawula tweet I decided to give it a try as i have MSDN subscription with ~130eur credit/month

I present here several options how to create a VM in Azure that is capable to run ws2016lab. I learned something new, I hope you will too.

# Creating VM with PowerShell

To create VM with PowerShell, run following command.

````PowerShell
#download Azure module if not installed
if (!(get-module -Name AzureRM*)){
    Install-Module -Name AzureRM
}

#login to your azure account
Login-AzureRmAccount

#Create VM
New-AzureRmVm `
    -ResourceGroupName "ws2016labRG" `
    -Name "ws2016lab" `
    -Location "West Europe" `
    -VirtualNetworkName "ws2016labVirtualNetwork" `
    -SubnetName "ws2016lab" `
    -SecurityGroupName "ws2016labSG" `
    -PublicIpAddressName "ws2016labPubIP" `
    -OpenPorts 80,3389 `
    -ImageName Win2016Datacenter `
    -Size Standard_D16s_v3 `
    -Credential (Get-Credential) `
    -Verbose

#connect to VM using RDP
mstsc /v:((Get-AzureRmPublicIpAddress -ResourceGroupName ws2016labRG).IpAddress)

````
# Create VM with JSON in UI

[![](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMicrosoft%2Fws2016lab%2Fdev%2FScenarios%2FRunning%2520ws2016lab%2520in%2520Azure%2Fws2016lab.json)
[![](http://armviz.io/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com/Microsoft/ws2016lab/dev/Scenarios/Running%20ws2016lab%20in%20Azure/ws2016lab.json)

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CustomizedTemplate.png)

# Cleanup the VM and resources
````PowerShell
Get-AzurermVM -Name ws2016lab -ResourceGroupName ws2016labRG | Remove-AzureRmVM -Force -verbose
Get-AzureRmResource | where name -like ws2016* | Remove-AzureRmResource -Force -verbose
Get-AzureRmResourceGroup | where name -eq ws2016labRG | Remove-AzureRmResourceGroup
````

# Creating VM Manually
To create VM, click on New and select Windows Server 2016 VM.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM01.png)

Provide some basic input, such as username and password you will use to connect to the VM.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM02.png)

The only machines with nested virtualization are D and E v3 machines. In MSDN you can consume up to 20 cores, therefore I selected D16S V3.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM03.png)

Select managed disks and also don't forget to enable Auto-Shutdown. Auto-Shutdown is really cool feature. Helps a lot managing costs of your lab. 

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM04.png)

Validate the settings and click on Create

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM05.png)

Once VM will finish deploying, you will be able to see it running on your dashboard.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM06.png)

## Adding premium disk (bit pricey)

**Note:** Premium disk is not the best choice as it drains your credit quite fast. So either use it and destroy, or use temp storage instead. You can store ws2016lab on OS and just copy to temp disk to deploy it there.

To add storage, click on add data disk under disks.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage01.png)

You will be able to specify disk. Since I did not have disk created, you can click on Create disk and wizard will open.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage02.png)

In wizard configure 4TB disk, just to have 7500 IOPS.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage03.png)

After disk is configured, you can configure host caching to Read/Write (since you don't care about loosing data)

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage04.png)

# Overall experience

I recommend using temp drive D: as its fast enough. After parent disk hydration, you can copy lab to c:\

**Data disappeared after shutting down a VM**
![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/TempDrive.png)

**I prefer to keep ws2016lab on c:\ and copy it to temp drive on machine resume**
![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CopyToTempDrive.png)

In machine overview you are able to connect (after click it will download rdp file with server IP in it), or you can just copy IP to clip and run remote desktop client from your pc. To cut down cots, you can stop VM from here

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/VMOverview.png)

Network is quite fast. Downloading image from eval center is ~ 200Mbits. I was able to see here also speeds around 500Mbits. I guess its because limited speed of source during the day in US.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/DownloadSpeeds.png)

Performance during file copy inside S2D cluster was quite impressive. Usually its around 200MB/s. On this screenshot you can see peak almost 800MB/s

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DSpeed.png)

Hydration of ws2016 lab took 81 minutes

DC and 4 s2d nodes takes 5,6 minutes

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DClusterHydration.png)

Scenario finishes in ~32 minutes

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DClusterScenarioScript.png)

Enjoy!

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DClusterScenarioScriptFinished.png)