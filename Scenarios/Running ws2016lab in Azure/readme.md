<!-- TOC -->

- [Overview](#overview)
- [Creating VM with PowerShell](#creating-vm-with-powershell)
- [Creating VM with JSON in UI](#creating-vm-with-json-in-ui)
    - [Windows Server 2016](#windows-server-2016)
    - [Windows 10 1709](#windows-10-1709)
- [Creating VM with JSON and PowerShell](#creating-vm-with-json-and-powershell)
    - [Windows Server 2016](#windows-server-2016-1)
    - [Windows 10 1709](#windows-10-1709-1)
- [Cleanup the VM and resources](#cleanup-the-vm-and-resources)
    - [Windows Server 2016](#windows-server-2016-2)
    - [Windows 10 1709](#windows-10-1709-2)
- [Creating VM Manually](#creating-vm-manually)
    - [Adding premium disk (bit pricey)](#adding-premium-disk-bit-pricey)
- [Overall experience](#overall-experience)

<!-- /TOC -->

# Overview

I was always wondering how fast will be Azure VM to host ws2016lab since we [announced](https://azure.microsoft.com/en-us/blog/nested-virtualization-in-azure/) availability of nested virtualization in Azure. Thanks to @DaveKawula tweet I decided to give it a try as i have MSDN subscription with ~130eur credit/month

You can find here several options on how to create a VM in Azure that is capable to run ws2016lab. I learned something new, I hope you will too. It will configure Hyper-V roles and download and extract scripts to d:\ drive.

**Note:** I recommend reverse engineering [JSON](/Scenarios/Running%20ws2016lab%20in%20Azure/ws2016lab.json) as you can learn how to configure VMs in Azure.

I also added Windows 10 1709 machine, as nested 1709 and insider builds does not work well on Windows Server 2016. You will see provisioning errors, but all works well (looks like it does not evaluate state correctly after enabling Hyper-V with DISM PowerShell module)

# Creating VM with PowerShell

To create VM with PowerShell, run following command.

**Note:** PowerShell DSC in this case does not run, therefore you need to install Hyper-V and download scripts manually.

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
# Creating VM with JSON in UI

Or you can just click button and deploy it into your portal

## Windows Server 2016
[![](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMicrosoft%2Fws2016lab%2Fdev%2FScenarios%2FRunning%2520ws2016lab%2520in%2520Azure%2Fws2016lab.json)
[![](http://armviz.io/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com/Microsoft/ws2016lab/dev/Scenarios/Running%20ws2016lab%20in%20Azure/ws2016lab.json)


## Windows 10 1709

**Note:** for some reason deployment fails, but everything is configured OK. Bug created [here](https://social.msdn.microsoft.com/Forums/en-US/1d5061fa-5135-4ec1-a8dc-32d63f6d261d/dsc-adding-hyperv-role-failing-on-windows-10?forum=WAVirtualMachinesforWindows)

[![](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMicrosoft%2Fws2016lab%2Fdev%2FScenarios%2FRunning%2520ws2016lab%2520in%2520Azure%2Fws2016labwin10.json)
[![](http://armviz.io/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com/Microsoft/ws2016lab/dev/Scenarios/Running%20ws2016lab%20in%20Azure/ws2016labwin10.json)

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CustomizedTemplate.png)

# Creating VM with JSON and PowerShell

Or you can create your VM using PowerShell

## Windows Server 2016
````PowerShell
#download Azure module if not installed
if (!(get-module -Name AzureRM*)){
    Install-Module -Name AzureRM
}

#login to your azure account
Login-AzureRmAccount

#Deploy VM to Azure using Template
    New-AzureRmResourceGroup -Name "ws2016labRG" -Location "West Europe"
    $TemplateUri="https://raw.githubusercontent.com/Microsoft/ws2016lab/master/Scenarios/Running%20ws2016lab%20in%20Azure/ws2016lab.json"
    New-AzureRmResourceGroupDeployment -Name ws2016lab -ResourceGroupName ws2016labRG -TemplateUri $TemplateUri -Verbose

#connect to VM using RDP
    mstsc /v:((Get-AzureRmPublicIpAddress -ResourceGroupName ws2016labRG).IpAddress)
 
````

## Windows 10 1709
````PowerShell
#download Azure module if not installed
if (!(get-module -Name AzureRM*)){
    Install-Module -Name AzureRM
}

#login to your azure account
Login-AzureRmAccount

#Deploy VM to Azure using Template
    New-AzureRmResourceGroup -Name "ws2016labwin10RG" -Location "West Europe"
    $TemplateUri="https://raw.githubusercontent.com/Microsoft/ws2016lab/master/Scenarios/Running%20ws2016lab%20in%20Azure/ws2016labwin10.json"
    New-AzureRmResourceGroupDeployment -Name ws2016labwin10 -ResourceGroupName ws2016labwin10RG -TemplateUri $TemplateUri -Verbose
#connect to VM using RDP
    mstsc /v:((Get-AzureRmPublicIpAddress -ResourceGroupName ws2016labwin10RG).IpAddress)
 
````

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/TemplatePowerShellDeployment.png)

# Cleanup the VM and resources

To cleanup your resources, you can run following command.

## Windows Server 2016
````PowerShell
Get-AzurermVM -Name ws2016lab -ResourceGroupName ws2016labRG | Remove-AzureRmVM -verbose #-Force
Get-AzureRmResource | where name -like ws2016* | Remove-AzureRmResource -verbose #-Force 
Get-AzureRmResourceGroup | where resourcegroupname -eq ws2016labRG | Remove-AzureRmResourceGroup -Verbose #-Force
 
````

## Windows 10 1709
````PowerShell
Get-AzurermVM -Name ws2016labwin10 -ResourceGroupName ws2016labwin10RG | Remove-AzureRmVM -verbose #-Force
Get-AzureRmResource | where name -like ws2016labwin10* | Remove-AzureRmResource -verbose #-Force 
Get-AzureRmResourceGroup | where resourcegroupname -eq ws2016labwin10RG | Remove-AzureRmResourceGroup -Verbose #-Force
 
````
# Creating VM Manually
To create VM, click on New and select Windows Server 2016 VM.

**Note:** this applies to Windows Server 2016 only. Win10 machine with GUI is not available in this size.

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