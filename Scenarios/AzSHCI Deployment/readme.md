# AzSHCI Deployment

## About the lab

Following lab simulates end-to-end deployment process (OS Configuration, Cluster Configuration, S2D Config and Volumes and VMs creation). It follows best practices, so the same code can be used for production install. In this scenario you will also deploy Windows Admin Center in GW mode.

If you will follow Scenario.ps1 region by region (or section by section), you will learn about steps required to successfully configure each component. WSLab scenarios are not about automation, but it is just a different way to document and deploy Azure Stack HCI cluster. Goal is to inspire IT Professionals to use PowerShell instead of Screenshots for documentation.

Example code from Scenario.ps1

![](/Scenarios/AzSHCI%20Deployment/Screenshots/PowerShell_ISE01.png)

Lab consumes ~15GB RAM and with NestedVirt=$true it is ~22 (depending on how much RAM you will assign to VMs in Labconfig). If this amount of RAM is not available in your personal machine, you can deploy the lab in Azure https://github.com/microsoft/WSLab/tree/master/Scenarios/Running%20WSLab%20in%20Azure. WSLab scripts will be automatically downloaded into temp drive and Hyper-V will be enabled on the VM.

[![](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMicrosoft%2FWSLab%2Fdev%2FScenarios%2FRunning%2520WSLab%2520in%2520Azure%2FWSLabwin10.json)
[![](http://armviz.io/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com/Microsoft/WSLab/master/Scenarios/Running%20WSLab%20in%20Azure/WSLabwin10.json)

## Prerequisites

As WSLab creates only Windows Server images, you will need to create Azure Stack HCI parent disk (VHDx file). Navigate to "ParentDisks" folder and run "CreateParentDisk.ps1) to create parent VHD. You can provide Azure Stack HCI ISO that you can download from [here](https://azure.microsoft.com/en-us/products/azure-stack/hci/)

![](/Scenarios/AzSHCI%20Deployment/Screenshots/Explorer01.png)

## The Lab

![](/Scenarios/AzSHCI%20Deployment/Screenshots/PowerShell_ISE02.png)

You can login to the DC and then paste regions into PowerShell window as you can see on screenshot below. This will allow you to see line-by-line what is the script doing.

![](/Scenarios/AzSHCI%20Deployment/Screenshots/VMConnect01.png)

### Region LabConfig

In this region you define almost everything about your cluster, that will be deployed. This region needs to be modified if deployed in real world.

### Region Install features for management

This region is there to install management tools that are necessary to manage Azure Stack HCI and it's infrastructure remotely with PowerShell or traditional tools (such as mmc). Logic will install different features depending on where you are running it from (Server/ServerCore/Windows 10)

### Region Update All Servers

You will learn here how to update all servers using two different methods - CIM and COM. You will learn how to install all or just recommended updates (or none if selected)

### Region Configure basic settings on servers

This region demonstrates all settings that you should consider when deploying Azure Stack HCI (such as Memory Dump settings, Meltdown-Spectre mitigations, role install...)

### Region Configure networking

The script will create converged setup. It assumes you have 2 physical NICs connected to some network (so it will create vSwitch and connect the NICs with IP address prefix you configure). It will also create vNICs, configure JumboFrames and demonstrate pNICs to vNICs mapping.

### Region Create cluster

The script will validate and then create cluster. You can modify labconfig to use static IP or you can also use distributed management point.

### Region Configure Cluster networks

The script will rename cluster networks and it will configure Live Migration not to use management network.

### Region Configure Cluster-Aware-Networking

This region demonstrates how to configure CAU to automatically deploy all updates every third wednesday.

### Region Configure Fault Domains

This region demonstrates how to configure Fault Domains - both XML and PowerShell. It is useful to describe your deployment (such as location), so when health service detects failure, it can include location information in the log (this is determined from Fault Domain). It also demonstrates how to create chassis/rack resiliency (note, this is just a demonstration. Rack/Chassis resiliency is much more complex topic)

### Region Enable Cluster S2D and check Pools and Tiers

Enables S2D - you can notice verbose output. And what tiers are created.

### Region Create volumes

The script will create 4 volumes (one per node). In the example you can learn how to calculate maximum size volume to leave reserve (size of largest physical disk in node)

### Region Create some VMs

This region creates some dummy VMs (no OS is installed). Just VM created and added to cluster. If RealVMs=$true in labconfig, it will deploy VMs with VHD you provided in Labconfig region.

### Region Register Azure Stack HCI to Azure

This region will add Azure Stack HCI to Azure Arc resources.

![](/Scenarios/AzSHCI%20Deployment/Screenshots/AzurePortal.png)

### Region (optional) Install Windows Admin Center

This region will install Windows Admin Center in GW mode into WACGW server. It will also install edge. You can notice, it will also configure kerberos constrained delegation, so it will not be asked for credentials once you will add your Azure Stack HCI cluster.

![](/Scenarios/AzSHCI%20Deployment/Screenshots/Edge01.png)
