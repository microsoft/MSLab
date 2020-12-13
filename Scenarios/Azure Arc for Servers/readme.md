# Azure Arc for Servers

## About the lab

Following lab will demonstrate how to onboard onprem infrastructure to Azure Arc for Servers. It will also demonstrate how to install monitoring extension, validate updates and also will demonstrate how to distribute certificates using Key Vault extension.

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/HVManager01.png)

## The Lab

You can login to the DC and then paste regions into PowerShell window as you can see on screenshot below. This will allow you to see line-by-line what is the script doing.

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/VMConnect01.png)

### Region Prerequisites

Will install Az modules and log in into Azure

### Region Create Azure Resources

Will register resource providers and will create Resource Group and Service Principal "Arc for Servers"

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge01.png)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge02.png)

### Region Install Azure Arc to servers

This region will download agent from internet and will push and install agents to servers

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/PowerShell01.png)

### Region Configure and Validate Arc on remote servers

This region will register agents to Azure. It will create secret for Azure Service Principal and using this password, it will onboard it to Azure.

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/PowerShell02.png)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge03.png)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/PowerShell03.png)

### Region Create Log Analytics Workspace

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge04.png)

### Region Add Automation Account

Will add automation account and will register it to Log Analytics Workspace

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge05.png)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge06.png)

### Region Add Monitoring extension and Dependency Agent extension

This region will push Monitoring agent and dependency agent to just one server. To onboard servers at scale, you should create a policy and remediation action to install agent (TBD)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge07.png)

### Region add Key Vault Extension

In this region will be Key Vault created and permissions assigned to selected user. It will then generate self-signed certificate and distribute to Server1 using extension.

Notice, that permissions (access policies) on secret were configured

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge08.png)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge09.png)

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/Edge10.png)

### Region Validate Deployed Cert

As you can see, certificate was successfully distributed to onprem machine

![](/Scenarios/Azure%20Arc%20for%20Servers/Screenshots/PowerShell04.png)