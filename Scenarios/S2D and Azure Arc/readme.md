<!-- TOC -->

- [S2D and Azure Arc](#s2d-and-azure-arc)
    - [About the lab](#about-the-lab)
    - [LabConfig](#labconfig)
    - [Setup Azure ARC](#setup-azure-arc)
        - [Install Management tools](#install-management-tools)
        - [Optional: install Windows Admin Center](#optional-install-windows-admin-center)
        - [Install Edge Dev](#install-edge-dev)
        - [Login to Azure](#login-to-azure)
        - [Create Azure Resources](#create-azure-resources)
        - [Install Azure Arc agent to servers](#install-azure-arc-agent-to-servers)
        - [Configure and validate Arc](#configure-and-validate-arc)
        - [Validate if agents are connected](#validate-if-agents-are-connected)
    - [Deploy Policy Definition (not effective ?yet)](#deploy-policy-definition-not-effective-yet)
        - [Explore available Policy Definitions](#explore-available-policy-definitions)
        - [Create definition that tests if Log Analytics agent is installed](#create-definition-that-tests-if-log-analytics-agent-is-installed)
        - [Cleanup from Azure if resources are no longer needed](#cleanup-from-azure-if-resources-are-no-longer-needed)

<!-- /TOC -->

# S2D and Azure Arc

## About the lab

In following lab you deploy Azure Arc for servers agents to servers using PowerShell remoting. 

You can learn more about Azure ARC at [Microsoft Docs](https://docs.microsoft.com/en-us/azure/azure-arc/servers/overview) or [Ignite Session](https://myignite.techcommunity.microsoft.com/sessions/83989?source=sessions)

You can deploy S2D Cluster, but it is not necessary as Azure Arc for Servers does not differentiate between regular server and S2D node. 

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/VMs.png)

Run all scripts from Windows 10 management machine (management) or DC. To deploy Windows 10 management machine, create parent disk first (with createparentdisk.ps1 located in Parent Disks folder) and uncomment line in Labconfig that defines management machine.

## The Lab

### Region Install management tools

This region just installs reqired management tools and Azure module. Notice, that all examples are using AZ module only (not AzureRM).

### Region Optional: install Windows Admin Center

To install Windows Admin Center including trusted certificate you can follow [Windows Admin Center and Enterprise CA scenario](/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA). In this example, Windows Admin Center is installed in Gateway mode with self-signed certificate, which is copied to local trusted root certstore.

### Region Install Edge Beta

To be able to login to Azure Portal, you may want to have modern browser (as Windows Server has IE only)

### Region Login to Azure

If running on Windows 10, Az module has to be loaded with RemoteSigned execution policy. With default (restricted) it refuses to load. So in this region, execution policy is detected, and set to remotesigned (scope process).

You will login into azure using device authentication. so just follow warning message (to open browser and login into device login page).

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/PowerShell01.png)

### Region Create Azure Resources

You will be prompted for location where Arc for servers can be created.

As result you will see Azure AD app registered and also new Resource Group

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/ResourceGroup01.png)

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/AppRegistrations01.png)

### Region Install Azure Arc agent to servers

Azure arc is downloaded and just pushed to remote machines.

### Region Configure and validate Arc on remote servers

New AzureADService principall password is generated (if not specified in $password variable). Server agents are then configured to use this password to authenticate to azure arc.

### Validate if agents are connected

Querying agents on servers will result in following output

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/ConnectedAgents01.png)

You will also see Azure Arc machines in Azure Portal

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/AzureArcResources01.png)

## Deploy Policy Definition

In following part we will create DSC out of secguide GPOs and convert it into policy definition

* https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create
* https://docs.microsoft.com/en-us/powershell/scripting/dsc/quickstarts/gpo-quickstart?view=powershell-6
* https://blogs.technet.microsoft.com/secguide/

### region Download Secguide GPOs and convert it to DSC

As result, you will have DSC folder inside downloaded SecGuide templates

Note, that CurrentUser settings are currently not supported

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/DSCFolders.png)


### region create Guestconfig policies (TBD)

![](/Scenarios/S2D%20and%20Azure%20Arc/Screenshots/PolicyDefinitions.png)

### Explore available Policy Definitions (TBD)

### Cleanup from Azure if resources are no longer needed (TBD)

```PowerShell
#remove resource group
Get-AzResourceGroup -Name "WSLabAzureArc" | Remove-AzResourceGroup -Force
#remove ServicePrincipal
Remove-AzADServicePrincipal -DisplayName Arc-for-servers -Force
Remove-AzADApplication -DisplayName Arc-for-servers -Force
 
```