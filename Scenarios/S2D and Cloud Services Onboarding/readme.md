<!-- TOC -->

- [S2D and Cloud Services Onboarding](#s2d-and-cloud-services-onboarding)
    - [About the lab](#about-the-lab)
    - [Lab Resources](#lab-resources)
    - [The Lab](#the-lab)
        - [Region Prereqs](#region-prereqs)
        - [Region Install Edge Beta](#region-install-edge-beta)
        - [Region (optional) Install Windows Admin Center in a GW Mode](#region-optional-install-windows-admin-center-in-a-gw-mode)
        - [Region Connect to Azure and create Log Analytics workspace if needed](#region-connect-to-azure-and-create-log-analytics-workspace-if-needed)
        - [Region setup Log Analytics Gateway](#region-setup-log-analytics-gateway)
        - [Region deploy a Windows Hybrid Runbook Worker](#region-deploy-a-windows-hybrid-runbook-worker)
        - [Region configure Hybrid Runbook Worker Addresses and Azure Automation Agent Service URL on Log Analytics Gateway](#region-configure-hybrid-runbook-worker-addresses-and-azure-automation-agent-service-url-on-log-analytics-gateway)
        - [Region download and deploy MMA Agent to S2D cluster nodes](#region-download-and-deploy-mma-agent-to-s2d-cluster-nodes)
        - [Region download and install dependency agent (for service map solution)](#region-download-and-install-dependency-agent-for-service-map-solution)
    - [Result](#result)

<!-- /TOC -->

# S2D and Cloud Services Onboarding

## About the lab

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/VMs.png)

This lab will help onboarding multiple servers to cloud services (such as Azure Monitor, Azure Security Center and Azure Update Management) at scale. This lab also demonstrates how to setup Azure Log Analytics Gateway and how to configure Hybrid Runtime Worker and Microsoft Monitoring Agents to communicate using Gateway.

Optionally, you can deploy [S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged) just to have some cluster to play with. Not exactly needed as servers without any role or feature are just fine.

Run all code from DC or Management machine (win10). Run code region by region to understand what happens.

## Lab Resources

[Hybrid Runbook Worker Overview](https://docs.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker)

[Log Analytics Gateway](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/gateway#install-the-log-analytics-gateway-using-the-command-line)

## The Lab

### Region Prereqs

This region just installs reqired management tools and Azure module. Notice, that all examples are using AZ module only (not AzureRM).

### Region Install Edge Beta

If running all code from DC, it's convenient to have HTML5 browser to be able to use it with Windows Admin Center and Azure Portal

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/EdgeBeta.png)

### Region (optional) Install Windows Admin Center in a GW Mode

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC01.png)

You can also connect Windows Admin Center to Azure

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC02.png)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC03.png)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC04.png)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC05.png)

The script will also configure Kerberos delegation, so you will not be prompted for credentials twice.

### Region Connect to Azure and create Log Analytics workspace if needed

The script will connect you to Azure (notice yellow text that tells you to go to browser nad insert code)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/PowerShell01.png)

Once you are authenticated, it will either let you select workspace (if exists) or will create new under WSLabWinAnalytics resource group.

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/Portal01.png)

### Region setup Log Analytics Gateway

In this region will script install Azure Log Analytics Gateway and Microsoft Monitoring Agent to LAGateway01. Microsoft Monitoring Agent is a prerequisite for Azure LAG.

### Region deploy a Windows Hybrid Runbook Worker

This step will first add "Security","Updates","LogManagement","AlertManagement","AzureAutomation","ServiceMap","InfrastructureInsights" solutions to Log Analytics workspace.

It will also add Automation Account and link it to workspace to be able to use Updates solution

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/Portal02.png)

Script will also install MMA agent and use LAGateway01 as a proxy.

Last step is to register hybrid runbook worker (just telling MMA agent that this machine is hybrid worker)

### Region configure Hybrid Runbook Worker Addresses and Azure Automation Agent Service URL on Log Analytics Gateway

This step is required to add addresses that Azure Log Analytics will proxy. Othwerise you will see errors in log.

Error on LAGateway

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/Logs01.png)

Error on MMAAgent on Hybrid Runbook Worker

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/Logs02.png)

### Region download and deploy MMA Agent to S2D cluster nodes

Just pushes and installs MMA agent configured to use LAGateway01 as proxy.

### Region download and install dependency agent (for service map solution)

Just pushes and installs dependency agent to all machines

## Result

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/Portal03.png)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/Portal04.png)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC06.png)

![](/Scenarios/S2D%20and%20Cloud%20Services%20Onboarding/Screenshots/WAC07.png)






