# Cluster and Storage Spaces Direct configuration

## Prerequisites

To complete following steps it is necessary, that servers are [domain joined](\02-os-deployment.md), [necessary features are installed](\03-os-configuration) and [network is correctly configured](\04-network-configuration)

## Validate cluster

Following script will validate cluster

```powershell
$Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
#validate cluster
Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
 
```

On every node is validation report generated under c:\Windows\Cluster\Reports (you can browse it by navigating \\azshci1\c$\Windows\Cluster\Reports from management machine)

[Sample Validation Report](05-Cluster-and-Storage-Spaces-Direct/media/validation_report.htm)

## Create cluster

There are several possible ways to create Cluster. With or without static IP address (where Cluster Name Object has its own IP) or using Distributed Network Name (DNN)

### Configure

```powershell
    #Using DHCP
    $ClusterName="AzSHCI-Clus"
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
    New-Cluster -Name $ClusterName -Node $servers

    #or using static IP
    <#
    $ClusterName="AzSHCI-Clus"
    $ClusterIP="10.0.0.101"
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
    New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
    #>

    #or using DNN
    <#
    $ClusterName="AzSHCI-Clus"
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
    New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType Distributed
    #>
 
```

### Validate

```powershell
$ClusterName="AzSHCI-Clus"
#Get Cluster ManagementPointNetworkType
Get-Cluster -Name $ClusterName | Select-Object Name,AdministrativeAccessPoint
#Get Cluster IP Address
Get-ClusterResource -Cluster $ClusterName -Name "Cluster IP Address" | Get-ClusterParameter
 
```

![](05-Cluster-and-Storage-Spaces/media/PowerShell01.png)