# Scenario description

* In this scenario is 4x4 converged setup created (4 Compute nodes and 4 Storage nodes) and then scaled to 5x5.
* The scenario contains all best practices - the same as S2D HyperConverged. With some modifications it can be used for real-world deployments
* You can choose, if you want Nano Servers or Core Servers (Nano is default as it starts really fast)
* You can choose, if you want one or two storage networks
* Simulates RDMA networks (just looks like RDMA is used, but performance is not there)
* Simulates VLANs (VLAN 0 for Management, VLAN 1 for SMB)
* Simulates SET Switch with 1 Management vNIC and 2 SMB vNICs
* Deploy script finishes in ~7 minutes. Scenario script finishes in ~33 minutes = Your clusters are up and running in 45 minutes.
* With small modification you can have up to 64 nodes in compute cluster and 16 nodes in storage cluster (beefy machine required)
* [Compute Cluster and Storage Cluster Validation Reports](/Scenarios/S2D%20Converged/Screenshots/ValidationReports.zip)

# Scenario requirements

* Win10 with 16GB RAM. Lab expands to ~80GB. SSD is a must.

# Screenshots

## Compute Cluster

**Cluster Overview**

![](/Scenarios/S2D%20Converged/Screenshots/ComputeClusterOverview.png)

**Compute Cluster Roles**

![](/Scenarios/S2D%20Converged/Screenshots/ComputeClusterRoles.png)

**Compute Cluster Nodes**

![](/Scenarios/S2D%20Converged/Screenshots/ComputeClusterNodes.png)

**Compute Cluster Networks**

![](/Scenarios/S2D%20Converged/Screenshots/ComputeClusterNetworks.png)

**VM properties (notice SOFS in the path)**

![](/Scenarios/S2D%20Converged/Screenshots/VMSettings.png)

## Storage Cluster

**Storage Cluster Roles**

![](/Scenarios/S2D%20Converged/Screenshots/StorageClusterRoles.png)

**Storage Cluster Nodes**

![](/Scenarios/S2D%20Converged/Screenshots/StorageClusterNodes.png)

**Storage Cluster Networks**

![](/Scenarios/S2D%20Converged/Screenshots/StorageClusterNetworks.png)

**Storage Cluster Disks**

![](/Scenarios/S2D%20Converged/Screenshots/StorageClusterDisks.png)

**Storage Cluster Pool**

![](/Scenarios/S2D%20Converged/Screenshots/StorageClusterPool.png)

**SOFS**

![](/Scenarios/S2D%20Converged/Screenshots/SOFS.png)

![](/Scenarios/S2D%20Converged/Screenshots/SOFSVMs.png)


## Other

**LAB VMs**

![](/Scenarios/S2D%20Converged/Screenshots/VMs_PowerShell.png)

**Server Manager**

![](/Scenarios/S2D%20Converged/Screenshots/ServerManager.png)

**Deploy.ps1 result**

![](/Scenarios/S2D%20Converged/Screenshots/Deploy.ps1_result.png)

**Scenario.ps1 result**

![](/Scenarios/S2D%20Converged/Screenshots/Scenario.ps1_result.png)

**Memory consumed by VMs**

![](/Scenarios/S2D%20Converged/Screenshots/MemoryConsumed.png)
