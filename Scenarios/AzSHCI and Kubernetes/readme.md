# AzSHCI and Kubernetes

## About the lab

In following lab you will deploy Azure Kubernetes Service into Azure Stack HCI cluster. There are currently two options. From PowerShell and from Windows Admin Center. Windows Admin Center can be installed on Windows 10 or on Windows Server in Gateway mode.

Note: there is a known issue, that deploying Azure Kubernetes Server from Windows Admin Center in Gateway mode does not work (importing extension succeeds, but then it is not able to display it).

## Docs

https://techcommunity.microsoft.com/t5/azure-stack-blog/azure-kubernetes-service-on-azure-stack-hci-deliver-storage/ba-p/1703996

https://github.com/Azure/aks-hci

https://aka.ms/AKSonHCI-Docs

## LabConfig with enabled telemetry (full)

Note: please download latest [WSLab](https://aka.ms/wslab/download) as there is new VMProcessorCount value Max, that will configure maximum available LP to VMs.

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#2 nodes for AzSHCI Cluster
1..2 | ForEach-Object {$VMNames="AzSHCI" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI20H2_G2.vhdx' ; HDDNumber = 4 ; HDDSize= 4TB ; MemoryStartupBytes= 16GB; VMProcessorCount="Max" ; NestedVirt=$true}}

#Windows 10 management machine (for Windows Admin Center)
$LabConfig.VMs += @{ VMName = 'Win10'; ParentVHD = 'Win1020H1_G2.vhdx' ; AddToolsVHD = $True ; MGMTNICs=1 }

#Windows Admin Center gateway
#$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MGMTNICs=1 }
 
```

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/hvmanager01.png)

## The lab

Run all code from DC. Follow [Scenario.ps1](/Scenarios/AzSHCI%20and%20Kubernetes/Scenario.ps1). Region Windows Admin Center on Win10 you should run from Win10 virtual machine.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell_ISE01.png)

Note: (optional) there is known issue, that when installing AKS, scripts checks for available space on C: drive (instead of cluster storage). Since it needs 50GB free space, it might not be enough if you run Windows Update on servers. If you want to expand disks, run following code

```PowerShell
#run from Host to expand C: drives in VMs to 120GB
$VMs=Get-VM -VMName WSLab*azshci*
$VMs | Get-VMHardDiskDrive -ControllerLocation 0 | Resize-VHD -SizeBytes 120GB
#VM Credentials
$secpasswd = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$VMCreds = New-Object System.Management.Automation.PSCredential ("corp\LabAdmin", $secpasswd)
Foreach ($VM in $VMs){
    Invoke-Command -VMname $vm.name -Credential $VMCreds -ScriptBlock {
        $part=Get-Partition -DriveLetter c
        $sizemax=($part |Get-PartitionSupportedSize).SizeMax
        $part | Resize-Partition -Size $sizemax
    }
}
 
```

### Region Create 2 node cluster

This region will deploy minimum configuration possible to have 2 node cluster. It does not configure any sophisticated networking or spectre/meltdown mitigation etc. For real clusters follow [S2D HyperConverged Scenario](https://github.com/microsoft/WSLab/tree/master/Scenarios/S2D%20Hyperconverged)

As result, you will have 2 node cluster "AzSHCI-Cluster" with file share witness configured and with virtual switch with name "vSwitch"

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Cluadmin01.png)

### Region Register Azure Stack HCI to Azure

This step will add Azure Stack HCI to Azure as a resource. It will then enable you to create VMs as cluster resources. Otherwise AKS setup would fail.

### Region Download AKS HCI module

In this region AKS HCI module is downloaded into Downloads and expanded. Notice that there is also nupkg - Windows Admin Center extension.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Explorer01.png)

### Region setup AKS (PowerShell)

First of all is needed to copy PowerShell module to nodes as we want to execute posh module there (as there is not yet remote support)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell01.png)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Explorer02.png)

Next step is to enable credSSP as executed commands will connect to another node, therefore [double-hop issue](https://blogs.technet.microsoft.com/ashleymcglone/2016/08/30/powershell-remoting-kerberos-double-hop-solved-securely/) is introduced.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell02.png)

The next step is to run Initialize-AksHciNode. It makes sure all prerequisites are met.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell03.png)

The next step will first create volume where AKS will be stored and then run configuration.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell05.png)

As you can see on below screenshot, config was changed as per powershell above.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell06.png)

Last step is to Install-AksHCI that will deploy cluster resources and Mariner VMs. On first run it will hang here: [bug](https://github.com/Azure/aks-hci/issues/28). So hit ctrl+c and run Install-AksHCI again.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell07.png)

This step will create cluster resources and AKS VMs

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell08.png)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/DC01.png)

If all goes OK, you will see following result

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell09.png)

### Region create AKS HCI cluster

Now AKS HCI cluster will be created. With one linux node, load balancer and control plane. The script will create the smallest possible VMs (4GB RAM) so it will fit lab cluster.

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Desktop01.png)

### Region onboard AKS cluster to Azure ARC

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/PowerShell10.png)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge01.png)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge02.png)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge03.png)

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge04.png)

### Region add sample configuration to the cluster

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge05.png)

### Region Create Log Analytics workspace

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge06.png)

### Region Enable monitoring

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/Edge07.png)

### Region deploy app

![](/Scenarios/AzSHCI%20and%20Kubernetes/Screenshots/DC02.png)