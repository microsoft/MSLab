Simple script to list all s2d cluster nodes and it's disks.

```PowerShell
$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster").Name

$nodes=Get-StorageSubSystem -CimSession $clusterName -FriendlyName Clus* | Get-StorageNode
$disks=foreach ($Node in $nodes){$node|Get-PhysicalDisk -PhysicallyConnected -CimSession $node.Name}

$disks | select PSComputerName,friendlyname,SerialNumber,healthstatus,OperationalStatus,CanPool,physicallocation,slotnumber | Out-GridView
#or all
$disks | select * | ogv
 
```

Alternatively you can add node name into Physical disk description

```PowerShell
$ClusterName="S2D-Cluster"
$StorageNodes=Get-StorageSubSystem -CimSession $clusterName -FriendlyName Clus* | Get-StorageNode
#add owner node name to description
foreach ($StorageNode in $StorageNodes){$StorageNode | Get-PhysicalDisk -PhysicallyConnected -CimSession $StorageNode.Name | Set-PhysicalDisk -Description $StorageNode.Name -CimSession $StorageNode.Name}
#display disks
Get-PhysicalDisk -CimSession $ClusterName | format-table DeviceId,FriendlyName,SerialNumber,MediaType,Description
 
```
