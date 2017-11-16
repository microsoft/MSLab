# Server Insider lab 17035

## Howto
To create Insider lab, hydrate regular 2016 lab (to have dc), download insider VHD and add it to parent disks. Following labconfig will hydrate 4 s2d nodes with VHD from insider and also machine, where you will paste script (as you need to have RS4 RSAT that was not provided this time).

You can create Win10 VHD with script provided in tools folder (please download latest prereq from dev as I just modified it, that if you hit cancel when asked for MSU, it will continue)

## LabConfig

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Windows_InsiderPreview_Server_VHDX_17035.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }} 
$LabConfig.VMs += @{ VMName = 'PasteScriptsHere' ; Configuration = 'Simple' ; ParentVHD = 'Windows_InsiderPreview_Server_VHDX_17035.vhdx'; MemoryStartupBytes= 1GB }
$LabConfig.VMs += @{ VMName = 'Honolulu' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
````

Deployment result

![](/Insider/Screenshots/17035with14393DC.png)

Continue with [S2D scenario](https://github.com/Microsoft/ws2016lab/tree/master/Scenarios/S2D%20Hyperconverged). To PowerShell in new window in server core, type "Start PowerShell" and paste script there. After finish, you can install Honolulu into Windows 10 machine to manage HyperConverged cluster.

Virtual disk will fail to create as there are different tiers in 17035.

![](/Insider/Screenshots/17035Tiers.png)

Run following command to create volumes and VMs

````PowerShell
#Create Volumes
    1..$NumberOfDisks | ForEach-Object {
        New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName Mirror$_ -FileSystem CSVFS_ReFS -StorageTierFriendlyNames MirrorOnHDD -StorageTierSizes 2TB -CimSession $ClusterName
    }

#Rename Volumes
    Get-ClusterSharedVolume -Cluster $ClusterName | % {
        $volumepath=$_.sharedvolumeinfo.friendlyvolumename
        $newname=$_.name.Substring(22,$_.name.Length-23)
        Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
    } 

#Create 3 VMs on each volume
    $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
    foreach ($CSV in $CSVs){
        $CSV=$CSV.Substring(22)
        $CSV=$CSV.TrimEnd(")")
        1..3 | ForEach-Object {
            $VMName="TestVM$($CSV)_$_"
            Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterName).name[0] -ArgumentList $CSV,$VMName -ScriptBlock {
                param($CSV,$VMName);
                New-VM -Name $VMName -NewVHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -NewVHDSizeBytes 32GB -SwitchName SETSwitch -Generation 2 -Path "c:\ClusterStorage\$CSV\"
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
        }
    }
 
````

## Result

![](/Insider/Screenshots/17035Honolulu.png)

## Issues

### Hydration fails

![](/Insider/Screenshots/17035HydrationFail.png)
