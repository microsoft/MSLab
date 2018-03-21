# Server Insider lab 17623

## Howto
To create Insider lab, you can reuse your already hydrated lab (DC can be reused), or hydrate all from scratch. You can use both VHD or ISO. VHD can be copied to Parent disks, and then its reused or ISO can be chosen during create parent disk phase (if not present in parent disks)

[Download location](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver)

You can create Win10 VHD with script provided in tools folder. You can then give a try to project Honolulu (just uncomment Win10 machine in labconfig and deploy honolulu there)

## Note

If hydrating from scratch, make sure you use latest scripts as DSC needed some adjustments.

known bug: **S2D fails to enable in 17623 inside VMs**

![](/Insider/enableS2Dfail.png)

**Workaround - EnableClusterS2D using following script** However if you have Rack fault domain/Chassis fault domain, it would be more complex.

````PowerShell
Enable-ClusterS2D -CimSession $ClusterName -AutoConfig:0 -Confirm:$false -Verbose -SkipEligibilityChecks

Invoke-Command -ComputerName $ClusterName  -ScriptBlock {
    #Create Pool
        $phydisks = Get-StorageSubSystem -FriendlyName "*$using:ClusterName" | Get-PhysicalDisk -CanPool $true
        $pool=New-StoragePool -FriendlyName  "S2D on $using:ClusterName" -PhysicalDisks $phydisks -StorageSubSystemFriendlyName "*$using:ClusterName"
    #Set mediatype to HDD
        $pool | get-physicaldisk | Set-PhysicalDisk -MediaType HDD
    #Create tiers
        if (($using:Servers).count -eq 2){
            New-StorageTier -FriendlyName Capacity    -MediaType HDD -ResiliencySettingName Mirror -StoragePoolFriendlyName "S2D on $using:ClusterName" -PhysicalDiskRedundancy 1
        }elseif(($using:Servers).count -eq 3){
            New-StorageTier -FriendlyName Capacity    -MediaType HDD -ResiliencySettingName Mirror -StoragePoolFriendlyName "S2D on $using:ClusterName" -PhysicalDiskRedundancy 2
        }elseif(($using:servers).count -gt 3){
            New-StorageTier -FriendlyName Capacity    -MediaType HDD -ResiliencySettingName Parity -StoragePoolFriendlyName "S2D on $using:ClusterName" -PhysicalDiskRedundancy 2
            New-StorageTier -FriendlyName Performance -MediaType HDD -ResiliencySettingName Mirror -StoragePoolFriendlyName "S2D on $using:ClusterName" -PhysicalDiskRedundancy 2
        }
}
 
````

## LabConfig for vNext LTSC preview

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016labInsider-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; CreateClientParent=$false ; ClientEdition='Enterprise'; PullServerDC=$false ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_17623.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }}
#$LabConfig.VMs += @{ VMName = 'Honolulu' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }

$LabConfig.ServerVHDs += @{
    Edition="DataCenter" 
    VHDName="Win2019_17623.vhdx"
    Size=60GB
}
$LabConfig.ServerVHDs += @{
    Edition="DataCenterCore" 
    VHDName="Win2019Core_17623.vhdx"
    Size=30GB
}
 
````

## LabConfig for SAC (if you reuse DC from 14393 and just copy VHD to parent disks)

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Windows_InsiderPreview_Server_VHDX_17623.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB }}
$LabConfig.VMs += @{ VMName = 'PasteScriptsHere' ; Configuration = 'Simple' ; ParentVHD = 'Windows_InsiderPreview_Server_VHDX_17623.vhdx'; MemoryStartupBytes= 1GB ;MemoryMinimumBytes=1GB }
$LabConfig.VMs += @{ VMName = 'Honolulu' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
````

## Result

![](/Insider/cluadmin.png)