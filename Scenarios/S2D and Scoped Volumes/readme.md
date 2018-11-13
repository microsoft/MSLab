<!-- TOC -->

- [S2D and Scoped Volumes](#s2d-and-scoped-volumes)
    - [LabConfig](#labconfig)
    - [About the lab](#about-the-lab)
    - [Prereq](#prereq)
    - [Fault domains](#fault-domains)
    - [Create volumes](#create-volumes)
    - [View scoped volumes](#view-scoped-volumes)
    - [Simulate 3 nodes failure](#simulate-3-nodes-failure)

<!-- /TOC -->

# S2D and Scoped Volumes

## LabConfig

```PowerShell
#Labconfig is same as default for Windows Server 2019. Just with 6 nodes instead of 4
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

1..6 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
#optional Win10 management machine
#$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10RS5_G2.vhdx'  ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; AddToolsVHD=$True ; DisableWCF=$True }
 
```

## About the lab

This lab introduces new feature present in Windows Server 2019 called Scoped Volumes (also known as delimited volume allocation) For more info visit [docs](https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/delimit-volume-allocation).

Run all scripts from DC

## Prereq

Run following script to configure necessary. Note: it's way simplified (no networking, no best practices, no CAU, no Hyper-V...).

```PowerShell
# LabConfig
    $Servers=1..6 | % {"S2D$_"}
    $ClusterName="S2D-Cluster"
    $ClusterIP="10.0.0.111"

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }

# Install features on servers
    Invoke-Command -computername $Servers -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell"
    }

#create cluster
    New-Cluster -Name $ClusterName -Node $Servers -StaticAddress $ClusterIP
    Start-Sleep 5
    Clear-DNSClientCache

#add file share witness
    #Create new directory
        $WitnessName=$ClusterName+"Witness"
        Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
        $accounts=@()
        $accounts+="corp\$($ClusterName)$"
        $accounts+="corp\Domain Admins"
        New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
    #Set NTFS permissions
        Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
    #Set Quorum
        Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"

#Enable S2D
    Enable-ClusterS2D -CimSession $ClusterName -Verbose -Confirm:0
 
```

## Fault domains

Let's explore fault domains first.

```PowerShell
Get-StorageFaultDomain -CimSession S2D-Cluster | ft -AutoSize
 
```

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/DefaultFaultDomains.png)

## Create volumes

So let's create deallocated volume. We can grab servers into variable and then use just 4 fault domains (FDs). Why 4 FDs? Because you need to maintain quorum after loosing nodes. Therefore just with 3 FDs, if you loose 2, your volume would go detached. While with 4 FDs, after loosing 2 FDs will volume stay online (quorum will be 2 FDs+file share witness in this case). See [this](https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/understand-quorum
) doc for understanding quorum.

Following code will display first 4 Fault Domains

```PowerShell
$FaultDomains = Get-StorageFaultDomain -Type StorageScaleUnit -CimSession S2D-Cluster | Sort FriendlyName
$FaultDomains[0,1,2,3]
 
```

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/FourFaultDomains.png)

If you would like to have random 4 fault domains, you can do it this way

```PowerShell
$FaultDomains = Get-StorageFaultDomain -Type StorageScaleUnit -CimSession S2D-Cluster| Sort FriendlyName
$FaultDomains | Get-Random -Count 4
 
```

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/RandomFourFaultDomains.png)

So let's create some volumes with 4 Fault Domains (or let's call it 4 scopes)

```PowerShell
$FaultDomains = Get-StorageFaultDomain -Type StorageScaleUnit -CimSession S2D-Cluster| Sort FriendlyName
1..10 | foreach-object {
    New-Volume -FriendlyName "MyVolume$_" -Size 100GB -StorageFaultDomainsToUse ($FaultDomains | Get-Random -Count 4) -CimSession S2D-Cluster -StoragePoolFriendlyName S2D*
}
 
```

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/VolumesCreated.png)

## View scoped volumes

And now let's take a look how is each volume occupied (credits for scripts goes to Cosmos, I just modifed it a bit)

```PowerShell
$S2DClusters=Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 

If ($S2DClusters.count -gt 1){
    $S2DClusters = $S2DClusters | Out-GridView -PassThru -Title "Please select your S2D Cluster(s)"
}

Function ConvertTo-PrettyCapacity {
    Param (
        [Parameter(
            Mandatory = $True,
            ValueFromPipeline = $True
            )
        ]
    [Int64]$Bytes,
    [Int64]$RoundTo = 0
    )
    If ($Bytes -Gt 0) {
        $Base = 1024
        $Labels = ("bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        $Order = [Math]::Floor( [Math]::Log($Bytes, $Base) )
        $Rounded = [Math]::Round($Bytes/( [Math]::Pow($Base, $Order) ), $RoundTo)
        [String]($Rounded) + " " + $Labels[$Order]
    }
    Else {
        "0"
    }
    Return
}

################################################
### Step 1: Gather Configuration Information ###
################################################

$output=@()
foreach ($S2DCluster in $S2DClusters){
    Write-Progress -Activity "Get-VirtualDiskFootprintByStorageFaultDomain" -CurrentOperation "Gathering configuration information..." -Status "Step 1/4" -PercentComplete 00

    $ErrorCannotGetClusterNode = "Cannot proceed because 'Get-ClusterNode' failed."
    $ErrorClusterNodeDown = "Cannot proceed because one or more cluster nodes is not Up."
    $ErrorCannotGetStoragePool = "Cannot proceed because 'Get-StoragePool' failed."
    $ErrorPhysicalDiskFaultDomainAwareness = "Cannot proceed because the storage pool is set to 'PhysicalDisk' fault domain awareness. This cmdlet only supports 'StorageScaleUnit', 'StorageChassis', or 'StorageRack' fault domain awareness."

    Try  {
        $GetClusterNode = $S2DCluster | Get-ClusterNode -ErrorAction Stop
    }
    Catch {
        throw $ErrorCannotGetClusterNode
    }

    If ($GetClusterNode | Where State -Ne Up) {
        throw $ErrorClusterNodeDown
    }

    Try {
        $GetStoragePool = Get-StoragePool -CimSession $S2DCluster.Name -IsPrimordial $False -ErrorAction Stop
    }
    Catch {
        throw $ErrorCannotGetStoragePool
    }

    If ($GetStoragePool.FaultDomainAwarenessDefault -Eq "PhysicalDisk") {
        throw $ErrorPhysicalDiskFaultDomainAwareness
    }

    ###########################################################
    ### Step 2: Create SfdList[] and PhysicalDiskToSfdMap{} ###
    ###########################################################

    Write-Progress -Activity "Get-VirtualDiskFootprintByStorageFaultDomain" -CurrentOperation "Analyzing physical disk information..." -Status "Step 2/4" -PercentComplete 25

    $SfdList = Get-StorageFaultDomain -Type ($GetStoragePool.FaultDomainAwarenessDefault) -CimSession $S2DCluster.Name | Sort FriendlyName # StorageScaleUnit, StorageChassis, or StorageRack

    $PhysicalDiskToSfdMap = @{} # Map of PhysicalDisk.UniqueId -> StorageFaultDomain.FriendlyName
    $SfdList | ForEach {
        $StorageFaultDomain = $_
        $_ | Get-StorageFaultDomain -Type PhysicalDisk -CimSession $S2DCluster.Name | ForEach {
            $PhysicalDiskToSfdMap[$_.UniqueId] = $StorageFaultDomain.FriendlyName
        }
    }

    ##################################################################################################
    ### Step 3: Create VirtualDisk.FriendlyName -> { StorageFaultDomain.FriendlyName -> Size } Map ###
    ##################################################################################################

    Write-Progress -Activity "Get-VirtualDiskFootprintByStorageFaultDomain" -CurrentOperation "Analyzing virtual disk information..." -Status "Step 3/4" -PercentComplete 50

    $GetVirtualDisk = Get-VirtualDisk -CimSession $S2DCluster.Name | Sort FriendlyName

    $VirtualDiskMap = @{}

    $GetVirtualDisk | ForEach {
        # Map of PhysicalDisk.UniqueId -> Size for THIS virtual disk
        $PhysicalDiskToSizeMap = @{}
        $_ | Get-PhysicalExtent -CimSession $S2DCluster.Name | ForEach {
            $PhysicalDiskToSizeMap[$_.PhysicalDiskUniqueId] += $_.Size
        }
        # Map of StorageFaultDomain.FriendlyName -> Size for THIS virtual disk
        $SfdToSizeMap = @{}
        $PhysicalDiskToSizeMap.keys | ForEach {
            $SfdToSizeMap[$PhysicalDiskToSfdMap[$_]] += $PhysicalDiskToSizeMap[$_]
        }
        # Store
        $VirtualDiskMap[$_.FriendlyName] = $SfdToSizeMap
    }

    #########################
    ### Step 4: Write-Out ###
    #########################

    Write-Progress -Activity "Get-VirtualDiskFootprintByStorageFaultDomain" -CurrentOperation "Formatting output..." -Status "Step 4/4" -PercentComplete 75

    $Output += $GetVirtualDisk | ForEach {
        $Row = [PsCustomObject]@{}

        $VirtualDiskFriendlyName = $_.FriendlyName
        $Row | Add-Member -MemberType NoteProperty "VirtualDiskFriendlyName" $VirtualDiskFriendlyName

        $TotalFootprint = $_.FootprintOnPool | ConvertTo-PrettyCapacity
        $Row | Add-Member -MemberType NoteProperty "TotalFootprint" $TotalFootprint

        $Row | Add-Member -MemberType NoteProperty "ClusterName" $S2DCluster.Name

        $SfdList | ForEach {
            $Size = $VirtualDiskMap[$VirtualDiskFriendlyName][$_.FriendlyName] | ConvertTo-PrettyCapacity
            $Row | Add-Member -MemberType NoteProperty $_.FriendlyName $Size
        }
        $Row
    }
}

# Calculate width, in characters, required to Format-Table
$RequiredWindowWidth = ("TotalFootprint").length + 1 + ("VirtualDiskFriendlyName").length + 1
$SfdList | ForEach {
    $RequiredWindowWidth += $_.FriendlyName.Length + 1
}
$ActualWindowWidth = (Get-Host).UI.RawUI.WindowSize.Width

If ($ActualWindowWidth -Lt $RequiredWindowWidth) {
    # Narrower window, Format-List
    Write-Warning "For the best experience, try making your PowerShell window at least $RequiredWindowWidth characters wide. Current width is $ActualWindowWidth characters."
    $Output | Format-List
}Else{
    # Wider window, Format-Table
    $Output | Format-Table
}
 
```

Result

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/FootPrint.png)

Looks great, so how it will look like if random 3 nodes will go down? Let's see...

## Simulate 3 nodes failure

```PowerShell
#Run from Hyper-V host to turn off random 3 VMs
Get-VM -Name WSLab2019-S2D* | Get-Random -Count 3 | Stop-VM -TurnOff
 
```

Three nodes are down

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/NodesDown.png)

And let's see what volumes survived

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/VolumesStatus.png)

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/VolumesStatusPowerShell.png)

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/VolumesStatusPowerShellReason.png)

Note: There is a 50:50 chance that volumes will go offline. For explanation take a look into [S2D and Metadata deep dive scenario](/Scenarios/S2D%20and%20Metadata%20deep%20dive/). Your systems will shut one by one (with 5 minutes pause, so Health service can re-balance metadata), you will be fine

After starting nodes again, storage jobs will kick in.

![](/Scenarios/S2D%20and%20Scoped%20Volumes/Screenshots/VolumesRepairing.png)