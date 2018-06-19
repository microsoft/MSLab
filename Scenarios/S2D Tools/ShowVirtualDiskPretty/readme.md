Little bit enhanced version of https://blogs.technet.microsoft.com/filecab/2016/08/29/deep-dive-volumes-in-spaces-direct/

Can query multiple clusters. Script will prompt for available clusters and you can multiselect.

```PowerShell
# Written by Cosmos Darwin, PM
# Copyright (C) 2016 Microsoft Corporation
# MIT License
# 8/2016
# Blogpost https://blogs.technet.microsoft.com/filecab/2016/08/29/deep-dive-volumes-in-spaces-direct/

Function ConvertTo-PrettyCapacity {

    Param (
        [Parameter(
            Mandatory=$True, 
            ValueFromPipeline=$True
            )
        ]
    [Int64]$Bytes,
    [Int64]$RoundTo = 0 # Default
    )

    If ($Bytes -Gt 0) {
        $Base = 1024 # To Match PowerShell
        $Labels = ("bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB") # Blame Snover
        $Order = [Math]::Floor( [Math]::Log($Bytes, $Base) )
        $Rounded = [Math]::Round($Bytes/( [Math]::Pow($Base, $Order) ), $RoundTo)
        [String]($Rounded) + $Labels[$Order]
    }
    Else {
        0
    }
    Return
}


Function ConvertTo-PrettyPercentage {

    Param (
        [Parameter(Mandatory=$True)]
            [Int64]$Numerator,
        [Parameter(Mandatory=$True)]
            [Int64]$Denominator,
        [Int64]$RoundTo = 0 # Default
    )

    If ($Denominator -Ne 0) { # Cannot Divide by Zero
        $Fraction = $Numerator/$Denominator
        $Percentage = $Fraction * 100
        $Rounded = [Math]::Round($Percentage, $RoundTo)
        [String]($Rounded) + "%"
    }
    Else {
        0
    }
    Return
}

### SCRIPT... ###
$S2DClusters=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -PassThru -Title "Please select your S2D Cluster(s)").Name

$Output = @()

# Query Cluster Shared Volumes
$Volumes = Get-StorageSubSystem -CimSession $S2DClusters -FriendlyName Cluster* | Get-Volume | Where-Object FileSystem -Eq "CSVFS"

ForEach ($Volume in $Volumes) {

    # Get MSFT_Volume Properties
    $Label = $Volume.FileSystemLabel
    $Capacity = $Volume.Size | ConvertTo-PrettyCapacity
    $Used = ConvertTo-PrettyPercentage ($Volume.Size - $Volume.SizeRemaining) $Volume.Size

    If ($Volume.FileSystemType -Like "*ReFS") {
        $Filesystem = "ReFS"
    }
    ElseIf ($Volume.FileSystemType -Like "*NTFS") {
        $Filesystem = "NTFS"
    }

    # Follow Associations
    $Partition   = $Volume    | Get-Partition
    $Disk        = $Partition | Get-Disk
    $VirtualDisk = $Disk      | Get-VirtualDisk

    # Get MSFT_VirtualDisk Properties
    $Footprint = $VirtualDisk.FootprintOnPool | ConvertTo-PrettyCapacity
    $Efficiency = ConvertTo-PrettyPercentage $VirtualDisk.Size $VirtualDisk.FootprintOnPool

    # Follow Associations
    $Tiers = $VirtualDisk | Get-StorageTier

    # Get MSFT_VirtualDisk or MSFT_StorageTier Properties...

    If ($Tiers.Length -Lt 2) {

        If ($Tiers.Length -Eq 0) {
            $ReadFrom = $VirtualDisk # No Tiers
        }
        Else {
            $ReadFrom = $Tiers[0] # First/Only Tier
        }

        If ($ReadFrom.ResiliencySettingName -Eq "Mirror") {
            # Mirror
            If ($ReadFrom.PhysicalDiskRedundancy -Eq 1) { $Resiliency = "2-Way Mirror" }
            If ($ReadFrom.PhysicalDiskRedundancy -Eq 2) { $Resiliency = "3-Way Mirror" }
            $SizeMirror = $ReadFrom.Size | ConvertTo-PrettyCapacity
            $SizeParity = [string](0)
        }
        ElseIf ($ReadFrom.ResiliencySettingName -Eq "Parity") {
            # Parity
            If ($ReadFrom.PhysicalDiskRedundancy -Eq 1) { $Resiliency = "Single Parity" }
            If ($ReadFrom.PhysicalDiskRedundancy -Eq 2) { $Resiliency = "Dual Parity" }
            $SizeParity = $ReadFrom.Size | ConvertTo-PrettyCapacity
            $SizeMirror = [string](0)
        }
        Else {
            Write-Host -ForegroundColor Red "What have you done?!"
        }
    }

    ElseIf ($Tiers.Length -Eq 2) { # Two Tiers

        # Mixed / Multi- / Hybrid
        $Resiliency = "Mix"

        ForEach ($Tier in $Tiers) {
            If ($Tier.ResiliencySettingName -Eq "Mirror") {
                # Mirror Tier
                $SizeMirror = $Tier.Size | ConvertTo-PrettyCapacity
                If ($Tier.PhysicalDiskRedundancy -Eq 1) { $Resiliency += " (2-Way" }
                If ($Tier.PhysicalDiskRedundancy -Eq 2) { $Resiliency += " (3-Way" }
            }
        }
        ForEach ($Tier in $Tiers) {
            If ($Tier.ResiliencySettingName -Eq "Parity") {
                # Parity Tier
                $SizeParity = $Tier.Size | ConvertTo-PrettyCapacity
                If ($Tier.PhysicalDiskRedundancy -Eq 1) { $Resiliency += " + Single)" }
                If ($Tier.PhysicalDiskRedundancy -Eq 2) { $Resiliency += " + Dual)" }
            }
        }
    }

    Else {
        Write-Host -ForegroundColor Red "What have you done?!"
    }

    $Cluster=$volume.PSComputerName
    # Pack

    $Output += [PSCustomObject]@{
        "Volume" = $Label
        "Filesystem" = $Filesystem
        "Capacity" = $Capacity
        "Used" = $Used
        "Resiliency" = $Resiliency
        "Size (Mirror)" = $SizeMirror
        "Size (Parity)" = $SizeParity
        "Footprint" = $Footprint
        "Efficiency" = $Efficiency
        "Cluster" = $Cluster
    }
}

$Output | Sort-Object Efficiency, Volume | Format-Table
 
```