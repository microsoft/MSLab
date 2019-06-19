# S2D and Tiers deep dive

<!-- TOC -->

- [S2D and Tiers deep dive](#s2d-and-tiers-deep-dive)
    - [LabConfig](#labconfig)
    - [About the lab](#about-the-lab)
        - [VMs](#vms)
        - [Memory Consumed](#memory-consumed)
    - [The Lab](#the-lab)
        - [Prereq](#prereq)
        - [Optional prereq: Install Windows Admin Center](#optional-prereq-install-windows-admin-center)
        - [Exploring tiers](#exploring-tiers)
            - [Capacity Tiers](#capacity-tiers)
            - [Performance Tiers](#performance-tiers)
            - [Mirror Tiers](#mirror-tiers)
            - [Parity Tiers](#parity-tiers)
            - [Summary Table](#summary-table)
        - [Adding missing tiers](#adding-missing-tiers)

<!-- /TOC -->

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

#Dedicated gateway for Windows Admin Center
$LabConfig.VMs += @{ VMName = 'WacGateway'; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB }

#Or Win10 Management machine
#$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win1019H1_G2.vhdx'; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }

1..2 | % {$VMNames="2T2node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..3 | % {$VMNames="2T3node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..4 | % {$VMNames="2T4node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..2 | % {$VMNames="3T2node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..3 | % {$VMNames="3T3node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
1..4 | % {$VMNames="3T4node"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 4; HDDSize= 4TB ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=512MB }}
 
```

## About the lab

Lab simulates 2Tier and 3Tier systems (actually we are not able to simuate cache in Hyper-V, so cache is just imaginary. So we have "2Tiers" and "3tiers"). Lab will demonstrate what default tiers (templates) are created in Windows Server 2019 and what are the gotchas.

All setting up mediatype is done just for lab purposes. You will never need it (and you should never use it) in real systems! Even combination of SCM and SSD where both tiers are capacity devices is very unlikely. As I said, it's here just for educational purposes.

Run all scripts from DC or Management machine.

### VMs

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/VMs.png)

### Memory Consumed

Entire lab consumes ~20GB of RAM (including 2 optional machines for Windows Admin Center)

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/VMs_Memory.png)

## The Lab

### Prereq

```PowerShell
# variables
    $Clusters=@()
    $Clusters+=@{Nodes=1..2 | % {"2T2node$_"} ; Name="2T2nodeClus" ; IP="10.0.0.112" }
    $Clusters+=@{Nodes=1..3 | % {"2T3node$_"} ; Name="2T3nodeClus" ; IP="10.0.0.113" }
    $Clusters+=@{Nodes=1..4 | % {"2T4node$_"} ; Name="2T4nodeClus" ; IP="10.0.0.114" }
    $Clusters+=@{Nodes=1..2 | % {"3T2node$_"} ; Name="3T2nodeClus" ; IP="10.0.0.115" }
    $Clusters+=@{Nodes=1..3 | % {"3T3node$_"} ; Name="3T3nodeClus" ; IP="10.0.0.116" }
    $Clusters+=@{Nodes=1..4 | % {"3T4node$_"} ; Name="3T4nodeClus" ; IP="10.0.0.117" }

# Install features for management
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
    }elseif ($WindowsInstallationType -eq "Client"){
        #Install RSAT tools
        $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        foreach ($Capability in $Capabilities){
            Add-WindowsCapability -Name $Capability -Online
        }
    }

# Install features on servers
    Invoke-Command -computername $Clusters.nodes -ScriptBlock {
        Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell","RSAT-Clustering-PowerShell" #RSAT is needed for Windows Admin Center
    }

#restart all servers since failover clustering in 2019 requires reboot
    Restart-Computer -ComputerName $Clusters.nodes -Protocol WSMan -Wait -For PowerShell

#create clusters
    foreach ($Cluster in $Clusters){
        New-Cluster -Name $cluster.Name -Node $Cluster.Nodes -StaticAddress $cluster.IP
        Start-Sleep 5
        Clear-DNSClientCache
    }

<#
#add file share witness
     foreach ($Cluster in $Clusters){
        $ClusterName=$Cluster.Name
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
     }
#>

#Enable S2D and configure mediatype to simulate 3 tier system with SCM (all 800GB disks are SCM, all 4T are SSDs). It's unreal! it just demonstrates SCM Names
   foreach ($cluster in $Clusters.Name){
        Enable-ClusterS2D -CimSession $Cluster -Verbose -Confirm:0
        if ($Cluster -like "3T*"){
            invoke-command -computername $Cluster -scriptblock {
                get-physicaldisk | where size -eq 800GB | set-physicaldisk -mediatype SCM
                get-physicaldisk | where size -eq 4TB | set-physicaldisk -mediatype SSD
            }
        }
    }

<#or with just SSDs (all 800GB disks)
    foreach ($cluster in $Clusters.Name){
        Enable-ClusterS2D -CimSession $Cluster -Verbose -Confirm:0
        if ($Cluster -like "3T*"){
            invoke-command -computername $Cluster -scriptblock {
                get-physicaldisk | where size -eq 800GB | set-physicaldisk -mediatype SSD
            }
        }
    }
#>
 
```

### Optional prereq: Install Windows Admin Center

Gateway mode install will add self signed certificate (I did not want to include complexity of generating certificate in Certification Authority as already demonstrated in another Scenario)

If running from Windows 10, it will install Windows Admin Center there.

```PowerShell
#region optional setup WACGateway
#Download Edge Dev
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2069324&Channel=Dev&language=en-us&Consent=1" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe"
#Install Edge Dev
Start-Process -FilePath "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe" -Wait

#Download and install Windows Admin Center
Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

#Install Windows Admin Center to WacGateway
$GatewayServerName="WacGateway"
#increase MaxEnvelopeSize to transfer msi
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 2048}
#Create PS Session and copy install files to remote server
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v waclog.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
}
#Configure kerberos delegation so WAC will not ask for credentials
$gateway = "WacGateway" # Machine where Windows Admin Center is installed
$nodes = Get-ADComputer -Filter * -SearchBase "ou=workshop,DC=corp,dc=contoso,DC=com"
$gatewayObject = Get-ADComputer -Identity $gateway
foreach ($node in $nodes){
    Set-ADComputer -Identity $node -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
 
#endregion

#region Setup WAC on Management PC (if running code from Win10)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Client"){
        $ProgressPreference='SilentlyContinue' #for faster download
        #Download Windows Admin Center to downloads
            Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

        #Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
            Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

        #Open Windows Admin Center
            Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
    }
#endregion
 
```

Notice, that Certificate is not trusted

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/WAC_Cert01.png)

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/WAC_Cert02.png)

To import S2D clusters to Windows Admin Center, you can generate text file like in following example

```PowerShell
#Generate text file for S2D clusters import to
(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1).Name | Out-File c:\s2dclusters.txt
 
```

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Import_Clusters01.png)

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Import_Clusters02.png)

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Import_Clusters03.png)

### Exploring tiers

```PowerShell
#Display Tiers on 2tier 2node cluster
Get-StorageTier -CimSession 2T2NodeClus
 
```

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers01.png)

As you can see, it's not so descriptive. Let's use format-table to display more properties

```PowerShell
Get-StorageTier -CimSession 2T2NodeClus |ft FriendlyName,MediaType,ResiliencySettingName,NumberOfDataCopies,PhysicalDiskRedundancy,FaultDomainAwareness,ColumnIsolation,NumberOfGroups,NumberOfColumns
 
```

OK, so on 2Tiers 2Node cluster where we do have HDDs only, 2 tiers were created. One is Capacity (this is here for compatibility with Windows Server 2016 naming) and MirrorOnHDD (new naming in Windows Server 2019). Notice NumberOfDataCopies (2way mirror) and PhysicalDiskRedundancy (ability to tolerate 1 fault). Fault domain awareness means, that copies are distributed across StorageScaleUnit (because it can be server and attached local jbod with storage, not just server). Columns are automatically calculated (depending how many nodes/disks in each node you have, number will be assigned once virtual disk is created). Number of groups is there for Parity.

You can also notice, that Tiers are created after Enable-ClusterS2D was run. It dynamically created only those tiers, that matches the mediatype present in systems.

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers02.png)

Let's take a look at all clusters

```PowerShell
$Clusters=(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1).Name
Get-StorageTier -CimSession $Clusters | Sort-Object PSComputerName |ft PSComputerName,FriendlyName,MediaType,ResiliencySettingName,NumberOfDataCopies,PhysicalDiskRedundancy,FaultDomainAwareness,ColumnIsolation,NumberOfGroups,NumberOfColumns
 
```

This table might be too much to process, but let's take a look. In 3Tier sysem I'm faking SCM to demonstrate all possible tiers. As result, we have all combinations in one view.

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers03.png)

Let's display those "2016" tiers first.

#### Capacity Tiers

```PowerShell
$Clusters=(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1).Name
Get-StorageTier -CimSession $Clusters |where friendlyname -eq capacity |Sort-Object PSComputerName |ft PSComputerName,FriendlyName,MediaType,ResiliencySettingName,NumberOfDataCopies,PhysicalDiskRedundancy,FaultDomainAwareness,ColumnIsolation,NumberOfGroups,NumberOfColumns
 
```

As you can see, on 2 and 3 node clusters are Capacity tiers Mirror, but in 4 node cluster it's parity. This is reason, why it was very confusing in 2016.

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers04.png)

#### Performance Tiers

It's again confusing. Performance tier in 2 tier systems is in 4 node cluster only. In 3 tier systems it's the faster one, also available on 2 and 3 node systems

```PowerShell
$Clusters=(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1).Name
Get-StorageTier -CimSession $Clusters |where friendlyname -eq performance |Sort-Object PSComputerName |ft PSComputerName,FriendlyName,MediaType,ResiliencySettingName,NumberOfDataCopies,PhysicalDiskRedundancy,FaultDomainAwareness,ColumnIsolation,NumberOfGroups,NumberOfColumns
 
```

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers05.png)

#### Mirror Tiers

As you can see, new 2019 tiers are much more easy to understand. You can find there MirrorOnHDD, MirrorOnSSD and MirrorOnSCM. In 2 node systems is different NumberOfCopies and PhysicalDiskRedundancy.

```PowerShell
$Clusters=(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1).Name
Get-StorageTier -CimSession $Clusters |where friendlyname -like mirror* |Sort-Object PSComputerName |ft PSComputerName,FriendlyName,MediaType,ResiliencySettingName,NumberOfDataCopies,PhysicalDiskRedundancy,FaultDomainAwareness,ColumnIsolation,NumberOfGroups,NumberOfColumns
 
```

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers06.png)

#### Parity Tiers

Parity tiers are created only on 4+ nodes systems. THere is one exception - Nested resiliency for 2 node systems. But it's not (yet) created automatically.

```PowerShell
$Clusters=(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1).Name
Get-StorageTier -CimSession $Clusters |where friendlyname -like parity* |Sort-Object PSComputerName |ft PSComputerName,FriendlyName,MediaType,ResiliencySettingName,NumberOfDataCopies,PhysicalDiskRedundancy,FaultDomainAwareness,ColumnIsolation,NumberOfGroups,NumberOfColumns
 
```

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers07.png)

#### Summary Table

Following tables are summarizing all possible tiers that are/can be created in Windows Server 2019 (without the confusing ones)

**NumberOfNodes: 2**

| FriendlyName      | MediaType | ResiliencySettingName | NumberOfDataCopies | PhysicalDiskRedundancy | NumberOfGroups | FaultDomainAwareness | ColumnIsolation | Note                    |
| ----------------- | :-------: | :-------------------: | :----------------: | :--------------------: |:--------------:| :------------------: | :-------------: | :---------------------: |
| MirrorOnHDD       | HDD       | Mirror                | 2                  | 1                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| MirrorOnSSD       | SSD       | Mirror                | 2                  | 1                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| MirrorOnSCM       | SCM       | Mirror                | 2                  | 1                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| NestedMirrorOnHDD | HDD       | Mirror                | 4                  | 3                      | 1              | StorageScaleUnit     | PhysicalDisk    | manual, 2019 only       |
| NestedMirrorOnSSD | SSD       | Mirror                | 4                  | 3                      | 1              | StorageScaleUnit     | PhysicalDisk    | manual, 2019 only       |
| NestedMirrorOnSCM | SCM       | Mirror                | 4                  | 3                      | 1              | StorageScaleUnit     | PhysicalDisk    | manual, 2019 only       |
| NestedParityOnHDD | HDD       | Parity                | 2                  | 1                      | 1              | StorageScaleUnit     | PhysicalDisk    | manual, 2019 only       |
| NestedParityOnSSD | SSD       | Parity                | 2                  | 1                      | 1              | StorageScaleUnit     | PhysicalDisk    | manual, 2019 only       |
| NestedParityOnSCM | SCM       | Parity                | 2                  | 1                      | 1              | StorageScaleUnit     | PhysicalDisk    | manual, 2019 only       |

**NumberOfNodes: 3**

| FriendlyName      | MediaType | ResiliencySettingName | NumberOfDataCopies | PhysicalDiskRedundancy | NumberOfGroups | FaultDomainAwareness | ColumnIsolation | Note                    |
| ----------------- | :-------: | :-------------------: | :----------------: | :--------------------: |:--------------:| :------------------: | :-------------: | :---------------------: |
| MirrorOnHDD       | HDD       | Mirror                | 3                  | 2                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| MirrorOnSSD       | SSD       | Mirror                | 3                  | 2                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| MirrorOnSCM       | SCM       | Mirror                | 3                  | 2                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |

**NumberOfNodes: 4+**

| FriendlyName      | MediaType | ResiliencySettingName | NumberOfDataCopies | PhysicalDiskRedundancy | NumberOfGroups | FaultDomainAwareness | ColumnIsolation | Note                    |
| ----------------- | :-------: | :-------------------: | :----------------: | :--------------------: |:--------------:| :------------------: | :-------------: | :---------------------: |
| MirrorOnHDD       | HDD       | Mirror                | 3                  | 2                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| MirrorOnSSD       | SSD       | Mirror                | 3                  | 2                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| MirrorOnSCM       | SCM       | Mirror                | 3                  | 2                      | 1              | StorageScaleUnit     | PhysicalDisk    | auto created in 2019    |
| ParityOnHDD       | HDD       | Parity                | 1                  | 2                      | Auto           | StorageScaleUnit     | StorageScaleUnit| auto created in 2019    |
| ParityOnSSD       | SSD       | Parity                | 1                  | 2                      | Auto           | StorageScaleUnit     | StorageScaleUnit| auto created in 2019    |
| ParityOnSCM       | SCM       | Parity                | 1                  | 2                      | Auto           | StorageScaleUnit     | StorageScaleUnit| auto created in 2019    |


### Adding missing tiers

What if you like new naming and you have 2016 systems? Or you have 2 node system and you are missing nested resiliency tiers. Let's fix it :)

```PowerShell
#Select clusters to fix tiers
$ClusterNames=(Get-Cluster -Domain $env:userdomain | where S2DEnabled -eq 1 | Out-GridView -OutputMode Multiple -Title "Select Clusters to Check on tiers").Name

foreach ($ClusterName in $ClusterNames){
    $StorageTiers=Get-StorageTier -CimSession $ClusterName
    $NumberOfNodes=(Get-ClusterNode -Cluster $ClusterName).Count
    $MediaTypes=(Get-PhysicalDisk -CimSession $ClusterName |where mediatype -ne Unspecified | where usage -ne Journal).MediaType | Select-Object -Unique
    $ClusterFunctionalLevel=(Get-Cluster -Name $ClusterName).ClusterFunctionalLevel

    Foreach ($MediaType in $MediaTypes){
        if ($NumberOfNodes -eq 2) {
            #Create Mirror Tiers
                if (-not ($StorageTiers | where FriendlyName -eq "MirrorOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MirrorOn$MediaType" -MediaType $MediaType -ResiliencySettingName Mirror -NumberOfDataCopies 2
                }

            if ($ClusterFunctionalLevel -ge 10){
                #Create NestedMirror Tiers
                    if (-not ($StorageTiers | where FriendlyName -eq "NestedMirrorOn$MediaType")){
                        New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "NestedMirrorOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Mirror -NumberOfDataCopies 4
                    }
                #Create NestedParity Tiers
                    if (-not ($StorageTiers | where FriendlyName -eq "NestedParityOn$MediaType")){
                        New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "NestedParityOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Parity -NumberOfDataCopies 2 -PhysicalDiskRedundancy 1 -NumberOfGroups 1 -ColumnIsolation PhysicalDisk
                    }
            }
        }elseif($NumberOfNodes -eq 3){
            #Create Mirror Tiers
                if (-not ($StorageTiers | where FriendlyName -eq "MirrorOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MirrorOn$MediaType" -MediaType $MediaType -ResiliencySettingName Mirror -NumberOfDataCopies 3
                }
        }elseif($NumberOfNodes -ge 4){
            #Create Mirror Tiers
                if (-not ($StorageTiers | where FriendlyName -eq "MirrorOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MirrorOn$MediaType" -MediaType $MediaType -ResiliencySettingName Mirror -NumberOfDataCopies 3
                }
            #Create Parity Tiers
                if (-not ($StorageTiers | where FriendlyName -eq "ParityOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "ParityOn$MediaType" -MediaType $MediaType -ResiliencySettingName Parity
                }
        }
    }
}

```

Result of above script (after all tiers were wiped with Get-StorageTier | Remove-StorageTier)

![](/Scenarios/S2D%20and%20Tiers%20deep%20dive/Screenshots/Tiers08.png)