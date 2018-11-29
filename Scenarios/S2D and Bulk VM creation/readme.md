## LabConfig Windows Server 2019

```PowerShell
#Labconfig is same as default for Windows Server 2019, just with nested virtualization and 4GB for startup memory
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true }}
 
```

## Prereq

Run following script on DC to configure necessary. Note: it's way simplified (no networking, no best practices, no CAU, no Hyper-V...).

Copy some core server VHD into tools.vhdx.

```PowerShell
# LabConfig
    $Servers=1..4 | % {"S2D$_"}
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
        Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell","Hyper-V"
    }

# restart servers
    Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell

# create vSwitch
    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

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

Note: Enable-ClusterS2D in Windows Server 2019 requires you to reach support to get steps to make it work on 2019 RTM as WSSD programme will be officially launched starting 2019.

```PowerShell
#Sample
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\SYSTEM\XYZ" -Name XYZ -value 1
}
 
```

## Create "Library" and copy your new parent disk there

```PowerShell
$ClusterName="S2D-Cluster"
$VolumeName="Library"
$ImageName="Win2019Core_G2.vhdx"

New-Volume -StoragePoolFriendlyName S2D* -FriendlyName $VolumeName -FileSystem CSVFS_ReFS -Size 100GB -ResiliencySettingName Mirror -CimSession $ClusterName

#Grab VHD and copy it to new library volume.
Copy-Item -Path "D:\$ImageName" -Destination "\\$ClusterName\ClusterStorage$\$VolumeName\"
 
```

## Create volumes for VMs

```PowerShell
$ClusterName="S2D-Cluster"
$VolumeName="VMs"
New-Volume -StoragePoolFriendlyName S2D* -FriendlyName $VolumeName -FileSystem CSVFS_ReFS -Size 1TB -ResiliencySettingName Mirror -CimSession $ClusterName
 
```

## Create some VMs now

### Variables and VMs definition

It's easiest to create some hash table that defines all VMs like following example. You can notice that it has different options as in script I'll demonstrate static IP and VLAN assignment.

```PowerShell
$ClusterName="S2D-Cluster"
$ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
$CSVPath="C:\ClusterStorage\VMs"
$LibraryPath="C:\ClusterStorage\Library"
$OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com"
$vSwitchName="SETSwitch"
$MountDir="c:\temp\MountDir" #cannot be CSV
$VMs=@()
$VMs+=@{VMName="VM01"; MemoryStartupBytes=512MB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ;ImageName="Win2019Core_G2.vhdx" }
$VMs+=@{VMName="VM02"; MemoryStartupBytes=512MB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ; ImageName="Win2019Core_G2.vhdx"; IPAddress="10.0.0.121" ; Subnet="255.255.255.0" ; DefaultGateway="10.0.0.1" ; DNSServer="10.0.0.1" }
$VMs+=@{VMName="VM03"; MemoryStartupBytes=512MB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ; ImageName="Win2019Core_G2.vhdx"; IPAddress="172.168.1.2" ; Subnet="255.255.255.0" ; DefaultGateway="172.168.1.1" ; DNSServer="172.168.1.1" ; VLAN="1"}
 
```

### Create VMs

```PowerShell
foreach ($VM in $VMs){
    #Copy VHD to destination
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        New-Item -Path "$using:CSVPath\$($using:VM.VMName)\Virtual Hard Disks\" -ItemType Directory -Force
        Copy-Item -Path "$using:LibraryPath\$($using:VM.ImageName)" -Destination "$using:CSVPath\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx"
    }
    #Create Answer File
    $djointemp=New-TemporaryFile
    & djoin.exe /provision /domain $env:USERDOMAIN /machine $VM.VMName /savefile $djointemp.fullname /machineou $VM.Oupath
    #extract blob blob from temp file
    $Blob=get-content $djointemp
    $Blob=$blob.Substring(0,$blob.Length-1)
    #remove temp file
    $djointemp | Remove-Item

    #Generate Unattend file
$unattend = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <OfflineIdentification>
           <Provisioning>
             <AccountData>$Blob</AccountData>
           </Provisioning>
         </OfflineIdentification>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$($VM.AdminPassword)</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
       <HideEULAPage>true</HideEULAPage>
       <SkipMachineOOBE>true</SkipMachineOOBE>
       <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RegisteredOwner>PFE</RegisteredOwner>
      <RegisteredOrganization>PFE</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    </component>
  </settings>
</unattend>
"@

#Mount VHD and Apply answer file
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        New-Item -Path "$using:Mountdir" -ItemType Directory -Force
        Mount-WindowsImage -Path "$using:Mountdir" -ImagePath "$using:CSVPath\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx" -Index 1
        New-item -type directory  "$using:Mountdir\Windows\Panther"
        Set-Content -Value $using:unattend -Path "$using:Mountdir\Windows\Panther\Unattend.xml"
        Use-WindowsUnattend -Path "$using:Mountdir" -UnattendPath "$using:Mountdir\Windows\Panther\Unattend.xml"
        Dismount-WindowsImage -Path "$using:Mountdir" -Save
        Remove-Item -Path "$using:Mountdir"
    }

#Create VM
    Invoke-Command -ComputerName ($ClusterNodes | Get-Random) -ScriptBlock {
        Function Set-VMNetworkConfiguration {
            #source:http://www.ravichaganti.com/blog/?p=2766 with some changes
            #example use: Get-VMNetworkAdapter -VMName Demo-VM-1 -Name iSCSINet | Set-VMNetworkConfiguration -IPAddress 192.168.100.1 00 -Subnet 255.255.0.0 -DNSServer 192.168.100.101 -DefaultGateway 192.168.100.1
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$true,
                        Position=1,
                        ParameterSetName='DHCP',
                        ValueFromPipeline=$true)]
                [Parameter(Mandatory=$true,
                        Position=0,
                        ParameterSetName='Static',
                        ValueFromPipeline=$true)]
                [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$NetworkAdapter,

                [Parameter(Mandatory=$true,
                        Position=1,
                        ParameterSetName='Static')]
                [String[]]$IPAddress=@(),

                [Parameter(Mandatory=$false,
                        Position=2,
                        ParameterSetName='Static')]
                [String[]]$Subnet=@(),

                [Parameter(Mandatory=$false,
                        Position=3,
                        ParameterSetName='Static')]
                [String[]]$DefaultGateway = @(),

                [Parameter(Mandatory=$false,
                        Position=4,
                        ParameterSetName='Static')]
                [String[]]$DNSServer = @(),

                [Parameter(Mandatory=$false,
                        Position=0,
                        ParameterSetName='DHCP')]
                [Switch]$Dhcp
            )

            $VM = Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $NetworkAdapter.VMName } 
            $VMSettings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }    
            $VMNetAdapters = $VMSettings.GetRelated('Msvm_SyntheticEthernetPortSettingData') 

            $NetworkSettings = @()
            foreach ($NetAdapter in $VMNetAdapters) {
                if ($NetAdapter.elementname -eq $NetworkAdapter.name) {
                    $NetworkSettings = $NetworkSettings + $NetAdapter.GetRelated("Msvm_GuestNetworkAdapterConfiguration")
                }
            }

            $NetworkSettings[0].IPAddresses = $IPAddress
            $NetworkSettings[0].Subnets = $Subnet
            $NetworkSettings[0].DefaultGateways = $DefaultGateway
            $NetworkSettings[0].DNSServers = $DNSServer
            $NetworkSettings[0].ProtocolIFType = 4096

            if ($dhcp) {
                $NetworkSettings[0].DHCPEnabled = $true
            } else {
                $NetworkSettings[0].DHCPEnabled = $false
            }

            $Service = Get-WmiObject -Class "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
            $setIP = $Service.SetGuestNetworkAdapterConfiguration($VM, $NetworkSettings[0].GetText(1))

            if ($setip.ReturnValue -eq 4096) {
                $job=[WMI]$setip.job 
                while ($job.JobState -eq 3 -or $job.JobState -eq 4) {
                    start-sleep 1
                    $job=[WMI]$setip.job
                }
                if ($job.JobState -eq 7) {
                    Write-Host "`t Success"
                }else {
                $job.GetError()
                }
            }elseif($setip.ReturnValue -eq 0) {
                Write-Host "`t Success"
            }
        }
        $VM=$using:vm
        $VMTemp=New-VM -Name $VM.VMName -MemoryStartupBytes $VM.MemoryStartupBytes -Generation 2 -Path "$Using:CSVPath" -VHDPath "$Using:CSVPath\$($VM.VMName)\Virtual Hard Disks\$($VM.VMName).vhdx" -SwitchName $Using:vSwitchName
        $VMTemp | Set-VMProcessor -Count $VM.NumberOfCPUs
        if ($VM.DynamicMemory){
            $VMTemp | Set-VM -DynamicMemory
        }
        if ($VM.IPAddress){
            $VMTemp | Get-VMNetworkAdapter | Set-VMNetworkConfiguration -IPAddress $VM.IPAddress -Subnet $VM.Subnet -DefaultGateway $VM.DefaultGateway -DNSServer $VM.DNSServer
        }
        if ($VM.VLAN){
            $VMTemp | Get-VMNetworkAdapter | Set-VMNetworkAdapterVlan -VlanId $VM.VLAN -Access
        }
        $VMTemp | Start-VM
    }
    #add VM as clustered role
    Add-ClusterVirtualMachineRole -VMName $VM.VMName -Cluster $ClusterName
}
 
```

### Screenshots

![](/Scenarios/S2D%20and%20Bulk%20VM%20creation/Screenshots/Cluster.png)

![](/Scenarios/S2D%20and%20Bulk%20VM%20creation/Screenshots/CSV.png)

![](/Scenarios/S2D%20and%20Bulk%20VM%20creation/Screenshots/StaticIP.png)

![](/Scenarios/S2D%20and%20Bulk%20VM%20creation/Screenshots/StaticIPandVLAN.png)