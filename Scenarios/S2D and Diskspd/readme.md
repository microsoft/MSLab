<!-- TOC -->

- [S2D and Diskspd](#s2d-and-diskspd)
    - [LabConfig for Windows Server 2019](#labconfig-for-windows-server-2019)
    - [Prereq](#prereq)
    - [Test network performance of S2D cluster](#test-network-performance-of-s2d-cluster)
        - [Copy Diskspd to nodes](#copy-diskspd-to-nodes)
        - [Run diskspd that utilizes every node to read from another random node for 30s](#run-diskspd-that-utilizes-every-node-to-read-from-another-random-node-for-30s)
        - [Display performance in PowerShell](#display-performance-in-powershell)
        - [Display performance in Windows Admin Center](#display-performance-in-windows-admin-center)
    - [Testing Storage Performance](#testing-storage-performance)
        - [Create some volumes](#create-some-volumes)
        - [Create some VMs on that volumes](#create-some-vms-on-that-volumes)
        - [Grab remote friendly watch-cluster.ps1 and run it](#grab-remote-friendly-watch-clusterps1-and-run-it)
        - [Start some load and enjoy](#start-some-load-and-enjoy)

<!-- /TOC -->

# S2D and Diskspd

## LabConfig for Windows Server 2019

```PowerShell
#Labconfig is same as default for Windows Server 2019, just with nested virtualization and 4GB for startup memory
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true }}
# Management machine
$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win10RS5_G2.vhdx'   ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }
 
```

## Prereq

Run first 9 regions of S2D [Hyperconverged scenario](https://raw.githubusercontent.com/Microsoft/WSLab/master/Scenarios/S2D%20Hyperconverged/Scenario.ps1). Run all code from DC

Collapse all regions with ctrl+m, select firs 9 regions and paste into elevated PowerShell (right-click)

![](/Scenarios/S2D%20and%20Diskspd/Screenshots/Regions.png)

## Test network performance of S2D cluster

Following test will be done with DiskSpd. This utility was downloaded already into tools.vhdx, therefore it's located on D: drive on DC. Optionally you can download it with following code

```PowerShell
Invoke-WebRequest -UseBasicParsing -Uri https://gallery.technet.microsoft.com/DiskSpd-A-Robust-Storage-6ef84e62/file/199535/2/DiskSpd-2.0.21a.zip -OutFile $env:USERPROFILE\Downloads\Diskspd.zip
Expand-Archive -Path $env:USERPROFILE\Downloads\Diskspd.zip -DestinationPath $env:USERPROFILE\Downloads\Diskspd -Force
 
```

### Copy Diskspd to nodes

```PowerShell
$ClusterName="S2D-Cluster"
$ClusterNodes="S2D1","S2D2","S2D3","S2D4"
$Sessions=New-PSSession -ComputerName $ClusterNodes
foreach ($session in $sessions){
    Copy-Item -Path D:\DiskSpd\DiskSpd.exe -Destination $env:USERPROFILE\Downloads -ToSession $session
}
 
```

### Run diskspd that utilizes every node to read from another random node for 30s

```PowerShell
$ClusterName="S2D-Cluster"
$ClusterNodes="S2D1","S2D2","S2D3","S2D4"
$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

#Enable CredSSP delegation to be able to pass creds
Enable-WSManCredSSP Client -DelegateComputer $ClusterNodes -Force
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {Enable-WSManCredSSP Server -Force}

#Permutate node pairs
$NodePairs=@()
foreach ($a in $ClusterNodes) {
    foreach ($b in $ClusterNodes) {
        if ($a -ne $b){
            $NodePairs += [PSCustomObject]@{Node1=$a;Node2=$b}
        }
    }
}

foreach ($NodePair in $NodePairs){
    Write-Host "Testing writes from $($NodePair.Node1) to $($NodePair.Node2)" -ForegroundColor green
    Invoke-Command -ComputerName $NodePair.Node1 -Credential $Credentials -Authentication Credssp -ScriptBlock {
        & $env:USERPROFILE\Downloads\diskspd.exe -b64K -c2M -t10 -r -o2 -d15 -Sr -ft -L -w100 "\\$($Using:NodePair.Node2)\c$\diskspd-$env:ComputerName.bin"
    }
}

#Disable CredSSP
Disable-WSManCredSSP -Role Client
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {Disable-WSManCredSSP Server}
 
```

### Display performance in PowerShell

```PowerShell
$ClusterName="S2D-Cluster"
$Output = Invoke-Command (Get-ClusterNode -Cluster $ClusterName).Name {

    Function Format-BitsPerSec {
        Param (
            $RawValue
        )
        $i = 0 ; $Labels = ("bps", "kbps", "Mbps", "Gbps", "Tbps", "Pbps") # Petabits, just in case!
        Do { $RawValue /= 1000 ; $i++ } While ( $RawValue -Gt 1000 )
        # Return
        [String][Math]::Round($RawValue) + " " + $Labels[$i]
    }

    Get-NetAdapter | ForEach-Object {

        $Inbound = $_ | Get-ClusterPerf -NetAdapterSeriesName "NetAdapter.bandwidth.Inbound" -TimeFrame "LastHour"
        $Outbound = $_ | Get-ClusterPerf -NetAdapterSeriesName "NetAdapter.bandwidth.Outbound" -TimeFrame "LastHour"

        If ($Inbound -Or $Outbound) {

            $InterfaceDescription = $_.InterfaceDescription
            $LinkSpeed = $_.LinkSpeed

            $MeasureInbound = $Inbound | Measure-Object -Property Value -Maximum
            $MaxInbound = $MeasureInbound.Maximum * 8 # Multiply to bits/sec

            $MeasureOutbound = $Outbound | Measure-Object -Property Value -Maximum
            $MaxOutbound = $MeasureOutbound.Maximum * 8 # Multiply to bits/sec

            $Saturated = $False

            # Speed property is Int, e.g. 10000000000
            If (($MaxInbound -Gt (0.90 * $_.Speed)) -Or ($MaxOutbound -Gt (0.90 * $_.Speed))) {
                $Saturated = $True
                Write-Warning "In the last day, adapter '$InterfaceDescription' on server '$Env:ComputerName' exceeded 90% of its '$LinkSpeed' theoretical maximum bandwidth. In general, network saturation leads to higher latency and diminished reliability. Not good!"
            }

            [PsCustomObject]@{
                "NetAdapter"  = $InterfaceDescription
                "LinkSpeed"   = $LinkSpeed
                "MaxInbound"  = Format-BitsPerSec $MaxInbound
                "MaxOutbound" = Format-BitsPerSec $MaxOutbound
                "Saturated"   = $Saturated
            }
        }
    }
}

$Output | Sort-Object PsComputerName, InterfaceDescription | Format-Table PsComputerName, NetAdapter, LinkSpeed, MaxInbound, MaxOutbound, Saturated
 
```

![](/Scenarios/S2D%20and%20Diskspd/Screenshots/NetworkResult.png)

### Display performance in Windows Admin Center

While logged on Management machine, install Windows Admin Center and navigate to network monitoring

```PowerShell
$ProgressPreference='SilentlyContinue' #for faster download
#Download Windows Admin Center to downloads
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

#Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

#Open Windows Admin Center
    Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
 
```

![](/Scenarios/S2D%20and%20Diskspd/Screenshots/ServerPerformance.png)

## Testing Storage Performance

Run all code from DC

### Create some volumes

```PowerShell
$ClusterName="S2D-Cluster"
$VolumeNames="CSV1","CSV2","CSV3","CSV4"
foreach ($Volumename in $Volumenames){
    New-Volume -StoragePoolFriendlyName S2D* -FriendlyName $VolumeName -FileSystem CSVFS_ReFS -Size 1TB -ResiliencySettingName Mirror -CimSession $ClusterName
}
 
```

### Create some VMs on that volumes

```PowerShell
$ClusterName="S2D-Cluster"
$ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
$vSwitchName="SETSwitch"
$MountDir="c:\temp\MountDir" #cannot be CSV
$VMs=@()
$VMs+=@{VMName="VM1"; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ; CSVName="CSV1"; Host="S2D1"}
$VMs+=@{VMName="VM2"; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ; CSVName="CSV2"; Host="S2D2"}
$VMs+=@{VMName="VM3"; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ; CSVName="CSV3"; Host="S2D3"}
$VMs+=@{VMName="VM4"; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=2 ; AdminPassword="LS1setup!" ; OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" ; CSVName="CSV4"; Host="S2D4"}

#Ask for VHD
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Title="Please select parent VHDx." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
    }
    $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx"
    If($openFile.ShowDialog() -eq "OK"){
        Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
    } 
    if (!$openFile.FileName){
        Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
    }
    $VHDPath = $openFile.FileName

foreach ($VM in $VMs){
    #Copy VHD to destination
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        New-Item -Path "c:\ClusterStorage\$($using:VM.CSVName)\$($using:VM.VMName)\Virtual Hard Disks\" -ItemType Directory -Force
    }
    Copy-Item -Path $VHDPath -Destination "\\$ClusterName\Clusterstorage$\$($VM.CSVName)\$($VM.VMName)\Virtual Hard Disks\$($VM.VMName).vhdx"

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
        Mount-WindowsImage -Path "$using:Mountdir" -ImagePath "c:\ClusterStorage\$($using:VM.CSVName)\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx" -Index 1
        New-item -type directory  "$using:Mountdir\Windows\Panther"
        Set-Content -Value $using:unattend -Path "$using:Mountdir\Windows\Panther\Unattend.xml"
        Use-WindowsUnattend -Path "$using:Mountdir" -UnattendPath "$using:Mountdir\Windows\Panther\Unattend.xml"
        Dismount-WindowsImage -Path "$using:Mountdir" -Save
        Remove-Item -Path "$using:Mountdir"
    }

#Create VM
    Invoke-Command -ComputerName $VM.Host -ScriptBlock {
        $VM=$using:vm
        $VMTemp=New-VM -Name $VM.VMName -MemoryStartupBytes $VM.MemoryStartupBytes -Generation 2 -Path "c:\ClusterStorage\$($using:VM.CSVName)" -VHDPath "c:\ClusterStorage\$($using:VM.CSVName)\$($VM.VMName)\Virtual Hard Disks\$($VM.VMName).vhdx" -SwitchName $Using:vSwitchName
        $VMTemp | Set-VMProcessor -Count $VM.NumberOfCPUs
        if ($VM.DynamicMemory){
            $VMTemp | Set-VM -DynamicMemory
        }

        $VMTemp | Start-VM
    }
    #add VM as clustered role
    Add-ClusterVirtualMachineRole -VMName $VM.VMName -Cluster $ClusterName
}
 
```

### Grab remote friendly watch-cluster.ps1 and run it

```PowerShell
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/jaromirk/diskspd/master/Frameworks/VMFleet/watch-cluster.ps1 -OutFile D:\Watch-Cluster.ps1
D:\Watch-Cluster.ps1 -sets * -ClusterName S2D-Cluster
 
```

### Start some load and enjoy

```PowerShell
$VMs="VM1","VM2","VM3","VM4"

#Copy Diskspd to VMs
$Sessions=New-PSSession -ComputerName $VMs
foreach ($session in $sessions){
    Copy-Item -Path D:\DiskSpd\DiskSpd.exe -Destination $env:USERPROFILE\Downloads -ToSession $session
}
#Start some load. You may want to modify binary file (like 10 GB instead of 1GB -c1G ...)
Invoke-Command -Session $sessions -ScriptBlock {
    & $env:USERPROFILE\Downloads\diskspd.exe -t8 -b4k -r4k -o1 -w30 -Suw -D -L -d180 -Rxml -c1G "c:\diskspd.bin"
}
 
```

![](/Scenarios/S2D%20and%20Diskspd/Screenshots/Watch-Cluster.png)

![](/Scenarios/S2D%20and%20Diskspd/Screenshots/StoragePerformanceWAC.png)