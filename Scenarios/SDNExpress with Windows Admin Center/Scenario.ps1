$ErrorActionPreference = "stop"


#########################
# Run from Hyper-V Host #
#region########################

#region Initialization
# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

$ErrorActionPreference = "stop"

##Load LabConfig....
. ".\LabConfig.ps1"

#VM Credentials
$secpasswd = ConvertTo-SecureString $LabConfig.AdminPassword -AsPlainText -Force
$VMCreds = New-Object System.Management.Automation.PSCredential ("corp\$($LabConfig.DomainAdminName)", $secpasswd)

#Define VMM
$MgmtVM = Get-VM | Where-Object {$_.Name -like "$($labconfig.Prefix)*Management"}

#ask for parent vhdx for and VMs
if (Test-Path .\ParentDisks\WinServerCore.vhdx) {
    $VHDPath = (get-item .\ParentDisks\WinServerCore.vhdx).FullName
    $VHDName = (get-item .\ParentDisks\WinServerCore.vhdx).Name
} else {
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Title = "Please select parent VHDx for SDN VMs (2016 or RS3)." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
    }
    $openFile.Filter = "VHDx files (*.vhdx)|*.vhdx" 
    If ($openFile.ShowDialog() -eq "OK") {
        Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
    } 
    if (!$openFile.FileName) {
        Write-Host "No VHD was selected... Skipping VM Creation" -ForegroundColor Red
    }
    $VHDPath = $openFile.FileName
    $VHDName = $openfile.SafeFileName
}

#ask for fabric config file
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$confopenFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Please select the MultiNodeConfig.psd1 file." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
}
$confopenFile.Filter = "PSD1 files (*.psd1)|*.psd1" 
If ($confopenFile.ShowDialog() -eq "OK") {
    Write-Host  "File $($confopenFile.FileName) selected" -ForegroundColor Cyan
} 
if (!$openFile.FileName) {
    Write-error -Message  "no files found"
}
$confFilePath = $confopenFile.FileName

#ask for WAC
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Please select Windows Admin Center MSI" 
}
$openFile.Filter = "Msi files (*.msi)|*.msi" 
If ($openFile.ShowDialog() -eq "OK") {
    Write-Host  "File $($openfile.FileName) selected" -ForegroundColor Cyan
} 
if (!$openFile.FileName) {
    Write-Error "File not found for Windows Admin Center!"
}
$WACPath = $openFile.FileName
$WACName = $openfile.SafeFileName
#>

#grab SDN from git
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/Microsoft/SDN/archive/master.zip" -OutFile .\SDN-Master.zip
Unblock-File -Path .\SDN-Master.zip
#grab Chrome
Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile .\chrome_installer.exe
Unblock-File -Path .\chrome_installer.exe
#endregion

#region Start VMs 
Write-host "Starting VMs" -foregroundcolor Green
Get-VM | Where-Object {$_.Name -like "$($labconfig.Prefix)*"} | Start-VM
#endregion Start VMs 

#wait for management VM
Write-Host "Waiting for PSDirect to $($VM.VMName) for $($VMCreds.UserName)"
$startTime = Get-Date
do {
    $timeElapsed = $(Get-Date) - $startTime
    if ($($timeElapsed).TotalMinutes -ge 10) {
        Write-Host "Could not connect to PS Direct after 10 minutes"
        throw
    } 
    Start-Sleep -sec 5
    $psReady = Invoke-Command -VMId $MgmtVM.VMId -Credential $VMCreds `
        -ScriptBlock { $True } -ErrorAction SilentlyContinue
} 
until ($psReady)

$MgmtVM | Copy-VMFile -SourcePath $VHDPath -FileSource Host -DestinationPath "C:\Library\WScore_Master.vhdx" -Force -CreateFullPath
$MgmtVM | Copy-VMFile -SourcePath $confFilePath -DestinationPath "C:\Library\MultiNodeConfig.psd1" -CreateFullPath -FileSource Host -Force
$MgmtVM | Copy-VMFile -SourcePath $WACPath -DestinationPath "C:\Library\WindowsAdminCenter.msi" -CreateFullPath -FileSource Host -Force
$MgmtVM | Copy-VMFile -SourcePath .\SDN-Master.zip -DestinationPath "C:\SDN-Master.zip" -CreateFullPath -FileSource Host -Force
$MgmtVM | Copy-VMFile -SourcePath .\chrome_installer.exe -DestinationPath "C:\Library\chrome_installer.exe" -CreateFullPath -FileSource Host -Force

#
Write-host "Add windows features to $($MgmtVM.Name)" -foregroundcolor Green
Invoke-Command -VMId $MgmtVM.Id -ScriptBlock {  
    Get-WindowsFeature *rsat* | Install-WindowsFeature
    Restart-Computer -Force
} -Credential $VMCreds

Write-Host "#------------ Done configuring VMs, Continue on $($MgmtVM.Name) ------------#" -foregroundcolor Yellow
Write-Host "#---------------------------------------------------------------------------#" -foregroundcolor Yellow
throw

#######################################
# ENDING Run from Hyper-V Host ENDING #
#endregion######################################







########################
# Run from DC / VMM #
#region########################

$ErrorActionPreference = "stop"

Get-WindowsFeature *rsat* | Install-WindowsFeature

#region Pre SDNExpress deployment
#region Initialization
$config = (Invoke-Expression (Get-content "C:\Library\MultiNodeConfig.psd1" -Raw))

$RouterName = "DC"
$DCName = "DC"

# 2,3,4,8, or 16 nodes  
$numberofnodes = 4
$ServersNamePrefix = "HV"
$ClusterName = "SDDC01"

#generate servernames (based number of nodes and serversnameprefix)
$Servers = @()
1..$numberofnodes | ForEach-Object {$Servers += "$($ServersNamePrefix)$_"}

## Networking ##
$ClusterIP = "10.0.0.111" #If blank (you can write just $ClusterIP="", DHCP will be used)
$StorNet = "172.16.1."
$StorVLAN = 1
$SRIOV = $false #Deploy SR-IOV enabled switch
#start IP
$IP = 1

#DisableNetBIOS on all vNICs? $True/$False It's optional. Works well with both settings default/disabled
$DisableNetBIOS = $False

#Number of Disks Created. If >4 nodes, then x Mirror-Accelerated Parity and x Mirror disks are created
$NumberOfDisks = $numberofnodes

#IncreaseHW Timeout for virtual environments to 30s? https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-direct-in-vm
$VirtualEnvironment = $true
        
$RouterCIM = New-CimSession $RouterName
$DCCIM = New-CimSession $DCName

New-SmbShare -Name "Library" -Path "C:\Library" -FullAccess "corp\labadmin", "Everyone"
#endregion Initialization

#region Rename BGP NICs
Write-host "Configure Router NICs" -ForegroundColor Green
foreach ($NetAdapter in (Get-NetAdapter -CimSession $RouterCIM)) {
    $NicName = $NetAdapter | Get-NetAdapterAdvancedProperty –DisplayName “Hyper-V Network Adapter Name” -CimSession $RouterCIM
    $NetAdapter | Rename-NetAdapter -NewName $NicName.DisplayValue -CimSession $RouterCIM
}
#endregion Rename router nics

#region exclude VMM IPs from dhcp
Write-host "Exclude ip range from DHCP" -ForegroundColor Green
(Get-DhcpServerv4Scope -CimSession $DCCIM) | Set-DhcpServerv4Scope -LeaseDuration (New-TimeSpan -Hours 8)  -CimSession $DCCIM
Add-DhcpServerv4ExclusionRange -ScopeId (Get-DhcpServerv4Scope -CimSession $DCCIM).ScopeId -StartRange "10.0.0.5" -EndRange "10.0.0.30" -CimSession $DCCIM
#endregion exclude VMM IPs from dhcp

#region Create AD Accounts
Write-host "Create AD Accounts" -ForegroundColor Green
$ServiceAccountPassword = "LS1setup!"

$NC_ManagementGroupName = "NCManagement"
$NC_ClientGroupName = "NCClient"

$NC_ManagementUserName = $config.NCUsername.Split("\")[1]

$SDNOUname = "Workshop"

$DomainDN = (Get-ADDomain).DistinguishedName
$ServiceAccountPasswordSEC = ConvertTo-SecureString $ServiceAccountPassword -AsPlainText -Force

#Create OU for all objects created for SDN LAB
$SDNOU = Get-ADOrganizationalUnit -LDAPFilter "(name=$SDNOUname)"

#Create an Active Directory security group for Network Controller management
$NC_ManagementGroup = New-ADGroup -Name $NC_ManagementGroupName -Description "Members of this group is able to create, delete, and update the deployed Network Controller configuration" -GroupCategory Security -GroupScope DomainLocal -Path $SDNOU -PassThru
$NC_ManagementGroup = Get-ADGroup $NC_ManagementGroupName

#Create an Active Directory security group for Network Controller clients
$NC_ClientGroup = New-ADGroup -Name $NC_ClientGroupName -Description "Members of this group is able to communicate with the controller via REST" -GroupCategory Security -GroupScope DomainLocal -Path $SDNOU
$NC_ClientGroup = Get-ADGroup $NC_ClientGroupName

#Create AD User for NC Management
$NC_ManagementUser = New-ADUser -Name $NC_ManagementUserName -UserPrincipalName $NC_ManagementUserName -DisplayName $NC_ManagementUserName -Description "Is able to create, delete, and update the deployed Network Controller configuration" -AccountPassword $ServiceAccountPasswordSEC -CannotChangePassword $true -PasswordNeverExpires $true -Path $SDNOU -Enabled $true
$NC_ManagementUser = Get-ADUser $NC_ManagementUserName

$ServerOps = Get-ADGroup -Identity "Server Operators"
$DNSAdmin = Get-ADGroup -Identity "DnsAdmins"
$DomainAdmins = Get-ADGroup -Identity "Domain Admins"

Add-ADGroupMember -Identity $NC_ManagementGroup -Members $NC_ManagementUser
Add-ADGroupMember -Identity $NC_ClientGroup -Members $NC_ManagementUser
Add-ADGroupMember -Identity $DomainAdmins -Members $NC_ManagementUser
#endregion Create AD Accounts

#region Prepare Hosts
$dnsJob = Start-Job -ScriptBlock {
    while ($true) {
        Clear-DnsClientCache
        Start-Sleep 20
    }
}

#region Configure basic settings on servers 
Write-host "Configure Basic settings on Hosts" -ForegroundColor Green
#IncreaseHW Timeout for virtual environments to 30s
if ($VirtualEnvironment) {
    Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530 -Force}
}


#Configure Active memory dump
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
}

#install roles and features         
#define features
$features = "Failover-Clustering", "Hyper-V-PowerShell", "Hyper-V"

Clear-DnsClientCache                
#install features
foreach ($server in $servers) {Install-WindowsFeature -Name $features -ComputerName $server -IncludeManagementTools} 
#restart and wait for computers
Clear-DnsClientCache
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region Add Switch
Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name sdnSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

Invoke-Command -ComputerName $servers -scriptblock {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393) {
        Set-VMSwitchTeam -Name sdnSwitch -LoadBalancingAlgorithm HyperVPort
    }
}

$Servers | ForEach-Object {
    #Configure vNICs
    Rename-VMNetworkAdapter -ManagementOS -Name sdnSwitch -NewName Mgmt -ComputerName $_
    Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName sdnSwitch -CimSession $_
    Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName sdnSwitch -Cimsession $_

    #configure IP Addresses
    New-NetIPAddress -IPAddress ($StorNet + $IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
    $IP++
    New-NetIPAddress -IPAddress ($StorNet + $IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
    $IP++
}

Start-Sleep 5
Clear-DnsClientCache

#Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN -Access -ManagementOS -CimSession $Servers
Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN -Access -ManagementOS -CimSession $Servers

#Restart each host vNIC adapter so that the Vlan is active.
Restart-NetAdapter "vEthernet (SMB01)" -CimSession $Servers 
Restart-NetAdapter "vEthernet (SMB02)" -CimSession $Servers

#Enable RDMA on the host vNIC adapters
Enable-NetAdapterRDMA "vEthernet (SMB01)", "vEthernet (SMB02)" -CimSession $Servers

#Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
Invoke-Command -ComputerName $servers -ScriptBlock {
    $physicaladapters = (get-vmswitch sdnSwitch).NetAdapterInterfaceDescriptions | Sort-Object
    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
}

#Disable NetBIOS on all vNICs https://msdn.microsoft.com/en-us/library/aa393601(v=vs.85).aspx
if ($DisableNetBIOS) {
    $vNICs = Get-NetAdapter -CimSession $Servers | Where-Object Name -like vEthernet*
    foreach ($vNIC in $vNICs) {
        Write-Host "Disabling NetBIOS on $($vNIC.Name) on computer $($vNIC.PSComputerName)"
        $output = Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $vNIC.PSComputerName | Where-Object Description -eq $vNIC.InterfaceDescription | Invoke-WmiMethod -Name settcpipNetBIOS -ArgumentList 2
        if ($output.Returnvalue -eq 0) {
            Write-Host "`t Success" -ForegroundColor Green
        } else {
            Write-Host "`t Failure"
        }
    }
}

#Verify Networking
#verify mapping
Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | ft ComputerName, NetAdapterName, ParentAdapter 
#Verify that the VlanID is set
Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | ft ComputerName, AccessVlanID, ParentAdapter -AutoSize -GroupBy ComputerName
#verify RDMA
Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | ft systemname, interfacedescription, name, enabled -AutoSize -GroupBy Systemname
#verify ip config 
Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername, interfacealias, ipaddress -AutoSize -GroupBy pscomputername

Clear-DnsClientCache
#endregion

#region Create Cluster
Test-Cluster -Node $servers -Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration", "Hyper-V Configuration"

New-Cluster -Name $ClusterName -Node $servers

Start-Sleep 10

(Get-Cluster $ClusterName).BlockCacheSize = 0

#Create new directory
$WitnessName = $Clustername + "Witness"
Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
$accounts = @()
$accounts += "corp\$ClusterName$"
$accounts += "corp\Domain Admins"
New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
#Set NTFS permissions 
Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
#Set Quorum
Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
#rename networks
(Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet"0").Name = "SMB"
(Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name = "Management"

Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose


Get-Job | Stop-Job
#endregion Create Cluster

#endregion

#region prepare SDN scripts
Expand-Archive -Path C:\SDN-Master.zip -DestinationPath C:\Library
Set-Location "C:\Library\SDN-master"

$EncodedPassword = ("LS1setup!" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)

$contentConfig = (Get-Content C:\Library\MultiNodeConfig.psd1)
$contentConfig = $contentConfig.Replace('##PASSWORD##', $EncodedPassword)
$contentConfig | Out-File C:\Library\MultiNodeConfig.psd1
#endregion prepare SDN scripts

Start-Sleep 30
#endregion

#region Start SDN Express Deployment

Set-Location "C:\Library\SDN-master\SDNExpress\scripts\"
. "C:\Library\SDN-master\SDNExpress\scripts\SDNExpress.ps1" -ConfigurationDataFile C:\Library\MultiNodeConfig.psd1 -Verbose

#endregion Start SDN Express Deployment

#region Post SDNExpress
#region Peer BGP
write-host "Configure BGPPeering" -ForegroundColor Cyan
$RouterCIM = New-CimSession -ComputerName $RouterName

$BGPRouterIP = $config.Routers.RouterIPAddress
$RouterASN = $config.Routers.RouterAsn
$NetworkControllerName = $config.RestName

Add-BgpRouter -BgpIdentifier $BGPRouterIP -LocalASN $RouterASN -CimSession $RouterCIM


$SLBWebRequest = ConvertFrom-Json (Invoke-WebRequest -Uri "https://$NetworkControllerName/networking/v1/loadbalancerMuxes" -Credential $NCClient -UseBasicParsing).Content

$GWWebRequest = ConvertFrom-Json (Invoke-WebRequest -Uri "https://$NetworkControllerName/networking/v1/Gateways" -Credential $NCClient -UseBasicParsing).Content


$SLBVMs = $SLBWebRequest.Value.properties
$GWVMs = $GWWebRequest.value

foreach ($SLBVM in $SLBVMs) {
    $vmName = $SLBVM.virtualServer.resourceRef.split("/") | select -last 1
    $vmASN = $SLBVM.routerConfiguration.localASN
    $vmIP = $SLBVM.routerConfiguration.peerRouterConfigurations.localIPAddress
    
    Get-BgpPeer -CimSession $RouterCIM | Where-Object {$_.Name -eq $vmName} | Remove-BgpPeer  -CimSession $RouterCIM
    add-bgppeer -Name $vmName -LocalIPAddress $BGPRouterIP -PeerIPAddress $VMIp -LocalASN $RouterASN -PeerASN $vmASN -OperationMode Mixed -PeeringMode Automatic -CimSession $RouterCIM
}

foreach ($GWVM in $GWVMs) {
    $gwVMName = $GWVM.resourceRef.split("/") | select -last 1
    $gwVMip = $GWVM.properties.externalIPAddress.ipAddress
    $gwVMASN = $GWVM.properties.bgpConfig.extASNumber.Split(".") | select -last 1

    Get-BgpPeer -CimSession $RouterCIM | Where-Object {$_.Name -eq $gwVMName} | Remove-BgpPeer  -CimSession $RouterCIM
    add-bgppeer -Name $gwVMName -LocalIPAddress $BGPRouterIP -PeerIPAddress $gwVMip -LocalASN $RouterASN -PeerASN $gwVMASN -OperationMode Mixed -PeeringMode Automatic -CimSession $RouterCIM
}

#endregion Peer BGP

#Region WAC
#Download Windows Admin Center to downloads

#Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
Start-Process msiexec.exe -Wait -ArgumentList "/i C:\Library\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=9999 SSL_CERTIFICATE_OPTION=generate"

#Open Windows Admin Center
New-NetFirewallRule -Name honolulu -DisplayName honolulu -Enabled True -Profile any -Action Allow -Direction Inbound -Protocol tcp -LocalPort 9999
#endRegion WAC

#Install Chrome
Start-Process -FilePath "C:\Library\chrome_installer.exe" -Args "/silent /install" -Verb RunAs -Wait

Write-Host "Completed...!" -ForegroundColor Green
#endregion
#endregion

