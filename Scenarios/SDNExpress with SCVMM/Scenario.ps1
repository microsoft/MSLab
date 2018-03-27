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
$VMMvm = Get-VM | Where-Object {$_.Name -like "$($labconfig.Prefix)*DC"}

#ask for parent vhdx for and VMs
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

#ask for fabric config file
[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
$confopenFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Please select the fabrigconfig.psd1 file." # You can copy it from parentdisks on the Hyper-V hosts somewhere into the lab and then browse for it"
}
$confopenFile.Filter = "PSD1 files (*.psd1)|*.psd1" 
If ($confopenFile.ShowDialog() -eq "OK") {
    Write-Host  "File $($confopenFile.FileName) selected" -ForegroundColor Cyan
} 
if (!$openFile.FileName) {
    Write-error -Message  "no files found"
}
$confFilePath = $confopenFile.FileName

#grab SDN from git
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/Microsoft/SDN/archive/master.zip" -OutFile .\SDN-Master.zip
Unblock-File -Path .\SDN-Master.zip

#endregion

#region Start VMs 
Write-host "Starting VMs" -foregroundcolor Green
Get-VM | Where-Object {$_.Name -like "$($labconfig.Prefix)*"} | Start-VM
#endregion Start VMs 

#region Add library disk and copy files
Write-host "Add library disk and copy files" -foregroundcolor Green
if (Test-Path "$($VMMvm.Path)\Virtual Hard Disks\Library.vhdx") {
    remove-item -Path "$($VMMvm.Path)\Virtual Hard Disks\Library.vhdx" -Confirm:$false -Force
}
New-VHD -Path "$($VMMvm.Path)\Virtual Hard Disks\Library.vhdx" -SizeBytes 150GB -Dynamic
$VMMvm |  Add-VMHardDiskDrive -Path "$($VMMvm.Path)\Virtual Hard Disks\Library.vhdx"
$VMMvm| Foreach-Object {  Invoke-Command -VMId $_.Id -ScriptBlock {   
        Get-Disk | Where-Object {$_.Size -eq 150GB} |
            Where partitionstyle -eq 'raw' |
            Initialize-Disk -PartitionStyle MBR -PassThru |
            New-Partition -DriveLetter E -UseMaximumSize |
            Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false

        mkdir e:\Library
        New-SmbShare -Name "Library" -Path "e:\Library" -FullAccess "corp\labadmin", "Everyone" 

    } -Credential $VMCreds }

$VMMvm | Copy-VMFile -SourcePath $VHDPath -FileSource Host -DestinationPath "e:\Library\WS2016_Master.vhdx" -Force
$VMMvm | Copy-VMFile -SourcePath $confFilePath -DestinationPath "e:\Library\Fabricconfig.psd1" -CreateFullPath -FileSource Host -Force
$VMMvm | Copy-VMFile -SourcePath .\SDN-Master.zip -DestinationPath "e:\SDN-Master.zip" -CreateFullPath -FileSource Host -Force
#endregion Add library disk and copy files

Write-Host "#------------ Done configuring VMs, Continue on DC ------------#" -foregroundcolor Yellow
Write-Host "#--------------------------------------------------------------#" -foregroundcolor Yellow
throw

#######################################
# ENDING Run from Hyper-V Host ENDING #
#endregion######################################





#########################
# Run from DC / VMM #
#region########################

$ErrorActionPreference = "stop"

#region Pre SDNExpress deployment
#region Initialization
$config = (Invoke-Expression (Get-content "\\dc\Library\Fabricconfig.psd1" -Raw)).AllNodes

$RouterName = "dc"
$DCName = "DC"
$VMMName = "DC"

$VMMHostAccessAccountName = "DomainAdmin"

#Switch Config
$LogicalSwitches = @{
    LogicalSwitches = 
    @(
        @{
            Name          = "SDN Switch"
            Description   = "SDN Swtich"
            SRIOV         = $false
            UplinkMode    = "EmbeddedTeam"
            BandwidthMode = "Weight"
            PortProfiles  = @(
                @{
                    PortClassification = "Host management"
                    NativePortProfile  = "Host management"
                },
                @{
                    PortClassification = "Guest Dynamic IP"
                    NativePortProfile  = "Guest Dynamic IP"
                }, 
                @{
                    PortClassification = "Medium bandwidth"
                    NativePortProfile  = "Medium Bandwidth Adapter"
                }
            )
            UplinkProfile = @(
                @{
                    Name                       = "SDN Switch Uplink" 
                    Description                = "SDN Switch Uplink"
                    LBFOLoadBalancingAlgorithm = "HyperVPort"
                    LBFOTeamMode               = "SwitchIndependent"
                    LogicalNetworkDefinitions  = @(
                        @{
                            LogicalNetwork = "Management"
                            Name           = "Management"
                        }
                    )
                }
            )
            vNics         = @(
                @{
                    Name                                      = "Management"
                    VMNetworkName                             = "Management"
                    PortClassification                        = "Host management"
                    IPv4AddressType                           = "Dynamic"
                    InheritsAddressFromPhysicalNetworkAdapter = $true
                    UsedForManagement                         = $true
                }
            )
        }
    )
} 


# 2,3,4,8, or 16 nodes  
$numberofnodes = 4
$ServersNamePrefix = "HV"

#generate servernames (based number of nodes and serversnameprefix)
$Servers = @()
1..$numberofnodes | ForEach-Object {$Servers += "$($ServersNamePrefix)$_"}
        
$RouterCIM = New-CimSession $RouterName
$DCCIM = New-CimSession $DCName
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
Add-DhcpServerv4ExclusionRange -ScopeId (Get-DhcpServerv4Scope -CimSession $DCCIM).ScopeId -StartRange ($config.LogicalNetworks | Where-Object {$_.Name -eq "Management"}).subnets.PoolStart -EndRange ($config.LogicalNetworks | Where-Object {$_.Name -eq "Management"}).subnets.PoolEnd -CimSession $DCCIM
#endregion exclude VMM IPs from dhcp

#region Ensure VMM is started
Write-host "Ensure VMM is started" -ForegroundColor Green
Get-Service MSSQLSERVER -ComputerName $VMMName | Start-Service
Get-Service SCVMMService -ComputerName $VMMName |  Start-Service
#endregion Ensure VMM is started

#region Create AD Accounts
Write-host "Create AD Accounts" -ForegroundColor Green
$ServiceAccountPassword = $config.ManagementDomainUserPassword

$NC_ManagementGroupName = $config.ManagementSecurityGroupName.Split("\")[1]
$NC_ClientGroupName = $config.ClientSecurityGroupName.Split("\")[1]
$NC_ManagementUserName = $config.ManagementDomainUser.Split("\")[1]

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

Add-ADGroupMember -Identity $NC_ManagementGroup -Members $NC_ManagementUser
Add-ADGroupMember -Identity $NC_ClientGroup -Members $NC_ManagementUser
Add-ADGroupMember -Identity $ServerOps -Members $NC_ManagementUser
#endregion Create AD Accounts

#region Add runAs Accounts
Write-host "Add runAs Accounts" -ForegroundColor Green

Get-SCVMMServer $VMMName
Set-SCVMMServer -AutomaticLogicalNetworkCreationEnabled $false
Add-SCLibraryShare -SharePath \\DC\Library

#LocalAdmin
$LocalADMINsecpasswd = ConvertTo-SecureString $config.LocalAdminPassword -AsPlainText -Force
$LocalAdminCreds = New-Object System.Management.Automation.PSCredential ("Administrator", $LocalADMINsecpasswd)
$LocalAdmin = New-SCRunAsAccount -Name "Local Admin" -Credential $LocalAdminCreds

##Domain Admin
$VMMADMINsecpasswd = ConvertTo-SecureString $config.LocalAdminPassword -AsPlainText -Force
$VMMAdminCreds = New-Object System.Management.Automation.PSCredential ("corp\LabAdmin", $VMMADMINsecpasswd)
$VMMAdmin = New-SCRunAsAccount -Name "VMMAdmin" -Credential $VMMAdminCreds

##Domain Admin
$DomainADMINsecpasswd = ConvertTo-SecureString $config.LocalAdminPassword -AsPlainText -Force
$DomainAdminCreds = New-Object System.Management.Automation.PSCredential ("corp\LabAdmin", $DomainADMINsecpasswd)
$DomainAdmin = New-SCRunAsAccount -Name "DomainAdmin" -Credential $DomainAdminCreds
#endregion Add runAs Accounts

#region Prepare Network
Write-host "Prepare VMM fabric network" -ForegroundColor Green
#create Host Group
if (!(Get-SCVMHostGroup | Where-Object {$_.Name -eq $config.NCHostGroupName})) {
    New-SCVMHostGroup -Name $config.NCHostGroupName
}

#Create Management network
$logicalNetworks = $config.LogicalNetworks | Where-Object {$_.Name -eq "Management"}
foreach ($logicalNetwork in $logicalNetworks) {
    $lNetwork = New-SCLogicalNetwork -Name $LogicalNetwork.Name
    $sNetwork = Get-SCLogicalNetworkDefinition -Name "$($LogicalNetwork.Name) - $($config.NCHostGroupName)" -LogicalNetwork $lNetwork -ErrorAction SilentlyContinue
    if ($sNetwork.count -eq 0) {
        $HostGroups = Get-SCVMHostGroup -Name $config.NCHostGroupName
        #Create Logical Network Definitions
        $Subnet = New-SCSubnetVLan -Subnet $logicalNetwork.Subnets.AddressPrefix -VLanID $logicalNetwork.Subnets.VLANID
        $sNetwork = New-SCLogicalNetworkDefinition -Name "$($LogicalNetwork.Name) - $($config.NCHostGroupName)" -LogicalNetwork $lNetwork -SubnetVLan $Subnet -VMHostGroup $HostGroups
    }
    $IPPool = Get-SCStaticIPAddressPool -Name "$($LogicalNetwork.Name) - $($config.NCHostGroupName) Pool" -LogicalNetworkDefinition $sNetwork
    if ($IPPool.count -eq 0 ) {
        if ($logicalNetwork.Subnets.Gateways -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}') {
            $Gateway = New-SCDefaultGateway -IPAddress $logicalNetwork.Subnets.Gateways
            $DNSServers = $logicalNetwork.Subnets.DNS

            $IPPool = New-SCStaticIPAddressPool -LogicalNetworkDefinition $sNetwork -Name "$($LogicalNetwork.Name) - $($config.NCHostGroupName) Pool" -Subnet $sNetwork.SubnetVLans.Subnet -IPAddressRangeStart  $logicalNetwork.Subnets.PoolStart `
                -IPAddressRangeEnd $logicalNetwork.Subnets.PoolEnd -DNSServer $DNSServers -DefaultGateway $Gateway
        }
        else {
            $IPPool = New-SCStaticIPAddressPool -LogicalNetworkDefinition $sNetwork -Name "$($LogicalNetwork.Name) - $($config.NCHostGroupName) Pool" -Subnet $sNetwork.SubnetVLans.Subnet -IPAddressRangeStart $logicalNetwork.Subnets.PoolStart -IPAddressRangeEnd $logicalNetwork.Subnets.PoolEnd -DNSServer $logicalNetwork.Subnets.DNS
        }   
    }
    #VMnetwork
    $VMNetwork = Get-SCVMNetwork -Name "$($LogicalNetwork.Name)" -LogicalNetwork $lNetwork -ErrorAction SilentlyContinue
    if (($VMNetwork.count -eq 0) ) {
        $VMNetwork = New-SCVMNetwork -Name "$($LogicalNetwork.Name)" -LogicalNetwork $lNetwork
    }
}

#Create Logical Switch
foreach ($LogicalSwitchConfig in $LogicalSwitches.LogicalSwitches) {
    
    $logicalSwitch = Get-SCLogicalSwitch | Where-Object {$_.Name -eq $LogicalSwitchConfig.Name }
    if ($logicalSwitch -eq $null) {
        #Create Switch
        $virtualSwitchExtensions = @()
        #$virtualSwitchExtensions += Get-SCVirtualSwitchExtension -Name "Microsoft Windows Filtering Platform"
        $logicalSwitch = New-SCLogicalSwitch -Name $LogicalSwitchConfig.Name -Description $LogicalSwitchConfig.Description -EnableSriov $false -SwitchUplinkMode $LogicalSwitchConfig.UplinkMode -MinimumBandwidthMode $LogicalSwitchConfig.BandwidthMode -VirtualSwitchExtensions $virtualSwitchExtensions
    }
    elseif (($logicalSwitch.MinimumBandwidthMode -ne $LogicalSwitchConfig.BandwidthMode)) {
        $logicalSwitch | Set-SCLogicalSwitch -MinimumBandwidthMode $LogicalSwitchConfig.BandwidthMode
    }

    #Create Port Profiles
    foreach ($PortProfile in $LogicalSwitchConfig.PortProfiles) {
        $portClassification = $null
        $nativeProfile = $null
        $portClassification = Get-SCPortClassification -Name $PortProfile.PortClassification
        $nativeProfile = Get-SCVirtualNetworkAdapterNativePortProfile -Name $PortProfile.NativePortProfile
        if ((Get-SCVirtualNetworkAdapterPortProfileSet -Name $portClassification.Name -LogicalSwitch $logicalSwitch) -eq $null) {
            New-SCVirtualNetworkAdapterPortProfileSet -Name $portClassification.Name -PortClassification $portClassification -LogicalSwitch $logicalSwitch -VirtualNetworkAdapterNativePortProfile $nativeProfile
        }
    }
    
    #Create Uplink Profile
    # Get Logical Network Definitions
    $definitions = @()
    foreach ($LogicalNetworkDefinitionConfig in $LogicalSwitchConfig.UplinkProfile.LogicalNetworkDefinitions) {
        $uplinkLogicalnetwork = $null
        $uplinkLogicalnetwork = Get-SCLogicalNetwork -Name $LogicalNetworkDefinitionConfig.LogicalNetwork
        $definitions += Get-SCLogicalNetworkDefinition -LogicalNetwork $uplinkLogicalnetwork -VMHostGroup $HostGroups
    }
    $nativeUppVar = $null
    $nativeUppVar = Get-SCNativeUplinkPortProfile -Name $LogicalSwitchConfig.UplinkProfile.Name
    if ($nativeUppVar -eq $null) {
        $nativeUppVar = New-SCNativeUplinkPortProfile -Name $LogicalSwitchConfig.UplinkProfile.Name -Description $LogicalSwitchConfig.UplinkProfile.Description -LogicalNetworkDefinition $definitions -EnableNetworkVirtualization $false -LBFOLoadBalancingAlgorithm $LogicalSwitchConfig.UplinkProfile.LBFOLoadBalancingAlgorithm -LBFOTeamMode $LogicalSwitchConfig.UplinkProfile.LBFOTeamMode
    }
    elseif (($nativeUppVar.LBFOLoadBalancingAlgorithm -ne $LogicalSwitchConfig.UplinkProfile.LBFOLoadBalancingAlgorithm)) {
        $nativeUppVar = Set-SCNativeUplinkPortProfile -NativeUplinkPortProfile $nativeUppVar -LBFOLoadBalancingAlgorithm $LogicalSwitchConfig.UplinkProfile.LBFOLoadBalancingAlgorithm
    }

    $uppSetVar = $null
    $uppSetVar = Get-SCUplinkPortProfileSet -Name $LogicalSwitchConfig.UplinkProfile.Name -LogicalSwitch $logicalSwitch
    if ($uppSetVar -eq $null) {
        $uppSetVar = New-SCUplinkPortProfileSet -Name $LogicalSwitchConfig.UplinkProfile.Name -LogicalSwitch $logicalSwitch -NativeUplinkPortProfile $nativeUppVar
    }

    #Create vNics
    foreach ($vNicConfig in $LogicalSwitchConfig.vNics) {
        $vNic = $null
        $vmNetwork = $null
        $vmNetwork = Get-SCVMNetwork -Name $vNicConfig.VMNetworkName
        $SubnetVlan = (get-SCLogicalNetworkDefinition -LogicalNetwork $VMNetwork.LogicalNetwork).SubnetVLans
        $vNICPortClassification = Get-SCPortClassification -Name $vNicConfig.PortClassification
        $vNic = (Get-SCLogicalSwitchVirtualNetworkAdapter -Name $vNicConfig.Name -UplinkPortProfileSet $uppSetVar)
        
        if (($vNic -eq $null) -and !($subnetVLAN.IsVLanEnabled)) {
            $vNic = New-SCLogicalSwitchVirtualNetworkAdapter -Name $vNicConfig.Name -UplinkPortProfileSet $uppSetVar -VMNetwork $vmNetwork -VLanEnabled $subnetVLAN.IsVLanEnabled -IsUsedForHostManagement $vNicConfig.UsedForManagement -InheritsAddressFromPhysicalNetworkAdapter $vNicConfig.InheritsAddressFromPhysicalNetworkAdapter -IPv4AddressType $vNicConfig.IPv4AddressType
            
        }
        elseif ($vNic -eq $null -and ($subnetVLAN.IsVLanEnabled)) {
            $vNic = New-SCLogicalSwitchVirtualNetworkAdapter -Name $vNicConfig.Name -UplinkPortProfileSet $uppSetVar -VMNetwork $vmNetwork -VLanEnabled $subnetVLAN.IsVLanEnabled -VLanID $SubnetVlan.VLanID -IsUsedForHostManagement $vNicConfig.UsedForManagement -InheritsAddressFromPhysicalNetworkAdapter $vNicConfig.InheritsAddressFromPhysicalNetworkAdapter -IPv4AddressType $vNicConfig.IPv4AddressType
            
        }

        if ($vNICPortClassification -ne $null) {
            Set-SCLogicalSwitchVirtualNetworkAdapter -LogicalSwitchVirtualNetworkAdapter $vNic -PortClassification $vNICPortClassification  -IsUsedForHostManagement $vNicConfig.UsedForManagement -InheritsAddressFromPhysicalNetworkAdapter $vNicConfig.InheritsAddressFromPhysicalNetworkAdapter 
        }
    }   
}
#endregion Prepare Network

#region Prepare Hosts

#region install features for management (Client needs RSAT, Server/Server Core have different features)
Write-host "Adding RSAT Tools" -ForegroundColor Green
$WindowsInstallationType = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
if ($WindowsInstallationType -eq "Server") {
    Install-WindowsFeature -Name RSAT-Clustering, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, RSAT-Hyper-V-Tools, RSAT-Feature-Tools-BitLocker-BdeAducExt, RSAT-NetworkController
}
elseif ($WindowsInstallationType -eq "Server Core") {
    Install-WindowsFeature -Name RSAT-Clustering, RSAT-Clustering-PowerShell, RSAT-Hyper-V-Tools, RSAT-NetworkController
}
elseif ($WindowsInstallationType -eq "Client") {
    #Validate RSAT Installed
    if (!((Get-HotFix).hotfixid -contains "KB2693643") ) {
        Write-Host "Please install RSAT, Exitting in 5s"
        Start-Sleep 5
        Exit
    }
    #Install Hyper-V Management features
    if ((Get-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -ne "Enabled") {
        #Install all features and then remove all except Management (fails when installing just management)
        Enable-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-All -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart
        $Q = Read-Host -Prompt "Restart is needed. Do you want to restart nowWhere-Object Y/N"
        If ($Q -eq "Y") {
            Write-Host "Restarting Computer"
            Start-Sleep 3
            Restart-Computer
        }
        else {
            Write-Host "You did not type Y, please restart Computer. Exitting"
            Start-Sleep 3
            Exit
        }
    }
    elseif ((get-command -Module Hyper-V) -eq $null) {
        $Q = Read-Host -Prompt "Restart is needed to load Hyper-V Management. Do you want to restart nowWhere-Object Y/N"
        If ($Q -eq "Y") {
            Write-Host "Restarting Computer"
            Start-Sleep 3
            Restart-Computer
        }
        else {
            Write-Host "You did not type Y, please restart Computer. Exitting"
            Start-Sleep 3
            Exit
        }
    }
}
#endregion

#region Configure basic settings on servers 
Write-host "Configure Basic settings on Hosts" -ForegroundColor Green

#Enable FW Rules and PSRemoting
Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetFirewallRule -Name *FPS* | Enable-NetFirewallRule ; Enable-PSRemoting -Force -Confirm:$false }
Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetFirewallRule -Name *rpc* | Enable-NetFirewallRule }
Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetFirewallRule -Name *wmi* | Enable-NetFirewallRule }

#Configure DataDisk
Invoke-Command -ComputerName $servers -ScriptBlock {   
                Get-Disk | Where-Object {$_.Size -eq 150GB } |
                Where partitionstyle -eq 'raw' |
                Initialize-Disk -PartitionStyle MBR -PassThru |
                New-Partition -DriveLetter D -UseMaximumSize |
                Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false
        }

#Configure Active memory dump
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
    Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
}

#install roles and features
#install Hyper-V using DISM (if nested virtualization is not enabled install-windowsfeature would fail)
Invoke-Command -ComputerName $servers -ScriptBlock {Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart}
            
#define features
$features = "Failover-Clustering", "Hyper-V-PowerShell"
                
#install features
foreach ($server in $servers) {Install-WindowsFeature -Name $features -ComputerName $server -IncludeManagementTools} 
#restart and wait for computers
Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region Add hosts
Write-host "Adding Hosts to VMM" -ForegroundColor Green
$DomainAdmin = get-SCRunAsAccount -Name $VMMHostAccessAccountName
$HostGroup = Get-SCVMHostGroup -Name $config.NCHostGroupName

$Servers | Foreach-Object { Add-SCVMHost -VMHostGroup $HostGroup -ComputerName $_ -Credential $DomainAdmin -RunAsynchronously}
start-sleep 180
Get-SCVMHost | Restart-SCVMHost -RunAsynchronously -Confirm:$false
start-sleep 60
Get-SCVMHost |Set-SCVMHost -VMPaths "D:\" 
#endregion Add hosts

Start-Sleep 120

$Servers | Foreach-Object {
    # Get Host
    $JobGuid = New-Guid
    $vmHost = Get-SCVMHost -ComputerName $_
    $logicalSwitch = Get-SCLogicalSwitch -Name $LogicalSwitches.LogicalSwitches[0].Name
    $uplinkPortProfileSet = Get-SCUplinkPortProfileSet -LogicalSwitch $logicalSwitch -Name $LogicalSwitches.LogicalSwitches[0].UplinkProfile.Name


    # Get Host Network Adapter 'Microsoft Hyper-V Network Adapter'
    $networkAdapter = Get-SCVMHostNetworkAdapter -VMHost $vmHost
    $networkAdapter | Set-SCVMHostNetworkAdapter -UplinkPortProfileSet $uplinkPortProfileSet -JobGroup $JobGuid

    New-SCVirtualNetwork -VMHost $vmHost -VMHostNetworkAdapters $networkAdapter -LogicalSwitch $logicalSwitch -DeployVirtualNetworkAdapters -JobGroup $JobGuid
    
    Set-SCVMHost -VMHost $vmHost -JobGroup $JobGuid -RunAsynchronously
}

#verify status of deployment jobs.
$jobs = Get-SCJob | Where-Object {($_.Name -like "Change properties of virtual machine host*") -and ($_.StartTime -le (get-date).AddMinutes(10))}| Sort-Object Name

foreach ($Job in $jobs) {
    If ($job.status -eq "Running") {
        Write-Output "Waiting for $($job.Name.Substring(41,($job.Name.Length-41))) to Finish"
        do {
            [System.Console]::Write("Progress {0}`r", $job.Progress)
            Start-Sleep 1
        } until (($job.status -eq "Completed") -or ($job.status -eq "Failed"))
    }
    if ($job.status -eq "Completed") {
        Write-Output "Job $($job.Name.Substring(41,($job.Name.Length-41))) Finished"
    }
    if ($job.status -eq "failed") {
        Write-Error "Job $($job.Name.Substring(41,($job.Name.Length-41))) Failed"
    }
}

start-sleep 15
Get-SCVMHost | Read-SCVMHost
#endregion Prepare Hosts
#endregion

Start-Sleep 300

#region Start SDN Express Deployment
Expand-Archive -Path E:\SDN-Master.zip -DestinationPath E:\
Set-Location "E:\SDN-master\VMM\VMM SDN Express"

##############################################################################################################################
## NOTES
## VMM SDN EXPRESS deployment can be unstable.
## On failure run the script block in the catch to clear our the entire SDN deployment and rerun VMMExpress.ps1
## It will succeed at some point :) happy deploying
##############################################################################################################################


try {
    .\VMMExpress.ps1 -ConfigurationDataFile "E:\library\Fabricconfig.psd1" -verbose
}
catch {
    Write-Host "$($_.Exception.Message) `nAt Line number: $($_.InvocationInfo.PositionMessage)" -ForegroundColor Red
    $Undo = "N"
    $Undo = Read-Host -Prompt "Undo Press Y"
    if ($Undo -eq "Y") {
        #Manually clean on failure
        #EDGEGW
        if(Get-SCNetworkService -ServiceType NetworkManager){
            (Get-SCFabricRole -Type Gateway -NetworkService(Get-SCNetworkService -ServiceType NetworkManager)).ConnectedResources |  Remove-SCFabricRoleResource
            start-sleep 15
            (Get-SCFabricRole -Type Gateway -NetworkService(Get-SCNetworkService -ServiceType NetworkManager)) | Set-SCFabricRole -GatewayConfiguration $null
        }
        Get-SCService | Where-Object {$_.Name -eq "Gateway Manager"} | Remove-SCService
        Get-SCServiceConfiguration | Where-Object {$_.Name -eq "Gateway Manager"} | Remove-SCServiceConfiguration 
        Get-SCServiceTemplate | Where-Object {$_.name -eq "Gateway Deployment service Template"} | Remove-SCServiceTemplate
        
        #Manually clean on failure
        #SLBMUX
        if(Get-SCNetworkService -ServiceType NetworkManager){
            (Get-SCFabricRole -Type LoadBalancer -NetworkService(Get-SCNetworkService -ServiceType NetworkManager)).ConnectedResources | Remove-SCFabricRoleResource
        }
        Get-SCService -Name "Software Load Balancer" | Remove-SCService
        Get-SCServiceConfiguration -Name "Software Load Balancer" | Remove-SCServiceConfiguration 
        Get-SCServiceTemplate -name "SLB Deployment service Template" | Remove-SCServiceTemplate

        #Clean up NC
        if(Get-SCNetworkService -ServiceType NetworkManager){
            Get-SCNetworkService -ServiceType NetworkManager | Set-SCNetworkService -RemoveLogicalNetworkVIP (Get-SCLogicalNetwork | Where-Object {$_.Name -notlike "*management*"}) -RemoveLogicalNetworkDedicatedIP (Get-SCLogicalNetwork | Where-Object {$_.Name -notlike "*management*"})
        }
        Get-SCVMNetwork | Where-Object {$_.Name -ne "management"} | Remove-SCVMNetwork
        Get-SCStaticIPAddressPool | Where-Object {$_.Name -notlike "*management*"} | Foreach-Object {Get-SCIPAddress -StaticIPAddressPool $_ | Revoke-SCIPAddress }
        Get-SCStaticIPAddressPool | Where-Object {$_.Name -notlike "*management*"} | Remove-SCStaticIPAddressPool -Force

        $portProfile = Get-SCNativeUplinkPortProfile -Name "SDN Switch Uplink"
        Set-SCNativeUplinkPortProfile -NativeUplinkPortProfile $portProfile -RemoveLogicalNetworkDefinition ($portProfile.LogicalNetworkDefinitions | Where-Object {$_.Name -notlike "*management*"})

        Get-SCLogicalNetworkDefinition | Where-Object {$_.Name -notlike "*management*"} | Remove-SCLogicalNetworkDefinition -Force

        Get-SCLogicalNetwork | Where-Object {$_.Name -notlike "*management*"} | Remove-SCLogicalNetwork -Force
        Get-SCNetworkService -ServiceType NetworkManager | Remove-SCNetworkService

        Get-SCService -Name "NC" | Remove-SCService
        Get-SCServiceConfiguration -Name "NC" | Remove-SCServiceConfiguration 
        Get-SCServiceTemplate -name "NC Deployment service Template" | Remove-SCServiceTemplate

        get-scrunasaccount | Where-Object {$_.name -like "NC*"} |  remove-scrunasaccount

        Get-SCCustomResource | Where-Object {$_.SharePath -like "*EdgeDeployment.cr*"} | Remove-SCCustomResource
        Get-SCCustomResource | Where-Object {$_.SharePath -like "*NCCertificate.cr*"} | Remove-SCCustomResource
        Get-SCCustomResource | Where-Object {$_.SharePath -like "*NCSetup.cr*"} | Remove-SCCustomResource
        Get-SCCustomResource | Where-Object {$_.SharePath -like "*ServerCertificate.cr*"} | Remove-SCCustomResource
        Get-SCCustomResource | Where-Object {$_.SharePath -like "*TrustedRootCertificate.cr*"} | Remove-SCCustomResource

        Get-DnsServerResourceRecord -ZoneName $config.ManagementDomainFDQN -ComputerName $config.ManagementDomainFDQN | Where-Object {$_.Hostname -LIke "NC*"} | Remove-DnsServerResourceRecord  -ZoneName $config.ManagementDomainFDQN -ComputerName $config.ManagementDomainFDQN -Force -Confirm:$false
        Clear-DnsClientCache
    }
    throw
    Write-Error "SDN DEPLOYMENT FAILED"
}

Start-sleep 300
#endregion Start SDN Express Deployment

#region finish SDN Config
write-host "Finish SDN Config" -ForegroundColor Cyan
$runAsAccount = Get-SCRunAsAccount -name "NC_MgmtAdminRAA"
$networkService = Get-SCNetworkService | Where-Object {$_.Model -eq "Microsoft Network Controller"}

$fabricRoleSLB = Get-SCFabricRole -Type LoadBalancer -NetworkService $networkService

$bgpPeers = @()
$bgpPeers += New-SCNCBGPPeer -RouterName "BGPRouter" -RouterIPAddress ($config.LogicalNetworks | Where-Object {$_.Name -eq "Transit"}).subnets.Gateways -RouterAsn 65000
$bgpRouter = New-SCNCBGPRouter -LocalASN 65530 -RouterPeers $bgpPeers
$fabricRoleSLB.ServiceVMs | Foreach-Object {Set-SCFabricRoleResource -FabricRoleResource $_ -NCBGPRouter $bgpRouter}

$fabricRoleGW = Get-SCFabricRole -Type Gateway -NetworkService $networkService
$bgpPeers = @()
$bgpPeers += New-SCNCBGPPeer -RouterName "BGPRouter" -RouterIPAddress ($config.LogicalNetworks | Where-Object {$_.Name -eq "Transit"}).subnets.Gateways -RouterAsn 65000
$bgpRouter = New-SCNCBGPRouter -LocalASN 65530 -RouterPeers $bgpPeers
$fabricRoleGW.ServiceVMs | Foreach-Object {Set-SCFabricRoleResource -FabricRoleResource $_ -NCBGPRouter $bgpRouter}

# Configure network affinity
$directIpLogicalnetworkToAdd = @()
$directIpLogicalnetworkToAdd += Get-SCLogicalNetwork -Name 'HNVPA'
$virtualIpLogicalNetworkToAdd = @()
$virtualIpLogicalNetworkToAdd += Get-SCLogicalNetwork -Name 'PublicVIP'
$virtualIpLogicalNetworkToAdd += Get-SCLogicalNetwork -Name 'PrivateVIP'
Set-SCNetworkService -NetworkService $networkService -AddLogicalNetworkDedicatedIP $directIpLogicalnetworkToAdd -AddLogicalNetworkVIP $virtualIpLogicalNetworkToAdd
#endregion finish SDN Config

#region Peer BGP
write-host "Configure BGPPeering" -ForegroundColor Cyan
$RouterCIM = New-CimSession -ComputerName $RouterName
$BGPRouterIP = ($config.LogicalNetworks | Where-Object {$_.Name -eq "Transit"}).subnets.Gateways

$RouterASN = 65000
Add-BgpRouter -BgpIdentifier $BGPRouterIP -LocalASN $RouterASN -CimSession $RouterCIM

$networkService = Get-SCNetworkService | Where-Object {$_.Model -eq "Microsoft Network Controller"}
$fabricRoleSLB = Get-SCFabricRole -Type LoadBalancer -NetworkService $networkService
$fabricRoleGW = Get-SCFabricRole -Type Gateway -NetworkService $networkService

$SLBVMs = $fabricRoleSLB.ServiceVMs
$GWVMs = $fabricRoleGW.ServiceVMs

foreach ($SLBVM in $SLBVMs) {
    $vm = $null
    $vm = $SLBVM.Resource
    $VMIp = $null
    $VMIp = ($vm.VirtualNetworkAdapters | Where-Object {$_.IPv4Addresses -like "$(($config.LogicalNetworks | Where-Object {$_.Name -eq "Transit"}).subnets.Gateways.TrimEnd(".1")).*"}).IPv4Addresses[0]
    Get-BgpPeer -CimSession $RouterCIM | Where-Object {$_.Name -eq $vm.Name} | Remove-BgpPeer  -CimSession $RouterCIM
    add-bgppeer -Name $vm.Name -LocalIPAddress $BGPRouterIP -PeerIPAddress $VMIp -LocalASN $RouterASN -PeerASN $SLBVM.LoadBalancerConfig.BGPRouter.LocalAsn -OperationMode Mixed -PeeringMode Automatic -CimSession $RouterCIM
}

foreach ($GWVM in $GWVMs) {
    $vm = $null
    $vm = $GWVM.Resource
    $VMIp = $null
    $VMIp = ($vm.VirtualNetworkAdapters | Where-Object {$_.IPv4Addresses -like "$(($config.LogicalNetworks | Where-Object {$_.Name -eq "Transit"}).subnets.Gateways.TrimEnd(".1")).*"}).IPv4Addresses[0]
    Get-BgpPeer -CimSession $RouterCIM | Where-Object {$_.Name -eq $vm.Name} | Remove-BgpPeer  -CimSession $RouterCIM
    add-bgppeer -Name $vm.Name -LocalIPAddress $BGPRouterIP -PeerIPAddress $VMIp -LocalASN $RouterASN -PeerASN $GWVM.GatewayConfig.BGPRouter.LocalAsn -OperationMode Mixed -PeeringMode Automatic -CimSession $RouterCIM
}

#endregion Peer BGP

Write-Host "Completed...!" -ForegroundColor Green
#endregion