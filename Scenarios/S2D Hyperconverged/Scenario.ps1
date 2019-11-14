################################
# Run from DC or Management VM #
################################

$StartDateTime = get-date
Write-host "Script started at $StartDateTime"

#region LAB Config

    # 2,3,4,8, or 16 nodes
        $numberofnodes=4
        $ServersNamePrefix="S2D"
    #generate servernames (based number of nodes and serversnameprefix)
        $Servers=1..$numberofnodes | ForEach-Object {"$ServersNamePrefix$_"}
        #alternatively you can just do $Servers="S2D1","S2D2","S2D3","S2D4". The result is the same

    #Cluster Name
        $ClusterName="S2D-Cluster"

    #Cluster-Aware-Updating role name
        $CAURoleName="S2D-Clus-CAU"

    #Witness type
        $WitnessType="FileShare" #or Cloud
        #if cloud then configure following (use your own, these are just examples)
        <#
        $CloudWitnessStorageAccountName="MyStorageAccountName"
        $CloudWitnessStorageKey="qi8QB/VSHHiA9lSvz1kEIEt0JxIucPL3l99nRHhkp+n1Lpabu4Ydi7Ih192A4VW42vccIgUnrXxxxxxxxxxxxx=="
        $CloudWitnessEndpoint="core.windows.net“
        #>

    #Disable CSV Balancer
        $DisableCSVBalancer=$False

    #Perform Windows update? (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
        $WindowsUpdate=$false

    ## Networking ##
        $ClusterIP="10.0.0.111" #If blank (you can write just $ClusterIP="", DHCP will be used)

        $NumberOfStorageNets=1 #1 or 2

        #IF Stornet is 1
        $StorNet="172.16.1."
        $StorVLAN=1

        #IF Stornets are 2
        $StorNet1="172.16.1."
        $StorNet2="172.16.2."
        $StorVLAN1=1
        $StorVLAN2=2

        $SRIOV=$true #Deploy SR-IOV enabled switch (best practice is to enable if possible)

    #start IP for storage network
        $IP=1

    #Real hardware?
        $RealHW=$False #will configure VMQ not to use CPU 0 if $True, configures power plan
        $DellHW=$False #include Dell recommendation to increase HW timeout to 10s becayse of their Hitachi HDDs. May be already obsolete.

    #IncreaseHW Timeout for virtual environments to 30s? https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-direct-in-vm
        $VirtualEnvironment=$true

    #Configure dcb? (more info at http://aka.ms/ConvergedRDMA)
        $DCB=$False #$true for ROCE, $false for iWARP

    #iWARP?
        $iWARP=$False

    #DisableNetBIOS on all vNICs? $True/$False It's optional. Works well with both settings default/disabled
        $DisableNetBIOS=$False

    #Number of Disks Created. If >4 nodes, then x Mirror-Accelerated Parity and x Mirror disks are created
        $NumberOfDisks=$numberofnodes

    #SMB Bandwith Limits for Live Migration? https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
        $SMBBandwidthLimits=$true

    #Additional Features
        $Bitlocker=$false #Install "Bitlocker" and "RSAT-Feature-Tools-BitLocker" on nodes?
        $StorageReplica=$false #Install "Storage-Replica" and "RSAT-Storage-Replica" on nodes?
        $Deduplication=$false #install "FS-Data-Deduplication" on nodes?
        $SystemInsights=$false #install "System-Insights" on nodes?

    #Enable Meltdown mitigation? https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
    #CVE-2017-5754 cannot be used to attack across a hardware virtualized boundary. It can only be used to read memory in kernel mode from user mode. It is not a strict requirement to set this registry value on the host if no untrusted code is running and no untrusted users are able to logon to the host.
        $MeltdownMitigationEnable=$false

    #Enable Microarchitectural Data Sampling Mitigation? https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
        $MicroarchitecturalDataSamplingMitigation=$false

    #Enable speculative store bypass mitigation? https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in , https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180012
        $SpeculativeStoreBypassMitigation=$false

    #Configure PCID to expose to VMS prior version 8.0 https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
        $ConfigurePCIDMinVersion=$true

    #Configure Core scheduler on Windows Server 2016? https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types#configuring-the-hypervisor-scheduler-type-on-windows-server-2016-hyper-v
        $CoreScheduler=$True

    #Memory dump type (Active or Kernel) https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
        $MemoryDump="Active"

    #real VMs? If true, script will create real VMs on mirror disks from vhd you will provide during the deployment. The most convenient is to provide NanoServer
        $realVMs=$false
        $NumberOfRealVMs=2 #number of VMs on each mirror disk

    #ask for parent VHDx if real VMs will be created
        if ($realVMs){
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
        }

#endregion

#region install features for management (Client needs RSAT, Server/Server Core have different features)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    $CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
        #Validate RSAT Installed
            if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                Write-Host "Please install RSAT, Exitting in 5s"
                Start-Sleep 5
                Exit
            }
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
        #Install RSAT tools
            $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            foreach ($Capability in $Capabilities){
                Add-WindowsCapability -Name $Capability -Online
            }
    }
    if ($WindowsInstallationType -eq "Client"){
        #Install Hyper-V Management features
            if ((Get-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -ne "Enabled"){
                #Install all features and then remove all except Management (fails when installing just management)
                Enable-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-All -NoRestart
                Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart
                $Q=Read-Host -Prompt "Restart is needed. Do you want to restart now? Y/N"
                If ($Q -eq "Y"){
                    Write-Host "Restarting Computer"
                    Start-Sleep 3
                    Restart-Computer
                }else{
                    Write-Host "You did not type Y, please restart Computer. Exitting"
                    Start-Sleep 3
                    Exit
                }
            }elseif((Get-command -Module Hyper-V) -eq $null){
                $Q=Read-Host -Prompt "Restart is needed to load Hyper-V Management. Do you want to restart now? Y/N"
                If ($Q -eq "Y"){
                    Write-Host "Restarting Computer"
                    Start-Sleep 3
                    Restart-Computer
                }else{
                    Write-Host "You did not type Y, please restart Computer. Exitting"
                    Start-Sleep 3
                    Exit
                }
            }
    }
#endregion

#region Update all servers (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
    if ($WindowsUpdate){
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $releaseid=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name ReleaseId).ReleaseID
            if ($releaseid -eq 1607){
                $Instance = New-CimInstance -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
                #find updates
                $ScanResult=$instance | Invoke-CimMethod -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0";OnlineScan=$true}
                #apply updates (if not empty)
                $CriticalUpdates= $ScanResult.updates | Where-Object MsrcSeverity -eq Critical
                if ($CriticalUpdates){
                    $instance | Invoke-CimMethod -MethodName DownloadUpdates -Arguments @{Updates=[ciminstance[]]$CriticalUpdates}
                    $instance | Invoke-CimMethod -MethodName InstallUpdates  -Arguments @{Updates=[ciminstance[]]$CriticalUpdates}
                }
            }else{
                #Grab updates
                $ScanResult=Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0"}
                #apply updates (if not empty)
                if ($ScanResult.Updates){
                    Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName InstallUpdates -Arguments @{Updates=$ScanResult.Updates}
                }
            }
        }
    }

#endregion

#region Configure basic settings on servers
    #Tune HW timeout to 10 seconds (6 seconds is default) in Dell servers (may be obsolete as it applies to Dell 730xd with Hitachi HDDs)
        if ($DellHW){
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
        }

    #IncreaseHW Timeout for virtual environments to 30s
        if ($VirtualEnvironment){
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530}
        }

    #configure memory dump
        if ($MemoryDump -eq "Kernel"){
        #Configure Kernel memory dump
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 2
            }
        }
        if ($MemoryDump -eq "Active"){
            #Configure Active memory dump
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
            }
        }

    #enable meltdown mitigation
        if ($MeltdownMitigationEnable){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #enable Speculative Store Bypass mitigation
        if ($SpeculativeStoreBypassMitigation){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #enable Microarchitectural Data Sampling mitigation
        if ($MicroarchitecturalDataSamplingMitigation){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                #Detect HT
                $processor=Get-WmiObject win32_processor | Select-Object -First 1
                if ($processor.NumberOfCores -eq $processor.NumberOfLogicalProcessors/2){
                    $HT=$True
                }
                if ($HT -eq $True){
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 72
                }else{
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8264
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #Configure MinVmVersionForCpuBasedMitigations (only needed if you are running VM versions prior 8.0)
        if ($ConfigurePCIDMinVersion){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization")){
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name Virtualization -Force
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -value "1.0"
            }
        }

    #Enable core scheduler
    if ($CoreScheduler){
        $RevisionNumber=Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name UBR
        }
        $CurrentBuildNumber=Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
        }
        if ($CurrentBuildNumber -eq 14393 -and $RevisionNumber -ge 2395){
            Invoke-Command -ComputerName $Servers {
                bcdedit /set hypervisorschedulertype Core
            }
        }
    }

    #install roles and features
        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
            if ($result.ExitCode -eq "failed"){
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            }
        }

        #define features
        $features="Failover-Clustering","Hyper-V-PowerShell"
        if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
        if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
        if ($Deduplication){$features+="FS-Data-Deduplication"}
        if ($SystemInsights){$features+="System-Insights","RSAT-System-Insights"}

        #install features
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA )
    #Create Virtual Switches and Virtual Adapters
        if ($SRIOV){
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        }else{
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name SETSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
        }

        #Configure Hyper-V Port Load Balancing algorithm (in 1709 its already Hyper-V, therefore setting only for Windows Server 2016)
            Invoke-Command -ComputerName $servers -scriptblock {
                if ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber) -eq 14393){
                    Set-VMSwitchTeam -Name SETSwitch -LoadBalancingAlgorithm HyperVPort
                }
            }

        $Servers | ForEach-Object {
            #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name SETSwitch -NewName Mgmt -ComputerName $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName SETSwitch -CimSession $_
            Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName SETSwitch -Cimsession $_

            #configure IP Addresses
            If ($NumberOfStorageNets -eq 1){
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                $IP++
                New-NetIPAddress -IPAddress ($StorNet+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }

            If($NumberOfStorageNets -eq 2){
                New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
                New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
                $IP++
            }
        }

        Start-Sleep 5
        Clear-DnsClientCache

        #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
            If ($NumberOfStorageNets -eq 1){
                Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN -Access -ManagementOS -CimSession $Servers
                Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN -Access -ManagementOS -CimSession $Servers
            }else{
                Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $Servers
                Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $Servers
            }

        #Restart each host vNIC adapter so that the Vlan is active.
            Restart-NetAdapter "vEthernet (SMB01)" -CimSession $Servers 
            Restart-NetAdapter "vEthernet (SMB02)" -CimSession $Servers

        #Enable RDMA on the host vNIC adapters
            Enable-NetAdapterRDMA "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $Servers

        #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
            Invoke-Command -ComputerName $servers -ScriptBlock {
                    $physicaladapters=(get-vmswitch SETSwitch).NetAdapterInterfaceDescriptions | Sort-Object
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
                    Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
                }

        #Disable NetBIOS on all vNICs https://msdn.microsoft.com/en-us/library/aa393601(v=vs.85).aspx
            if ($DisableNetBIOS){
                $vNICs = Get-NetAdapter -CimSession $Servers | Where-Object Name -like vEthernet*
                foreach ($vNIC in $vNICs){
                    Write-Host "Disabling NetBIOS on $($vNIC.Name) on computer $($vNIC.PSComputerName)"
                    $output=Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $vNIC.PSComputerName | Where-Object Description -eq $vNIC.InterfaceDescription | Invoke-WmiMethod -Name settcpipNetBIOS -ArgumentList 2
                    if ($output.Returnvalue -eq 0){
                        Write-Host "`t Success" -ForegroundColor Green
                    }else{
                        Write-Host "`t Failure"
                    }
                }
            }

    #Verify Networking
        #verify mapping
            Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | ft ComputerName,NetAdapterName,ParentAdapter 
        #Verify that the VlanID is set
            Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | ft ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName
        #verify RDMA
            Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | ft systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
        #verify ip config 
            Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | ft pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername

    #configure DCB if requested
        if ($DCB -eq $True){
            #Install DCB
                if (!$NanoServer){
                    foreach ($server in $servers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 
                }
            ##Configure QoS
                New-NetQosPolicy "SMB"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers
                New-NetQosPolicy "ClusterHB" -Cluster                         -PriorityValue8021Action 7 -CimSession $servers
                New-NetQosPolicy "Default"   -Default                         -PriorityValue8021Action 0 -CimSession $servers

            #Turn on Flow Control for SMB
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

            #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
                Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

            #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

            #Configure IeeePriorityTag
                #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}

            #validate flow control setting
                Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | ft PSComputerName,Priority,Enabled -GroupBy PSComputerName

            #Validate DCBX setting
                Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName

            #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

            #validate policy
                Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName

            #Create a Traffic class and give SMB Direct 60% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB"       -Priority 3 -BandwidthPercentage 60 -Algorithm ETS}
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "ClusterHB" -Priority 7 -BandwidthPercentage 1 -Algorithm ETS}
        }

    #enable iWARP firewall rule if requested
        if ($iWARP -eq $True){
            Enable-NetFirewallRule -Name "FPSSMBD-iWARP-In-TCP" -CimSession $servers
        }

#endregion

#region Create HyperConverged cluster and configure basic settings
    Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
    if ($ClusterIP){
        New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
    }else{
        New-Cluster -Name $ClusterName -Node $servers
    }
    Start-Sleep 5
    Clear-DnsClientCache

    #Configure CSV Cache (value is in MB)
        if (Get-PhysicalDisk -cimsession $servers[0] | Where-Object bustype -eq SCM){
            #disable CSV cache if SCM storage is used
            (Get-Cluster $ClusterName).BlockCacheSize = 0
        }elseif ((Invoke-Command -ComputerName $servers[0] -ScriptBlock {(get-wmiobject win32_computersystem).Model}) -eq "Virtual Machine"){
            #disable CSV cache for virtual environments
            (Get-Cluster $ClusterName).BlockCacheSize = 0
        }

    #ConfigureWitness
    if ($WitnessType -eq "FileShare"){
        ##Configure Witness on DC
        #Create new directory
            $WitnessName=$Clustername+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$ClusterName$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions 
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
    }elseif($WitnessType -eq $Cloud){
        Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $CloudWitnessStorageAccountName -AccessKey $CloudWitnessStorageKey -Endpoint $CloudWitnessEndpoint 
    }
    #Disable CSV Balancer
        if ($DisableCSVBalancer){
            (Get-Cluster $ClusterName).CsvBalancer = 0
        }

#endregion

#region Configure Cluster Networks
    #rename networks
        if ($NumberOfStorageNets -eq 1){
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet"0").Name="SMB"
        }else{
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB1"
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB2"
        }
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq "10.0.0.0").Name="Management"

    #configure Live Migration 
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -eq "Management"}).ID))
        Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers

    #Configure SMB Bandwidth Limits for Live Migration https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
        if ($SMBBandwidthLimits){
            #install feature
            Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name "FS-SMBBW"}
            #Calculate 40% of capacity of NICs in vSwitch (considering 2 NICs, if 1 fails, it will not consume all bandwith, therefore 40%)
            $Adapters=(Get-VMSwitch -CimSession $Servers[0]).NetAdapterInterfaceDescriptions
            $BytesPerSecond=((Get-NetAdapter -CimSession $Servers[0] -InterfaceDescription $adapters).TransmitLinkSpeed | Measure-Object -Sum).Sum/8
            Set-SmbBandwidthLimit -Category LiveMigration -BytesPerSecond ($BytesPerSecond*0.4) -CimSession $Servers
        }

#endregion

#region configure Cluster-Aware-Updating
    if (!$NanoServer){
        #Install required features on nodes.
            $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
            foreach ($ClusterNode in $ClusterNodes){
                Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
            }
        #add role
            Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    }
#endregion

#region Create Fault Domains (just an example) https://docs.microsoft.com/en-us/windows-server/failover-clustering/fault-domains

#just some examples for Rack/Chassis fault domains.
    if ($numberofnodes -eq 4){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
                <Node Name="$($ServersNamePrefix)1"/>
                <Node Name="$($ServersNamePrefix)2"/>
                <Node Name="$($ServersNamePrefix)3"/>
                <Node Name="$($ServersNamePrefix)4"/>
        </Rack>
    </Site>
</Topology>
"@
    
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }
    
    if ($numberofnodes -eq 8){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Node Name="$($ServersNamePrefix)1"/>
            <Node Name="$($ServersNamePrefix)2"/>
        </Rack>
        <Rack Name="Rack02" Location="Contoso HQ, Room 4010, Aisle A, Rack 02">
            <Node Name="$($ServersNamePrefix)3"/>
            <Node Name="$($ServersNamePrefix)4"/>
        </Rack>
        <Rack Name="Rack03" Location="Contoso HQ, Room 4010, Aisle A, Rack 03">
            <Node Name="$($ServersNamePrefix)5"/>
            <Node Name="$($ServersNamePrefix)6"/>
        </Rack>
        <Rack Name="Rack04" Location="Contoso HQ, Room 4010, Aisle A, Rack 04">
            <Node Name="$($ServersNamePrefix)7"/>
            <Node Name="$($ServersNamePrefix)8"/>
        </Rack>
    </Site>
</Topology>
"@
    
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }

    if ($numberofnodes -eq 16){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Chassis Name="Chassis01" Location="Rack Unit 1 (Upper)" >
                <Node Name="$($ServersNamePrefix)1"/>
                <Node Name="$($ServersNamePrefix)2"/>
                <Node Name="$($ServersNamePrefix)3"/>
                <Node Name="$($ServersNamePrefix)4"/>
            </Chassis>
            <Chassis Name="Chassis02" Location="Rack Unit 1 (Upper)" >
                <Node Name="$($ServersNamePrefix)5"/>
                <Node Name="$($ServersNamePrefix)6"/>
                <Node Name="$($ServersNamePrefix)7"/>
                <Node Name="$($ServersNamePrefix)8"/>
            </Chassis>
            <Chassis Name="Chassis03" Location="Rack Unit 1 (Lower)" >
                <Node Name="$($ServersNamePrefix)9"/>
                <Node Name="$($ServersNamePrefix)10"/>
                <Node Name="$($ServersNamePrefix)11"/>
                <Node Name="$($ServersNamePrefix)12"/>
            </Chassis>
            <Chassis Name="Chassis04" Location="Rack Unit 1 (Lower)" >
                <Node Name="$($ServersNamePrefix)13"/>
                <Node Name="$($ServersNamePrefix)14"/>
                <Node Name="$($ServersNamePrefix)15"/>
                <Node Name="$($ServersNamePrefix)16"/>
            </Chassis>
        </Rack>
    </Site>
</Topology>
"@
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }
    
    #show fault domain configuration
        Get-ClusterFaultDomainxml -CimSession $ClusterName
    
    <#Alternate way
    if ($numberofnodes -eq 4){
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..4 | ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_"  -Parent "Rack01" -CimSession $ClusterName}
        Set-ClusterFaultDomain -Name "Rack01" -Parent "SEA"    -CimSession $ClusterName
    
    }
    
    if ($numberofnodes -eq 8){
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack02"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 02"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack03"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 03"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack04"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 04"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..2 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack01"    -CimSession $ClusterName}
        3..4 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack02"    -CimSession $ClusterName}
        5..6 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack03"    -CimSession $ClusterName}
        7..8 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack04"    -CimSession $ClusterName}
        1..4 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
    }
    
    if ($numberofnodes -eq 16){
        New-ClusterFaultDomain -Name "Chassis01" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Chassis02" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Chassis03" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName 
        New-ClusterFaultDomain -Name "Chassis04" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis01" -CimSession $ClusterName}
        5..8   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis02" -CimSession $ClusterName}
        9..12  |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis03" -CimSession $ClusterName}
        13..16 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis04" -CimSession $ClusterName}
    
        1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "Chassis0$_" -Parent "Rack01"    -CimSession $ClusterName}
        
        1..1 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
    
    }
    #>

#endregion

#region Enable Cluster S2D and check Pool and Tiers

    #Enable-ClusterS2D
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #display pool
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName

    #Display disks
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

    #Get Storage Tiers
        Get-StorageTier -CimSession $ClusterName
    
    <#alternate way
        #register storage provider 
            Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName

        #display pool
            Get-StoragePool "S2D on $ClusterName"

        #Display disks
            Get-StoragePool "S2D on $ClusterName" | Get-PhysicalDisk

        #display tiers
            Get-StorageTier

        #unregister StorageSubsystem
            $ss=Get-StorageSubSystem -FriendlyName *$ClusterName
            Unregister-StorageSubsystem -ProviderName "Windows Storage Management Provider" -StorageSubSystemUniqueId $ss.UniqueId
    #>

#endregion

#region add missing tiers (effective just for 2 node 2019 or 2016 servers)
    $StorageTiers=Get-StorageTier -CimSession $ClusterName
    $NumberOfNodes=(Get-ClusterNode -Cluster $ClusterName).Count
    $MediaTypes=(Get-PhysicalDisk -CimSession $ClusterName |where mediatype -ne Unspecified | Where-Object usage -ne Journal).MediaType | Select-Object -Unique
    $ClusterFunctionalLevel=(Get-Cluster -Name $ClusterName).ClusterFunctionalLevel

    Foreach ($MediaType in $MediaTypes){
        if ($NumberOfNodes -eq 2) {
            #Create Mirror Tiers
                if (-not ($StorageTiers | Where-Object FriendlyName -eq "MirrorOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MirrorOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Mirror -NumberOfDataCopies 2
                }

            if ($ClusterFunctionalLevel -ge 10){
                #Create NestedMirror Tiers
                    if (-not ($StorageTiers | Where-Object FriendlyName -eq "NestedMirrorOn$MediaType")){
                        New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "NestedMirrorOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Mirror -NumberOfDataCopies 4
                    }
                #Create NestedParity Tiers
                    if (-not ($StorageTiers | Where-Object FriendlyName -eq "NestedParityOn$MediaType")){
                        New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "NestedParityOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Parity -NumberOfDataCopies 2 -PhysicalDiskRedundancy 1 -NumberOfGroups 1 -ColumnIsolation PhysicalDisk
                    }
            }
        }elseif($NumberOfNodes -eq 3){
            #Create Mirror Tiers
                if (-not ($StorageTiers | Where-Object FriendlyName -eq "MirrorOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MirrorOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Mirror -NumberOfDataCopies 3
                }
        }elseif($NumberOfNodes -ge 4){
            #Create Mirror Tiers
                if (-not ($StorageTiers | Where-Object FriendlyName -eq "MirrorOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "MirrorOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Mirror -NumberOfDataCopies 3
                }
            #Create Parity Tiers
                if (-not ($StorageTiers | Where-Object FriendlyName -eq "ParityOn$MediaType")){
                    New-StorageTier -CimSession $ClusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName "ParityOn$MediaType" -MediaType $MediaType  -ResiliencySettingName Parity
                }
        }
    }
#endregion

#region Create Volumes to use max capacity. It also depends what mix of devices you have. For more info https://github.com/Microsoft/WSLab/tree/master/Scenarios/S2D%20and%20Volumes%20deep%20dive

    #calculate reserve
    $pool=Get-StoragePool -CimSession $clustername -FriendlyName s2D*
    $HDDCapacity= ($pool |Get-PhysicalDisk -CimSession $clustername | where mediatype -eq HDD | where mediatype -ne Unspecified | Measure-Object -Property Size -Sum).Sum
    $HDDMaxSize=  ($pool |Get-PhysicalDisk -CimSession $clustername | where mediatype -eq HDD | where mediatype -ne Unspecified | Measure-Object -Property Size -Maximum).Maximum
    $SSDCapacity= ($pool |Get-PhysicalDisk -CimSession $clustername | where mediatype -eq SSD | where mediatype -ne Unspecified | where usage -ne journal | Measure-Object -Property Size -Sum).Sum
    $SSDMaxSize=  ($pool |Get-PhysicalDisk -CimSession $clustername | where mediatype -eq SSD | where mediatype -ne Unspecified | where usage -ne journal | Measure-Object -Property Size -Maximum).Maximum

    $numberofNodes=(Get-ClusterNode -Cluster $clustername).count
    if ($numberofNodes -eq 2){
        if ($SSDCapacity){
        $SSDCapacityToUse=$SSDCapacity-($numberofNodes*$SSDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonSSDs=$SSDCapacityToUse/2/$numberofNodes
        }
        if ($HDDCapacity){
        $HDDCapacityToUse=$HDDCapacity-($numberofNodes*$HDDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonHDDs=$HDDCapacityToUse/2/$numberofNodes
        }
    }else{
        if ($SSDCapacity){
        $SSDCapacityToUse=$SSDCapacity-($numberofNodes*$SSDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonSSDs=$SSDCapacityToUse/3/$numberofNodes
        }
        if ($HDDCapacity){
        $HDDCapacityToUse=$HDDCapacity-($numberofNodes*$HDDMaxSize)-100GB #100GB just some reserve (16*3 = perfhistory)+some spare capacity
        $sizeofvolumeonHDDs=$HDDCapacityToUse/3/$numberofNodes
        }
    }

    #create volumes
    1..$numberofNodes | ForEach-Object {
        if ($sizeofvolumeonHDDs){
            New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size $sizeofvolumeonHDDs -FriendlyName "MyVolumeonHDDs$_" -MediaType HDD
        }
        if ($sizeofvolumeonSSDs){
            New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size $sizeofvolumeonSSDs -FriendlyName "MyVolumeonSSDs$_" -MediaType SSD   
        }
    }

    start-sleep 10

    #rename CSV(s) to match name on Windows Server 2016 (in 2019 it is not needed as it's already renamed)
    $CurrentBuildNumber=Invoke-Command -ComputerName $ClusterName -scriptblock {Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber}
    if ($CurrentBuildNumber -eq 14393) {
        $CSVs=Get-ClusterSharedVolume -Cluster $ClusterName
        foreach ($CSV in $CSVs){
            $volumepath=$CSV.sharedvolumeinfo.friendlyvolumename
            $newname=$CSV.name.Substring(22,$CSV.name.Length-23)
            $CSV_Owner=(Get-ClusterSharedVolume -Cluster $ClusterName -Name $CSV.Name).ownernode
            Invoke-Command -ComputerName $CSV_Owner -ScriptBlock {Rename-Item -Path $using:volumepath -NewName $using:newname} -ErrorAction SilentlyContinue
        }
    }

#endregion

#region move VMQ out of CPU 0 and set correct BaseProcessorNumber based on NUMA for every pNIC in external vSwitch.
#not necessary needed as if dVMMQ in 2019 works well, it will move out CPU0 if CPU0 is utilized.
#more info: https://techcommunity.microsoft.com/t5/Networking-Blog/Synthetic-Accelerations-in-a-Nutshell-Windows-Server-2019/ba-p/653976
    if ($RealHW){
        $Switches=Get-VMSwitch -CimSession $servers -SwitchType External

        foreach ($switch in $switches){
            $processor=Get-WmiObject win32_processor -ComputerName $switch.ComputerName | Select-Object -First 1
            if ($processor.NumberOfCores -eq $processor.NumberOfLogicalProcessors/2){
                $HT=$True
            }
            $adapters=@()
            $switch.NetAdapterInterfaceDescriptions | ForEach-Object {$adapters+=Get-NetAdapterHardwareInfo -InterfaceDescription $_ -CimSession $switch.computername}
            foreach ($adapter in $adapters){
                $BaseProcessorNumber=$adapter.NumaNode*$processor.NumberOfLogicalProcessors
                if ($adapter.NumaNode -eq 0){
                    if($HT){
                        $BaseProcessorNumber=$BaseProcessorNumber+2
                    }else{
                        $BaseProcessorNumber=$adapter.NumaNode*$processor.NumberOfLogicalProcessors+1
                    }
                }
                $adapter=Get-NetAdapter -InterfaceDescription $adapter.InterfaceDescription -CimSession $adapter.PSComputerName
                $adapter | Set-NetAdapterVmq -BaseProcessorNumber $BaseProcessorNumber
            }
        }
    }
#endregion

#region activate High Performance Power plan
    if ($RealHW){
        <#Cim method for nano servers
        #show enabled power plan
            Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | Where-Object isactive -eq $true | ft PSComputerName,ElementName
        #Grab instances of power plans
            $instances=Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | Where-Object Elementname -eq "High performance"
        #activate plan
            foreach ($instance in $instances) {Invoke-CimMethod -InputObject $instance -MethodName Activate}
        #show enabled power plan
            Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | Where-Object isactive -eq $true | ft PSComputerName,ElementName
        #>
        #set high performance
            Invoke-Command -ComputerName $servers -ScriptBlock {powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}
        #check settings
            Invoke-Command -ComputerName $servers -ScriptBlock {powercfg /list}
    }
#endregion

#region Create some dummy VMs (3 per each CSV disk)
    Start-Sleep -Seconds 60 #just to a bit wait as I saw sometimes that first VMs fails to create
    if ($realVMs -and $VHDPath){
        $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
        foreach ($CSV in $CSVs){
            $CSV=$CSV.Substring(22)
            $CSV=$CSV.TrimEnd(")")
            1..$NumberOfRealVMs | ForEach-Object {
                $VMName="TestVM$($CSV)_$_"
                New-Item -Path "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks" -ItemType Directory
                Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" 
                New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\$CSV\" -VHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random)
                Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
            }
        }
        #Start all VMs
        Start-VM -VMname * -CimSession (Get-ClusterNode -Cluster $clustername).Name
    }else{
        $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
        foreach ($CSV in $CSVs){
                $CSV=$CSV.Substring(22)
                $CSV=$CSV.TrimEnd(")")
                1..3 | ForEach-Object {
                    $VMName="TestVM$($CSV)_$_"
                    Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random) -ArgumentList $CSV,$VMName -ScriptBlock {
                        #create some fake VMs
                        New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\$($using:CSV)\$($using:VMName)\Virtual Hard Disks\$($using:VMName).vhdx" -NewVHDSizeBytes 32GB -SwitchName SETSwitch -Generation 2 -Path "c:\ClusterStorage\$($using:CSV)\" -MemoryStartupBytes 32MB
                    }
                    Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
                }
        }
    }

#endregion

#finishing
Write-Host "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
 
