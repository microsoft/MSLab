################################
# Run from DC or Management VM #
################################

#region Create cluster and perform CAU to push cluster to preview
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
    $ClusterName="AzSHCI-Cluster"
    $CAURoleName="AzSHCI-Cl-CAU"

#install features for management remote cluster
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica

#install roles and features to servers
    #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
        if ($result.ExitCode -eq "failed"){
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        }
    }
    #define features
    $features="Failover-Clustering","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
    #install features
    Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
    #restart and wait for computers
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
    Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#Create Cluster
    New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"

#configure Witness on DC
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

        #Install required features on nodes.
        $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
        foreach ($ClusterNode in $ClusterNodes){
            Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
        }
    #add role
        Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose

#endregion

#region invoke CAU update including preview updates
    $ClusterName="AzSHCI-Cluster"

    $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}
    $scan | Select NodeName,UpdateTitle | Out-GridView

    Invoke-CauRun -ClusterName $ClusterName -MaxFailedNodes 0 -MaxRetriesPerNode 1 -RequireAllNodesOnline -Force -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
                                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                IsPresent=1 and DeploymentAction='Uninstallation' or
                                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}

#endregion

#region configure AzSHCI preview channel

$Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"

#validate if at least 5C update was installed https://support.microsoft.com/en-us/topic/may-20-2021-preview-update-kb5003237-0c870dc9-a599-4a69-b0d2-2e635c6c219c
$RevisionNumbers=Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name UBR
    }

    foreach ($item in $RevisionNumbers) {
        if ($item -lt 1737){
            Write-Output "Something went wrong. UBR is $item. Should be higher thah 1737"
        }else{
            Write-Output "UBR is $item, you're good to go"
        }
    }

#once updated to at least 1737, you can configure preview channel
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Set-PreviewChannel
    }

#reboot machines to apply
    Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell

#validate if all is OK
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-PreviewChannel
    }

#unload module for next step
Remove-Module -Name ClusterAwareUpdating

Read-Host "Posh will now exit. Press a key"
exit

#endregion

#region perform Rolling Upgrade
$ClusterName="AzSHCI-Cluster"

#copy CAU plugin from cluster

#download NTFSSecurity module to replace permissions to be able to delete existing version
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module NTFSSecurity -Force
    $items=Get-ChildItem -Path "c:\Windows\system32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating" -Recurse
    $items | Set-NTFSOwner -Account $env:USERNAME
    $items | Get-NTFSAccess | Add-NTFSAccess -Account "Administrators" -AccessRights FullControl
    Remove-Item c:\Windows\system32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating -Recurse -Force
    $session=New-PSSession -ComputerName $ClusterName
    Copy-Item -FromSession $Session -Path c:\Windows\system32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating -Destination C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ -Recurse
    Import-Module -Name ClusterAwareUpdating

#perform update
    $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.RollingUpgradePlugin" -CauPluginArguments @{'WuConnected'='true';} -Verbose
    $scan.upgradeinstallproperties.WuUpdatesInfo | Out-GridView

    Invoke-CauRun -ClusterName $ClusterName -Force -CauPluginName "Microsoft.RollingUpgradePlugin" -CauPluginArguments @{'WuConnected'='true';} -Verbose

#validate version
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name DisplayVersion
}
#endregion

#region validate cluster version and upgrade functional level

$ClusterName="AzSHCI-Cluster"
#version before upgrade
    Get-Cluster -Name $ClusterName | Select-Object Cluster*
# upgrade Cluster version
    Update-ClusterFunctionalLevel -Cluster $ClusterName -Force
#and version after upgrade
    Get-Cluster -Name $ClusterName | Select-Object Cluster*

#endregion

#region configure networking with Network ATC https://docs.microsoft.com/en-us/azure-stack/hci/deploy/network-atc

$ClusterName="AzSHCI-Cluster"
$Servers=(Get-ClusterNode -Cluster $ClusterName).Name

#Install Network ATC feature and DCB
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-WindowsFeature -Name NetworkATC,Data-Center-Bridging
    }

#since ATC is not available on managment machine, PowerShell module needs to be copied. This is workaround since RSAT is not availalbe.
    $session=New-PSSession -ComputerName $ClusterName
    $items="C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetworkATC","C:\Windows\System32\NetworkAtc.Driver.dll","C:\Windows\System32\Newtonsoft.Json.dll"
    foreach ($item in $items){
        Copy-Item -FromSession $session -Path $item -Destination $item -Recurse -Force
    }
    Import-Module NetworkATC
#add network intent
    Add-NetIntent -Name ConvergedIntent -Management -Compute -Storage -ClusterName $ClusterName -AdapterName "Ethernet","Ethernet 2"

#validate status
    Get-NetIntentStatus -clustername azshci-cluster | Select-Object *
    Write-Output "applying intent"
    do {
        $status=Get-NetIntentStatus -clustername azshci-cluster
        Write-Host "." -NoNewline
        Start-Sleep 5
    } while ($status.ProvisioningStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")
    $status | Select-Object *

#validate what was/was not configured. Since Enable-NetAdapterQos does not work in virtual environment, QoS will not be enabled...
    Get-VMSwitch -CimSession $servers
    Get-VMNetworkAdapter -CimSession $servers -ManagementOS
    #validate vNICs
    Get-VMNetworkAdapter -CimSession $servers -ManagementOS
    #validate if VLANs were set
    Get-VMNetworkAdapterVlan -CimSession $Servers -ManagementOS
    #Validate DCBX setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName
    #validate policy (no result since it's not available in VM)
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName
    #Validate QOS Policies
    Get-NetQosPolicy -CimSession $servers | Sort-Object PSComputerName | Select-Object PSComputer,Name,NetDirectPort,PriorityValue
    #validate flow control setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | Format-Table PSComputerName,Priority,Enabled -GroupBy PSComputerName
    #Validate DCBX setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName
    #validate policy
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName
    #validate QoS Traffic Classes
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass} |Sort-Object PSComputerName |Select-Object PSComputerName,Name,PriorityFriendly,Bandwidth


#in MSLab it unfortunately does not work, therefore let's remove intent and cleanup vSwitches
    Remove-NetIntent -Name ConvergedIntent -ClusterName $ClusterName 
    Get-VMSwitch -CimSession $Servers | Remove-VMSwitch -Force
    Get-NetQosPolicy -CimSession $servers | Remove-NetQosPolicy -Confirm:0
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass | Remove-NetQosTrafficClass -Confirm:0}
#endregion

#region Configure networking (traditional converged, 2 subnets for SMB). Simplified version. For full guide see S2D HyperConverged or AzSHCI Deployment scenario.
    $ClusterName="AzSHCI-Cluster"
    $Servers=(Get-ClusterNode -Cluster $ClusterName).Name
    $vSwitchName="ConvergedSwitch"
    $StorNet1="172.16.1."
    $StorNet2="172.16.2."
    $StorVLAN1=1
    $StorVLAN2=2
    $IP=1 #Start IP for SMB adapters

    Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}
    Start-Sleep 5
    Clear-DnsClientCache
    #Check VMSwitches
    Get-VMSwitch -CimSession $Servers

    $Servers | ForEach-Object {
        #Configure vNICs
        Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Management -ComputerName $_
        Add-VMNetworkAdapter -ManagementOS -Name SMB01 -SwitchName $vSwitchName -CimSession $_
        Add-VMNetworkAdapter -ManagementOS -Name SMB02 -SwitchName $vSwitchName -Cimsession $_

        #configure IP Addresses
        New-NetIPAddress -IPAddress ($StorNet1+$IP.ToString()) -InterfaceAlias "vEthernet (SMB01)" -CimSession $_ -PrefixLength 24
        New-NetIPAddress -IPAddress ($StorNet2+$IP.ToString()) -InterfaceAlias "vEthernet (SMB02)" -CimSession $_ -PrefixLength 24
        $IP++
    }

    #Configure the host vNIC to use a Vlan.  They can be on the same or different VLans 
    Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB01 -VlanId $StorVLAN1 -Access -ManagementOS -CimSession $Servers
    Set-VMNetworkAdapterVlan -VMNetworkAdapterName SMB02 -VlanId $StorVLAN2 -Access -ManagementOS -CimSession $Servers

    #Restart each host vNIC adapter so that the Vlan is active.
    Restart-NetAdapter "vEthernet (SMB01)" -CimSession $Servers 
    Restart-NetAdapter "vEthernet (SMB02)" -CimSession $Servers

    #Enable RDMA on the host vNIC adapters
    Enable-NetAdapterRDMA "vEthernet (SMB01)","vEthernet (SMB02)" -CimSession $Servers

    #Associate each of the vNICs configured for RDMA to a physical adapter that is up and is not virtual (to be sure that each RDMA enabled ManagementOS vNIC is mapped to separate RDMA pNIC)
    Invoke-Command -ComputerName $servers -ScriptBlock {
        $physicaladapters=(get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions | Sort-Object
        Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB01" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[0]).name
        Set-VMNetworkAdapterTeamMapping -VMNetworkAdapterName "SMB02" -ManagementOS -PhysicalNetAdapterName (get-netadapter -InterfaceDescription $physicaladapters[1]).name
    }
    #configure JumboFrames
    Set-NetAdapterAdvancedProperty -CimSession $Servers  -DisplayName "Jumbo Packet" -RegistryValue 9014

    #Configure DCB
        #Cinstall DCB feature
            foreach ($server in $servers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 
        #Configure QoS
            New-NetQosPolicy "SMB_Direct"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers
            New-NetQosPolicy "Cluster"          -Cluster                         -PriorityValue8021Action 7 -CimSession $servers
        #Turn on Flow Control for SMB
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}
        #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
            Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}
        #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}
        #Configure IeeePriorityTag
            #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}
        #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch. This fails in MSLab (since NICs are virtual)
            Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}
        #Create a Traffic class and give SMB Direct 60% of the bandwidth minimum. The name of the class will be "SMB".
        #This value needs to match physical switch configuration. Value might vary based on your needs.
        #If connected directly (in 2 node configuration) skip this step.
            Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB_Direct" -Priority 3 -BandwidthPercentage 50 -Algorithm ETS}
            Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "Cluster"    -Priority 7 -BandwidthPercentage 2 -Algorithm ETS}

    #Validate

    #grab Vswitches
    Get-VMSwitch -CimSession $servers
    #validate vNICs
    Get-VMNetworkAdapter -CimSession $servers -ManagementOS
    #validate if VLANs were set
    Get-VMNetworkAdapterVlan -CimSession $Servers -ManagementOS
    #verify mapping
    Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | Format-Table ComputerName,NetAdapterName,ParentAdapter 
    #verify RDMA
    Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | Format-Table systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
    #verify ip config 
    Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputerName | Format-Table PSComputerName,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
    #verify JumboFrames
    Get-NetAdapterAdvancedProperty -CimSession $servers -DisplayName "Jumbo Packet"
    #Validate DCBX setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName
    #validate policy (no result since it's not available in VM)
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName
    #Validate QOS Policies
    Get-NetQosPolicy -CimSession $servers | Sort-Object PSComputerName | Select-Object PSComputerName,Name,NetDirectPort,PriorityValue
    #validate flow control setting
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | Format-Table PSComputerName,Priority,Enabled -GroupBy PSComputerName
    #validate QoS Traffic Classes
    Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass} |Sort-Object PSComputerName |Select-Object PSComputerName,Name,PriorityFriendly,Bandwidth

#endregion

#region Enable Storage Spaces Direct
    #make sure all nodes are up
    get-clusternode -Cluster $clustername

    #might happen that after network configuration some nodes will be Quarantined since networking was configured after Cluster was created
    Get-ClusterNode -Cluster $ClusterName | Where-Object State -ne UP | Start-ClusterNode -ClearQuarantine
    #wait for node(s) to finish joining
    do {
        Write-Host "." -NoNewline
        Start-Sleep 5
    } while (Get-ClusterNode -Cluster $ClusterName | Where-Object State -ne Up)

    #Enable-ClusterS2D
    Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #display pool
    Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName

    #Display disks
    Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

    #Get Storage Tiers
    Get-StorageTier -CimSession $ClusterName

#endregion