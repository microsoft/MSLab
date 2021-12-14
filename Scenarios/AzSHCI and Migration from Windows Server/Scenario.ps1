#Run all code from DC

#region prereqs - will setup two simplified clusters
    #setup 2 clusters
    # variables
    $Clusters=@()
    $Clusters+=@{Nodes=1..4 | Foreach-Object {"S2D$_"}    ; Name="S2D-Cluster"    ; IP="10.0.0.112" ; vSwitchName="vSwitch"}
    $Clusters+=@{Nodes=1..4 | Foreach-Object {"AzSHCI$_"} ; Name="AzSHCI-Cluster" ; IP="10.0.0.113" ; vSwitchName="vSwitch"}

    # Install features for management
        $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
        if ($WindowsInstallationType -eq "Server"){
            Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
        }elseif ($WindowsInstallationType -eq "Server Core"){
            Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
        }

    # Install features on servers
        Invoke-Command -computername $Clusters.nodes -ScriptBlock {
            Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell"
        }

        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $Clusters.nodes -ScriptBlock {
            $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
            if ($result.ExitCode -eq "failed"){
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            }
        }

    #restart all servers since failover clustering in 2019 requires reboot
        Restart-Computer -ComputerName $Clusters.nodes -Protocol WSMan -Wait -For PowerShell -Force
        Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
        #make sure computers are restarted
        Foreach ($Server in $Clusters.nodes){
            do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
        }

    #create virtual switches
        foreach ($Cluster in $Clusters){
            Invoke-Command -ComputerName $Cluster.Nodes -ScriptBlock {
                $NetAdapters=Get-NetAdapter | Sort-Object Name
                New-VMSwitch -Name $using:Cluster.vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName $NetAdapters.Name
            }
        }

    #create clusters
        foreach ($Cluster in $Clusters){
            New-Cluster -Name $cluster.Name -Node $Cluster.Nodes -StaticAddress $cluster.IP
            Start-Sleep 5
            Clear-DNSClientCache
        }

    #add file share witness
        foreach ($Cluster in $Clusters){
            $ClusterName=$Cluster.Name
            #Create new directory
            $WitnessName=$ClusterName+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            #create fileshare
            $accounts=@()
            $accounts+="corp\$($ClusterName)$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
            #Set NTFS permissions
                Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
            #Set Quorum
                Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
        }

    #Enable S2D
        Enable-ClusterS2D -CimSession $Clusters.Name -Verbose -Confirm:0

    #Create Volumes
        Foreach ($Cluster in $Clusters){
            1..$Cluster.Nodes.Count | ForEach-Object {
                New-Volume -CimSession $Cluster.Name -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 1TB -FriendlyName "CSV$_"
            }
        }

    #Create VMs on first cluster only
        $ClusterName=$Clusters[0].Name
        $vSwitchName=$Clusters[0].vSwitchName
        $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
        foreach ($CSV in $CSVs){
                $CSV=($CSV -split '\((.*?)\)')[1]
                1..3 | ForEach-Object {
                    $VMName="TestVM$($CSV)_$_"
                    Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random) -ScriptBlock {
                        #create some dummy VMs
                        New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\$($using:CSV)\$($using:VMName)\Virtual Hard Disks\$($using:VMName).vhdx" -NewVHDSizeBytes 32GB -SwitchName $using:vSwitchName -Generation 2 -Path "c:\ClusterStorage\$($using:CSV)\" -MemoryStartupBytes 32MB
                    }
                    Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
                }
        }
        #Start VMs
        Start-VM -VMName * -CimSession $Clusters[0].Nodes
#endregion

#region attempt Live Migration
    #Configure kerberos constrained delegation to move from Firstcluster to SecondCluster and back
    # https://technet.microsoft.com/en-us/windows-server-docs/compute/hyper-v/deploy/set-up-hosts-for-live-migration-without-failover-clustering

        #define cluster names.
        $Clusters="S2D-Cluster","AzSHCI-Cluster"

        #configure kerberos constrained delegation for cifs and Microsoft Virtual System Migration Service, both name and FQDN
        foreach ($Cluster in $Clusters){
            $SourceNodes=(Get-ClusterNode -Cluster $Cluster).Name
            $DestinationNodes=$clusters | ForEach-Object {if ($_ -ne $cluster){(Get-ClusterNode -Cluster $_).Name}}

            Foreach ($DestinationNode in $DestinationNodes){
                $HostName = $DestinationNode 
                $HostFQDN = (Resolve-DnsName $HostName).name | Select-Object -First 1
                Foreach ($SourceNode in $SourceNodes){
                    Get-ADComputer $SourceNode | Set-ADObject -Add @{"msDS-AllowedToDelegateTo"="Microsoft Virtual System Migration Service/$HostFQDN", "Microsoft Virtual System Migration Service/$HostName", "cifs/$HostFQDN", "cifs/$HostName"}
                }
            }
        }

        #Switch to any authentication protocol https://blogs.technet.microsoft.com/virtualization/2017/02/01/live-migration-via-constrained-delegation-with-kerberos-in-windows-server-2016/
        foreach ($Cluster in $clusters){
            $ClusterNodes=(Get-ClusterNode -Cluster $Cluster).Name
            Foreach ($ClusterNode in $ClusterNodes){
                $GUID=(Get-ADComputer $clusternode).ObjectGUID
                $comp=Get-ADObject -identity $Guid -Properties "userAccountControl"
                #Flip the ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION bit using powershell bitwise OR operation (-bor)
                $Comp.userAccountControl = $Comp.userAccountControl -bor 16777216
                Set-ADObject -Instance $Comp
            }
        }

        #Switch to kerberos authentication for live migration
        foreach ($Cluster in $Clusters){
            $ClusterNodes=(Get-ClusterNode -Cluster $Cluster).Name
            Set-VMHost -CimSession $ClusterNodes -VirtualMachineMigrationAuthenticationType Kerberos
        }

    #Attempt Live Migration of one VM
    $SourceClusterName="S2D-Cluster"
    $DestinationClusterName="AzSHCI-Cluster"
    $SourceStoragePath="C:\ClusterStorage\CSV1"
    $DestinationStoragePath="C:\ClusterStorage\CSV1"
    $VMNames=(Get-VM -cimsession (get-clusternode -cluster $SourceClusterName).Name | Where-Object Path -Like "$SourceStoragePath*").Name
    #remove VMs from HA Resources
    foreach ($VMName in $VMNames){
        Get-ClusterResource -Cluster $SourceClusterName -name "Virtual Machine $VMName" | Remove-ClusterResource -force
        Get-ClusterGroup -Cluster $SourceClusterName -Name $VMName | Remove-ClusterGroup -force
    }

    #attempt Live migration to different cluster (this will fail)
    foreach ($VMName in $VMNames){
        #Grab random node in cluster $DestinationClusterName
        $DestinationHost=(get-clusternode -cluster $DestinationClusterName | get-random).Name
        $VM=Get-VM -Cimsession (get-clusternode -cluster $SourceClusterName).Name -Name $VMName
        $VM | Move-VM -DestinationHost $DestinationHost -DestinationStoragePath  "$DestinationStoragePath\$($VM.Name)" -IncludeStorage
    }

#endregion

#region Let's try just simply copy VMs one by one
    $SourceClusterName="S2D-Cluster"
    $DestinationClusterName="AzSHCI-Cluster"
    $SourceStoragePath="C:\ClusterStorage\CSV1"
    $DestinationStoragePath="C:\ClusterStorage\CSV1"
    $VMNames=(Get-VM -cimsession (get-clusternode -cluster $SourceClusterName).Name | Where-Object Path -Like "$SourceStoragePath*").Name

    # Temporarily enable CredSSP delegation to avoid double-hop issue
    $Servers=(get-clusternode -cluster $SourceClusterName).Name
    foreach ($Server in $Servers){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Server -Force
    }
    Invoke-Command -ComputerName $servers -ScriptBlock { Enable-WSManCredSSP Server -Force }
    #$Credentials=Get-Credential
    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    #do the move
    foreach ($VMName in $VMNames){
        #remove VM from HA Resources
        Get-ClusterResource -Cluster $SourceClusterName -name "Virtual Machine $VMName" -ErrorAction Ignore | Remove-ClusterResource -force
        Get-ClusterGroup -Cluster $SourceClusterName -Name $VMName -ErrorAction Ignore | Remove-ClusterGroup -force
        #Grab random node in cluster $DestinationClusterName
        $VM=Get-VM -Cimsession (get-clusternode -cluster $SourceClusterName).Name -Name $VMName
        $VM | Stop-VM -Save
        #Backup config
        Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Copy-Item -Path "$($using:VM.Path)\Virtual Machines" -Destination "$($using:VM.Path)\Virtual Machines Bak" -Recurse}
        #If there is different switch name in destination node, you should consider disconnecting vNICs first
        #$VM | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter
        #Remove VM
        $VM | Remove-VM -Force
        #Restore Config
        #Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Copy-Item -Path "$($using:VM.Path)\Virtual Machines Bak\*" -Destination "$($using:VM.Path)\Virtual Machines" -Recurse}
        Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Move-Item -Path "$($using:VM.Path)\Virtual Machines Bak\*" -Destination "$($using:VM.Path)\Virtual Machines"}
        Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Remove-Item -Path "$($using:VM.Path)\Virtual Machines Bak\"}
        #Copy machine to destination node using CredSSP
        $VolumeName=$DestinationStoragePath | Split-Path -Leaf
        Invoke-Command -ComputerName ($Servers | Get-Random) -Credential $Credentials -Authentication Credssp  -ScriptBlock {Copy-Item -Path "$($using:VM.Path)" -Destination "\\$using:DestinationClusterName\ClusterStorage$\$using:VolumeName\" -Recurse}
        #Import VM and Start
        $DestinationHost=(get-clusternode -cluster $DestinationClusterName | get-random).Name
        $NewVM=Import-VM -Path "$DestinationStoragePath\$($VM.Name)\Virtual Machines\$($VM.ID.GUID).vmcx" -CimSession $DestinationHost
        $NewVM | Start-VM
    }

    #disable credssp
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $servers -ScriptBlock { Disable-WSManCredSSP Server }

#endregion

#region move all VMs in cluster volume by volume
    $SourceClusterName="S2D-Cluster"
    $DestinationClusterName="AzSHCI-Cluster"
    $SourceClusterVolumes=(Get-ClusterSharedVolume -Cluster $SourceClusterName).sharedvolumeinfo.Friendlyvolumename
    $DestinationClusterVolumes=(Get-ClusterSharedVolume -Cluster $DestinationClusterName).sharedvolumeinfo.Friendlyvolumename

    # Temporarily enable CredSSP delegation to avoid double-hop issue
    $Servers=(get-clusternode -cluster $SourceClusterName).Name
    foreach ($Server in $Servers){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Server -Force
    }
    Invoke-Command -ComputerName $servers -ScriptBlock { Enable-WSManCredSSP Server -Force }
    #$Credentials=Get-Credential
    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    #do the move
    Foreach ($SourceClusterVolume in $SourceClusterVolumes){
        $index=$SourceClusterVolumes.IndexOf($SourceClusterVolume)
        #Grab destination Volume
        #adjust index if there are more volumes in source cluster than in destination
        if ($index -gt ($DestinationClusterVolumes.Count-1)){
            $index=$index % ($DestinationClusterVolumes.Count-1)
        }
        $VMNames=(Get-VM -cimsession (get-clusternode -cluster $SourceClusterName).Name | Where-Object Path -Like "$SourceClusterVolume*").Name
        foreach ($VMName in $VMNames){
            #remove VM from HA Resources
            Get-ClusterResource -Cluster $SourceClusterName -name "Virtual Machine $VMName" -ErrorAction Ignore | Remove-ClusterResource -force
            Get-ClusterGroup -Cluster $SourceClusterName -Name $VMName -ErrorAction Ignore | Remove-ClusterGroup -force
            $VM=Get-VM -Cimsession (get-clusternode -cluster $SourceClusterName).Name -Name $VMName
            $VM | Stop-VM -Save
            #If there is different switch name in destination node, you should consider disconnecting vNICs first
            #$VM | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter
            #Backup config
            Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Copy-Item -Path "$($using:VM.Path)\Virtual Machines" -Destination "$($using:VM.Path)\Virtual Machines Bak" -Recurse}
            #Remove VM
            $VM | Remove-VM -Force
            #Restore Config
            #Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Copy-Item -Path "$($using:VM.Path)\Virtual Machines Bak\*" -Destination "$($using:VM.Path)\Virtual Machines" -Recurse}
            Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Move-Item -Path "$($using:VM.Path)\Virtual Machines Bak\*" -Destination "$($using:VM.Path)\Virtual Machines"}
            Invoke-Command -ComputerName $SourceClusterName -ScriptBlock {Remove-Item -Path "$($using:VM.Path)\Virtual Machines Bak\"}
            #Copy machine to destination node using CredSSP
            $VolumeName=$DestinationClusterVolumes[$index] | Split-Path -Leaf
            Invoke-Command -ComputerName ($Servers | Get-Random) -Credential $Credentials -Authentication Credssp  -ScriptBlock {Copy-Item -Path "$($using:VM.Path)" -Destination "\\$using:DestinationClusterName\ClusterStorage$\$using:VolumeName\" -Recurse}
            #Import VM and Start
            $DestinationHost=(get-clusternode -cluster $DestinationClusterName | get-random).Name
            $NewVM=Import-VM -Path "$($DestinationClusterVolumes[$index])\$($VM.Name)\Virtual Machines\$($VM.ID.GUID).vmcx" -CimSession $DestinationHost
            $NewVM | Start-VM
        }
    }
    #disable credssp
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $servers -ScriptBlock { Disable-WSManCredSSP Server }
#endregion

#region add VMs as HA Resources on destination cluster
    $DestinationClusterName="AzSHCI-Cluster"
    #register Azure Stack HCI first
        $ClusterName=$DestinationClusterName
        #download Azure module
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
            Install-Module -Name Az.StackHCI -Force
        }
    
        #login to azure
        #download Azure module
        if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
            Install-Module -Name Az.Accounts -Force
        }
        if (-not (Get-AzContext)){
            Login-AzAccount -UseDeviceAuthentication
        }
        #select context if more available
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context | Out-GridView -OutputMode Single | Set-AzContext
        }
    
        #select subscription if more available
        $subscriptions=Get-AzSubscription
        if (($subscriptions).count -gt 1){
            $SubscriptionID=($subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription).Subscription.Id
        }else{
            $SubscriptionID=$subscriptions.id
        }

        #register Azure Stack HCI
        $ResourceGroupName="AzureStackHCIClusters"
        if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
            Install-Module -Name Az.Resources -Force
        }
        #choose location for cluster (and RG)
        $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata").Location
        If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
            New-AzResourceGroup -Name $ResourceGroupName -Location $region
        }
        #Register AZSHCi without prompting for creds
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        #Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id
        Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName  $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName


    #add VMs as HA Resources on destination cluster
    $VMNames=(Get-VM -cimsession (get-clusternode -cluster $DestinationClusterName).Name).Name
    foreach ($VMName in $VMNames){
        Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $DestinationClusterName -ErrorAction Ignore
    }
#endregion

#region refresh OS on S2D cluster nodes from "NewAzSHCI" VMs - like you would reinstall OS completely
    ###############################
    # Run all from Hyper-V host ! #
    ###############################
    #assuming all VMs are now saved, you can simply turn off all cluster nodes and replace all disks
    $VMsWithOldOS=Get-VM -Name *S2D* | Sort-Object Name
    $VMsWithNewOS=Get-VM -Name *NewAzSHCI* | Sort-Object Name
    foreach ($VM in $VMsWithOldOS){
        $VM | Stop-VM -TurnOff
        $index=$VMsWithOldOS.IndexOf($VM)
        Remove-VMHardDiskDrive -VMName $VM.Name -ControllerNumber 0 -ControllerLocation 0 -ControllerType SCSI
        $NewVhd=$VMsWithNewOS[$index] | Get-VMHardDiskDrive
        #make sure source OS VM is shut down
        $VMsWithNewOS[$index] | Stop-VM
        #add disk to VM = "reinstall"
        Add-VMHardDiskDrive -VMName $VM.Name -Path $NewVhd.Path
        $VM | Start-VM
    }
#endregion

#region Install cluster and enable Cluster-S2D
    ###########################
    # Run all from DC Again ! #
    ###########################
    #just recycling the same code as in first region
    # variables
    $Clusters=@()
    $Clusters+=@{Nodes=1..4 | Foreach-Object {"NewAzSHCI$_"}    ; Name="NewHCI-Cluster"    ; IP="10.0.0.114" ; vSwitchName="vSwitch"}

    # Install features for management
        $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
        if ($WindowsInstallationType -eq "Server"){
            Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
        }elseif ($WindowsInstallationType -eq "Server Core"){
            Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools
        }

    # Install features on servers
        Invoke-Command -computername $Clusters.nodes -ScriptBlock {
            Install-WindowsFeature -Name "Failover-Clustering","Hyper-V-PowerShell"
        }

        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $Clusters.nodes -ScriptBlock {
            $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
            if ($result.ExitCode -eq "failed"){
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            }
        }

    #restart all servers since failover clustering in 2019 requires reboot
        Restart-Computer -ComputerName $Clusters.nodes -Protocol WSMan -Wait -For PowerShell -Force
        Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up
        #make sure computers are restarted
        Foreach ($Server in $Clusters.nodes){
            do{$Test= Test-NetConnection -ComputerName $Server -CommonTCPPort WINRM}while ($test.TcpTestSucceeded -eq $False)
        }

    #create virtual switches
        foreach ($Cluster in $Clusters){
            Invoke-Command -ComputerName $Cluster.Nodes -ScriptBlock {
                $NetAdapters=Get-NetAdapter | Sort-Object Name
                New-VMSwitch -Name $using:Cluster.vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName $NetAdapters.Name
            }
        }

    #create clusters
        foreach ($Cluster in $Clusters){
            New-Cluster -Name $cluster.Name -Node $Cluster.Nodes -StaticAddress $cluster.IP
            Start-Sleep 5
            Clear-DNSClientCache
        }

    #add file share witness
        foreach ($Cluster in $Clusters){
            $ClusterName=$Cluster.Name
            #Create new directory
            $WitnessName=$ClusterName+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            #create fileshare
            $accounts=@()
            $accounts+="corp\$($ClusterName)$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
            #Set NTFS permissions
                Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
            #Set Quorum
                Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
        }

    #Enable S2D
        Enable-ClusterS2D -CimSession $Clusters.Name -Verbose -Confirm:0

#endregion

#region fix volumes and import VMs
$ClusterName="NewHCI-Cluster"
$ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name

#remove cluster disk from resources to be able to find correct ID
    Get-ClusterResource -Cluster $ClusterName | Where-Object ResourceType -eq "Physical Disk" | Remove-ClusterResource -Force

#match VDisks and Cluster Available Disks, and rename
    $ClusterAvailableDisks=Get-ClusterAvailableDisk -Cluster $ClusterName
    foreach ($ClusterAvailableDisk in $ClusterAvailableDisks){
        $VirtualDisk=Get-VirtualDisk -CimSession $ClusterName | Where-Object ObjectID -like "*$($ClusterAvailableDisk.ID)*"
        $ClusterDisk=$ClusterAvailableDisk | Add-ClusterDisk
        $ClusterDisk.Name="Cluster Virtual Disk ($($VirtualDisk.FriendlyName))"
    }

#Add disks to CSV
Get-ClusterResource -Cluster $ClusterName | Where-Object ResourceType -eq "Physical Disk" | Where-Object Name -NotLike "Cluster Virtual Disk (ClusterPerformanceHistory)" | Add-ClusterSharedVolume

#wait a bit
Start-Sleep 20

#import all VMs
Invoke-Command -ComputerName $ClusterNodes[0] -ScriptBlock{
    get-childitem C:\ClusterStorage -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')} | ForEach-Object -Process {
            Import-VM -Path $_.FullName -ErrorAction SilentlyContinue
    }
}

#endregion

#region add VMs as HA Resources on destination cluster
$DestinationClusterName="NewHCI-Cluster"
#register Azure Stack HCI first
    $ClusterName=$DestinationClusterName
    #download Azure module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
        Install-Module -Name Az.StackHCI -Force
    }

    #login to azure
    #download Azure module
    if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
        Install-Module -Name Az.Accounts -Force
    }
    if (-not (Get-AzContext)){
        Login-AzAccount -UseDeviceAuthentication
    }

    #select context if more available
    $context=Get-AzContext -ListAvailable
    if (($context).count -gt 1){
        $context | Out-GridView -OutputMode Single | Set-AzContext
    }

    #select subscription if more available
    $subscriptions=Get-AzSubscription
    if (($subscriptions).count -gt 1){
        $SubscriptionID=($subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription).Subscription.Id
    }else{
        $SubscriptionID=$subscriptions.id
    }

    #register Azure Stack HCI
    $ResourceGroupName="AzureStackHCIClusters"
    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }
    #choose location for cluster (and RG)
    $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata").Location
    If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
        New-AzResourceGroup -Name $ResourceGroupName -Location $region
    }
    #Register AZSHCi without prompting for creds
    $armTokenItemResource = "https://management.core.windows.net/"
    $graphTokenItemResource = "https://graph.windows.net/"
    $azContext = Get-AzContext
    $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
    $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id
    #Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id
    Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName  $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName


#add VMs as HA Resources on destination cluster
$VMNames=(Get-VM -cimsession (get-clusternode -cluster $DestinationClusterName).Name).Name
foreach ($VMName in $VMNames){
    Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $DestinationClusterName -ErrorAction Ignore
}
#endregion

#region Cleanup Azure Resources
    <#
    $ClustersNames="AzSHCI-Cluster","NewHCI-Cluster"
    if (-not (Get-AzContext)){
        Login-AzAccount -UseDeviceAuthentication
    }

    foreach ($ClusterName in $ClustersNames){
        Get-AzResource -Name $ClusterName -ErrorAction Ignore | Remove-AzResource -Force
    }

    #if resource Group is Empty, delete it
    if (-not (Get-AzResource -ResourceGroupName AzureStackHCIClusters)){
        Remove-AzResourceGroup -Name AzureStackHCIClusters -Force
    }
    #>
#endregion