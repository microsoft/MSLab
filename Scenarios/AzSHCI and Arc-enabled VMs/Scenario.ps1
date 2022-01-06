#https://aka.ms/ArcEnabledHCI

###################
### Run from DC ###
###################

#region Create 2 node cluster (just simple. Not for prod - follow hyperconverged scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20Deployment)
    # LabConfig
    $ClusterNodeNames="ArcVMs1","ArcVMs2"
    $ClusterName="ArcVMs-Cluster"

    # Install features for management on server
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

    # Update servers
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $ClusterNodeNames -ConfigurationName 'VirtualAccount' {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            $Session = New-Object -ComObject Microsoft.Update.Session
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $SearchResult
            $Downloader.Download()
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $SearchResult
            $Result = $Installer.Install()
            $Result
        }
        #remove temporary PSsession config
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }

    # Install features on servers
    Invoke-Command -computername $ClusterNodeNames -ScriptBlock {
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
        Install-WindowsFeature -Name "Failover-Clustering","RSAT-Clustering-Powershell","Hyper-V-PowerShell"
    }

    # restart servers
    Restart-Computer -ComputerName $ClusterNodeNames -Protocol WSMan -Wait -For PowerShell
    #failsafe - sometimes it evaluates, that servers completed restart after first restart (hyper-v needs 2)
    Start-sleep 20

    # create vSwitch
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {New-VMSwitch -Name vSwitch -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

    #create cluster
    New-Cluster -Name $ClusterName -Node $ClusterNodeNames
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

#endregion

#region Register Azure Stack HCI to Azure - if not registered, VMs are not added as cluster resources = AKS script will fail
    $ClusterName="ArcVMs-Cluster"

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
    Connect-AzAccount -UseDeviceAuthentication

    #select subscription if more available
    $subscription=Get-AzSubscription
    if (($subscription).count -gt 1){
        $subscription | Out-GridView -OutputMode Single | Set-AzContext
    }

    #grab subscription ID
    $subscriptionID=(Get-AzContext).Subscription.id

    <# Register AZSHCi without prompting for creds, 
    Notes: As Dec. 2021, in Azure Stack HCI 21H2,  if you Register-AzStackHCI the cluster multiple times in same ResourceGroup (e.g. default
    resource group name is AzSHCI-Cluster-rg) without run UnRegister-AzStackHCI first, although you may succeed in cluster registration, but
    sever node Arc integration will fail, even if you have deleted the ResourceGroup in Azure Portal before running Register-AzStackHCI #>

    $armTokenItemResource = "https://management.core.windows.net/"
    $graphTokenItemResource = "https://graph.windows.net/"
    $azContext = Get-AzContext
    $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
    $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id

    #grab location
    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }
    $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single

    #register
    Register-AzStackHCI -SubscriptionID $subscriptionID -Region $location.location -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

    #Install Azure Stack HCI RSAT Tools to all nodes
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
        Install-WindowsFeature -Name RSAT-Azure-Stack-HCI
    }
    #Validate registration (query on just one node is needed)
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Get-AzureStackHCI
    }
#endregion

#region Install modules and  create MOC agent Service

    #variables
    $ClusterName="ArcVMs-Cluster"
    $ClusterNodeNames=(Get-ClusterNode -Cluster $ClusterName).Name
    $vswitchName="vSwitch"
    $controlPlaneIP="10.0.0.111"
    $VolumeName="MOC"
    $VolumePath="c:\ClusterStorage\$VolumeName"
    $DHCPScopeID="10.0.0.0"
    $DHCPServer="DC"


    #Install required modules
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
    Update-Module -Name PowerShellGet
    #to be able to install ArcHci and MOC, powershellget 2.2.5 needs to be used - to this posh restart is needed
    Start-Process -Wait -FilePath PowerShell -ArgumentList {
        Install-Module -Name MOC    -Repository PSGallery -Force -AcceptLicense
        Install-Module -Name ArcHci -RequiredVersion 0.2.6 -Force -Confirm:$false -SkipPublisherCheck -AcceptLicense
    }

    #distribute modules to cluster nodes
        $ModuleNames="ArcHci","Moc","DownloadSDK"
        $PSSessions=New-PSSession -ComputerName $ClusterNodeNames
        Foreach ($PSSession in $PSSessions){
            Foreach ($ModuleName in $ModuleNames){
                Copy-Item -Path $env:ProgramFiles\windowspowershell\modules\$ModuleName -Destination $env:ProgramFiles\windowspowershell\modules -ToSession $PSSession -Recurse -Force
            }
            Foreach ($ModuleName in $RequiredModules.ModuleName){
                Copy-Item -Path $env:ProgramFiles\windowspowershell\modules\$ModuleName -Destination $env:ProgramFiles\windowspowershell\modules -ToSession $PSSession -Recurse -Force
            }
        }

    #Enable CredSSP
        # Temporarily enable CredSSP delegation to avoid double-hop issue
        foreach ($ClusterNodeName in $ClusterNodeNames){
            Enable-WSManCredSSP -Role "Client" -DelegateComputer $ClusterNodeName -Force
        }
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Enable-WSManCredSSP Server -Force }

        $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    #initialize MOC
        Invoke-Command -ComputerName $ClusterNodeNames -Credential $Credentials -Authentication Credssp -ScriptBlock {
            Initialize-MocNode
        }

    #Create volume for MOC if does not exist
    if (-not (Get-Volume -FriendlyName $VolumeName -CimSession $ClusterName -ErrorAction SilentlyContinue)) {
        New-Volume -FriendlyName $VolumeName -CimSession $ClusterName -Size 1TB -StoragePoolFriendlyName S2D*
    }

    #prepare arc resource bridge
        #Configure MOC
        Invoke-Command -ComputerName $ClusterNodeNames[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
            $Vnet=New-MocNetworkSetting -Name hcirb-vnet -vswitchName $using:vswitchName -vipPoolStart $using:controlPlaneIP -vipPoolEnd $using:controlPlaneIP
            Set-MocConfig -workingDir $using:VolumePath\workingDir  -vnet $vnet -imageDir $using:VolumePath\imageStore -skipHostLimitChecks -cloudConfigLocation $using:VolumePath\cloudStore -catalog aks-hci-stable-catalogs-ext -ring stable
        }

        #Install MOC Cloud Agent Service
        Invoke-Command -ComputerName $ClusterNodeNames[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
            Install-moc
        }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Disable-WSManCredSSP Server }

#endregion

#region Create custom location and install Arc Resource Bridge
    #Login to azure
    if (!(Get-AzContext)){
        Connect-AzAccount -UseDeviceAuthentication
    }

    #generate variables
        $ClusterName="ArcVMs-Cluster"
        $ClusterNodeNames=(Get-ClusterNode -Cluster $ClusterName).Name
        $CustomLocationName="$ClusterName-cl"
        $VolumeName="MOC"

        #Grab registration info
        $RegistrationInfo=Invoke-Command -ComputerName $CLusterName -ScriptBlock {Get-AzureStackHCI}
        $AzureResourceUri= $RegistrationInfo
        $ResourceGroupName=$AzureResourceUri.split("/")[4]
        $SubscriptionID=$AzureResourceUri.split("/")[2]
        #grab location
        $Location=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.ResourceConnector" | Out-GridView -OutputMode Single).Location
        #create bridge resource name
        $BridgeResourceName="$($RegistrationInfo.AzureResourceName)-arcbridge"

    #install Az CLI
        #download
        Start-BitsTransfer -Source https://aka.ms/installazurecliwindows -Destination $env:userprofile\Downloads\AzureCLI.msi
        #install
        Start-Process msiexec.exe -Wait -ArgumentList "/I  $env:userprofile\Downloads\AzureCLI.msi /quiet"
        #add az to enviromental variables so no posh restart is needed
        [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin')



    #add Az extensions
        az extension add --name customlocation
        az extension add --name azurestackhci
        az extension add --name arcappliance
        az extension add --name k8s-extension
    #register namespaces
        #register
        $Providers="Microsoft.ExtendedLocation","Microsoft.ResourceConnector"
        foreach ($Provider in $Providers){
            Register-AzResourceProvider -ProviderNamespace $Provider
        }
        #wait until resource providers are registered
        foreach ($Provider in $Providers){
            do {
                $Status=Get-AzResourceProvider -ProviderNamespace $Provider
                Write-Output "Registration Status - $Provider : $(($status.RegistrationState -match 'Registered').Count)/$($Status.Count)"
                Start-Sleep 1
            } while (($status.RegistrationState -match "Registered").Count -ne ($Status.Count))
        }
    
    #create arc appliance
        #generate config files
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            New-ArcHciConfigFiles -subscriptionID $using:SubscriptionID -location $using:location -resourceGroup $using:ResourceGroupName -resourceName $using:BridgeResourceName -workDirectory "\\$using:ClusterName\ClusterStorage$\$using:VolumeName\workingDir"
        }
        #prepare
        az arcappliance prepare hci --config-file \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-appliance.yaml
        
        #Create folder for config
        New-Item -Path $env:USERPROFILE\.kube -ItemType Directory -ErrorAction Ignore

        #deploy control plane and export kube config
        az arcappliance deploy hci --config-file  \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-appliance.yaml --outfile $env:USERPROFILE\.kube\config
        #create connection to Azure
        az arcappliance create hci --config-file  \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-appliance.yaml --kubeconfig $env:USERPROFILE\.kube\config

    #wait until appliance is running
        do {
            $Status=az arcappliance show --resource-group $ResourceGroupName --name $BridgeResourceName | ConvertFrom-Json
            Start-Sleep 1
        } while (-not ($status.status -match "Running"))

    #verify if appliance is running
        az arcappliance show --resource-group $ResourceGroupName --name $BridgeResourceName

    #Add K8s extension
        #create
        az k8s-extension create --cluster-type appliances --cluster-name $BridgeResourceName --resource-group $ResourceGroupName --name hci-vmoperator --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace helm-operator2 --configuration-settings Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --configuration-protected-settings-file \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-config.json --configuration-settings HCIClusterID=$AzureResourceUri --auto-upgrade true
        #validate
        az k8s-extension show --cluster-type appliances --cluster-name $BridgeResourceName --resource-group $ResourceGroupName --name hci-vmoperator
    
    #Create custom location (has to be created after arcappliance deployment)
        az customlocation create --resource-group $ResourceGroupName --name $CustomLocationName --cluster-extension-ids "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName/providers/Microsoft.KubernetesConfiguration/extensions/hci-vmoperator" --namespace hci-vmoperator --host-resource-id "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName" --location $Location

        <# Or with PowerShell
        #install Az.CustomLocation module
        if (!(Get-InstalledModule -Name az.CustomLocation -ErrorAction Ignore)){
            Install-Module -Name Az.CustomLocation -Force
        }
        New-AzCustomLocation -ResourceGroupName $ResourceGroupName -Name $CustomLocationName -ClusterExtensionID "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName/providers/Microsoft.KubernetesConfiguration/extensions/hci-vmoperator" -NameSpace hci-vmoperator -HostResourceID "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName" -Location $Location
        #>

#endregion

#region Copy kube config to nodes to have it available there
    $ClusterName="ArcVMs-Cluster"
    $ClusterNodeNames=(Get-ClusterNode -Cluster $clustername).Name
    $Sessions=New-PSSession -ComputerName $ClusterNodeNames

    #copy kube to cluster nodes
    Foreach ($Session in $Sessions){
        Copy-Item -Path "$env:userprofile\.kube" -Destination $env:userprofile -ToSession $Session -Recurse -Force
    }

    $Sessions | Remove-PSSession
#endregion

#region add Bridge Cluster NIC (IP and MAC) into DHCP reservations
    #Variables
    $ClusterName="ArcVMs-Cluster"
    $controlPlaneIP="10.0.0.111"
    $DHCPScopeID="10.0.0.0"
    $DHCPServer="DC"
    $ReservationName="$ClusterName-ControlPlane"
    $ClusterNodeNames=(Get-ClusterNode -Cluster $clustername).Name
    
    #grab VMNic with Controlplane IP
        $NetAdapter = Get-VMNetworkAdapter -CimSession $ClusterNodeNames -VMName * -ErrorAction Ignore | Where-Object IPAddresses -Contains $controlPlaneIP

    #Add MOC Control Plane IP into reservation
        Install-WindowsFeature -Name RSAT-DHCP
        Add-DhcpServerv4Reservation -Name $netadapter.VMName -ScopeId $DHCPScopeID -CimSession $DHCPServer -IPAddress $controlPlaneIP -ClientId $NetAdapter.MacAddress
#endregion

#region collect logs
        #Enable CredSSP
        # Temporarily enable CredSSP delegation to avoid double-hop issue
        foreach ($ClusterNodeName in $ClusterNodeNames){
            Enable-WSManCredSSP -Role "Client" -DelegateComputer $ClusterNodeName -Force
        }
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Enable-WSManCredSSP Server -Force }

        $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

        #generate logs
        Invoke-Command -ComputerName $ClusterNodeNames[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
            get-archcilogs
        }

        # Disable CredSSP
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Disable-WSManCredSSP Server }

        #copy logs to downloads
        $Session=New-PSSession -ComputerName $ClusterNodeNames[0]
        Copy-Item -Path $env:userprofile\Documents\archcilogs.zip -Destination $env:userprofile\Downloads -FromSession $Sessions
        $Session | Remove-PSSession
#endregion

#region cleanup

<#
TBD
#>

#endregion