#https://learn.microsoft.com/en-us/azure/aks/hybrid/deploy-aks-service-hci?tabs=powershell#step-2-install-the-aks-hybrid-extension-on-the-azure-arc-resource-bridge
#https://aka.ms/ArcEnabledHCI

#region Variables 
$ClusterNodeNames="ASHCIRB1","ASHCIRB2"
$ClusterName="ASHCIRB-Cluster"
$VirtualSwitchName="vSwitch" #with network atc the virtual switch name might be something like "ConvergedSwitch(compute_management_storage)"
$controlPlaneIP="10.0.0.101"
$VolumeName="MOC"
$VolumePath="c:\ClusterStorage\$VolumeName"
$CredSSPUserName="CORP\LabAdmin"
$CredSSPPassword="LS1setup!"
$CustomLocationName="$ClusterName"
$CustomLocationNameSpace="customlocation-ns"

#ARC VMs virtual networks (the one that is visible in portal when you create a VM)
$VirtualNetworks=@()
$VirtualNetworks+=[PSCustomObject]@{ Name="Management" ; VLANID=$Null}
$VirtualNetworks+=[PSCustomObject]@{ Name="VMs701" ; VLANID=701}

#AKS config
$AKSvnetName="aksvnet"
$VIPPoolStart="10.0.1.2"
$VIPPoolEnd="10.0.1.50"
$DHCPServer="DC"
$DHCPScopeID="10.0.1.0"
$VLANID=11

#for static aks deployment
$IPAddressPrefix="10.0.1.0/24"
$Gateway="10.0.1.1"
$dnsservers="10.0.1.1"
$k8snodeippoolstart="10.0.1.51"
$k8snodeippoolend="10.0.1.254"

#if you want custom images to add
$LibraryVolumeName="Library" #volume for Gallery images for VMs
$AzureImages=@()
$AzureImages+=@{PublisherName = "microsoftwindowsserver";Offer="windowsserver";SKU="2022-datacenter-azure-edition-smalldisk";OSType="Windows"} #OS TYpe can be "Windows" or "Linux" - first letter has to be capital!
$AzureImages+=@{PublisherName = "microsoftwindowsserver";Offer="windowsserver";SKU="2022-datacenter-azure-edition-core-smalldisk";OSType="Windows"} #OS TYpe can be "Windows" or "Linux" - first letter has to be capital!


#Install or update Azure packages
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
$ModuleNames="Az.Accounts","Az.Compute","Az.Resources","Az.StackHCI"
foreach ($ModuleName in $ModuleNames){
    $Module=Get-InstalledModule -Name $ModuleName -ErrorAction Ignore
    if ($Module){$LatestVersion=(Find-Module -Name $ModuleName).Version}
    if (-not($Module) -or ($Module.Version -lt $LatestVersion)){
        Install-Module -Name $ModuleName -Force
    }
}

#login to Azure
if (-not (Get-AzContext)){
    Login-AzAccount -UseDeviceAuthentication
}

$ResourceGroupName="$ClusterName-rg"
$SubscriptionID=(Get-AzContext).Subscription.ID

#select context
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context=$context | Out-GridView -OutputMode Single
    $context | Set-AzContext
}

#I did only test same for all (EastUS)
$VMImageLocation="eastus"
$ArcResourceBridgeLocation="eastus"
$AzureStackLocation="eastus"

<#or populate by choosing your own
#grab region where to grab VMs from
$VMImageLocation = (Get-AzLocation | Where-Object Providers -Contains "Microsoft.Compute" | Out-GridView -OutputMode Single -Title "Choose location where to grab VMs from").Location

#grab location for Arc Resource Bridge and Custom location
$ArcResourceBridgeLocation=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.ResourceConnector" | Out-GridView -OutputMode Single -Title "Choose location for Arc Resource Bridge and Custom location").Location

#grab location for Azure Stack
$AzureStackLocation=(Get-AzResourceProvider -ProviderNamespace Microsoft.AzureStackHCI).Where{($_.ResourceTypes.ResourceTypeName -eq 'clusters' -and $_.RegistrationState -eq 'Registered')}.Locations | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata"
$AzureStackLocation = $region -replace '\s',''
$AzureStackLocation = $region.ToLower()
#>

#endregion

#region Create 2 node cluster (just simple. Not for prod - follow hyperconverged scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20Deployment%2022H2%20Edition)
# Install features for management on server
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

# Update servers (optional)
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

# create vSwitch (sometimes happens, that I need to restart servers again and then it will create vSwitch...)
Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {New-VMSwitch -Name $using:vswitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress -IPAddress 10.* ).InterfaceAlias}

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

#configure thin volumes a default if available (because why not :)
$OSInfo=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
}
if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuild -ge 20348){
    Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
}


#endregion

#region Register Azure Stack HCI to Azure - if not registered, VMs are not added as cluster resources = AKS script will fail
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
$armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
$id = $azContext.Account.Id

#register
Register-AzStackHCI -SubscriptionID $subscriptionID -Region $AzureStackLocation -ComputerName $ClusterName -ArmAccessToken $armToken -AccountId $id

#Install Azure Stack HCI RSAT Tools to all nodes
Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
    Install-WindowsFeature -Name RSAT-Azure-Stack-HCI
}
#Validate registration (query on just one node is needed)
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Get-AzureStackHCI
}
#endregion

#region Install modules and create MOC agent Service
    #Install required modules
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
    Update-Module -Name PowerShellGet

    #to be able to install ArcHci and MOC, powershellget 2.2.5 needs to be used - to this posh restart is needed
    Start-Process -Wait -FilePath PowerShell -ArgumentList {
        Install-Module -Name MOC    -Repository PSGallery -Force -AcceptLicense
        Install-Module -Name ArcHci -Force -Confirm:$false -SkipPublisherCheck -AcceptLicense
    }

    #Increase MaxEvenlope and create session to copy files to
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}

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

        $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

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
            Set-MocConfig -workingDir $using:VolumePath\workingDir -imageDir $using:VolumePath\imageStore -skipHostLimitChecks -cloudConfigLocation $using:VolumePath\cloudStore -catalog aks-hci-stable-catalogs-ext -ring stable -createAutoConfigContainers $false
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

    $subscription=Get-AzSubscription
    if (($subscription).count -gt 1){
        $subscription | Out-GridView -OutputMode Single | Set-AzContext
    }

    #generate variables
        #Grab registration info
        $RegistrationInfo=Invoke-Command -ComputerName $CLusterName -ScriptBlock {Get-AzureStackHCI}
        $AzureResourceUri= $RegistrationInfo.AzureResourceUri
        $HCIResourceGroupName=$AzureResourceUri.split("/")[4]
        $HCISubscriptionID=$AzureResourceUri.split("/")[2]
        #create bridge resource name
        $BridgeResourceName=("$($RegistrationInfo.AzureResourceName)-arcbridge").ToLower()

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
        az extension add --name connectedk8s

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

    #login with device authentication
        az login --use-device-code
        $allSubscriptions = (az account list | ConvertFrom-Json).ForEach({$_ | Select-Object -Property Name, id, tenantId })
        if (($allSubscriptions).Count -gt 1){
            $subscription = ($allSubscriptions | Out-GridView -OutputMode Single)
            az account set --subscription $subscription.id
        }
    #create arc appliance
        #generate config files
            #Enable CredSSP
            # Temporarily enable CredSSP delegation to avoid double-hop issue
            foreach ($ClusterNodeName in $ClusterNodeNames){
                Enable-WSManCredSSP -Role "Client" -DelegateComputer $ClusterNodeName -Force
            }
            Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Enable-WSManCredSSP Server -Force }

            $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
            $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

            Invoke-Command -ComputerName $ClusterNodeNames[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
                New-ArcHciConfigFiles -subscriptionID $using:HCISubscriptionID -location $using:ArcResourceBridgeLocation -resourceGroup $using:HCIResourceGroupName -resourceName $using:BridgeResourceName -workDirectory "C:\ClusterStorage\$using:VolumeName\workingDir" -controlPlaneIP $using:controlPlaneIP -vipPoolStart $using:controlPlaneIP -vipPoolEnd $using:controlPlaneIP -vswitchName $using:vswitchName #-vLanID $vlanID
            }

            #prepare,(unfortunately this does not work against remote server, so it has to run locally, so invoke-command with credssp)
 
            $session=New-PSSession -ComputerName $ClusterNodeNames[0]
            Copy-Item -Path $env:userprofile\Downloads\AzureCLI.msi -Destination $env:userprofile\Downloads\AzureCLI.msi -ToSession $session
            Invoke-Command -ComputerName $ClusterNodeNames[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
                #install
                Start-Process msiexec.exe -Wait -ArgumentList "/I  $env:userprofile\Downloads\AzureCLI.msi /quiet"
                #add az to enviromental variables so no posh restart is needed
                [System.Environment]::SetEnvironmentVariable('PATH',$Env:PATH+';C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin')
                az login --use-device-code
                az account set --subscription ($using:subscription).id
                #add Az extensions
                az extension add --name customlocation
                az extension add --name azurestackhci
                az extension add --name arcappliance
                az extension add --name k8s-extension
                az extension add --name connectedk8s
                #prepare
                az arcappliance prepare hci --config-file C:\ClusterStorage\$using:VolumeName\workingDir\hci-appliance.yaml
                #Create folder for config
                New-Item -Path $env:USERPROFILE\.kube -ItemType Directory -ErrorAction Ignore
                #deploy
                az arcappliance deploy hci --config-file  C:\ClusterStorage\$using:VolumeName\workingDir\hci-appliance.yaml --outfile $env:USERPROFILE\.kube\config
                #create
                az arcappliance create hci --config-file  C:\ClusterStorage\$using:VolumeName\workingDir\hci-appliance.yaml --kubeconfig $env:USERPROFILE\.kube\config
            }

            #copy kube config to local machine
            Copy-Item -Path $env:USERPROFILE\.kube\config -Destination $env:USERPROFILE\.kube\config -FromSession $session -Recurse
            Remove-PSSession $session

        # Disable CredSSP
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Disable-WSManCredSSP Server }

    #wait until appliance is running
        do {
            $Status=az arcappliance show --only-show-errors --resource-group $HCIResourceGroupName --name $BridgeResourceName | ConvertFrom-Json
            Write-Host -NoNewline -Object "."
            Start-Sleep 2
        } until ($status.status -match "Running")

    #verify if appliance is running
        az arcappliance show --resource-group $HCIResourceGroupName --name $BridgeResourceName | ConvertFrom-Json

    #Add hci-vmoperator extension
        #create
        az k8s-extension create --cluster-type appliances --cluster-name $BridgeResourceName --resource-group $HCIResourceGroupName --name hci-vmoperator --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace helm-operator2 --configuration-settings Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --config-protected-file \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-config.json --configuration-settings HCIClusterID=$AzureResourceUri --auto-upgrade true
        #validate
        az k8s-extension show --cluster-type appliances --cluster-name $BridgeResourceName --resource-group $HCIResourceGroupName --name hci-vmoperator
    
    #Create custom location (has to be created after arcappliance deployment)
        az customlocation create --resource-group $HCIResourceGroupName --name $CustomLocationName --cluster-extension-ids "/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName/providers/Microsoft.KubernetesConfiguration/extensions/hci-vmoperator" --namespace $CustomLocationNameSpace --host-resource-id "/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName" --location $ArcResourceBridgeLocation

        <# Or with PowerShell
        #install Az.CustomLocation module
        if (!(Get-InstalledModule -Name az.CustomLocation -ErrorAction Ignore)){
            Install-Module -Name Az.CustomLocation -Force
        }
        New-AzCustomLocation -ResourceGroupName $ResourceGroupName -Name $CustomLocationName -ClusterExtensionID "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName/providers/Microsoft.KubernetesConfiguration/extensions/hci-vmoperator" -NameSpace hci-vmoperator -HostResourceID "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName" -Location $ArcResourceBridgeLocation
        #>

#endregion

#region create virtual network for arcVMs
    #Grab registration info
    $RegistrationInfo=Invoke-Command -ComputerName $CLusterName -ScriptBlock {Get-AzureStackHCI}
    $AzureResourceUri= $RegistrationInfo.AzureResourceUri
    $HCIResourceGroupName=$AzureResourceUri.split("/")[4]
    $HCISubscriptionID=$AzureResourceUri.split("/")[2]
    $Location=$ArcResourceBridgeLocation
    #if network atc is used, this code might be helpful to grab vswitch name
        <#
        $VirtualSwitchName=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            $IntentName=(get-netintent | Where-Object iscomputeintentset -eq $true).IntentName
            (Get-VMSwitch | Where-Object Name -like "*($intentName)").name
        }
        #>

    #create network

    #add virtual networks for VMs
    $tags = @{
    'VSwitch-Name' = $VirtualSwitchName #hyper-v switch name
    }
  
    foreach ($VirtualNetwork in $VirtualNetworks){
        if ($VirtualNetwork.VlanID){
            Invoke-Command -ComputerName $CLusterName -ScriptBlock {
                $VirtualNetwork=$using:VirtualNetwork
                $Tags=$using:Tags
                New-MocVirtualNetwork -Name $VirtualNetwork.Name -group "Default_Group" -tags $tags -vlanID $VirtualNetwork.VlanID
            }
             az azurestackhci virtualnetwork create --subscription $HCISubscriptionID --resource-group $HCIResourceGroupName --extended-location name="/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ExtendedLocation/customLocations/$CustomLocationName" type="CustomLocation" --location $Location --network-type "Transparent" --name $VirtualNetwork.Name
        }else{
            Invoke-Command -ComputerName $CLusterName -ScriptBlock {
                $VirtualNetwork=$using:VirtualNetwork
                $Tags=$using:Tags
                New-MocVirtualNetwork -Name $VirtualNetwork.Name -group "Default_Group" -tags $tags
            }
             az azurestackhci virtualnetwork create --subscription $HCISubscriptionID --resource-group $HCIResourceGroupName --extended-location name="/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ExtendedLocation/customLocations/$CustomLocationName" type="CustomLocation" --location $Location --network-type "Transparent" --name $VirtualNetwork.Name
        }
   }
#endregion

#region Copy kube config to nodes to have it available there
$Sessions=New-PSSession -ComputerName $ClusterNodeNames

#copy kube to cluster nodes
Foreach ($Session in $Sessions){
    Copy-Item -Path "$env:userprofile\.kube" -Destination $env:userprofile -ToSession $Session -Recurse -Force
}

$Sessions | Remove-PSSession
#endregion

#region add aks hybrid extension to the custom location 
#https://learn.microsoft.com/en-us/azure/aks/hybrid/deploy-aks-service-hci?tabs=powershell#step-2-install-the-aks-hybrid-extension-on-the-azure-arc-resource-bridge

    #add extension
    $aksHybridExtnName = "aks-hybrid-extn"
    az k8s-extension create --resource-group $HCIResourceGroupName --cluster-name $BridgeResourceName --cluster-type appliances --name $aksHybridExtnName --extension-type Microsoft.HybridAKSOperator --config Microsoft.CustomLocation.ServiceAccount=$CustomLocationNameSpace

    #Patch your existing custom location to support AKS hybrid alongside Arc VMs
    $ArcResourceBridgeId=az arcappliance show -g $HCIResourceGroupName --name $BridgeResourceName --query id -o tsv
    $VMClusterExtensionResourceId=az k8s-extension list -g $HCIResourceGroupName --cluster-name $BridgeResourceName --cluster-type appliances --query "[?extensionType == ``microsoft.azstackhci.operator``].id" -o tsv
    $AKSClusterExtensionResourceId=az k8s-extension show -g $HCIResourceGroupName --cluster-name $BridgeResourceName --cluster-type appliances --name $aksHybridExtnName --query id -o tsv
    az customlocation patch --name $customLocationName --namespace $CustomLocationNameSpace --host-resource-id $ArcResourceBridgeId --cluster-extension-ids $VMClusterExtensionResourceId $AKSClusterExtensionResourceId --resource-group $HCIResourceGroupName

    #check
    az customlocation show --name $customLocationName --resource-group $HCIResourceGroupName --query "clusterExtensionIds" -o tsv
#endregion

#region create virtual network for AKS
#https://learn.microsoft.com/en-us/azure/aks/hybrid/create-aks-hybrid-preview-networks?tabs=dhcp%2Clinux-vhd

    #make sure latest module is installed (note required version)
    Start-Process -Wait -FilePath PowerShell -ArgumentList {
        Install-Module -Name MOC    -Repository PSGallery -Force -AcceptLicense
        Install-Module -Name ArcHci -Force -Confirm:$false -SkipPublisherCheck -AcceptLicense
    }

    #distribute new module to cluster nodes
    $ModuleNames="ArcHci"
    $PSSessions=New-PSSession -ComputerName $ClusterNodeNames
    Foreach ($PSSession in $PSSessions){
        Foreach ($ModuleName in $ModuleNames){
            Copy-Item -Path $env:ProgramFiles\windowspowershell\modules\$ModuleName -Destination $env:ProgramFiles\windowspowershell\modules -ToSession $PSSession -Recurse -Force
        }
        Foreach ($ModuleName in $RequiredModules.ModuleName){
            Copy-Item -Path $env:ProgramFiles\windowspowershell\modules\$ModuleName -Destination $env:ProgramFiles\windowspowershell\modules -ToSession $PSSession -Recurse -Force
        }
    }

    #since there was a subnet configured for AKS (note the labconfig), let's exclude VIP pool from dhcp
    #make sure dhcp tools are installed
    install-windowsfeature -name RSAT-DHCP
    #exclude
    Add-DhcpServerv4ExclusionRange -StartRange $VIPPoolStart -EndRange $VIPPoolEnd -ScopeId $DHCPScopeID -ComputerName $DHCPServer

    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        #dhcp does not work as it keeps asking for gw, dns servers...
        #New-ArcHciVirtualNetwork -name AKSvnet -vswitchname $using:vswitchname -vippoolstart $using:vipPoolStart -vippoolend $using:vipPoolEnd -vlanid $using:vlanid 
        #without dhcp
        New-ArcHciVirtualNetwork -name $using:AKSVnetName -vswitchname $using:vswitchname -vippoolstart $using:vipPoolStart -vippoolend $using:vipPoolEnd -vlanid $using:vlanid -ipAddressPrefix $Using:ipaddressprefix -gateway $using:gateway -dnsservers $using:DNSServers -k8sNodeIpPoolStart $using:k8sNodeIpPoolStart -k8sNodeIpPoolEnd $using:k8sNodeIpPoolend
    }

    #Connect your on-premises AKS hybrid network to Azure
    az extension add --name hybridaks
    #register namespace provider
    $Providers="Microsoft.HybridContainerService"
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

    #add network
    az hybridaks vnet create -n $AKSVnetName -g $HCIResourceGroupName --custom-location $customLocationName --moc-vnet-name $AKSVnetName

#endregion

#region add image for aks
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    Add-ArcHciK8sGalleryImage -k8sVersion 1.24.11
}
#endregion

