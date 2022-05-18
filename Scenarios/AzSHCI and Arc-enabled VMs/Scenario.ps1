#https://aka.ms/ArcEnabledHCI
#https://aka.ms/AzureArcVM

###################
### Run from DC ###
###################

#region Variables 
    $ClusterNodeNames="ArcVMs1","ArcVMs2"
    $ClusterName="ArcVMs-Cluster"
    $vswitchName="vSwitch"
    $controlPlaneIP="10.0.0.111"
    $VolumeName="MOC"
    $VolumePath="c:\ClusterStorage\$VolumeName"
    $CredSSPUserName="CORP\LabAdmin"
    $CredSSPPassword="LS1setup!"
    $CustomLocationName="$ClusterName-cl"
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
    $AzureStackLocation=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Choose location for Azure Stack HCI - where it should be registered").Location
    #>

    #virtual network name
    $vnetName=$vswitchName
    
#endregion

#region Create 2 node cluster (just simple. Not for prod - follow hyperconverged scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20Deployment)
    # Install features for management on server
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools

    # Update servers (optional)
        <#
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
        #>

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
    $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id

    #grab location
    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }

    #register
    Register-AzStackHCI -SubscriptionID $subscriptionID -Region $AzureStackLocation -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

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
            $Vnet=New-MocNetworkSetting -Name hcirb-vnet -vswitchName $using:vswitchName -vipPoolStart $using:controlPlaneIP -vipPoolEnd $using:controlPlaneIP
            Set-MocConfig -workingDir "\\$using:ClusterName\ClusterStorage$\$using:VolumeName\workingDir" -vnet $vnet -imageDir $using:VolumePath\imageStore -skipHostLimitChecks -cloudConfigLocation $using:VolumePath\cloudStore -catalog aks-hci-stable-catalogs-ext -ring stable
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
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            New-ArcHciConfigFiles -subscriptionID $using:HCISubscriptionID -location $using:ArcResourceBridgeLocation -resourceGroup $using:HCIResourceGroupName -resourceName $using:BridgeResourceName -workDirectory "\\$using:ClusterName\ClusterStorage$\$using:VolumeName\workingDir"
        }
        #prepare
        az arcappliance prepare hci --config-file \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-appliance.yaml

        #Create folder for config
        New-Item -Path $env:USERPROFILE\.kube -ItemType Directory -ErrorAction Ignore

        #deploy control plane and export kube config
        az arcappliance deploy hci --config-file  \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-appliance.yaml --outfile $env:USERPROFILE\.kube\config
        #create connection to Azure (might throw error, dont worry! It's being deployed on background)
        az arcappliance create hci --config-file  \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-appliance.yaml --kubeconfig $env:USERPROFILE\.kube\config

    #wait until appliance is running
        do {
            $Status=az arcappliance show --only-show-errors --resource-group $HCIResourceGroupName --name $BridgeResourceName | ConvertFrom-Json
            Write-Host -NoNewline -Object "."
            Start-Sleep 2
        } until ($status.status -match "Running")

    #verify if appliance is running
        az arcappliance show --resource-group $HCIResourceGroupName --name $BridgeResourceName | ConvertFrom-Json

    #Add K8s extension
        #create
        az k8s-extension create --cluster-type appliances --cluster-name $BridgeResourceName --resource-group $HCIResourceGroupName --name hci-vmoperator --extension-type Microsoft.AZStackHCI.Operator --scope cluster --release-namespace helm-operator2 --configuration-settings Microsoft.CustomLocation.ServiceAccount=hci-vmoperator --configuration-protected-settings-file \\$ClusterName\ClusterStorage$\$VolumeName\workingDir\hci-config.json --configuration-settings HCIClusterID=$AzureResourceUri --auto-upgrade true
        #validate
        az k8s-extension show --cluster-type appliances --cluster-name $BridgeResourceName --resource-group $HCIResourceGroupName --name hci-vmoperator
    
    #Create custom location (has to be created after arcappliance deployment)
        az customlocation create --resource-group $HCIResourceGroupName --name $CustomLocationName --cluster-extension-ids "/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName/providers/Microsoft.KubernetesConfiguration/extensions/hci-vmoperator" --namespace hci-vmoperator --host-resource-id "/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName" --location $ArcResourceBridgeLocation

        <# Or with PowerShell
        #install Az.CustomLocation module
        if (!(Get-InstalledModule -Name az.CustomLocation -ErrorAction Ignore)){
            Install-Module -Name Az.CustomLocation -Force
        }
        New-AzCustomLocation -ResourceGroupName $ResourceGroupName -Name $CustomLocationName -ClusterExtensionID "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName/providers/Microsoft.KubernetesConfiguration/extensions/hci-vmoperator" -NameSpace hci-vmoperator -HostResourceID "/subscriptions/$SubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.ResourceConnector/appliances/$BridgeResourceName" -Location $ArcResourceBridgeLocation
        #>

#endregion

#region Copy kube config to nodes to have it available there
$Sessions=New-PSSession -ComputerName $ClusterNodeNames

#copy kube to cluster nodes
Foreach ($Session in $Sessions){
    Copy-Item -Path "$env:userprofile\.kube" -Destination $env:userprofile -ToSession $Session -Recurse -Force
}

$Sessions | Remove-PSSession
#endregion

#region create virtual network
    #Grab registration info
        $RegistrationInfo=Invoke-Command -ComputerName $CLusterName -ScriptBlock {Get-AzureStackHCI}
        $AzureResourceUri= $RegistrationInfo.AzureResourceUri
        $HCIResourceGroupName=$AzureResourceUri.split("/")[4]
        $HCISubscriptionID=$AzureResourceUri.split("/")[2]
    #create network
    az azurestackhci virtualnetwork create --subscription $HCISubscriptionID --resource-group $HCIResourceGroupName --extended-location name="/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ExtendedLocation/customLocations/$CustomLocationName" type="CustomLocation" --location $ArcResourceBridgeLocation --network-type "Transparent" --name $vnetName
#endregion

#region create images
    #Create library volume
        if (-not (Get-VirtualDisk -CimSession $ClusterName -FriendlyName $LibraryVolumeName -ErrorAction Ignore)){
            New-Volume -StoragePoolFriendlyName "S2D*" -FriendlyName $LibraryVolumeName -FileSystem CSVFS_ReFS -Size 500GB -ResiliencySettingName Mirror -CimSession $ClusterName
        }

    #region download Azure images to library
        #list windows server Offers
        Get-AzVMImageSku -Location $VMImageLocation -PublisherName "microsoftwindowsserver"  -Offer "WindowsServer"

        #Create managed disks with azure images
            foreach ($AzureImage in $AzureImages){
                $image=Get-AzVMImage -Location $VMImageLocation -PublisherName $AzureImage.PublisherName -Offer $AzureImage.Offer -SKU $AzureImage.SKU | Sort-Object Version -Descending |Select-Object -First 1
                $ImageVersionID = $image.id
                # Export the OS disk
                $imageOSDisk = @{Id = $ImageVersionID}
                $OSDiskConfig = New-AzDiskConfig -Location $VMImageLocation -CreateOption "FromImage" -ImageReference $imageOSDisk
                New-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $AzureImage.SKU -Disk $OSDiskConfig
            }

        #Download AZCopy
            # Download the package 
            Start-BitsTransfer -Source "https://aka.ms/downloadazcopy-v10-windows" -Destination "$env:UserProfile\Downloads\AzCopy.zip"
            Expand-Archive -Path "$env:UserProfile\Downloads\AzCopy.zip" -DestinationPath "$env:UserProfile\Downloads\AZCopy" -Force
            $item=Get-ChildItem -Name azcopy.exe -Recurse -Path "$env:UserProfile\Downloads\AZCopy" 
            Move-Item -Path "$env:UserProfile\Downloads\AZCopy\$item" -Destination "$env:UserProfile\Downloads\" -Force
            Remove-Item -Path "$env:UserProfile\Downloads\AZCopy\" -Recurse
            Remove-Item -Path "$env:UserProfile\Downloads\AzCopy.zip"

        #Download Images
            foreach ($AzureImage in $AzureImages){
                #Grant Access https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview
                $output=Grant-AzDiskAccess -ResourceGroupName $ResourceGroupName -DiskName $AzureImage.SKU -Access 'Read' -DurationInSecond 3600
                #Grab shared access signature
                $SAS=$output.accesssas
                #Download
                & $env:UserProfile\Downloads\azcopy.exe copy $sas "\\$ClusterName\ClusterStorage$\$LibraryVolumeName\$($AzureImage.SKU).vhd" --check-md5 NoCheck --cap-mbps 500
                #once disk is downloaded, disk access can be revoked
                Revoke-AzDiskAccess -ResourceGroupName  $ResourceGroupName -Name $AzureImage.SKU
                #and disk itself can be removed
                Remove-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $AzureImage.SKU -Force
                #and disk itself can be converted to VHDx and compacted
                Invoke-Command -ComputerName $ClusterName -ScriptBlock {
                    Convert-VHD -Path "c:\clusterstorage\$using:LibraryVolumeName\$($using:AzureImage.sku).vhd" -DestinationPath "c:\clusterstorage\$using:LibraryVolumeName\$($using:AzureImage.sku).vhdx" -VHDType Dynamic -DeleteSource
                    Optimize-VHD -Path "c:\clusterstorage\$using:LibraryVolumeName\$($using:AzureImage.sku).vhdx" -Mode Full
                }
                if ($AzureImage.SKU -like "*-smalldisk*"){
                    #and it can be also expanded from default 32GB (since image is small to safe some space)
                    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
                        Resize-VHD -Path "c:\clusterstorage\$using:LibraryVolumeName\$($using:AzureImage.sku).vhdx" -SizeBytes 127GB
                        #mount VHD
                        $VHDMount=Mount-VHD "c:\clusterstorage\$using:LibraryVolumeName\$($using:AzureImage.sku).vhdx" -Passthru
                        $partition = $vhdmount | Get-Disk | Get-Partition | Where-Object PartitionNumber -Eq 4
                        $partition | Resize-Partition -Size ($Partition | Get-PartitionSupportedSize).SizeMax
                        $VHDMount| Dismount-VHD 
                    }
                    #and since it's no longer smalldisk, it can be renamed
                    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
                        $NewName=($using:AzureImage.SKU).replace("-smalldisk","")
                        Rename-Item -Path "c:\clusterstorage\$using:LibraryVolumeName\$($using:AzureImage.sku).vhdx" -NewName "$NewName.vhdx"
                    }
                }
            }
    #endregion

    #region create gallery image offer
        $RegistrationInfo=Invoke-Command -ComputerName $CLusterName -ScriptBlock {Get-AzureStackHCI}
        $AzureResourceUri= $RegistrationInfo.AzureResourceUri
        $HCIResourceGroupName=$AzureResourceUri.split("/")[4]
        $HCISubscriptionID=$AzureResourceUri.split("/")[2]
        foreach ($AzureImage in $AzureImages){
            #Since disk was expandend, -smalldisk can be removed from name
            $NewName=($AzureImage.SKU).replace("-smalldisk","")
            $galleryImageName=$NewName
            $galleryImageSourcePath="c:\ClusterStorage\$LibraryVolumeName\$galleryImageName.vhdx" 
            $osType=$AzureImage.OSType
            az azurestackhci galleryimage create --subscription $HCISubscriptionID --resource-group $HCIResourceGroupName --extended-location name="/subscriptions/$HCISubscriptionID/resourceGroups/$HCIResourceGroupName/providers/Microsoft.ExtendedLocation/customLocations/$CustomLocationName" type="CustomLocation" --location $ArcResourceBridgeLocation --image-path $galleryImageSourcePath --name $galleryImageName --os-type $osType
        }
    #endregion
#endregion

#now you can navigate to https://aka.ms/AzureArcVM to create VMs!

#region collect logs
    #Enable CredSSP
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    foreach ($ClusterNodeName in $ClusterNodeNames){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $ClusterNodeName -Force
    }
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

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

    #unregister Azure Stack HCI
        #Grab registration info
        $RegistrationInfo=Invoke-Command -ComputerName $CLusterName -ScriptBlock {Get-AzureStackHCI}
        $AzureResourceUri= $RegistrationInfo.AzureResourceUri
        $HCIResourceGroupName=$AzureResourceUri.split("/")[4]
        $HCISubscriptionID=$AzureResourceUri.split("/")[2]
        #login to Azure
        if (-not (Get-AzContext)){
            Login-AzAccount -UseDeviceAuthentication
        }
        $subscriptionID=(Get-AzContext).Subscription.id
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        UnRegister-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -Confirm:0

    #login to Azure
    if (-not (Get-AzContext)){
        Login-AzAccount -UseDeviceAuthentication
    }

    #remove virtual network
    az azurestackhci virtualnetwork delete --subscription $HCISubscriptionID --resource-group $HCIResourceGroupName --name $vnetName --yes

    #remove gallery images
    foreach ($AzureImage in $AzureImages){
        az azurestackhci galleryimage delete --subscription $HCISubscriptionID --resource-group $HCIResourceGroupName --name $AzureImage.SKU
    }

    #remove custom location
    az customlocation delete --resource-group $HCIResourceGroupName --name $customLocationName --yes

    #remove Kubernetes Extension
    $BridgeResourceName=("$($RegistrationInfo.AzureResourceName)-arcbridge").ToLower()
    az k8s-extension delete --cluster-type appliances --cluster-name $BridgeResourceName  --resource-group $HCIResourceGroupName --name hci-vmoperator --yes

    #remove appliance
    az arcappliance delete hci --config-file \\$ClusterName\clusterstorage$\MOC\workingDir\hci-appliance.yaml --yes

    #remove configfiles
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Remove-ArcHciConfigFiles
    }

    #remove resource group
    #login to Azure
    if (-not (Get-AzContext)){
        Login-AzAccount -UseDeviceAuthentication
    }
    Remove-AzResourceGroup -Name $ResourceGroupName -Force

    #uninstall MOC
        #Enable CredSSP
        # Temporarily enable CredSSP delegation to avoid double-hop issue
        foreach ($ClusterNodeName in $ClusterNodeNames){
            Enable-WSManCredSSP -Role "Client" -DelegateComputer $ClusterNodeName -Force
        }
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Enable-WSManCredSSP Server -Force }

        $SecureStringPassword = ConvertTo-SecureString $CredSSPPassword -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($CredSSPUserName, $SecureStringPassword)

        #uninstall MOC
        Invoke-Command -ComputerName $ClusterNodeNames[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
            Uninstall-Moc
        }
        # Disable CredSSP
        Disable-WSManCredSSP -Role Client
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock { Disable-WSManCredSSP Server }

    #remove volume for MOC
    Remove-VirtualDisk -FriendlyName $VolumeName -CimSession $ClusterName -Confirm:0

    #remove volume for MOC
    Remove-VirtualDisk -FriendlyName $LibraryVolumeName -CimSession $ClusterName -Confirm:0

#endregion