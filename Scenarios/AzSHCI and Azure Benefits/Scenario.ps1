#https://docs.microsoft.com/en-us/azure-stack/hci/manage/azure-benefits

#region Variables
$ClusterName="AzSHCI-Cluster"
#$ClusterName="Ax6515-Cluster"
$ClusterNodeNames=(Get-ClusterNode -Cluster $ClusterName).Name
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
$AzureImages=@()
$AzureImages+=@{PublisherName = "microsoftwindowsserver";Offer="windowsserver";SKU="2022-datacenter-azure-edition-smalldisk"}
$AzureImages+=@{PublisherName = "microsoftwindowsserver";Offer="windowsserver";SKU="2022-datacenter-azure-edition-core-smalldisk"}


#login to Azure
if (-not (Get-AzContext)){
    Login-AzAccount -UseDeviceAuthentication
}

#select context
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context=$context | Out-GridView -OutputMode Single
    $context | Set-AzContext
}

$region = (Get-AzLocation | Where-Object Providers -Contains "Microsoft.Compute" | Out-GridView -OutputMode Single -Title "Please select your Azure Region").Location
$ResourceGroupName="MSLabAzureBenefits"
$LibraryVolumeName="Library"

#Create Resource Group for Images and Arc Service principal
If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
    New-AzResourceGroup -Name $ResourceGroupName -Location $region
}

$CSVPath=((Get-ClusterSharedVolume -Cluster $ClusterName).SharedVolumeInfo).FriendlyVolumeName | Out-GridView -OutputMode Single -Title "Please select volume where VMs will be created"
$OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" #OU where AVD VMs will be djoined
$vSwitchName="vSwitch"
$MountDir="c:\temp\MountDir" #cannot be CSV. Location for temporary mount of VHD to inject answer file

$VMs=@()
$VMs+=@{VMName="WS2022Azure01"    ; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=4 ; AdminPassword="LS1setup!" ; ImageName="2022-datacenter-azure-edition.vhdx"}
$VMs+=@{VMName="WS2022Azure02"    ; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=4 ; AdminPassword="LS1setup!" ; ImageName="2022-datacenter-azure-edition.vhdx"}
$VMs+=@{VMName="WS2022AzCore01"   ; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=4 ; AdminPassword="LS1setup!" ; ImageName="2022-datacenter-azure-edition-core.vhdx"}
$VMs+=@{VMName="WS2022AzCore02"   ; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=4 ; AdminPassword="LS1setup!" ; ImageName="2022-datacenter-azure-edition-core.vhdx"}

#endregion

#region Create 2 node cluster (just simple. Not for prod - follow hyperconverged scenario for real clusters https://github.com/microsoft/MSLab/tree/master/Scenarios/AzSHCI%20Deployment)
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

#region register cluster to Azure
    #register in Azure
        #login to azure
        #download Azure module
        if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
            Install-Module -Name Az.Accounts -Force
        }
        Login-AzAccount -UseDeviceAuthentication

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

        #choose location for cluster
        $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata").Location

        #Register AZSHCi without prompting for creds
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        #Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id
        Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName  $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -ResourceName $ClusterName
#endregion

#region prerequisites https://docs.microsoft.com/en-us/azure-stack/hci/manage/azure-benefits#enable-azure-benefits
    #Install Updates if needed
        #Check OS Version
        $OSInfo=Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        }
        $OSInfo | Select-Object PSComputerName,CurrentBuildNumber,DisplayVersion,UBR

        if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuild -ge 20348){
            Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
        }
        #All nodes has to be at least 12b update (UBR 405 on 21H2)
        $UpdateNeeded=($OSInfo.UBR | Sort-Object | Select-Object -First 1) -lt 405

        #Update
        If ($UpdateNeeded){
            #run scan
            $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
            IsInstalled=0 and DeploymentAction='OptionalInstallation' or
            IsPresent=1 and DeploymentAction='Uninstallation' or
            IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
            IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}

            #list available updates
            $scan | Select-Object NodeName,UpdateTitle | Out-GridView

            #run install
            Invoke-CauRun -ClusterName $ClusterName -AttemptSoftReboot -MaxFailedNodes 0 -MaxRetriesPerNode 1 -RequireAllNodesOnline -Force -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
            IsInstalled=0 and DeploymentAction='OptionalInstallation' or
            IsPresent=1 and DeploymentAction='Uninstallation' or
            IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
            IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}

        #explore result
            $report=Get-CauReport -ClusterName $ClusterName -Last -Detailed
            $report
            $report.ClusterResult.NodeResults
        }

        #Check version again
        #Check OS Version
        $OSInfo=Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        }
        $OSInfo | Select-Object PSComputerName,CurrentBuildNumber,DisplayVersion,UBR


    #distribute Az.StackHCI module to Azure Stack HCI nodes
        #Increase MaxEvenlope and create session to copy files to
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
        #Create Session
        $sessions=New-PSSession -ComputerName $ClusterNodeNames
        #Copy Az.StackHCI module
        foreach ($Session in $sessions){
            Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\Az.StackHCI" -Destination "C:\Program Files\WindowsPowerShell\Modules\" -Recurse -ToSession $Session -Force
        }
        $Sessions | Remove-PSSession

    #Install Hyper-V PowerShell on Azure Nodes
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
            Add-WindowsFeature -Name RSAT-Hyper-V-Tools
        }

    #make sure Cluster is registered to Azure
        Invoke-Command -ComputerName $CLusterName -ScriptBlock {
            Get-AzureStackHCI
        }

    #configure thin volumes a default if available (because why not :)
        $OSInfo=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        }
        if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuild -ge 20348){
            Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
        }
        #validate pool setting
        Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Select-Object FriendlyName,ProvisioningTypeDefault

    #Create library volume
        if (-not (Get-VirtualDisk -CimSession $ClusterName -FriendlyName $LibraryVolumeName -ErrorAction Ignore)){
            New-Volume -StoragePoolFriendlyName "S2D*" -FriendlyName $LibraryVolumeName -FileSystem CSVFS_ReFS -Size 500GB -ResiliencySettingName Mirror -CimSession $ClusterName
        }
#endregion

#region Enable IMDS Attestation on Azure Stack HCI Cluster
    Enable-AzStackHCIAttestation -ComputerName $ClusterName -Force

    #Check Attestation on nodes
        Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
            Get-AzureStackHCIAttestation
        }

    #Check overall registration
    Invoke-Command -ComputerName $CLusterName -ScriptBlock {
        Get-AzureStackHCI
    }

    #explore VMSwitch that was created for attestation
        Get-VMSwitch -CimSession $ClusterNodeNames -Name AZSHCI_HOST-IMDS_DO_NOT_MODIFY

    #display vNICs that were created in Azure Host
        Get-VMNetworkAdapter -ManagementOS -CimSession $ClusterNodeNames -Name AZSHCI_HOST-IMDS_DO_NOT_MODIFY
#endregion

#region Download Azure Images

    #list windows server Offers
        Get-AzVMImageSku -Location $region -PublisherName "microsoftwindowsserver"  -Offer "WindowsServer"

    #Create managed disks with azure images
        foreach ($AzureImage in $AzureImages){
            $image=Get-AzVMImage -Location $region -PublisherName $AzureImage.PublisherName -Offer $AzureImage.Offer -SKU $AzureImage.SKU | Sort-Object Version -Descending |Select-Object -First 1
            $ImageVersionID = $image.id
            # Export the OS disk
            $imageOSDisk = @{Id = $ImageVersionID}
            $OSDiskConfig = New-AzDiskConfig -Location $region -CreateOption "FromImage" -ImageReference $imageOSDisk
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

#region Create Windows Server 2022 Azure Edition Servers
    #Create VMs
    foreach ($VM in $VMs){
        #Copy VHD to destination
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            New-Item -Path "$using:CSVPath\$($using:VM.VMName)\Virtual Hard Disks\" -ItemType Directory -Force
            Copy-Item -Path "c:\ClusterStorage\$using:LibraryVolumeName\$($using:VM.ImageName)" -Destination "$using:CSVPath\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx"
        }
        #Create Answer File
        $djointemp=New-TemporaryFile
        & djoin.exe /provision /domain $env:USERDOMAIN /machine $VM.VMName /savefile $djointemp.fullname /machineou $OUPath
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
<RegisteredOwner>GEOSRules!</RegisteredOwner>
<RegisteredOrganization>GEOSRules!</RegisteredOrganization>
</component>
<component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<RunSynchronous>
</RunSynchronous>
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
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            $VM=$using:vm
            $VMTemp=New-VM -Name $VM.VMName -MemoryStartupBytes $VM.MemoryStartupBytes -Generation 2 -Path "$using:CSVPath" -VHDPath "$using:CSVPath\$($VM.VMName)\Virtual Hard Disks\$($VM.VMName).vhdx" -SwitchName $Using:vSwitchName
            $VMTemp | Set-VMProcessor -Count $VM.NumberOfCPUs
            if ($VM.DynamicMemory){
                $VMTemp | Set-VM -DynamicMemory
            }
            $VMTemp | Start-VM
        }
        #add VM as clustered role
        Add-ClusterVirtualMachineRole -VMName $VM.VMName -Cluster $ClusterName
    }

#endregion

#region Enable IMDS Attestation on all VMs
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
        Add-AzStackHCIVMAttestation -AddAll -Force
    }

    #Check IMDS Attestation
    Invoke-Command -ComputerName $ClusterNodeNames -ScriptBlock {
        Get-AzStackHCIVMAttestation -Local
    }

    #restart those Azure VMs (it looks like restart is needed)
        restart-computer -ComputerName $VMs.VMName -Protocol WSMan -Wait -For PowerShell -Force
#endregion

#region deploy Arc Agent
    $servers=$VMs.VMName

    # Download the package
    Start-BitsTransfer -Source https://aka.ms/AzureConnectedMachineAgent -Destination "$env:UserProfile\Downloads\AzureConnectedMachineAgent.msi"
    #Copy ARC agent to VMs
    #increase max evenlope size first
    Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
    #create sessions
    $sessions=New-PSSession -ComputerName $servers
    #copy ARC agent
    foreach ($session in $sessions){
        Copy-Item -Path "$env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force
    }

    $Sessions | Remove-PSSession

    #install package
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /l*v $env:USERPROFILE\Downloads\ACMinstallationlog.txt /qn" -Wait
    }
    <#uninstall if needed
    Invoke-Command -ComputerName $servers -ScriptBlock {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/uninstall $env:USERPROFILE\Downloads\AzureConnectedMachineAgent.msi /qn" -Wait
    }
    #>

    #Some variables
    $ServicePrincipalName="Arc-for-servers"
    $TenantID=(Get-AzContext).Tenant.ID
    $SubscriptionID=(Get-AzContext).Subscription.ID
    $location=(Get-AzResourceGroup -Name $ResourceGroupName).Location
    $tags="Platform=Windows"
    $password="" #here goes ADApp password. If empty, script will generate new secret. Make sure this secret is the same as in Azure


    #Register ARC Resource provider
        Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute
        Register-AzResourceProvider -ProviderNamespace Microsoft.GuestConfiguration

    #Create AzADServicePrincipal if it does not already exist
        $SP=Get-AZADServicePrincipal -DisplayName $ServicePrincipalName
        if (-not $SP){
            $SP=New-AzADServicePrincipal -DisplayName "Arc-for-servers" -Role "Azure Connected Machine Onboarding"
            #remove default cred
            Remove-AzADAppCredential -ApplicationId $SP.AppId
        }

    #Create new password
    if (-not ($password)){
        $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential" -Property @{
            "KeyID"         = (new-guid).Guid ;
            "EndDateTime" = [DateTime]::UtcNow.AddYears(10)
        }
        $Creds=New-AzADAppCredential -PasswordCredentials $credential -ApplicationID $SP.AppID
        $password=$Creds.SecretText
        Write-Host "Your Password is: " -NoNewLine ; Write-Host $password -ForegroundColor Cyan
    }

    #sleep for 1m just to let ADApp password to propagate
    Start-Sleep 60

    #configure Azure ARC agent on servers
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Start-Process -FilePath "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" -ArgumentList "connect --service-principal-id $($using:SP.AppID) --service-principal-secret $using:password --resource-group $using:ResourceGroupName --tenant-id $using:TenantID --location $($using:Location) --subscription-id $using:SubscriptionID --tags $using:Tags" -Wait
    }

    #Validate if agents are connected
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        & "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe" show
    }

#endregion

#region (optional) Install Windows Admin Center Gateway https://github.com/microsoft/WSLab/tree/master/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA#gw-mode-installation-with-self-signed-cert
    ##Install Windows Admin Center Gateway 
    $GatewayServerName="WACGW"
    #Download Windows Admin Center if not present
    if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
        Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
    }
    #Create PS Session and copy install files to remote server
    Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
    $Session=New-PSSession -ComputerName $GatewayServerName
    Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

    #Install Windows Admin Center
    Invoke-Command -Session $session -ScriptBlock {
        Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
    } -ErrorAction Ignore

    $Session | Remove-PSSession

    #add certificate to trusted root certs (workaround to trust HTTPs cert on WACGW)
    start-sleep 10
    $cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
    $cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
    Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

    #Configure Resource-Based constrained delegation
    $gatewayObject = Get-ADComputer -Identity $GatewayServerName
    $computers = (Get-ADComputer -Filter {OperatingSystem -eq "Azure Stack HCI"}).Name

    foreach ($computer in $computers){
        $computerObject = Get-ADComputer -Identity $computer
        Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
    }

#endregion