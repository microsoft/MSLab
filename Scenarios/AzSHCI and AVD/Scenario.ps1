#region Variables
    $ClusterName="ax6515-cluster"
    $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
    $LibraryVolumeName="Library" #volume for images for VMs
    $VMsVolumeSize=1TB #size of volumes for AVD VMs
    $OUPath="OU=Workshop,DC=Corp,DC=contoso,DC=com" #OU where AVD VMs will be djoined
    $vSwitchName="vSwitch"
    $MountDir="c:\temp\MountDir" #cannot be CSV. Location for temporary mount of VHD to inject answer file

    $AVDResourceGroupName="MSLabAVD"
    $AVDHostPoolName="MSLabAVDPool"
    $AVDWorkspaceName="MSLabAVDWorkspace"

    $ManagedDiskName = "AVD_OS_Disk_Windows11_m365"
    $Offer="windows11preview"
    $SKU="win11-21h2-avd-m365"

    #Install Azure packages
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        $ModuleNames="Az.Accounts","Az.Compute","Az.Resources","Az.DesktopVirtualization"
        foreach ($ModuleName in $ModuleNames){
            if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
                Install-Module -Name $ModuleName -Force
            }
        }

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

    #location (all locations where HostPool can be created)
        $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.DesktopVirtualization" | Out-GridView -OutputMode Single -Title "Please select Location for AVD Host Pool metadata").Location


    #Generate list of VMs to be created
        #Session hosts
        $VMs=@()
        $VMsPerNode=4
        Foreach ($ClusterNode in $ClusterNodes){
            foreach ($number in 1..$VMsPerNode){
                $VMs+=@{VMName="$($ClusterNode)_AVD$("{0:D2}" -f $Number)"; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=4 ; AdminPassword="LS1setup!" ; CSVPath="c:\ClusterStorage\$ClusterNode" ; Owner=$ClusterNode}
            }
        }
        #fileserver (fileservers)
        $ServerVMs=@()
        $ServerVMs+=@{VMName="FileServer"; MemoryStartupBytes=1GB ; DynamicMemory=$true ; NumberOfCPUs=4 ; AdminPassword="LS1setup!" ; CSVPath="c:\ClusterStorage\$($ClusterNodes[0])" ; Owner=$($ClusterNodes[0])}
#endregion

#region prepare cluster

    #configure thin volumes a default if available (because why not :)
        $OSInfo=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        }
        if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuildNumber -ge 20348){
            Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
        }

    #Create library volume
        if (-not (Get-VirtualDisk -CimSession $ClusterName -FriendlyName $LibraryVolumeName -ErrorAction Ignore)){
            New-Volume -StoragePoolFriendlyName "S2D*" -FriendlyName $LibraryVolumeName -FileSystem CSVFS_ReFS -Size 500GB -ResiliencySettingName Mirror -CimSession $ClusterName
        }

    # Create volumes for VMs
        #note - for easier tracking, we will create volume names with same name as node
        foreach ($ClusterNode in $ClusterNodes){
            if (-not (Get-VirtualDisk -CimSession $ClusterName -FriendlyName $ClusterNode -ErrorAction Ignore)){
                New-Volume -StoragePoolFriendlyName S2D* -FriendlyName $ClusterNode -FileSystem CSVFS_ReFS -Size $VMsVolumeSize -ResiliencySettingName Mirror -CimSession $ClusterName
            }
        }

#endregion

#region create host pool
    #install modules
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        $ModuleNames="Az.DesktopVirtualization","Az.Resources","Az.Accounts","Az.Compute"
        foreach ($ModuleName in $ModuleNames){
            if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
                Install-Module -Name $ModuleName -Force
            }
        }

    #login to Azure
        if (-not (Get-AzContext)){
            Login-AzAccount -UseDeviceAuthentication
        }

    #Create AVD Host Pool
        #Create resource Group
        If (-not (Get-AzResourceGroup -Name $AVDResourceGroupName -ErrorAction Ignore)){
            New-AzResourceGroup -Name $AVDResourceGroupName -Location $region
        }

        #Create Host Pool
        New-AzWvdHostPool -Name $AVDHostPoolName -ResourceGroupName $AVDResourceGroupName -HostPoolType "Pooled" -LoadBalancerType "BreadthFirst" -PreferredAppGroupType "Desktop" -Location $Region -WorkspaceName $AVDWorkspaceName -DesktopAppGroupName "Desktop"
#endregion

#region Grab VHD from Azure and copy to library CSV
    #login to Azure
    if (-not (Get-AzContext)){
        Login-AzAccount -UseDeviceAuthentication
    }

    #Create resource Group
    If (-not (Get-AzResourceGroup -Name $AVDResourceGroupName -ErrorAction Ignore)){
        New-AzResourceGroup -Name $AVDResourceGroupName -Location $region
    }
    #explore available disks
        #list offers
        Get-AzVMImageOffer -Location $region -PublisherName "microsoftwindowsdesktop"
        #list win10 SKUs
        Get-AzVMImageSku -Location $region -PublisherName  "microsoftwindowsdesktop" -Offer "Windows-10"
        #list win11 preview SKUs
        Get-AzVMImageSku -Location $region -PublisherName  "microsoftwindowsdesktop" -Offer "Windows11preview"

    #let's work with win11-21h2-avd-m365
        $image=Get-AzVMImage -Location $region -PublisherName  "microsoftwindowsdesktop" -Offer $Offer -SKU $SKU | Sort-Object Version -Descending |Select-Object -First 1

    #export image to a disk https://docs.microsoft.com/en-us/powershell/module/az.compute/new-azdisk?view=azps-6.6.0#example-3--export-a-gallery-image-version-to-disk-
    $ImageVersionID = $image.id

    # Export the OS disk
    $imageOSDisk = @{Id = $ImageVersionID}
    $OSDiskConfig = New-AzDiskConfig -Location $region -CreateOption "FromImage" -ImageReference $imageOSDisk
    New-AzDisk -ResourceGroupName $AVDResourceGroupName -DiskName $ManagedDiskName -Disk $OSDiskConfig
    $output=Grant-AzDiskAccess -ResourceGroupName $AVDResourceGroupName -DiskName $ManagedDiskName -Access 'Read' -DurationInSecond 3600
    $SAS=$output.accesssas
    #Start-BitsTransfer -Source $SAS -Destination "\\$ClusterName\ClusterStorage$\$LibraryVolumeName\$SKU.vhd"
    #download using AzCopy as it's faster than bits transfer. But it cannot be downloaded directly to CSV
    #https://aka.ms/downloadazcopy-v10-windows\
        # Download the package 
        Start-BitsTransfer -Source "https://aka.ms/downloadazcopy-v10-windows" -Destination "$env:UserProfile\Downloads\AzCopy.zip"
        Expand-Archive -Path "$env:UserProfile\Downloads\AzCopy.zip" -DestinationPath "$env:UserProfile\Downloads\AZCopy" -Force
        $item=Get-ChildItem -Name azcopy.exe -Recurse -Path "$env:UserProfile\Downloads\AZCopy" 
        Move-Item -Path "$env:UserProfile\Downloads\AZCopy\$item" -Destination "$env:UserProfile\Downloads\"
        Remove-Item -Path "$env:UserProfile\Downloads\AZCopy\" -Recurse
        Remove-Item -Path "$env:UserProfile\Downloads\AzCopy.zip"
        #download VHD to library
        & $env:UserProfile\Downloads\azcopy.exe copy $sas "\\$ClusterName\ClusterStorage$\$LibraryVolumeName\$SKU.vhd" --check-md5 NoCheck --cap-mbps 500
    #convert image to dynamic VHDx
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Convert-VHD -Path "c:\clusterstorage\$using:LibraryVolumeName\$using:sku.vhd" -DestinationPath "c:\clusterstorage\$using:LibraryVolumeName\$using:sku.vhdx" -VHDType Dynamic -DeleteSource
        Optimize-VHD -Path "c:\clusterstorage\$using:LibraryVolumeName\$using:sku.vhdx" -Mode Full
    }
    #once disk is downloaded, disk access can be revoked
    Revoke-AzDiskAccess -ResourceGroupName  $AVDResourceGroupName -Name $ManagedDiskName
    #and disk itself can be removed
    #Remove-AzDisk -ResourceGroupName $AVDResourceGroupName -DiskName $ManagedDiskName -Force
#endregion

#region Create VMs on Azure Stack HCI cluster

    <#In case you have your own VHD you can provide it
    #Ask for VHD
    Write-Output "Please select VHD for AVD created using CreateParentDisk.ps1"
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
    $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        Title="Please select VHD created using CreateParentDisk.ps1"
    }
    $openFile.Filter = "vhdx files (*.vhdx)|*.vhdx|All files (*.*)|*.*" 
    If($openFile.ShowDialog() -eq "OK"){
        Write-Output  "File $($openfile.FileName) selected"
    }
    $VHDPath=$openfile.FileName
    #Copy image
    Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$LibraryVolumeName\"
    #Generate Image Name
    $ImageName=$VHDPath | Split-Path -Leaf
    #>

    #or the image that was downloaded from Azure 
    $ImageName="$SKU.vhdx"

    #Create VMs
    foreach ($VM in $VMs){
        #Copy VHD to destination
        Invoke-Command -ComputerName $VM.Owner -ScriptBlock {
            New-Item -Path "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\" -ItemType Directory -Force
            Copy-Item -Path "c:\ClusterStorage\$using:LibraryVolumeName\$using:ImageName" -Destination "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx"
        }
        #Create Answer File
        $djointemp=New-TemporaryFile
        & djoin.exe /provision /domain $env:USERDOMAIN /machine $VM.VMName /savefile $djointemp.fullname /machineou $OUPath
        #extract blob blob from temp file
        $Blob=get-content $djointemp
        $Blob=$blob.Substring(0,$blob.Length-1)
        #remove temp file
        $djointemp | Remove-Item

        #Generate Unattend file with WINRM Enabled
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
        <RunSynchronousCommand wcm:action="add">
          <Path>cmd.exe /c winrm quickconfig -q -force</Path>
          <Description>enable winrm</Description>
          <Order>1</Order>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
"@

    #Mount VHD and Apply answer file
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            New-Item -Path "$using:Mountdir" -ItemType Directory -Force
            Mount-WindowsImage -Path "$using:Mountdir" -ImagePath "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx" -Index 1
            New-item -type directory  "$using:Mountdir\Windows\Panther"
            Set-Content -Value $using:unattend -Path "$using:Mountdir\Windows\Panther\Unattend.xml"
            Use-WindowsUnattend -Path "$using:Mountdir" -UnattendPath "$using:Mountdir\Windows\Panther\Unattend.xml"
            Dismount-WindowsImage -Path "$using:Mountdir" -Save
            Remove-Item -Path "$using:Mountdir"
        }

    #Create VM
        Invoke-Command -ComputerName $VM.Owner -ScriptBlock {
            $VM=$using:vm
            $VMTemp=New-VM -Name $VM.VMName -MemoryStartupBytes $VM.MemoryStartupBytes -Generation 2 -Path "$($using:VM.CSVPath)" -VHDPath "$($using:VM.CSVPath)\$($VM.VMName)\Virtual Hard Disks\$($VM.VMName).vhdx" -SwitchName $Using:vSwitchName
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

#region install and register Azure Arc agent
    #install connected machine agent (Azure Arc) = See Azure Arc for servers scenario https://github.com/microsoft/MSLab/tree/master/Scenarios/Azure%20Arc%20for%20Servers
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

    #register Connected mahine agent (Azure Arc)
        $ResourceGroupName=$AVDResourceGroupName
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

#region install and register AVD agent
#https://docs.microsoft.com/en-us/azure/virtual-desktop/create-host-pools-powershell?tabs=azure-powershell#register-the-virtual-machines-to-the-azure-virtual-desktop-host-pool

    #Download Agent and Bootloader
        Start-BitsTransfer -Source https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv -Destination "$env:UserProfile\Downloads\AVDAgent.msi"
        Start-BitsTransfer -Source https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH -Destination "$env:UserProfile\Downloads\AVDAgentBootloader.msi"

    #Copy agent and bootloader to VMs
        #create sessions
        $sessions=New-PSSession -ComputerName $VMs.VMName
        #copy ARC agent
        foreach ($session in $sessions){
            Copy-Item -Path "$env:USERPROFILE\Downloads\AVDAgent.msi" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force
            Copy-Item -Path "$env:USERPROFILE\Downloads\AVDAgentBootloader.msi" -Destination "$env:USERPROFILE\Downloads\" -tosession $session -force
        }
        $sessions | Remove-PSSession

    #Install agents
        #Grab registration token
        $Token=(Get-AzWvdHostPoolRegistrationToken -HostPoolName $AVDHostPoolName -ResourceGroupName $AVDResourceGroupName).Token
        if (-not ($Token)){
            $Token=(New-AzWvdRegistrationInfo -ResourceGroupName $AVDResourceGroupName -HostPoolName $AVDHostPoolName -ExpirationTime $((get-date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))).TOken
        }

        Invoke-Command -ComputerName $VMs.VMName -ScriptBlock {
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:USERPROFILE\Downloads\AVDAgent.msi /l*v $env:USERPROFILE\Downloads\AVDAgentInstallationLog.txt /qn /norestart REGISTRATIONTOKEN=$using:token RDInfraAgent=BYODesktop" -Wait -PassThru
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $env:USERPROFILE\Downloads\AVDAgentBootloader.msi /l*v $env:USERPROFILE\Downloads\AVDAgentBootloaderInstallationLog.txt /qn /norestart" -Wait -PassThru
        }
    #Restart VMs to finish installation
        Restart-Computer -ComputerName $VMs.VMName -Protocol WSMan -Wait -For PowerShell
#endregion

#region configure Azure Benefits
    Enable-AzStackHCIAttestation -ComputerName $ClusterName -Force

    #Check Attestation on nodes
        Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
            Get-AzureStackHCIAttestation
        }

    #Check overall registration
    Invoke-Command -ComputerName $CLusterName -ScriptBlock {
        Get-AzureStackHCI
    }

    #distribute Az.StackHCI module to Azure Stack HCI nodes
        #Increase MaxEvenlope and create session to copy files to
        Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
        #Create Session
        $sessions=New-PSSession -ComputerName $ClusterNodes
        #Copy Az.StackHCI module
        foreach ($Session in $sessions){
            Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\Az.StackHCI" -Destination "C:\Program Files\WindowsPowerShell\Modules\" -Recurse -ToSession $Session -Force
        }
        $Sessions | Remove-PSSession
    
    #enable attestation on AVD VMs
    Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
        Add-AzStackHCIVMAttestation -VMName ($using:VMs | Where-Object VMName -like "$env:COMPUTERNAME*").VMName -Force
    }

    #Check IMDS Attestation
    Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
        Get-AzStackHCIVMAttestation -Local
    }

    #Restart VMs to finish installation
    Restart-Computer -ComputerName $VMs.VMName -Protocol WSMan -Wait -For PowerShell

#endregion

#region setup FSLogix (based on https://github.com/microsoft/MSLab/blob/master/Scenarios/FSLogix/Scenario.ps1)
    #Grab VHD for FileServer VM and copy it to new library volume
        #Ask for VHD
        Write-Output "Please select VHD With Windows Server"
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select VHD created using CreateVMFleetDisk.ps1"
        }
        $openFile.Filter = "vhdx files (*.vhdx)|*.vhdx|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK"){
            Write-Output  "File $($openfile.FileName) selected"
        }
        $ServerVHDPath=$openfile.FileName
        #Copy image
        Copy-Item -Path $ServerVHDPath -Destination "\\$ClusterName\ClusterStorage$\$LibraryVolumeName\"
        #Generate Image Name
        $ServerImageName=$ServerVHDPath | Split-Path -Leaf

    #Create Server VM
        #Just recycling script from VMs creation
        $ImageName=$ServerImageName

        foreach ($VM in $ServerVMs){
            #Copy VHD to destination
            Invoke-Command -ComputerName $VM.Owner -ScriptBlock {
                New-Item -Path "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\" -ItemType Directory -Force
                Copy-Item -Path "c:\ClusterStorage\$using:LibraryVolumeName\$using:ImageName" -Destination "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx"
            }
            #Create Answer File
            $djointemp=New-TemporaryFile
            & djoin.exe /provision /domain $env:USERDOMAIN /machine $VM.VMName /savefile $djointemp.fullname /machineou $OUPath
            #extract blob blob from temp file
            $Blob=get-content $djointemp
            $Blob=$blob.Substring(0,$blob.Length-1)
            #remove temp file
            $djointemp | Remove-Item

            #Generate Unattend file with WINRM Enabled
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
    <RunSynchronousCommand wcm:action="add">
      <Path>cmd.exe /c winrm quickconfig -q -force</Path>
      <Description>enable winrm</Description>
      <Order>1</Order>
    </RunSynchronousCommand>
  </RunSynchronous>
</component>
</settings>
</unattend>
"@

    #Mount VHD and Apply answer file
        Invoke-Command -ComputerName $ClusterName -ScriptBlock {
            New-Item -Path "$using:Mountdir" -ItemType Directory -Force
            Mount-WindowsImage -Path "$using:Mountdir" -ImagePath "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\$($using:VM.VMName).vhdx" -Index 1
            New-item -type directory  "$using:Mountdir\Windows\Panther"
            Set-Content -Value $using:unattend -Path "$using:Mountdir\Windows\Panther\Unattend.xml"
            Use-WindowsUnattend -Path "$using:Mountdir" -UnattendPath "$using:Mountdir\Windows\Panther\Unattend.xml"
            Dismount-WindowsImage -Path "$using:Mountdir" -Save
            Remove-Item -Path "$using:Mountdir"
        }

    #Create VM
        Invoke-Command -ComputerName $VM.Owner -ScriptBlock {
            $VM=$using:vm
            $VMTemp=New-VM -Name $VM.VMName -MemoryStartupBytes $VM.MemoryStartupBytes -Generation 2 -Path "$($using:VM.CSVPath)" -VHDPath "$($using:VM.CSVPath)\$($VM.VMName)\Virtual Hard Disks\$($VM.VMName).vhdx" -SwitchName $Using:vSwitchName
            $VMTemp | Set-VMProcessor -Count $VM.NumberOfCPUs
            if ($VM.DynamicMemory){
                $VMTemp | Set-VM -DynamicMemory
            }
            $VMTemp | Start-VM
        }
        #add VM as clustered role
        Add-ClusterVirtualMachineRole -VMName $VM.VMName -Cluster $ClusterName
    }

    #add 1TB disk
    foreach ($VM in $ServerVMs){
        Invoke-Command -ComputerName $VM.Owner -ScriptBlock {
            New-VHD -Path "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\DATA01.vhdx" -SizeBytes 1TB
            Add-VMHardDiskDrive -VMName $using:VM.VMName -Path "$($using:VM.CSVPath)\$($using:VM.VMName)\Virtual Hard Disks\DATA01.vhdx"
        }
    }

    #wait a bit for VM to start
    Start-Sleep 60

    #prepare disk
        Get-Disk -CimSession $ServerVMs.VMName | Where-Object PartitionStyle -eq RAW | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -Filesystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel "Storage"

    #setup file share
        $FolderName="FSLogix"
        Invoke-Command -ComputerName $ServerVMs.VMName -ScriptBlock {new-item -Path D:\Shares -Name $using:FolderName -ItemType Directory}
        $accounts=@()
        $accounts+="corp\Domain Users"
        New-SmbShare -Name $FolderName -Path "D:\Shares\$FolderName" -FullAccess $accounts -CimSession $ServerVMs.VMName

    #setup NTFS permissions https://docs.microsoft.com/en-us/fslogix/fslogix-storage-config-ht
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module ntfssecurity -Force

        foreach ($ComputerName in $ServerVMs.VMName){
            $item=Get-Item -Path "\\$ComputerName\D$\shares\$foldername"
            $item | Disable-NTFSAccessInheritance
            $item | Get-NTFSAccess | Remove-NTFSAccess -Account "Corp\Domain Users"
            $item | Get-NTFSAccess | Remove-NTFSAccess -Account "BUILTIN\Users"
            $item | Get-NTFSAccess | Add-NTFSAccess -Account "corp\Domain Users" -AccessRights Modify -AppliesTo ThisFolderOnly
            $item | Get-NTFSAccess | Add-NTFSAccess -Account "Creator owner" -AccessRights Modify -AppliesTo SubfoldersAndFilesOnly
        }

    #Download FSLogix and expand
        Start-BitsTransfer -Source https://aka.ms/fslogix_download -Destination $env:USERPROFILE\Downloads\FSLogix_Apps.zip
        Expand-Archive -Path $env:USERPROFILE\Downloads\FSLogix_Apps.zip -DestinationPath $env:USERPROFILE\Downloads\FSLogix_Apps -Force

    #install fslogix admx template
        Copy-Item -Path $env:UserProfile\Downloads\FSLogix_Apps\fslogix.admx -Destination C:\Windows\PolicyDefinitions
        Copy-Item -Path $env:UserProfile\Downloads\FSLogix_Apps\fslogix.adml -Destination C:\Windows\PolicyDefinitions\en-US

    #grab recommended GPOs (original source https://github.com/shawntmeyer/WVD/tree/master/Image-Build/Customizations/GPOBackups)
        Start-BitsTransfer -Source https://github.com/microsoft/WSLab/raw/dev/Scenarios/FSLogix/WVD-GPO-Backups.zip -Destination $env:USERPROFILE\Downloads\WVD-GPO-Backups.zip
        #extract
        Expand-Archive -Path $env:USERPROFILE\Downloads\WVD-GPO-Backups.zip -DestinationPath $env:USERPROFILE\Downloads\WVDBackups\ -Force
        #import GPOs (and link)
        Install-WindowsFeature -Name GPMC
        $OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"
        $names=(Get-ChildItem -Path "$env:UserProfile\Downloads\WVDBackups" -Filter *.htm).BaseName
        foreach ($name in $names) {
            New-GPO -Name $name  | New-GPLink -Target $OUPath
            Import-GPO -BackupGpoName $name -TargetName $name -path "$env:UserProfile\Downloads\WVDBackups"
        }

    #install FSLogix to session hosts
        #create sessions
        $Sessions=New-PSSession -ComputerName $VMs.VMName
        foreach ($session in $Sessions){
            Copy-Item -Path $env:Userprofile\downloads\FSLogix_Apps\x64\Release\FSLogixAppsSetup.exe -Destination $env:Userprofile\downloads\ -ToSession $session
        }
        $Session | Remove-PSSession

        #install fslogix
        Invoke-Command -ComputerName $VMs.VMName -ScriptBlock {
            Start-Process -FilePath $env:Userprofile\downloads\FSLogixAppsSetup.exe -ArgumentList "/install /quiet / norestart" -Wait
        }

    #reboot machines
        Restart-Computer -ComputerName $VMs.VMName -Protocol WSMan -Wait -For PowerShell

    #Create users with password LS1setup!
        New-ADUser -Name JohnDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"
        New-ADUser -Name JaneDoe -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"

#endregion

#region cleanup
<#
#remove Azure Resource group
    Remove-AzResourceGroup -Name $AVDResourceGroupName -Force
#remove Azure Service Principal
    $SP=Get-AzADServicePrincipal -DisplayName "Arc-for-servers"
    Remove-AzADServicePrincipal -ObjectId $SP.Id -Force
#remove VMs
    foreach ($VM in $VMs){
        $VMObject=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name -Name $VM.VMName -ErrorAction Ignore
        if ($VMObject){
            $VMObject | Stop-VM -TurnOff
            Get-ClusterGroup -Cluster $CLusterName -Name $VM.VMName | Remove-ClusterGroup -RemoveResources -Force
            $VMObject | Remove-VM -Force -ErrorAction Ignore
            Invoke-Command -ComputerName $VMObject.ComputerName -ScriptBlock {Remove-Item -Path $using:VMObject.Path -Recurse -ErrorAction Ignore}
        }
    }
    foreach ($VM in $ServerVMs){
        $VMObject=Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name -Name $VM.VMName -ErrorAction Ignore
        if ($VMObject){
            $VMObject | Stop-VM -TurnOff
            Get-ClusterGroup -Cluster $CLusterName -Name $VM.VMName | Remove-ClusterGroup -RemoveResources -Force
            $VMObject | Remove-VM -Force -ErrorAction Ignore
            Invoke-Command -ComputerName $VMObject.ComputerName -ScriptBlock {Remove-Item -Path $using:VMObject.Path -Recurse -ErrorAction Ignore}
        }
    }
#remove CSVs
    Foreach ($node in (Get-ClusterNode -Cluster $ClusterName).Name){
        Get-VirtualDisk -CimSession $Node -FriendlyName $Node | Remove-VirtualDisk -Confirm:0
    }
    Get-VirtualDisk -CimSession $ClusterName -FriendlyName $LibraryVolumeName | Remove-VirtualDisk -Confirm:0
#Remove AD Objects, DNS Records and leases
    foreach ($VM in $VMs){
        Remove-DnsServerResourceRecord -CimSession DC -ZoneName corp.contoso.com -RRType "A" -Name $VM.VMName -Force
        Get-DhcpServerv4Lease -CimSession DC -ScopeId 10.0.0.0 | WHere Hostname -eq "$($VM.VMName).corp.contoso.com" | Remove-DhcpServerv4Lease
        Get-ADComputer -Identity $VM.VMName | Remove-ADObject -Confirm:0 -recursive
    }
    foreach ($VM in $ServerVMs){
        Remove-DnsServerResourceRecord -CimSession DC -ZoneName corp.contoso.com -RRType "A" -Name $VM.VMName -Force
        Get-DhcpServerv4Lease -CimSession DC -ScopeId 10.0.0.0 | WHere Hostname -eq "$($VM.VMName).corp.contoso.com" | Remove-DhcpServerv4Lease
        Get-ADComputer -Identity $VM.VMName | Remove-ADObject -Confirm:0 -recursive
    }
#remove GPOs
    $names=(Get-ChildItem -Path "$env:UserProfile\Downloads\WVDBackups" -Filter *.htm).BaseName
    foreach ($name in $names) {
        Get-GPO -Name $name  | Remove-GPO
    }
#remove sample users
    $Names="JohnDoe","JaneDoe"
    Foreach ($Name in $Names){
        Get-ADUSer -Identity $Name | Remove-ADObject -Confirm:0 -recursive
    }
#>
#endregion
