#region Rolling Cluster Upgrade - Prereqs
    $Servers="Rolling1","Rolling2","Rolling3","Rolling4"
    $ClusterName="Roll-Cluster"
    $CAURoleName="Roll-Cl-CAU"
    #Configure S2D and create some VMs
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
        $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
        #install features
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force #force is needed as there is a ?bug that prevents restarting older versions of OS from Windows Server 2022
        Start-Sleep 30 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

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

    #add CAU role (Optional)
        #Install required features on nodes.
            $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
            foreach ($ClusterNode in $ClusterNodes){
                Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
            }
        #Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose

    #enable S2D
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #create volume
        New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 1TB -FriendlyName "VMs01"

    #register cluster to Azure
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
        Login-AzAccount -UseDeviceAuthentication

        #select context if more available
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context=$context | Out-GridView -OutputMode Single
            $context | Set-AzContext
        }

        $subscriptionID=$context.subscription.id

        #register Azure Stack HCI
        Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication
    #create some dummy VMs
        1..3 | ForEach-Object {
            $VMName="TestVM$_"
            Invoke-Command -ComputerName ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random) -ScriptBlock {
                #create some fake VMs
                New-VM -Name $using:VMName -NewVHDPath "c:\ClusterStorage\VMs01\$($using:VMName)\Virtual Hard Disks\$($using:VMName).vhdx" -NewVHDSizeBytes 32GB -Generation 2 -Path "c:\ClusterStorage\VMs01\" -MemoryStartupBytes 32MB
            }
            Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
        }
#endregion

#region Rolling Cluster Upgrade - The Lab
    $Servers="Rolling1","Rolling2","Rolling3","Rolling4"
    $ClusterName="Roll-Cluster"

    #invoke CAU update including preview updates (optional)
        <#
        $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}
        $scan | Select-Object NodeName,UpdateTitle | Out-GridView

        Invoke-CauRun -ClusterName $ClusterName -MaxFailedNodes 0 -MaxRetriesPerNode 1 -RequireAllNodesOnline -Force -CauPluginArguments @{QueryString = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"}
        #>
    #configure AzSHCI preview channel

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
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell -Force

    #validate if all is OK
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            Get-PreviewChannel
        }

    #perform Rolling Upgrade
        #copy CAU plugin from cluster (only if your management machine is 2019. If it's 2022 or newer, you are good to go)
            if (-not (Get-CauPlugin Microsoft.RollingUpgradePlugin)){
                #unload module for next step
                Remove-Module -Name ClusterAwareUpdating
                Read-Host "Posh will now exit. Press a key"
                exit
            }
            if (-not (Get-CauPlugin Microsoft.RollingUpgradePlugin)){
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
            }

        #perform update
            $scan=Invoke-CauScan -ClusterName $ClusterName -CauPluginName "Microsoft.RollingUpgradePlugin" -CauPluginArguments @{'WuConnected'='true';} -Verbose
            #display updates that will be applied
            $scan.upgradeinstallproperties.WuUpdatesInfo | Out-GridView
            Invoke-CauRun -ClusterName $ClusterName -Force -CauPluginName "Microsoft.RollingUpgradePlugin" -CauPluginArguments @{'WuConnected'='true';} -Verbose -EnableFirewallRules

    #validate version after rolling upgrade
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name DisplayVersion
    }

    #validate version of cluster
        #version before upgrade
        Get-Cluster -Name $ClusterName | Select-Object Cluster*
        # upgrade Cluster version
        Update-ClusterFunctionalLevel -Cluster $ClusterName -Force
        #and version after upgrade
        Get-Cluster -Name $ClusterName | Select-Object Cluster*

    #validate version of pool
        #version before upgrade
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | Select-Object Version
        # update storage pool
        Update-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" -Confirm:0
        #and version after upgrade
        Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | Select-Object Version

    #validate VMs version
        #version before upgrade
        Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name
        #update VMs
        #Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name | Update-VMVersion -Confirm:0
        Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterName).Name -ScriptBlock {Get-VM | Update-VMVersion -Confirm:0}
        Start-Sleep 10
        #version after upgrade
        Get-VM -CimSession (Get-ClusterNode -Cluster $ClusterName).Name

    #register cluster to Azure again, to unlock newest features
        if (-not (Get-AzContext)){
            Login-AzAccount -UseDeviceAuthentication
        }
        #select context
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context=$context | Out-GridView -OutputMode Single
            $context | Set-AzContext
        }

        $subscriptionID=$context.subscription.id

        #Register AZSHCi without prompting for creds
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

#endregion

#region Azure Stack HCI and Azure Arc - Prereqs
    $Servers="Arc1","Arc2","Arc3","Arc4"
    $ClusterName="Arc-Cluster"

    #Configure S2D
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
        $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
        #install features
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 30 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

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

        #enable S2D
            Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

#endregion

#region Azure Stack HCI and Azure Arc - The Lab
    $ClusterName="Arc-Cluster"

    #register cluster to Azure
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
        Login-AzAccount -UseDeviceAuthentication

        #select context if more available
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context=$context | Out-GridView -OutputMode Single
            $context | Set-AzContext
        }

        $subscriptionID=$context.subscription.id

        #enable debug logging in case something goes wrong
            $servers=(Get-ClusterNode -Cluster $ClusterName).Name
            Invoke-Command -ComputerName $servers -ScriptBlock {wevtutil.exe sl /q /e:true Microsoft-AzureStack-HCI/Debug}
        #register Azure Stack HCI
        #Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication

        #Register AZSHCi without prompting for creds again
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        Register-AzStackHCI -Verbose -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

        #grab logs if something went wrong
            $lognames = "Microsoft-AzureStack-HCI/Debug", "Microsoft-AzureStack-HCI/Admin", "Microsoft-Windows-Kernel-Boot/Operational", "Microsoft-Windows-Kernel-IO/Operational"
            $events=foreach ($logname in $Lognames){
                Invoke-Command -ComputerName $Servers -ScriptBlock {Get-WinEvent -LogName $using:logname -oldest}   
            }
            $events | Out-File $env:USERPROFILE\Downloads\events.txt
            $events | Export-Clixml -Path $env:USERPROFILE\Downloads\events.xml
            
    #Create Log Analytics Workspace if not available
        #Install module
        if (!(Get-InstalledModule -Name Az.OperationalInsights -ErrorAction Ignore)){
            Install-Module -Name Az.OperationalInsights -Force
        }
        #Grab Insights Workspace if some already exists
            if (-not (Get-AzContext)){
                Login-AzAccount -UseDeviceAuthentication
            }
            #select context
            $context=Get-AzContext -ListAvailable
            if (($context).count -gt 1){
                $context=$context | Out-GridView -OutputMode Single
                $context | Set-AzContext
            }
            $subscriptionID=$context.subscription.id
            $WorkspaceName="MSLabWorkspace-$SubscriptionID"
            $ResourceGroupName="MSLabAzureArc"
            $Workspace=Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction Ignore
            if (-not($Workspace)){
                #Pick Region
                $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.OperationalInsights" | Out-GridView -OutputMode Single -Title "Please select location where Insights workspace will be created"
                if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)){
                    New-AzResourceGroup -Name $ResourceGroupName -Location $location.Location
                }
                $Workspace=New-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -Location $location.Location
            }
        #add automation account to workspace (not needed for now)
        <#
            $AutomationAccountName="MSLabAutomationAccount"
            $location=$Workspace.Location
            #Install module
            if (!(Get-InstalledModule -Name Az.Automation -ErrorAction Ignore)){
                Install-Module -Name Az.Automation -Force
            }

            New-AzAutomationAccount -Name $AutomationAccountName -ResourceGroupName $ResourceGroupName -Location $Location -Plan Free 

            #link workspace to Automation Account (via an ARM template deployment)
            $json = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace_name": {
            "type": "string"
        },
        "automation_name": {
            "type": "string"
        }
    },
    "resources": [
        {
            "type": "Microsoft.OperationalInsights/workspaces",
            "name": "[parameters('workspace_name')]",
            "apiVersion": "2015-11-01-preview",
            "location": "[resourceGroup().location]",
            "resources": [
                {
                    "name": "Automation",
                    "type": "linkedServices",
                    "apiVersion": "2015-11-01-preview",
                    "dependsOn": [
                        "[parameters('workspace_name')]"
                    ],
                    "properties": {
                        "resourceId": "[resourceId(resourceGroup().name, 'Microsoft.Automation/automationAccounts', parameters('automation_name'))]"
                    }
                }
            ]
        },
        {
            "type": "Microsoft.OperationsManagement/solutions",
            "name": "[concat('Updates', '(', parameters('workspace_name'), ')')]",
            "apiVersion": "2015-11-01-preview",
            "location": "[resourceGroup().location]",
            "plan": {
                "name": "[concat('Updates', '(', parameters('workspace_name'), ')')]",
                "promotionCode": "",
                "product": "OMSGallery/Updates",
                "publisher": "Microsoft"
            },
            "properties": {
                "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace_name'))]"
            },
            "dependsOn": [
                "[parameters('workspace_name')]"
            ]
        }
    ]
}
"@

                $templateFile = New-TemporaryFile
                Set-Content -Path $templateFile.FullName -Value $json

                $templateParameterObject = @{
                    workspace_name = $WorkspaceName
                    automation_name = $AutomationAccountName
                }
                New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $templateFile.FullName -TemplateParameterObject $templateParameterObject
                Remove-Item $templateFile.FullName
        #>
    #Enable monitoring (it's easiest to do it in portal) https://docs.microsoft.com/en-us/azure-stack/hci/manage/monitor-azure-portal
        #add Monitoring extension and dependency agent extension https://docs.microsoft.com/en-us/azure/azure-arc/servers/manage-vm-extensions-powershell
            <#
            $WorkspaceName="MSLabWorkspace-$SubscriptionID"
            $servers=(Get-ClusterNode -Cluster $ClusterName).Name

            #Install module
            if (!(Get-InstalledModule -Name Az.ConnectedMachine -ErrorAction Ignore)){
                Install-Module -Name Az.ConnectedMachine -Force
            }

            $workspace=Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName
            $keys=Get-AzOperationalInsightsWorkspaceSharedKey -Name $WorkspaceName -ResourceGroupName $ResourceGroupName

            $Setting = @{ "workspaceId" = "$($workspace.CustomerId.GUID)" }
            $protectedSetting = @{ "workspaceKey" = "$($keys.PrimarySharedKey)" }

            foreach ($Server in $Servers){
                $machine=Get-AzConnectedMachine | Where-Object Name -eq $server
                $location=$machine.location
                $ResourceGroupName=$machine.id.Split("/") | Select-Object -First 5 | Select-Object -Last 1
                New-AzConnectedMachineExtension -Name "MicrosoftMonitoringAgent"-ResourceGroupName $ResourceGroupName -MachineName $server -Location $location -Publisher "Microsoft.EnterpriseCloud.Monitoring"       -Settings $Setting -ProtectedSetting $protectedSetting -ExtensionType "MicrosoftMonitoringAgent" #-TypeHandlerVersion "1.0.18040.2"
                New-AzConnectedMachineExtension -Name "DependencyAgentWindows"  -ResourceGroupName $ResourceGroupName -MachineName $server -Location $location -Publisher "Microsoft.Azure.Monitoring.DependencyAgent" -Settings $Setting -ProtectedSetting $protectedSetting -ExtensionType "DependencyAgentWindows"
            }
            #>
        #or add extension at scale https://docs.microsoft.com/en-us/azure/azure-monitor/insights/vminsights-enable-policy (TBD)

#endregion

#region Network ATC - Prereqs
    $Servers="NetATC1","NetATC2","NetATC3","NetATC4"
    $ClusterName="NetATC-Cluster"

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
        $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
        #install features
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 30 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

    #Create Cluster
        New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"
#endregion

#region Network ATC - The Lab
    $ClusterName="NetATC-Cluster"
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
        Get-NetIntentStatus -clustername $ClusterName | Select-Object *
        Write-Output "applying intent"
        do {
            $status=Get-NetIntentStatus -clustername $ClusterName
            Write-Host "." -NoNewline
            Start-Sleep 5
        } while ($status.ConfigurationStatus -contains "Provisioning" -or $status.ConfigurationStatus -contains "Retrying")
        $status | Select-Object *

    #validate what was/was not configured. Since Enable-NetAdapterQos does not work in virtual environment, QoS will not be enabled...
            #validate vSwitch
            Get-VMSwitch -CimSession $servers
            #validate vNICs
            Get-VMNetworkAdapter -CimSession $servers -ManagementOS
            #validate vNICs to pNICs mapping
            Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | Format-Table ComputerName,NetAdapterName,ParentAdapter
            #validate JumboFrames setting
            Get-NetAdapterAdvancedProperty -CimSession $servers -DisplayName "Jumbo Packet"
            #verify RDMA settings
            Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | Format-Table systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
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
            #validate QoS Traffic Classes
            Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass} |Sort-Object PSComputerName |Select-Object PSComputerName,Name,PriorityFriendly,Bandwidth
            #verify ip config 
            Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputerName | Format-Table PSComputerName,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
            #verify cluster network names
            Get-ClusterNetwork -Cluster $clustername
            #verify live migration networks configured in cluster
            Get-ClusterNetwork -Cluster $ClusterName | Where-Object ID -notlike (Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Get-ClusterParameter -Name MigrationExcludeNetworks).Value
            #verify Live Migration option (should be SMB)
            Get-VMHost -cimsession $servers | Select-Object Name,VirtualMachineMigrationPerformanceOption
            #verify bandwidth limit for SMB
            Get-SmbBandwidthLimit -Category LiveMigration -CimSession $servers

    #in MSLab it unfortunately does not work, therefore let's remove intent and cleanup vSwitches
        Remove-NetIntent -Name ConvergedIntent -ClusterName $ClusterName 
        Get-VMSwitch -CimSession $Servers | Remove-VMSwitch -Force
        Get-NetQosPolicy -CimSession $servers | Remove-NetQosPolicy -Confirm:0
        Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass | Remove-NetQosTrafficClass -Confirm:0}

    #let's do the same "manually" (+ let's configure other networking settings as per best practice).
    #in regular deployment it's recommended to do this before cluster is created (because of disconnections)
        $ClusterName="NetATC-Cluster"
        $Servers=(Get-ClusterNode -Cluster $ClusterName).Name
        $vSwitchName="ConvergedSwitch"
        $StorNet1="172.16.1."
        $StorNet2="172.16.2."
        $StorVLAN1=711
        $StorVLAN2=712
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
            #Create a Traffic class and give SMB Direct 50% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB_Direct" -Priority 3 -BandwidthPercentage 50 -Algorithm ETS}
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "Cluster"    -Priority 7 -BandwidthPercentage 2 -Algorithm ETS}

        #configure cluster networks
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB01"
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB02"
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Role -eq ClusterAndClient).Name="Management"

        #configure Live Migration
            Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Role -eq "ClusterAndClient"}).ID))
            Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers

        #Configure SMB Bandwidth Limits for Live Migration https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
            #install feature
            Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name "FS-SMBBW"}
            #Calculate 40% of capacity of NICs in vSwitch (considering 2 NICs, if 1 fails, it will not consume all bandwith, therefore 40%)
            $Adapters=(Get-VMSwitch -CimSession $Servers[0]).NetAdapterInterfaceDescriptions
            $BytesPerSecond=((Get-NetAdapter -CimSession $Servers[0] -InterfaceDescription $adapters).TransmitLinkSpeed | Measure-Object -Sum).Sum/8
            Set-SmbBandwidthLimit -Category LiveMigration -BytesPerSecond ($BytesPerSecond*0.4) -CimSession $Servers

        #validate what was/was not configured. Since Enable-NetAdapterQos does not work in virtual environment, QoS will not be enabled...
            #validate vSwitch
            Get-VMSwitch -CimSession $servers
            #validate vNICs
            Get-VMNetworkAdapter -CimSession $servers -ManagementOS
            #validate vNICs to pNICs mapping
            Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | Format-Table ComputerName,NetAdapterName,ParentAdapter
            #validate JumboFrames setting
            Get-NetAdapterAdvancedProperty -CimSession $servers -DisplayName "Jumbo Packet"
            #verify RDMA settings
            Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | Format-Table systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
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
            #validate QoS Traffic Classes
            Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosTrafficClass} |Sort-Object PSComputerName |Select-Object PSComputerName,Name,PriorityFriendly,Bandwidth
            #verify ip config 
            Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputerName | Format-Table PSComputerName,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
            #verify cluster network names
            Get-ClusterNetwork -Cluster $clustername
            #verify live migration networks configured in cluster
            Get-ClusterNetwork -Cluster $ClusterName | Where-Object ID -notlike (Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Get-ClusterParameter -Name MigrationExcludeNetworks).Value
            #verify Live Migration option (should be SMB)
            Get-VMHost -cimsession $servers | Select-Object Name,VirtualMachineMigrationPerformanceOption
            #verify bandwidth limit for SMB
            Get-SmbBandwidthLimit -Category LiveMigration -CimSession $servers
#endregion

#region Thin provisioning - Prereqs
    $Servers="Thin1","Thin2","Thin3","Thin4"
    $ClusterName="Thin-Cluster"

    #Configure S2D
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
            $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
            #install features
            Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
            #restart and wait for computers
            Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
            Start-Sleep 30 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

        #Create Cluster
            New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"

        #enable S2D
            Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

#endregion

#region Thin provisioning - The Lab
    $ClusterName="Thin-Cluster"
    #check Storage Pool (and AllocatedSize)
    Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName"
    #create thick volume
    New-Volume -CimSession $ClusterName -FriendlyName ThickVolume01 -Size 1TB -StoragePoolFriendlyName "S2D on $ClusterName"
    #check pool again
    Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName"
    #and now let's create thin provisioned volume
    New-Volume -CimSession $ClusterName -FriendlyName ThinVolume01 -Size 1TB -StoragePoolFriendlyName "S2D on $ClusterName" -ProvisioningType Thin
    #let's compare sizes
    $FootPrintOnPool=@{label="FootPrintOnPool(TB)";expression={$_.FootPrintOnPool/1TB}}
    $Size=@{label="Size(TB)";expression={$_.Size/1TB}}
    Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName,$Size,$FootprintOnPool,ProvisioningType
    #let's explore default settings in Pool
    Get-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" | Select-Object ProvisioningTypeDefault
    #and let's set default to Thin
    Set-StoragePool -CimSession $ClusterName -FriendlyName "S2D on $ClusterName" -ProvisioningTypeDefault Thin
    #and now if provisioningtype is not specified, thin volume is created
    New-Volume -CimSession $ClusterName -FriendlyName ThinVolume02 -Size 1TB -StoragePoolFriendlyName "S2D on $ClusterName"
    #validate
    Get-VirtualDisk -CimSession $ClusterName | Select-Object FriendlyName,ProvisioningType
#endregion

#region Other features - Prereqs
    $Servers="Other1","Other2","Other3","Other4"
    $ClusterName="Other-Cluster"
    $CAURoleName="Other-Cl-CAU"
    #Configure S2D and create some VMs
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
        $features="Failover-Clustering","RSAT-Clustering-PowerShell","Hyper-V-PowerShell","Bitlocker","RSAT-Feature-Tools-BitLocker","Storage-Replica","RSAT-Storage-Replica","FS-Data-Deduplication","System-Insights","RSAT-System-Insights"
        #install features
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 30 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

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

    #add CAU role
        #Install required features on nodes.
            $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
            foreach ($ClusterNode in $ClusterNodes){
                Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
            }
        Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose

    #enable S2D
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #create volumes
        1..4 | Foreach-Object {
            New-Volume -CimSession $ClusterName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 10TB -FriendlyName "Volume$_" -ProvisioningType Thin
        }

    #register cluster to Azure
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
        Login-AzAccount -UseDeviceAuthentication

        #select context if more available
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context=$context | Out-GridView -OutputMode Single
            $context | Set-AzContext
        }

        $subscriptionID=$context.subscription.id

        #Register AZSHCi without prompting for creds again
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        Register-AzStackHCI -Verbose -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id

    #create some VMs
        $CSVs=(Get-ClusterSharedVolume -Cluster $ClusterName).Name
        foreach ($CSV in $CSVs){
            $CSV=($CSV -split '\((.*?)\)')[1]
            1..2 | ForEach-Object {
                $VMName="TestVM$($CSV)_$_"
                New-Item -Path "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks" -ItemType Directory
                Copy-Item -Path $VHDPath -Destination "\\$ClusterName\ClusterStorage$\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" 
                New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -Path "c:\ClusterStorage\$CSV\" -VHDPath "c:\ClusterStorage\$CSV\$VMName\Virtual Hard Disks\$VMName.vhdx" -CimSession ((Get-ClusterNode -Cluster $ClusterName).Name | Get-Random)
                Add-ClusterVirtualMachineRole -VMName $VMName -Cluster $ClusterName
            }
        }
        #Start all VMs
        Start-VM -VMname * -CimSession (Get-ClusterNode -Cluster $clustername).Name

#endregion

#region Other features - The Lab

#endregion

#region Storage bus cache with Storage Spaces on standalone servers https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-storage-bus-cache

    #Install feature
    $ServerName="SBC"
    Install-WindowsFeature -ComputerName $ServerName -Name Failover-Clustering

    #set mediatype of 1TB disks to SSD and 4TB to HDD (this is needed as it's virtual environment that only simulates two tiers). In Virtual Environment is all HDD by default
    Get-PhysicalDisk -CimSession $servername | Where-Object Canpool -eq $true | Where-Object Size -eq 1TB | Set-PhysicalDisk -MediaType "SSD" -CimSession $servername
    Get-PhysicalDisk -CimSession $servername | Where-Object Canpool -eq $true | Where-Object Size -eq 4TB | Set-PhysicalDisk -MediaType "HDD" -CimSession $servername

    #Validate SBC settings
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Get-StorageBusCache}
    #Validate MediaType
    Get-PhysicalDisk -CimSession $ServerName

    #Enable SBC
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Enable-StorageBusCache}
    #as you can see, it will result in error as script logic will detect virtual disks, setting mediatype to back to "Unspecified"

    #Validate MediaType to see the error reason
    Get-PhysicalDisk -CimSession $ServerName

    #let's explore enabling SBC manually 
    #!!! This is totally unsupported and we are doing it just to be able to see how it behaves in virtual environment such as MSLab to explore each component!!!
    #I personally found it very useful to be able to understand how this "single node S2D" works. You can study even more by reading StorageBusCache module "Get-Content C:\Windows\system32\WindowsPowerShell\v1.0\Modules\StorageBusCache\StorageBusCache.psm1"
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Enable-StorageBusCache -AutoConfig:0}
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Get-StorageBusCache}

    #and now let's create a pool
    Get-PhysicalDisk -CimSession $servername | Where-Object Canpool -eq $true | Where-Object Size -eq 1TB | Set-PhysicalDisk -MediaType "SSD" -CimSession $servername
    Get-PhysicalDisk -CimSession $servername | Where-Object Canpool -eq $true | Where-Object Size -eq 4TB | Set-PhysicalDisk -MediaType "HDD" -CimSession $servername
    Invoke-Command -ComputerName $ServerName -ScriptBlock {New-StoragePool -FriendlyName "Storage Bus Cache on $using:ServerName" -PhysicalDisks (Get-PhysicalDisk | Where-Object Canpool -eq $True) -StorageSubSystemFriendlyName (Get-StorageSubSystem).FriendlyName}

    #validate disks in pool
    Get-StoragePool -CimSession $ServerName | Get-PhysicalDisk -CimSession $ServerName

    #Create tiers
    New-StorageTier -CimSession $ServerName -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -FriendlyName "Capacity"    -MediaType HDD  -ResiliencySettingName Parity
    New-StorageTier -CimSession $ServerName -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -FriendlyName "Performance" -MediaType SSD  -ResiliencySettingName Mirror -NumberOfDataCopies 2
    New-StorageTier -CimSession $ServerName -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -FriendlyName "ParityOnHDD" -MediaType HDD  -ResiliencySettingName Parity
    New-StorageTier -CimSession $ServerName -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -FriendlyName "MirrorOnHDD" -MediaType HDD  -ResiliencySettingName Mirror -NumberOfDataCopies 2
    New-StorageTier -CimSession $ServerName -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -FriendlyName "ParityOnSSD" -MediaType SSD  -ResiliencySettingName Parity
    New-StorageTier -CimSession $ServerName -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -FriendlyName "MirrorOnSSD" -MediaType SSD  -ResiliencySettingName Mirror -NumberOfDataCopies 2

    #the last step would be to validate cache binding
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Get-StorageBusCache}
    #as you can see, there is no binding

    #let's try to update binding
    Invoke-Command -ComputerName $ServerName -ScriptBlock {Update-StorageBusCache}
    #as you can see, it fails as disks are just virtual

    #let's try to add disks manually
    Invoke-Command -ComputerName $ServerName -ScriptBlock {New-StorageBusBinding -CacheNumber $using:SSDs[0].DeviceID -CapacityNumber $using:HDDs[0].DeviceID}
    Invoke-Command -ComputerName $ServerName -ScriptBlock {New-StorageBusBinding -CacheNumber $using:SSDs[1].DeviceID -CapacityNumber $using:HDDs[1].DeviceID}
    Invoke-Command -ComputerName $ServerName -ScriptBlock {New-StorageBusBinding -CacheNumber $using:SSDs[0].DeviceID -CapacityNumber $using:HDDs[2].DeviceID}
    Invoke-Command -ComputerName $ServerName -ScriptBlock {New-StorageBusBinding -CacheNumber $using:SSDs[1].DeviceID -CapacityNumber $using:HDDs[3].DeviceID}
    #as you can see, we got into the same error

    #anyway, with above commands we can create volume spanning both tiers (SSD and HDD), but without cache - as we are inside MSLab
    #mirror and parity
    New-Volume -CimSession $ServerName -FriendlyName "Mirror-Parity" -DriveLetter D -FileSystem ReFS -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -StorageTierFriendlyNames "MirrorOnSSD","ParityOnHDD" -StorageTierSizes 250GB,1TB
    #mirror and mirror
    New-Volume -CimSession $ServerName -FriendlyName "Mirror-Mirror" -DriveLetter E -FileSystem ReFS -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -StorageTierFriendlyNames "MirrorOnSSD","MirrorOnHDD" -StorageTierSizes 250GB,1TB
    #or just single-tier volume on SSD
    New-Volume -CimSession $ServerName -FriendlyName "Simple-SSD"    -DriveLetter F -FileSystem ReFS -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -ResiliencySettingName Simple -MediaType SSD -Size 100GB
    #or just single-tier volume on HDD
    New-Volume -CimSession $ServerName -FriendlyName "Simple-HDD"    -DriveLetter G -FileSystem ReFS -StoragePoolFriendlyName "Storage Bus Cache on $ServerName" -ResiliencySettingName Simple -MediaType HDD -Size 500GB

    #you can find more useful information here:
    Get-Content C:\Windows\system32\WindowsPowerShell\v1.0\Modules\StorageBusCache\StorageBusCache.psm1

#endregion

#region Install Windows Admin Center in GW Mode (with self-signed cert)
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
    }

    $Session | Remove-PSSession

    #add certificate to trusted root certs
    start-sleep 20
    $cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
    $cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
    Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

    #Configure Resource-Based constrained delegation on all AD computers
    $gatewayObject = Get-ADComputer -Identity $GatewayServerName
    $computers = (Get-ADComputer -Filter *).Name

    foreach ($computer in $computers){
        $computerObject = Get-ADComputer -Identity $computer
        Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
    }
#endregion

#region Install Windows Admin Center on Windows 11 machine (run from Windows 11)
    #Download Windows Admin Center to downloads
    Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

    #Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
        Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

    #Open Windows Admin Center
        Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
#endregion

