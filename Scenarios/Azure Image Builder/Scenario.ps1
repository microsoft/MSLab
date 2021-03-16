#region prereqs
    $ModuleNames="Az.Accounts","Az.Resources","Az.ManagedServiceIdentity","Az.Compute","Az.ImageBuilder"

    #download Azure modules
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    foreach ($ModuleName in $ModuleNames){
        if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
            Install-Module -Name $ModuleName -Force
        }
    }

    #login to azure
    Connect-AzAccount -UseDeviceAuthentication

    #select context if more available
    $context=Get-AzContext -ListAvailable
    if (($context).count -gt 1){
        $context | Out-GridView -OutputMode Single | Set-AzContext
    }

    #select subscription
    $subscriptions=Get-AzSubscription
    if (($subscriptions).count -gt 1){
        $subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription
    }

    #Register Azure Image Builder and check registration
    Register-AzProviderFeature -ProviderNamespace Microsoft.VirtualMachineImages -FeatureName VirtualMachineTemplatePreview
    #Check Registration status
    Get-AzProviderFeature -FeatureName VirtualMachineTemplatePreview -ProviderNamespace Microsoft.VirtualMachineImages
    #Check Provider Registration status
    Get-AzProviderFeature -ProviderNamespace Microsoft.VirtualMachineImages -FeatureName VirtualMachineTemplatePreview
    Get-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages | Select-Object RegistrationState
    Get-AzResourceProvider -ProviderNamespace Microsoft.Storage | Select-Object RegistrationState
#endregion

#region Create Role Identity and Role Definition for Azure Image Builder
    # Get existing context
    $currentAzContext = Get-AzContext
    # Get your current subscription ID. 
    $subscriptionID=$currentAzContext.Subscription.Id
    # Destination image resource group
    $ResourceGroupName="ImageBuilderDemoRG"
    # Location
    $location="westeurope"

    #Create RG for Image Template and Shared Image Gallery
    New-AzResourceGroup -Name $ResourceGroupName -Location $location

    #Create a user assigned identity. This will be used to add the image to the Shared Image Gallery
    $RoleDefinitionName="Azure Image Builder Service Image Creation Role $ResourceGroupName"
    $identityName="AzureImageBuilderService"

    # Create role identity and role definition
    New-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName
    #$identityNameResourceId=$(Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName).Id
    $identityNamePrincipalId=$(Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName).PrincipalId

    $RoleDefinitionJSON='
    {
        "Name": "Azure Image Builder Service Image Creation Role",
        "IsCustom": true,
        "Description": "Image Builder access to create resources for the image build, you should delete or split out as appropriate",
        "Actions": [
            "Microsoft.Compute/galleries/read",
            "Microsoft.Compute/galleries/images/read",
            "Microsoft.Compute/galleries/images/versions/read",
            "Microsoft.Compute/galleries/images/versions/write",

            "Microsoft.Compute/images/write",
            "Microsoft.Compute/images/read",
            "Microsoft.Compute/images/delete"
        ],
        "NotActions": [
    
        ],
        "AssignableScopes": [
        "/subscriptions/<subscriptionID>/resourceGroups/<rgName>"
        ]
    }
    '
    $RoleDefinitionJSON=($RoleDefinitionJSON).Replace("<rgName>",$ResourceGroupName)
    $RoleDefinitionJSON=($RoleDefinitionJSON).Replace("<subscriptionID>",$subscriptionID)
    $RoleDefinitionJSON=($RoleDefinitionJSON).Replace("Azure Image Builder Service Image Creation Role",$RoleDefinitionName)

    $RoleDefinitionJSON | Out-File "$env:TEMP\aibRoleImageCreation.json"
    # Create the  role definition
    New-AzRoleDefinition -InputFile "$env:TEMP\aibRoleImageCreation.json"
    Start-Sleep 20

    # Grant role definition to image builder service principal
    New-AzRoleAssignment -ObjectId $identityNamePrincipalId -RoleDefinitionName $RoleDefinitionName -Scope "/subscriptions/$subscriptionID/resourceGroups/$ResourceGroupName"

    ### NOTE: If you see this error: 'New-AzRoleDefinition: Role definition limit exceeded. No more role definitions can be created.' See this article to resolve:
    #https://docs.microsoft.com/azure/role-based-access-control/troubleshooting

#endregion

#region Create Shared Image Gallery and Gallery definition 
    #Image gallery name
    $sigGalleryName= "AzureImageBuilderSharedGallery"
    #resource Group Name
    $ResourceGroupName="ImageBuilderDemoRG"
    #location
    $location="westeurope"
    # ImageDefinitionName 
    $imageDefName ="Win10_20H2_WVD"
    #Subscription ID
    $subscriptionID = (Get-AzContext).Subscription.Id
    # Create the gallery
    New-AzGallery -GalleryName $sigGalleryName -ResourceGroupName $ResourceGroupName -Location $location

    #create image gallery definition https://techcommunity.microsoft.com/t5/windows-virtual-desktop/building-a-windows-10-enterprise-multi-session-master-image-with/m-p/1503913
    #inspired by this image Get-AzVMImage -Location westeurope -PublisherName MicrosoftWindowsDesktop -Offer office-365 -Skus 20h2-evd-o365pp
    $GalleryParams = @{
        GalleryName = $sigGalleryName
        ResourceGroupName = $ResourceGroupName
        Location = $location
        Name = $imageDefName
        OsState = 'generalized'
        OsType = 'Windows'
        Publisher = 'WSLab-MicrosoftWindowsDesktop'
        Offer = 'WSLab-office-365'
        Sku = 'WSLab-20h2-evd-o365pp'
        HyperVGeneration = 'V1'
      }
      New-AzGalleryImageDefinition @GalleryParams
    
#endregion

#region build the image
    # Destination image resource group name
    $ResourceGroupName = 'ImageBuilderDemoRG'
    #name of Identity for Azure Image Builder Service
    $identityName="AzureImageBuilderService"
    # ImageDefinitionName 
    $imageDefName ="Win10_20H2_WVD"
    #Image gallery name
    $sigGalleryName= "AzureImageBuilderSharedGallery"
    #grab identity
    $identityNameResourceId = (Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $identityName).Id
    # Azure region
    $location="westeurope"
    # Azure replication region
    $replocation = 'northeurope'
    # Name of the image to be created
    $date=get-date -Format "yyMMdd"
    $imageTemplateName = "Win10_20H2_WVD_$date"
    # Distribution properties of the managed image upon completion
    $runOutputName = 'myDistResults'
    # Grab Subscription ID
    $subscriptionID=$currentAzContext.Subscription.Id
    #Define JSON
    $templateFilePath="$env:TEMP\armTemplateWinSIG.json"
    #grab json for Windows 10 20H2 WVD
    $JSON=(Invoke-WebRequest -Uri https://raw.githubusercontent.com/microsoft/WSLab/dev/Scenarios/Azure%20Image%20Builder/armTemplateWVD.json -UseBasicParsing).Content

    #customize json
    $json=($json).replace("<subscriptionID>",$subscriptionID)
    $json=($json).replace("<rgName>",$ResourceGroupName)
    $json=($json).replace("<region>",$location)
    $json=($json).replace("<runOutputName>",$runOutputName)
    $json=($json).replace("<imageDefName>",$imageDefName)
    $json=($json).replace("<sharedImageGalName>",$sigGalleryName)
    $json=($json).replace("<region1>",$location)
    $json=($json).replace("<region2>",$replocation)
    $json=($json).replace("<imgBuilderId>",$identityNameResourceId)
    #output it to temp
    $json | Out-File -FilePath $templateFilePath

    #Create Image Version
    New-AzResourceGroupDeployment `
    -ResourceGroupName $ResourceGroupName `
    -TemplateFile $templateFilePath `
    -api-version "2020-02-14" `
    -imageTemplateName $imageTemplateName `
    -svclocation $location

    #Build the image
    Invoke-AzResourceAction `
    -ResourceName $imageTemplateName `
    -ResourceGroupName $ResourceGroupName `
    -ResourceType Microsoft.VirtualMachineImages/imageTemplates `
    -ApiVersion "2020-02-14" `
    -Action Run `
    -Force

    #validate deployment
    (Get-AzResource –ResourceGroupName $ResourceGroupName -ResourceType Microsoft.VirtualMachineImages/imageTemplates -Name $ImageTemplateName).Properties.lastRunStatus
#endregion

#region cleanup
<#
    Get-AzUserAssignedIdentity -Name $identityName -ResourceGroupName $ResourceGroupName
    Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName | Remove-AzUserAssignedIdentity -Force
    Get-AzRoleAssignment -RoleDefinitionName $RoleDefinitionName | Remove-AzRoleAssignment -Confirm:0
    Get-AzResourceGroup -ResourceGroupName $ResourceGroupName | Remove-AzResourceGroup -Force
#>
#endregion
