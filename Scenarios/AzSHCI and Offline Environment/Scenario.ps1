#this scenario assumes limited connectivity from AX nodes with normal connectivity from management machine
#run all code from management machine (DC, or dedicated management machine)
#you can download all stuff on completely separate machine and then just transfer to management machine

#region variables
    $Servers="AzSHCI1","AzSHCI2","AzSHCI3","AzSHCI4"
    #proxy (example http://itg.contoso.com:3128)
    $ProxyURL=""
#endregion

#region download all possible binaries (useful if you need to download it outside lab)
    #if there is any proxy, this might be useful
        $webclient=New-Object System.Net.WebClient
        $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

    #grab PowerShell modules
        $PSModulesDownloadFolder="$Env:UserProfile\Downloads\PowerShellModules"
        if (-not (Test-Path $PSModulesDownloadFolder -ErrorAction Ignore)){New-Item -Path $PSModulesDownloadFolder -ItemType Directory}
        $PowerShellModules="WinInetProxy", "AzStackHci.EnvironmentChecker","Az.StackHCI","Az.Accounts","Az.Resources","VMFleet","PrivateCloud.DiagnosticInfo"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        foreach ($PowerShellModule in $PowerShellModules){
            Save-Module -Name $PowerShellModule -Path $PSModulesDownloadFolder
        }

    #grab some binaries to tools folder
        $ToolsDownloadFolder="$Env:UserProfile\Downloads\Tools\"
        $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/DownloadLatestCUs.ps1").Content
        if (-not (Test-Path $ToolsDownloadFolder -ErrorAction Ignore)){New-Item -Path $ToolsDownloadFolder -ItemType Directory}
        Set-Content -path "$ToolsDownloadFolder\DownloadLatestCUs.ps1" -value $FileContent
        #run download latest CU
        & "$ToolsDownloadFolder\DownloadLatestCUs.ps1"
        #grab windows admin center
        Start-BitsTransfer -Source https://aka.ms/WACDownload -Destination "$ToolsDownloadFolder\WindowsAdminCenter.msi"

    #grab dell tools and updates
        $DellToolsDownloadFolder="$Env:UserProfile\Downloads\Dell\"
        if (-not (Test-Path $DellToolsDownloadFolder -ErrorAction Ignore)){New-Item -Path $DellToolsDownloadFolder -ItemType Directory}
        #grab DSU links from Dell website
            $URL="https://dl.dell.com/omimswac/dsu/"
            $Results=Invoke-WebRequest $URL -UseDefaultCredentials
            $Links=$results.Links.href | Select-Object -Skip 1
            #create PSObject from results
            $DSUs=@()
            foreach ($Link in $Links){
                $DSUs+=[PSCustomObject]@{
                    Link = "https://dl.dell.com$Link"
                    Version = $link -split "_" | Select-Object -Last 2 | Select-Object -First 1
                }
            }
            #download latest
            $LatestDSU=$DSUs | Sort-Object Version | Select-Object -Last 1
            Start-BitsTransfer -Source $LatestDSU.Link -Destination $DellToolsDownloadFolder\DSU.exe

        #grab IC
            #grab IC links from Dell website
            $URL="https://downloads.dell.com/omimswac/ic/"
            $Results=Invoke-WebRequest $URL -UseDefaultCredentials
            $Links=$results.Links.href | Select-Object -Skip 1
            #create PSObject from results
            $ICs=@()
            foreach ($Link in $Links){
                $ICs+=[PSCustomObject]@{
                    Link = "https://dl.dell.com$Link"
                    Version = [int]($link -split "_" | Select-Object -Last 2 | Select-Object -First 1)
                }
            }
            #download latest
            $LatestIC=$ICs | Sort-Object Version | Select-Object -Last 1
            Start-BitsTransfer -Source $LatestIC.Link -Destination $DellToolsDownloadFolder\IC.exe

        #grab Dell Azure Stack HCI driver catalog https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz
            #Download catalog
            Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
            #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
            Function Expand-GZipArchive{
                Param(
                    $infile,
                    $outfile = ($infile -replace '\.gz$','')
                    )
                $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
                $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
                $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
                $buffer = New-Object byte[](1024)
                while($true){
                    $read = $gzipstream.Read($buffer, 0, 1024)
                    if ($read -le 0){break}
                    $output.Write($buffer, 0, $read)
                    }
                $gzipStream.Close()
                $output.Close()
                $input.Close()
            }
            Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$DellToolsDownloadFolder\ASHCI-Catalog.xml"

        #download all dell updates from catalog
            [xml]$XML=Get-Content "$DellToolsDownloadFolder\ASHCI-Catalog.xml"

            #ask for what items should be downloaded to fileshare
            $items=$xml.manifest.softwarecomponent #| Out-GridView -OutputMode Multiple -Title "Please Select components you want to download"
            
            #download
            foreach ($item in $items){
                $Path=$item.path.replace("/","\")
                $Folder=$Path | Split-Path
                New-Item -Path $DellToolsDownloadFolder -Name $Folder -ItemType Directory -Force
                Start-BitsTransfer -Source "https://downloads.dell.com/$($item.path)" -Destination "$DellToolsDownloadFolder\$Path" -DisplayName "Downloading $Path releasedate $($item.releaseDate)"
            }

        #grab WAC OpenManage extension
            #WAC Feeds
            #https://dev.azure.com/WindowsAdminCenter/Windows%20Admin%20Center%20Feed/_artifacts/feed/WAC
            #or wac extension from dell site
            #https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=ynvkt
            Start-BitsTransfer -Source "https://dl.dell.com/FOLDER08583345M/1/Dell_OpenManage_Integration_MS_WAC_2.3.0_707_A00.zip" -Destination "$env:userprofile\Downloads\Dell_OpenManage_Integration_MS_WAC_2.3.0_707_A00.zip"
            Expand-Archive -Path "$env:userprofile\Downloads\Dell_OpenManage_Integration_MS_WAC_2.3.0_707_A00.zip" -DestinationPath $DellToolsDownloadFolder
#endregion

#region Proxy
    if ($ProxyURL){
        #region configure proxy if needed on nodes
            #copy module to servers
            $PSSessions=New-PSSession $Servers
            Foreach ($PSSession in $PSSessions){
                Copy-Item -Path $Env:UserProfile\Downloads\PowerShellModules\WinInetProxy -Destination "C:\Program Files\WindowsPowerShell\Modules" -ToSession $PSSession -Recurse
            }
            Invoke-Command -ComputerName $Servers -ScriptBlock {
                Set-WinInetProxy -ProxySettingsPerUser 0 -ProxyServer $using:ProxyURL
                #or remove settings
                #Set-WinInetProxy
            }
        #endregion
    }
#endregion

#region validate connection
    #validate servers connectivity with Azure Stack HCI Environment Checker https://www.powershellgallery.com/packages/AzStackHci.EnvironmentChecker
    Import-Module $Env:UserProfile\Downloads\PowerShellModules\AzStackHci.EnvironmentChecker

    $PSSessions=New-PSSession $Servers
    Invoke-AzStackHciConnectivityValidation -PsSession $PSSessions
    #or if proxy is used
    #Invoke-AzStackHciConnectivityValidation -PsSession $PSSessions -Proxy $Proxy

    #validate https endpoints certificate (if https inspected, you wont see Microsoft/Digicert certificate)
    Import-Module $Env:UserProfile\Downloads\PowerShellModules\AzStackHci.EnvironmentChecker
    Get-SigningRootChain -Uri https://login.microsoftonline.com
#endregion

#region install latest updates
    $ToolsDownloadFolder="$Env:UserProfile\Downloads\Tools\"
    #grab MSU(s)
    $Updates=get-childitem -Path $ToolsDownloadFolder -Recurse | Where-Object Extension -eq ".msu"
    #copy it to servers (in this case failover clustering is not yet installed-firewall will not allow SMB, therefore enabling smb rule if not reachable)
    foreach ($Server in $Servers){
        if (-not (Test-NetConnection -ComputerName $Server -CommonTCPPort SMB).TcpTestSucceeded){
            Enable-NetFirewallRule -Name FPS-SMB-In-TCP -CimSession $Server
        }
        Copy-item -Path $Update.FullName -Destination \\$Server\C$\users\$env:USERNAME\Downloads
    }

    Invoke-Command -ComputerName $Servers -ScriptBlock {
        foreach ($update in $Using:Updates){
            Start-Process -FilePath "$env:systemroot\System32\wusa.exe" -ArgumentList "$env:userprofile\Downloads\$($Update.Name) /quiet /norestart" -Wait
        }
    }
#endregion

#region perform Dell Drivers update https://www.dell.com/support/home/en-us/product-support/product/system-update/docs
    #region prepare DSU binaries
        #copy dell tools to c:\Dell
        $DellToolsDownloadFolder="$Env:UserProfile\Downloads\Dell\"
        foreach ($Server in $Servers){
            if (-not (Test-NetConnection -ComputerName $Server -CommonTCPPort SMB).TcpTestSucceeded){
                Enable-NetFirewallRule -Name FPS-SMB-In-TCP -CimSession $Server
            }
            Copy-item -Path $DellToolsDownloadFolder -Destination \\$Server\C$\ -Recurse
        }

        #install DSU on servers
            Invoke-Command -ComputerName $Nodes -ScriptBlock {
                Start-Process -FilePath "c:\Dell\DSU.exe" -ArgumentList "/silent" -Wait 
            }

        #install dell updates
        Invoke-Command -ComputerName $Servers -ScriptBlock {
            #create answerfile for DU
            $content='@
            a
            c
            @'
            Set-Content -Path "C:\Dell\answer.txt" -Value $content -NoNewline
            #Create CMD to install updates
            $content='"C:\Program Files\Dell\DELL System Update\DSU.exe" --source-location="C:\Dell" --source-type="Repository" --catalog-location="C:\Dell\ASHCI-Catalog.xml" --ic-location="C:\Dell\IC.exe" --apply-upgrades <answer.txt'
            Set-Content -Path "C:\Dell\install.cmd" -Value $content -NoNewline
            #install DSU updates
            Start-Process -FilePath "C:\Dell\install.cmd" -Wait -WorkingDirectory "C:\Dell"
            #display result
            Get-Content "C:\ProgramData\Dell\DELL System Update\dell_dup\DSU_STATUS.json"
        }
    #endregion

#endregion

#region install WAC + Dell Openmanage extension
    ##Install Windows Admin Center Gateway
    $ToolsDownloadFolder="$Env:UserProfile\Downloads\Tools\"
    $DellToolsDownloadFolder="$env:UserProfile\Downloads\Dell"
    $GatewayServerName="WACGW"
    #Create PS Session and copy install files to remote server
    #make sure maxevenlope is 8k
    Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192}
    $Session=New-PSSession -ComputerName $GatewayServerName
    Copy-Item -Path "$ToolsDownloadFolder\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

    #Install Windows Admin Center
    Invoke-Command -Session $session -ScriptBlock {
        Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
    } -ErrorAction Ignore

    $Session | Remove-PSSession

    #add certificate to trusted root certs (workaround to trust HTTPs cert on WACGW)
    start-sleep 30
    $cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
    $cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
    Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

    #Configure Resource-Based constrained delegation
    Install-WindowsFeature -Name RSAT-AD-PowerShell
    $gatewayObject = Get-ADComputer -Identity $GatewayServerName
    $computers = (Get-ADComputer -Filter {OperatingSystem -eq "Azure Stack HCI"}).Name

    foreach ($computer in $computers){
        $computerObject = Get-ADComputer -Identity $computer
        Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
    }

    #add openmanage extension
    #https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/configure/use-powershell
        #Copy Posh Modules from wacgw
        $Session=New-PSSession -ComputerName $GatewayServerName
        Copy-Item -Path "C:\Program Files\Windows Admin Center\PowerShell\" -Destination "C:\Program Files\Windows Admin Center\PowerShell\" -Recurse -FromSession $Session
        $Session | Remove-PSSession

        #Import Posh Modules
        $Items=Get-ChildItem -Path "C:\Program Files\Windows Admin Center\PowerShell\Modules" -Recurse | Where-Object Extension -eq ".psm1"
        foreach ($Item in $Items){
            Import-Module $Item.fullName
        }

        #copy nupkg to wac folder somewhere
        Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {
            New-Item -Path c:\ -Name WAC -ItemType Directory -ErrorAction Ignore
        }
        $Session=New-PSSession -ComputerName $GatewayServerName
        $packages=Get-ChildItem -Path $DellToolsDownloadFolder -Recurse | Where-Object Extension -EQ ".nupkg"
        foreach ($Package in $packages){
            Copy-Item -Path $Package.FullName -Destination c:\WAC -ToSession $Session
        }
        $Session | Remove-PSSession

        #add feed
        Add-Feed -GatewayEndpoint "https://$GatewayServerName" -Feed "c:\WAC"
        #remove online feed
        Remove-Feed -GatewayEndpoint "https://$GatewayServerName" -Feed https://aka.ms/sme-extension-catalog-feed
        #install dell extension
        Install-Extension -GatewayEndpoint https://$GatewayServerName -ExtensionId dell-emc.openmanage-integration
#endregion

#region register to Azure
if ((Get-CimInstance -ClassName win32_computersystem -CimSession $Servers[0]).Manufacturer -like "*Dell Inc."){
    #Add OEM Information so hardware is correctly billed
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name SupportProvider -Value DellEMC​
    }
}

#import modules
$PSModulesDownloadFolder="$Env:UserProfile\Downloads\PowerShellModules"
$ModuleNames="Az.Accounts","Az.StackHCI"
foreach ($ModuleName in $ModuleNames){
    Copy-Item -Path "$PSModulesDownloadFolder\$ModuleName" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -ErrorAction Ignore
    Import-Module $ModuleName
}

if (-not (Get-AzContext)){
    Connect-AzAccount -UseDeviceAuthentication
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

#enable debug logging in case something goes wrong
    $servers=(Get-ClusterNode -Cluster $ClusterName).Name
    Invoke-Command -ComputerName $servers -ScriptBlock {wevtutil.exe sl /q /e:true Microsoft-AzureStack-HCI/Debug} -ErrorAction Ignore
#register Azure Stack HCI
    $ResourceGroupName="" #if blank, default will be used
    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }
    #choose location for cluster (and RG)
    $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata").Location
    if ($ResourceGroupName){
        If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
            New-AzResourceGroup -Name $ResourceGroupName -Location $region
        }
    }

    #Register AzSHCI with prompting for creds
    #Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication

    #Register AZSHCi without prompting for creds again
    $armTokenItemResource = "https://management.core.windows.net/"
    #$graphTokenItemResource = "https://graph.windows.net/"
    $azContext = Get-AzContext
    $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
    $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
    $id = $azContext.Account.Id
    if ($ResourceGroupName){
        Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ArmAccessToken $armToken -ComputerName $ClusterName -AccountId $id -ResourceName $ClusterName -ResourceGroupName $ResourceGroupName #-ArmAccessToken $armToken
    }else{
        Register-AzStackHCI -Region $Region -SubscriptionID $subscriptionID -ArmAccessToken $armToken -ComputerName $ClusterName -AccountId $id -ResourceName $ClusterName
    }

#validate registration status
    #grab available commands for registration
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-Command -Module AzureStackHCI}
    #validate cluster registration
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-AzureStackHCI}
    #validate certificates
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-AzureStackHCIRegistrationCertificate}
    #validate Arc integration
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {Get-AzureStackHCIArcIntegration}

#endregion