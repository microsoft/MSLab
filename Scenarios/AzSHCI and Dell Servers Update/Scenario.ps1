#I created this scenario for updating my Ax6515 based lab. I don't think it's robust enough for production usage.
#Ideas grabbed from here https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1
#DSU documentation: https://www.dell.com/support/manuals/en-us/system-update/dsu_2.0.2.0_ug/introduction-to-dell-system-update?guid=guid-3061ce04-4779-4d50-8276-ddf911e3884a&lang=en-us
#you can rewrite code to upload binaries to \\$node\c$ .. but I decided to use pssession. Just make sure maxevenlopesize is big enough.

#region Variables
    #make sure failover clustering management is installed
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell
    #Grab failover cluster
    $ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single -Title "Please select failover cluster to patch").Name
    $Nodes=(Get-ClusterNode -Cluster $ClusterName).Name

    $DellToolsDownloadFolder="$Env:UserProfile\Downloads\Dell\"

    $MicrosoftUpdatesDownloadFolder="$Env:UserProfile\Downloads\Microsoft\"

    #folder on servers where all binaries will be staged
    $BinariesLocation="c:\Dell\"

    $Offline=$false #assuming nodes are offline. If true, all tools will be downloaded to management machine, all updates will be installed "offline"

    $MSUpdates="Recommended" #or $false (to skip MS updates) or "All" - for online version only

    $DellUpdates=$True #or $False to skip dell updates

    $ForceReboot=$false #or $true, to reboot even if there were no updates applied

    #Configure Search Criteria for windows update when running online
        if ($MSUpdates -eq "Recommended"){
            $UpdatesSearchCriteria = "IsInstalled=0 and DeploymentAction='Installation' or
                IsPresent=1 and DeploymentAction='Uninstallation' or
                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        }elseif ($MSUpdates -eq "All"){
            $UpdatesSearchCriteria = "IsInstalled=0 and DeploymentAction='Installation' or
                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                IsPresent=1 and DeploymentAction='Uninstallation' or
                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        }
#endregion

#region download all required Dell binaries
    #create downloads folder
    if (-not (Test-Path $DellToolsDownloadFolder -ErrorAction Ignore)){New-Item -Path $DellToolsDownloadFolder -ItemType Directory}
        #grab DSU links from Dell website
            if (-not ([Net.ServicePointManager]::SecurityProtocol).tostring().contains("Tls12")){ #there is no need to set Tls12 in 1809 releases, therefore for insider it does not apply
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            }
            $URL="https://dl.dell.com/omimswac/dsu/"
            $Results=Invoke-WebRequest $URL -UseDefaultCredentials -UseBasicParsing
            $Links=$results.Links.href | Select-Object -Skip 1
            #create PSObject from results
            $DSUs=@()
            foreach ($Link in $Links){
                $DSUs+=[PSCustomObject]@{
                    Link = "https://dl.dell.com$Link"
                    Version = $link -split "_" | Select-Object -Last 2 | Select-Object -First 1
                }
            }
            #download latest DSU
            $LatestDSU=$DSUs | Sort-Object Version | Select-Object -Last 1
            Start-BitsTransfer -Source $LatestDSU.Link -Destination $DellToolsDownloadFolder\DSU.exe

        #grab IC (inventory collection tool. Required for offline patching)
            if ($Offline){
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
            }

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
        #
#endregion

#region download all Microsoft updates
    if ($Offline){
        $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/DownloadLatestCUs.ps1").Content
        if (-not (Test-Path $MicrosoftUpdatesDownloadFolder -ErrorAction Ignore)){New-Item -Path $MicrosoftUpdatesDownloadFolder -ItemType Directory}
        Set-Content -path "$MicrosoftUpdatesDownloadFolder\DownloadLatestCUs.ps1" -value $FileContent
        #run download latest CU (will prompt for what OS you want to download for)
        & "$MicrosoftUpdatesDownloadFolder\DownloadLatestCUs.ps1"
    }
#endregion

#region prepare DSU binaries
    #upload DSU to servers
    $Sessions=New-PSSession -ComputerName $Nodes
    Invoke-Command -Session $Sessions -ScriptBlock {
        if (-not (Test-Path $using:BinariesLocation -ErrorAction Ignore)){New-Item -Path $using:BinariesLocation -ItemType Directory}
    }
    foreach ($Session in $Sessions){
        Copy-Item -Path "$DellToolsDownloadFolder\DSU.exe" -Destination "$BinariesLocation" -ToSession $Session -Force -Recurse
    }
    #install DSU
    Invoke-Command -ComputerName $Nodes -ScriptBlock {
        Start-Process -FilePath "$using:BinariesLocation\DSU.exe" -ArgumentList "/silent" -Wait 
    }

    #upload IC.exe to servers
    if ($Offline){
        foreach ($Session in $Sessions){
            Copy-Item -Path "$DellToolsDownloadFolder\IC.exe" -Destination "$BinariesLocation" -ToSession $Session -Force -Recurse
        }
    }

    #upload catalog
    foreach ($Session in $Sessions){
        Copy-Item -Path "$DellToolsDownloadFolder\ASHCI-Catalog.xml" -Destination "$BinariesLocation" -ToSession $Session -Force -Recurse
    }

    #close sessions
    $Sessions | Remove-PSSession
#endregion

#region check Dell compliance
    #scan for compliance
    if ($offline){
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --ic-location="$using:BinariesLocation\ic.exe" --output-format="json" --output="$using:BinariesLocation\Compliance.json"
        }
    }else{
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --output-format="json" --output="$using:BinariesLocation\Compliance.json"
        }
    }
    #collect results
    $Compliance=@()
    foreach ($Node in $Nodes){
        $json=Invoke-Command -ComputerName $node -ScriptBlock {Get-Content "$using:BinariesLocation\Compliance.json"}
        $object = $json | ConvertFrom-Json 
        $components=$object.SystemUpdateCompliance.UpdateableComponent
        $components | Add-Member -MemberType NoteProperty -Name "ClusterName" -Value $ClusterName
        $components | Add-Member -MemberType NoteProperty -Name "NodeName" -Value $Node
        $Compliance+=$Components
    }

    #display results
    $Compliance | Out-GridView
    
    #you can also select what updates you want to deploy to each node
    #$Compliance=$Compliance | Out-GridView -OutputMode Multiple
#endregion

#region check Dell inventory
    <#
    #scan for inventory
    if ($offline){
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --inventory --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --ic-location="$using:BinariesLocation\ic.exe" --output-format="json" --output="$using:BinariesLocation\Inventory.json"
        }
    }else{
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --inventory --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --output-format="json" --output="$using:BinariesLocation\Inventory.json"
        }
    }
    #collect results
    $Inventory=@()
    foreach ($Node in $Nodes){
        $json=Invoke-Command -ComputerName $node -ScriptBlock {Get-Content "$using:BinariesLocation\Inventory.json"}
        $object = $json | ConvertFrom-Json 
        $components=$object.UpdatableComponentsInventory.Updateablecomponent
        $components | Add-Member -MemberType NoteProperty -Name "ClusterName" -Value $ClusterName
        $components | Add-Member -MemberType NoteProperty -Name "NodeName" -Value $Node
        $Inventory+=$Components
    }

    #display results
    $Inventory | Out-GridView
    #>
#endregion

#region download updates to $DellToolsDownloadFolder on management machine based on compliance scan if offline
    if ($offline){
        $DellUpdatesList=($Compliance | Where-Object ComplianceStatus -eq $False | Group-Object PackageFilePath | ForEach-Object {$_.Group | Select-Object PackageFilePath -First 1}).PackageFilePath
        foreach ($Update in $DellUpdatesList){
            #create destination folder
            New-Item -Path ("$DellToolsDownloadFolder\Updates\$update" | Split-Path -Parent) -ItemType Directory -Force
            Start-BitsTransfer -Source https://dl.dell.com/$Update -Destination "$DellToolsDownloadFolder\Updates\$update"
        }
    }
#endregion

#region upload drivers to nodes
    if ($offline){
        $Sessions=New-PSSession -ComputerName ($Compliance.NodeName | Select-Object -Unique)
        foreach ($session in $sessions){
            Copy-Item -Path "$DellToolsDownloadFolder\Updates\" -Destination $BinariesLocation -Recurse -ToSession $Session
        }
        #close sessions
        $Sessions | Remove-PSSession
    }
#endregion

#region upload Microsoft update(s) to nodes
if ($offline){
    #Grab CAB
    $MSUs=Get-ChildItem -Path $MicrosoftUpdatesDownloadFolder -Recurse | Where-Object Extension -eq ".msu"
    #copy over to nodes
    $Sessions=New-PSSession -ComputerName ($Compliance.NodeName | Select-Object -Unique)
    foreach ($session in $sessions){
        #copy microsoft update
        foreach ($MSU in $MSUs) {
            Copy-Item $MSU.FullName -Destination "$BinariesLocation\Updates\" -ToSession $Session -Force
        }
    }
    #close sessions
    $Sessions | Remove-PSSession
}
#endregion

#region check Microsoft Compliance
    $ScanResult=Invoke-Command -ComputerName $Nodes -ScriptBlock {
        if ($using:Offline){
            $SearchResult=get-childitem -Path $using:BinariesLocation\Updates\ | Where-Object Extension -eq ".msu"
            if ($SearchResult){
                $MicrosoftUpdateRequired=$True
            }else{
                $MicrosoftUpdateRequired=$False
            }
        }else{
            #scan for microsoft updates
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchResult = $Searcher.Search($using:UpdatesSearchCriteria).Updates
            if ($SearchResult.Count -gt 0){
                $MicrosoftUpdateRequired=$True
            }else{
                $MicrosoftUpdateRequired=$False
            }
        }

        #grab windows version
        $ComputersInfo  = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
        $Output=@()
        $Output += [PSCustomObject]@{
                "MicrosoftUpdateRequired" = $MicrosoftUpdateRequired
                "MicrosoftUpdates"        = $SearchResult
                "ComputerName"            = $env:COMPUTERNAME
                "CurrentBuildNumber"      = $ComputersInfo.CurrentBuildNumber
                "UBR"                     = $ComputersInfo.UBR
        }
        return $Output
    }
    $ScanResult
#endregion

#region apply updates on nodes
    foreach ($Node in $Nodes){
        #check for repair jobs, if found, wait until finished
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Waiting for Storage jobs to finish"
        if ((Get-StorageSubSystem -CimSession $ClusterName -FriendlyName Clus* | Get-StorageJob -CimSession $ClusterName | Where-Object Name -eq Repair) -ne $Null){
            do{
                $jobs=(Get-StorageSubSystem -CimSession $ClusterName -FriendlyName Clus* | Get-StorageJob -CimSession $ClusterName)
                if ($jobs | Where-Object Name -eq Repair){
                    $count=($jobs | Measure-Object).count
                    $BytesTotal=($jobs | Measure-Object BytesTotal -Sum).Sum
                    $BytesProcessed=($jobs | Measure-Object BytesProcessed -Sum).Sum
                    [System.Console]::Write("$count Repair Storage Job(s) Running. GBytes Processed: $($BytesProcessed/1GB) GBytes Total: $($BytesTotal/1GB)               `r")
                    #Check for Suspended jobs (if there are no running repair jobs, only suspended and still unhealthy disks). Kick the repair with Repair-Virtual disk if so... 
                    if ((($jobs | where-Object Name -eq Repair | where-Object JobState -eq "Running") -eq $Null) -and ($jobs | where-Object Name -eq Repair | where-Object JobState -eq "Suspended") -and (Get-VirtualDisk -CimSession $ClusterName | where healthstatus -ne Healthy)){
                        Write-Output "Suspended repair job and Degraded virtual disk found. Invoking Virtual Disk repair"
                        Get-VirtualDisk -CimSession $ClusterName | where-Object HealthStatus -ne "Healthy" | Repair-VirtualDisk
                    }
                    Start-Sleep 5
                }
            }until (($jobs | Where-Object Name -eq Repair) -eq $null)
        }

        #Check if all disks are healthy. Wait if not
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Checking if all disks are healthy"
        if (Get-VirtualDisk -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy"){
            Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Waiting for virtual disks to become healthy"
            do{Start-Sleep 5}while(Get-VirtualDisk -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy")
        }

        #Check if all fault domains are healthy. Wait if not
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Checking if all fault domains are healthy"
        if (Get-StorageFaultDomain -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy"){
            Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Waiting for fault domains to become healthy"
            do{Start-Sleep 5}while(Get-StorageFaultDomain -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy")
        }

        #install microsoft updates (we will do it online to limit time when node is suspended)
        if ($MSUpdates){
            if ($offline){
                Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Applying offline MSUs"
                #apply all MSU from $BinariesLocation
                Invoke-Command -ComputerName $Node -ScriptBlock {
                    $MSUs=Get-ChildItem -Path $using:BinariesLocation\Updates | Where-Object Extension -eq ".msu"
                    foreach ($MSU in $MSUs) {
                        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($using:Node): Applying MSU $($MSU.FullName)"
                        <#
                        $CabName="$($MSU.basename -split "_" | Select-Object -First 1).cab"
                        expand.exe $MSU.FullName $using:BinariesLocation\Updates\ -f:"$CabName" | Out-Null
                        Add-WindowsPackage -PackagePath "$using:BinariesLocation\Updates\$CabName" -Online | Out-Null
                        #>
                        Start-Process -FilePath "$env:systemroot\System32\wusa.exe" -ArgumentList "$($MSU.FullName) /quiet /norestart" -Wait
                    }
                }
            }else{
                #install Microsoft updates
                if (($ScanResult | Where-Object ComputerName -eq $node).MicrosoftUpdateRequired){
                    Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Installing $MSUpdates Microsoft Updates online"
                    #Configure virtual account
                    Invoke-Command -ComputerName $node -ScriptBlock {
                        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
                        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
                    } -ErrorAction Ignore
                    #wait a bit for virtual account
                    Start-Sleep 5
                    #install update
                    $MSUpdateInstallResult=Invoke-Command -ComputerName $Node -ConfigurationName 'VirtualAccount' {
                        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
                        $SearchResult = $Searcher.Search($using:UpdatesSearchCriteria).Updates
                        $Session = New-Object -ComObject Microsoft.Update.Session
                        $Downloader = $Session.CreateUpdateDownloader()
                        $Downloader.Updates = $SearchResult
                        $Downloader.Download()
                        $Installer = New-Object -ComObject Microsoft.Update.Installer
                        $Installer.Updates = $SearchResult
                        $Result = $Installer.Install()
                        $Result
                    }
                    #remove temporary virtual account config
                    Invoke-Command -ComputerName $Node -ScriptBlock {
                        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
                        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
                    }
                }else{
                    Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Microsoft Updates not required"
                    $MSUpdateInstallResult=$Null
                }
            }
        }

        #Suspend node
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Suspending Cluster Node"
        Suspend-ClusterNode -Name "$Node" -Cluster $ClusterName -Drain -Wait | Out-Null

        if (Get-ClusterResource -Cluster $ClusterName | Where-Object OwnerNode -eq $Node | Where-Object State -eq "Online"){
            Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Suspending Cluster Node Failed. Resuming and terminating patch run"
            Resume-ClusterNode -Name "$Node" -Cluster $ClusterName -Failback Immediate | Out-Null
            break
        }

        #enable storage maintenance mode
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Enabling Storage Maintenance mode"
        Get-StorageFaultDomain -CimSession $ClusterName -FriendlyName $Node | Enable-StorageMaintenanceMode -CimSession $ClusterName

        #Install Dell updates https://dl.dell.com/content/manual36290092-dell-emc-system-update-version-1-9-3-0-user-s-guide.pdf?language=en-us&ps=true
        #assuming dell updates might interrupt server, therefore it's done during maintenance mode
        if ($DellUpdates){
            $UpdateNames=(($Compliance | Where-Object {$_.NodeName -eq $Node -and $_.compliancestatus -eq $false}).PackageFilePath | Split-Path -Leaf) -join ","
            if ($UpdateNames){
                if ($offline){
                    Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Installing Dell Updates Offline"
                    Invoke-Command -ComputerName $node -ScriptBlock {
                        & "C:\Program Files\Dell\DELL System Update\DSU.exe" --source-location="$using:BinariesLocation\Updates" --source-type="Repository" --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --ic-location="$using:BinariesLocation\IC.exe" --update-list="$using:UpdateNames" --apply-upgrades
                    }
                }else{
                    Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Installing Dell Updates Online (downloading updates from internet)"
                    Invoke-Command -ComputerName $node -ScriptBlock {
                        & "C:\Program Files\Dell\DELL System Update\DSU.exe" --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --update-list="$using:UpdateNames" --apply-upgrades
                    }
                }
            }
        }

        #Check if reboot is required and reboot
        if (($Compliance | Where-Object {$_.NodeName -eq $Node -and $_.rebootrequired -eq $True}) -or ($Scanresult | Where-Object ($_.ComputerName -eq $node -and $_.MicrosoftUpdateRequired -eq $True) -or ($ForceReboot -eq $True))){
            Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Reboot is required"
            #restart node and wait for PowerShell to come up (with powershell 7 you need to wait for WINRM :)
            Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Restarting Cluster Node"
            Restart-Computer -ComputerName $Node -Protocol WSMan -Wait -For PowerShell -Force | Out-Null
        }

        #wait until node is in paused state (might not be yet up - cluster service)
        do {
            $State=(Get-ClusterNode -Cluster $ClusterName).State
            Start-Sleep 5
        }while($state -ne "Paused")

        #disable storage maintenance mode
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Disabling Storage Maintenance mode"
        Get-StorageFaultDomain -Type StorageScaleUnit -CimSession $Node | Where-Object FriendlyName -eq $Node | Disable-StorageMaintenanceMode -CimSession $Node

        #resume cluster node
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Resuming Cluster Node"
        Resume-ClusterNode -Name "$Node" -Cluster $ClusterName -Failback Immediate | Out-Null

        #wait for machines to finish live migration
        Write-Output "$(get-date -Format 'yyyy/MM/dd hh:mm:ss tt') $($Node): Waiting for Live migrations to finish"
        do {Start-Sleep 5}while(
            Get-CimInstance -CimSession $Nodes -Namespace root\virtualization\v2 -ClassName Msvm_MigrationJob | Where-Object StatusDescriptions -eq "Job is running"
        )
    }

    #cleanup updates folder on nodes
    Invoke-Command -ComputerName $Nodes -ScriptBlock {
        Remove-Item -Path $using:BinariesLocation\Updates -Recurse -Force -ErrorAction Ignore
    }
#endregion

#region check Microsoft Update Levels
    #check OS Build Number on all cluster nodes
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    $ComputersInfo  = Invoke-Command -ComputerName (Get-ClusterNode -Cluster $ClusterName).Name -ScriptBlock {
        Get-ItemProperty -Path $using:RegistryPath
    }
    $ComputersInfo | Select-Object PSComputerName,CurrentBuildNumber,UBR
#endregion

#region check Dell compliance again
    #scan for compliance
    if ($offline){
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --ic-location="$using:BinariesLocation\ic.exe" --output-format="json" --output="$using:BinariesLocation\Compliance.json"
        }
    }else{
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            & "C:\Program Files\Dell\DELL System Update\DSU.exe" --compliance --catalog-location="$using:BinariesLocation\ASHCI-Catalog.xml" --output-format="json" --output="$using:BinariesLocation\Compliance.json"
        }
    }
    #collect results
    $Compliance=@()
    foreach ($Node in $Nodes){
        $json=Invoke-Command -ComputerName $node -ScriptBlock {Get-Content "$using:BinariesLocation\Compliance.json"}
        $object = $json | ConvertFrom-Json 
        $components=$object.SystemUpdateCompliance.UpdateableComponent
        $components | Add-Member -MemberType NoteProperty -Name "ClusterName" -Value $ClusterName
        $components | Add-Member -MemberType NoteProperty -Name "NodeName" -Value $Node
        $Compliance+=$Components
    }

    #display results
    $Compliance | Out-GridView

#endregion

