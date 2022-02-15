#I created this scenario for updating my Ax6515 based lab. I don't think it's robust enough for production usage.
#Ideas grabbed from here https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1
#todo: update offline from file share

#region Variables
    #make sure failover clustering management is installed
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell
    #Grab failover cluster
    $ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Out-GridView -OutputMode Single -Title "Please select failover cluster to patch").Name
    $Nodes=(Get-ClusterNode -Cluster $ClusterName).Name

    $DSUDownloadFolder="$env:USERPROFILE\Downloads\DSU"
    $DSUPackageDownloadFolder="$env:USERPROFILE\Downloads\DSUPackage"

    $Updates="Recommended" #or "All"

    $ForceReboot=$false #or $true, to reboot even if there were no updates applied

    # Configure Search Criteria for windows update
        if ($Updates -eq "Recommended"){
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                IsPresent=1 and DeploymentAction='Uninstallation' or
                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        }elseif ($Updates -eq "All"){
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                IsPresent=1 and DeploymentAction='Uninstallation' or
                IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
        }
#endregion

#region prepare DSU binaries
    #Download DSU
        #https://github.com/DellProSupportGse/Tools/blob/main/DART.ps1

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
        #download latest to separate folder
        $LatestDSU=$DSUs | Sort-Object Version | Select-Object -Last 1
        if (-not (Test-Path $DSUDownloadFolder -ErrorAction Ignore)){New-Item -Path $DSUDownloadFolder -ItemType Directory}
        Start-BitsTransfer -Source $LatestDSU.Link -Destination $DSUDownloadFolder\DSU.exe

        #upload DSU to servers
        $Sessions=New-PSSession -ComputerName $Nodes
        foreach ($Session in $Sessions){
            Copy-Item -Path $DSUDownloadFolder -Destination $DSUDownloadFolder -ToSession $Session -Recurse -Force
        }
        $Sessions | Remove-PSSession
        #install DSU
        Invoke-Command -ComputerName $Nodes -ScriptBlock {
            Start-Process -FilePath "$using:DSUDownloadFolder\DSU.exe" -ArgumentList "/silent" -Wait 
        }

    #download catalog and copy DSU Package to servers
        #Dell Azure Stack HCI driver catalog https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz
        #Download catalog
        Start-BitsTransfer -Source "https://downloads.dell.com/catalog/ASHCI-Catalog.xml.gz" -Destination "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz"
        #unzip gzip to a folder https://scatteredcode.net/download-and-extract-gzip-tar-with-powershell/
        if (-not (Test-Path $DSUPackageDownloadFolder -ErrorAction Ignore)){New-Item -Path $DSUPackageDownloadFolder -ItemType Directory}
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
        Expand-GZipArchive "$env:UserProfile\Downloads\ASHCI-Catalog.xml.gz" "$DSUPackageDownloadFolder\ASHCI-Catalog.xml"
        #create answerfile for DU
        $content='@
        a
        c
        @'
        Set-Content -Path "$DSUPackageDownloadFolder\answer.txt" -Value $content -NoNewline
        $content='"C:\Program Files\Dell\DELL EMC System Update\DSU.exe" --catalog-location=ASHCI-Catalog.xml --apply-upgrades <answer.txt'
        Set-Content -Path "$DSUPackageDownloadFolder\install.cmd" -Value $content -NoNewline

        #upload DSU package to servers
        $Sessions=New-PSSession -ComputerName $Nodes
        foreach ($Session in $Sessions){
            Copy-Item -Path $DSUPackageDownloadFolder -Destination $DSUPackageDownloadFolder -ToSession $Session -Recurse -Force
        }
        $Sessions | Remove-PSSession
#endregion

#region check if there are any updates needed
$ScanResult=Invoke-Command -ComputerName $Nodes -ScriptBlock {
    & "C:\Program Files\Dell\DELL EMC System Update\DSU.exe" --catalog-location="$using:DSUPackageDownloadFolder\ASHCI-Catalog.xml" --preview | Out-Null
    $Result=(Get-content "C:\ProgramData\Dell\DELL EMC System Update\dell_dup\DSU_STATUS.json" | ConvertFrom-JSon).systemupdatestatus.invokerinfo.statusmessage
    if ($Result -like "No Applicable Update*" ){
        $DellUpdateRequired=$false
    }else{
        $DellUpdateRequired=$true
    }

    #scan for microsoft updates
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchResult = $Searcher.Search($using:SearchCriteriaAllUpdates).Updates
    if ($SearchResult.Count -gt 0){
        $MicrosoftUpdateRequired=$True
    }else{
        $MicrosoftUpdateRequired=$False
    }

    #grab windows version
    $ComputersInfo  = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'

    $Output=@()
    $Output += [PSCustomObject]@{
            "DellUpdateRequired"      = $DellUpdateRequired
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

#region install DSU and Microsoft updates and restart
    #Configure virtual account
    Invoke-Command -ComputerName $nodes -ScriptBlock {
        New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
        Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
    } -ErrorAction Ignore
    

    #let's update do node by node (in case something goes wrong). It would be definitely faster if we would install both updates at once. But if something would go wrong on one node, it's easier to roll back
    foreach ($Node in $Nodes){
        #Install Dell updates https://dl.dell.com/content/manual36290092-dell-emc-system-update-version-1-9-3-0-user-s-guide.pdf?language=en-us&ps=true
        if (($ScanResult | Where-Object ComputerName -eq $node).DellUpdateRequired){
            Write-Output "$($Node): Installing Dell System Updates"
            Invoke-Command -ComputerName $Node -ScriptBlock {
                #install DSU updates
                Start-Process -FilePath "install.cmd" -Wait -WorkingDirectory $using:DSUPackageDownloadFolder
                #display result
                Get-Content "C:\ProgramData\Dell\DELL EMC System Update\dell_dup\DSU_STATUS.json"
            }
        }

        #install Microsoft updates
        if (($ScanResult | Where-Object ComputerName -eq $node).MicrosoftUpdateRequired){
            Write-Output "$($Node): Installing Microsoft $Updates Updates"
            $MSUpdateInstallResult=Invoke-Command -ComputerName $Node -ConfigurationName 'VirtualAccount' {
                $Searcher = New-Object -ComObject Microsoft.Update.Searcher
                $SearchResult = $Searcher.Search($using:SearchCriteriaAllUpdates).Updates
                $Session = New-Object -ComObject Microsoft.Update.Session
                $Downloader = $Session.CreateUpdateDownloader()
                $Downloader.Updates = $SearchResult
                $Downloader.Download()
                $Installer = New-Object -ComObject Microsoft.Update.Installer
                $Installer.Updates = $SearchResult
                $Result = $Installer.Install()
                $Result
            }
        }

        #Check if reboot is required
        if (($ScanResult | Where-Object ComputerName -eq $node).DellUpdateRequired -or $MSUpdateInstallResult.RebootRequired -or $ForceReboot){
            Write-Output "$($Node): Reboot is required"
            #check for repair jobs, if found, wait until finished
            Write-Output "$($Node): Waiting for Storage jobs to finish"
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
            Write-Output "$($Node): Checking if all disks are healthy"
            if (Get-VirtualDisk -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy"){
                Write-Output "$($Node): Waiting for virtual disks to become healthy"
                do{Start-Sleep 5}while(Get-VirtualDisk -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy")
            }
            #Check if all fault domains are healthy. Wait if not
            Write-Output "$($Node): Checking if all fault domains are healthy"
            if (Get-StorageFaultDomain -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy"){
                Write-Output "$($Node): Waiting for fault domains to become healthy"
                do{Start-Sleep 5}while(Get-StorageFaultDomain -CimSession $ClusterName | Where-Object HealthStatus -ne "Healthy")
            }

            #Suspend node
            Write-Output "$($Node): Suspending Cluster Node"
            Suspend-ClusterNode -Name "$Node" -Cluster $ClusterName -Drain -Wait | Out-Null

            #enable storage maintenance mode
            Write-Output "$($Node): Enabling Storage Maintenance mode"
            Get-StorageFaultDomain -CimSession $ClusterName -FriendlyName $Node | Enable-StorageMaintenanceMode -CimSession $ClusterName

            #restart node and wait for PowerShell to come up
            Write-Output "$($Node): Restarting Cluster Node"
            Restart-Computer -ComputerName $Node -Protocol WSMan -Wait -For PowerShell

            #disable storage maintenance mode
            Write-Output "$($Node): Disabling Storage Maintenance mode"
            Get-StorageFaultDomain -CimSession $ClusterName -FriendlyName $Node | Disable-StorageMaintenanceMode -CimSession $ClusterName

            #resume cluster node
            Write-Output "$($Node): Resuming Cluster Node"
            Resume-ClusterNode -Name "$Node" -Cluster $ClusterName -Failback Immediate | Out-Null

            #wait for machines to finish live migration
            Write-Output "$($Node): Waiting for Live migrations to finish"
            do {Start-Sleep 5}while(
                Invoke-Command -ComputerName $Nodes -ScriptBlock {Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_MigrationJob} | Where-Object StatusDescriptions -eq "Job is running"
            )
        }else{
            Write-Output "$($Node): Reboot is not required"
        }
    }

    #remove temporary virtual account config
    Invoke-Command -ComputerName $Nodes -ScriptBlock {
        Unregister-PSSessionConfiguration -Name 'VirtualAccount'
        Remove-Item -Path $env:TEMP\VirtualAccount.pssc
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