````PowerShell
#Grab cluster name
$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster").Name

if (-not $ClusterName){
    Write-Output "No cluster was selected. Exitting"
    Start-Sleep 5
    Exit
}

#get cluster nodes
$ClusterNodes=(Get-ClusterNode -Cluster $clustername).name

foreach ($ClusterNode in $ClusterNodes){
    #check for repair jobs, if found, wait until finished
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
    Write-Output ""
    Write-Output "Checking if all disks are healthy"
    if(((Get-VirtualDisk -CimSession $ClusterName).healthstatus | Select-Object -Unique) -eq "Healthy"){
        Write-Output "All Disks are healthy"
    }else{
        Write-Output "Waiting for disks to become healthy"
        do{ Start-Sleep 5}until(((Get-VirtualDisk -CimSession $ClusterName).healthstatus | Select-Object -Unique) -eq "Healthy")
    }

    #Suspend node
    Write-Output "Suspending Cluster Node $ClusterNode"
    do{
        Start-Sleep 10 
        Suspend-ClusterNode -Name $ClusterNode -Cluster $ClusterName -Drain -ErrorAction SilentlyContinue
    }until((Get-ClusterNode -Cluster $ClusterName -Name $ClusterNodes).State -eq "Paused")

    #restart node and wait for PowerShell to come up
    Write-Output "Restarting Cluster Node $ClusterNode"
    Restart-Computer -ComputerName $ClusterNode -Protocol WSMan -Wait -For PowerShell

    #resume cluster node
    Write-Output "Resuming Cluster node $ClusterNode"
    do{
        Start-Sleep 10 
        Resume-ClusterNode -Name $ClusterNode -Cluster $ClusterName -ErrorAction SilentlyContinue
    }until((Get-ClusterNode -Cluster $ClusterName -Name $ClusterNodes).State -eq "Up")
 
````



