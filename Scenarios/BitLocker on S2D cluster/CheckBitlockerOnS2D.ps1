#Install AD PowerShell if not available
if (-not (Get-WindowsFeature RSAT-AD-PowerShell)){
    Install-WindowsFeature RSAT-AD-PowerShell
}
$ClusterName=((Get-ADComputer -Filter 'serviceprincipalname -like "MSServercluster/*"').Name | ForEach-Object {get-cluster -Name $_ | Where-Object S2DEnabled -eq 1} | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster(s)").Name

if (-not $ClusterName){
    Write-Output "No cluster was selected. Exitting"
    Start-Sleep 5
    Exit
}

#check if bitlocker powershell is installed on nodes
$InstallStates=Invoke-Command -computername (Get-ClusterNode -Cluster $ClusterName).Name -scriptblock {Get-WindowsFeature -Name RSAT-Feature-Tools-BitLocker}
$NodesWithMissingBL=$InstallStates | Where-Object installstate -ne "Installed"

#RSAT-Feature-Tools-BitLocker is missing, exit
if ($NodesWithMissingBL){
    Write-Output "RSAT-Feature-Tools-BitLocker is missing on following computers: "
    $NodesWithMissingBL.PSComputername
    Write-Output "Exitting"
    Start-Sleep 5
    Exit
}

#list all CSVs and check for bitlocker status
$Output=@()
$CSVs=Get-ClusterSharedVolume -Cluster $clustername
foreach ($CSV in $CSVs){
    $owner=$csv.ownernode.name
    $CsvPath = ($CSV).SharedVolumeInfo.FriendlyVolumeName
    $Status=Invoke-Command -ComputerName $owner -ArgumentList $CSVPath -ScriptBlock {param($CsvPath); Get-BitLockerVolume -MountPoint $CSVPath}
    $Output += [PSCustomObject]@{
        "CSVPath"          = $CSVPath
        "VolumeStatus"     = $Status.VolumeStatus
        "KeyProtector"     = $Status.KeyProtector
        "EncryptionMethod" = $Status.EncryptionMethod
        "MountPoint"       = $Status.MountPoint
        "ProtectionStatus" = $Status.ProtectionStatus
    }
}

$Output | ft -AutoSize
