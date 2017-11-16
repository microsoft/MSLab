#End-To-End script for 2 node cluster inside AWS or VMware

    #Variables
        $Servers="S2D1","S2D2"
        $ClusterName="S2D-Cluster"
        $VolumeNames="MirrorDisk1","MirrorDisk2"
        $VolumeSize=10GB

        #Azure Blob credentials (this is just an example)
        $StorageAccountName="MyStorageAccountName"
        $Key="qi8QB/VSHHiA9lSvz1kEIEt0JxIucPL3l99nRHhkp+n1Lpabu4Ydi7Ih192A4VW42vccIgUnrXxxxxxxxxxxxx=="
        $Endpoint="core.windows.net"

    #Install features for management
        Install-WindowsFeature -Name "RSAT-Clustering","RSAT-Clustering-PowerShell"

    #Install failover clustering into cluster nodes
        foreach ($server in $servers) {Install-WindowsFeature -Name "Failover-Clustering" -ComputerName $server} 

    #test and create new cluster 
        Test-Cluster -Node $servers -Include "Storage Spaces Direct",Inventory,Network,"System Configuration"
        New-Cluster -Name $ClusterName -Node $servers
        Start-Sleep 5
        Clear-DnsClientCache

    #Enable Storage Spaces Direct
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Autoconfig:0 -Verbose

    #register remote storage subsystem to work with disks as it was connected locally
        Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName

    #Create Pool
        $phydisks = Get-StorageSubSystem -FriendlyName *$ClusterName | Get-PhysicalDisk -CanPool $true
        $pool=New-StoragePool -FriendlyName  "S2D on $clustername" -PhysicalDisks $phydisks -StorageSubSystemFriendlyName *$ClusterName 

    #set mediatype to HDD
        $pool | get-physicaldisk | Set-PhysicalDisk -MediaType HDD
    
    #unregister remote storage subsystem as its no longer needed
        $ss=Get-StorageSubSystem -FriendlyName *$ClusterName
        Unregister-StorageSubsystem -ProviderName "Windows Storage Management Provider" -StorageSubSystemUniqueId $ss.UniqueId

    #Create template (tier) for 2-way mirror (notice -PhysicalDiskRedundancy 1)
        New-StorageTier -FriendlyName Capacity -MediaType HDD -ResiliencySettingName Mirror -StoragePoolFriendlyName "S2D on $clustername" -PhysicalDiskRedundancy 1 -CimSession $ClusterName
        
    #Create Volumes
        foreach ($VolumeName in $VolumeNames){
            New-Volume -StoragePoolFriendlyName "S2D on $ClusterName" -FriendlyName $VolumeName -FileSystem CSVFS_ReFS -StorageTierFriendlyNames Capacity -StorageTierSizes $VolumeSize -CimSession $ClusterName
        }

    #rename csv paths to match volume names
        Get-ClusterSharedVolume -Cluster $ClusterName | % {
            $volumepath=$_.sharedvolumeinfo.friendlyvolumename
            $newname=$_.name.Substring(22,$_.name.Length-23)
            Invoke-Command -ComputerName (Get-ClusterSharedVolume -Cluster $ClusterName -Name $_.Name).ownernode -ScriptBlock {param($volumepath,$newname); Rename-Item -Path $volumepath -NewName $newname} -ArgumentList $volumepath,$newname -ErrorAction SilentlyContinue
        }

    #Configure Quorum - just example, use yours blob
        #Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $StorageAccountName -AccessKey $key -Endpoint $Endpoint 



