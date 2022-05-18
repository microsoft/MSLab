#Run from DC or Management machine

#region Variables and prerequisites
    $ClusterName="AzSHCI-Cluster"
    $Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
    $VolumeSize=1TB

    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name VMFleet -Force
    Install-Module -Name PrivateCloud.DiagnosticInfo -Force

#endregion

#region Configure VMFleet prereqs

    #configure thin volumes a default if available (because why not :)
    $OSInfo=Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    }
    if ($OSInfo.productname -eq "Azure Stack HCI" -and $OSInfo.CurrentBuild -ge 20348){
        Get-StoragePool -CimSession $ClusterName -FriendlyName S2D* | Set-StoragePool -ProvisioningTypeDefault Thin
    }

    #Create Volumes
    Foreach ($Node in $Nodes){
        if (-not (Get-Virtualdisk -CimSession $ClusterName -FriendlyName $Node -ErrorAction Ignore)){
            New-Volume -CimSession $Node -StoragePoolFriendlyName "S2D on $ClusterName" -FileSystem CSVFS_ReFS -FriendlyName $Node -Size $VolumeSize
        }
    }

    if (-not (Get-Virtualdisk -CimSession $ClusterName -FriendlyName Collect -ErrorAction Ignore)){
        New-Volume -CimSession $CLusterName -StoragePoolFriendlyName "S2D on $ClusterName" -FileSystem CSVFS_ReFS -FriendlyName Collect -Size 100GB
    }

    #Ask for VHD
        Write-Output "Please select VHD created using CreateVMFleetDisk.ps1"
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
        $openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Title="Please select VHD created using CreateVMFleetDisk.ps1"
        }
        $openFile.Filter = "vhdx files (*.vhdx)|*.vhdx|All files (*.*)|*.*" 
        If($openFile.ShowDialog() -eq "OK"){
            Write-Output  "File $($openfile.FileName) selected"
        }
        $VHDPath=$openfile.FileName

    #Copy VHD to collect folder
        Copy-Item -Path $VHDPath -Destination \\$ClusterName\ClusterStorage$\Collect\
    #Copy VMFleet to cluster nodes
        $Sessions=New-PSSession -ComputerName $Nodes
        Foreach ($Session in $Sessions){
            Copy-Item -Recurse -Path "C:\Program Files\WindowsPowerShell\Modules\VMFleet" -Destination "C:\Program Files\WindowsPowerShell\Modules\" -ToSession $Session -Force
        }
#endregion

#region install and create VMFleet
    $VHDName=$VHDPath | Split-Path -Leaf
    $AdminUsername="CORP\LabAdmin"
    $AdminPassword="LS1setup!"
    $securedpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($AdminUsername, $securedpassword)

    $VHDAdminPassword="P@ssw0rd"
    #Enable CredSSP
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    foreach ($Node in $Nodes){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Node -Force
    }
    Invoke-Command -ComputerName $Nodes -ScriptBlock { Enable-WSManCredSSP Server -Force }

    Invoke-Command -ComputerName $Nodes[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Install-Fleet #as vmfleet has issues with Install-Fleet -ClusterName https://github.com/microsoft/diskspd/issues/172
        #It's probably more convenient to run this command on cluster (using invoke-command) as all VHD copying will happen on cluster itself.
        #Grab nubmer of Logical Processors per node divided by 2 (Hyper thread CPUs) - no need to do it, this will happen automagically if -VMs not specified
        #$NumberOfVMs=(Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors/2
        #New-Fleet -BaseVHD "c:\ClusterStorage\Collect\$using:VHDName" -VMs $using:NumberOfVMs -AdminPass P@ssw0rd -Admin Administrator -ConnectUser corp\LabAdmin -ConnectPass LS1setup!
        New-Fleet -BaseVHD "c:\ClusterStorage\Collect\$using:VHDName" -AdminPass $using:VHDAdminPassword -Admin Administrator -ConnectUser $using:AdminUsername -ConnectPass $using:AdminPassword
    }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $nodes -ScriptBlock { Disable-WSManCredSSP Server }
#endregion

#region Measure Performance
    #make sure PrivateCloud.DiagnosticInfo is present
    $Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
    $Sessions=New-PSSession $Nodes
    foreach ($Session in $Sessions){
        Copy-Item -Path 'C:\Program Files\WindowsPowerShell\Modules\PrivateCloud.DiagnosticInfo' -Destination 'C:\Program Files\WindowsPowerShell\Modules\' -ToSession $Session -Recurse -Force
    }

    # Temporarily enable CredSSP delegation to avoid double-hop issue
    foreach ($Node in $Nodes){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Node -Force
    }
    Invoke-Command -ComputerName $Nodes -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    Invoke-Command -ComputerName $Nodes[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Measure-FleetCoreWorkload
    }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $nodes -ScriptBlock { Disable-WSManCredSSP Server }
#endregion

#region Remove Fleet
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    foreach ($Node in $Nodes){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Node -Force
    }
    Invoke-Command -ComputerName $Nodes -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $securedpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($AdminUsername, $securedpassword)

    Invoke-Command -ComputerName $Nodes[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Remove-Fleet
    }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $nodes -ScriptBlock { Disable-WSManCredSSP Server }

    # Remove CSVs/
    foreach ($Node in $Nodes){
        Remove-VirtualDisk -FriendlyName $Node -CimSession $ClusterName -Confirm:0 
    }
    Remove-VirtualDisk -FriendlyName Collect -CimSession $ClusterName -Confirm:0 
#endregion


#### TBD ####

#region Customize measurement
    #Stop all VMs
    Stop-Fleet -Cluster $ClusterName
    #Adjust VMs size
    Set-Fleet -Cluster $ClusterName -ProcessorCount 1 -MemoryStartupBytes 2GB
    #Start all VMs
    Start-Fleet -Cluster $ClusterName

    #show profile
    #note: default profiles are defined in PowerShell module (Peak,General,VDI and SQL)
    #Notepad "$((Get-Module VMFleet).ModuleBase)\Profile.psm1"

    $Profile=Get-FleetProfileXml -Name General -WriteRatio 0 -BlockSize 4kb -Warmup 30 -Duration 60 -Cooldown 30
    Start-FleetRun -Cluster $ClusterName -ProfileXml $Profile

    #if profile was already captured, then you ave to delete result first
    #Get-ChildItem -Path \\$ClusterName\ClusterStorage$\Collect\result | Remove-Item -Confirm:0

    #or run custom tests without profile
    #move VMs first (Does not work)
    #Move-Fleet -Cluster $ClusterName –DistributeVMPercent 100
    #run test (Does not work well)
    #Start-FleetSweep -Cluster $ClusterName -b 4 -t 2 -o 4 -w 0 -d 60 -p r -Warm 10 -Cool 10

#endregion
