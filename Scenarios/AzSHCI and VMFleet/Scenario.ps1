#Run from DC or Management machine

#region Variables and prerequisites
    $ClusterName="AzSHCI-Cluster"
    $Nodes=(Get-ClusterNode -Cluster $ClusterName).Name
    $VolumeSize=1TB

    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name VMFleet -Force
    Install-Module -Name PrivateCloud.DiagnosticInfo -Force

    #Make sure Hyper-V is installed (to be able to work with VHD)
    $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed"){
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
#endregion

#region Configure VMFleet prereqs
    #Create Volumes
    Foreach ($Node in $Nodes){
        if (-not (Get-Virtualdisk -CimSession $ClusterName -FriendlyName $Node)){
            New-Volume -CimSession $Node -StoragePoolFriendlyName "S2D on $ClusterName" -FileSystem CSVFS_ReFS -FriendlyName $Node -Size $VolumeSize
        }
    }

    if (-not (Get-Virtualdisk -CimSession $ClusterName -FriendlyName Collect)){
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
    #Grab nubmer of Logical Processors per node divided by 2
    $NumberOfVMs=(Get-CimInstance -CimSession $ClusterName -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors/2

    #Enable CredSSP
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    foreach ($Node in $Nodes){
        Enable-WSManCredSSP -Role "Client" -DelegateComputer $Node -Force
    }
    Invoke-Command -ComputerName $Nodes -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    Invoke-Command -ComputerName $Nodes[0] -Credential $Credentials -Authentication Credssp -ScriptBlock {
        Install-Fleet #as vmfleet has issues with Install-Fleet -ClusterName https://github.com/microsoft/diskspd/issues/157
        #It's probably more convenient to run this command on cluster as all VHD copying will happen on cluster itself.
        #if you will run Measure-FleetCoreWorkload, creating VMs is not necessary
        #New-Fleet -BaseVHD "c:\ClusterStorage\Collect\$using:VHDName" -VMs $using:NumberOfVMs -AdminPass P@ssw0rd -Admin Administrator -ConnectUser corp\LabAdmin -ConnectPass LS1setup!
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