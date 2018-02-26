````PowerShell
#Grab cluster name
$ClusterName=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1 | Out-GridView -OutputMode Single -Title "Please select your S2D Cluster").Name

#Grab ClusterNodes
    $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name

#to get unique device per node, it will run node by node
    $Devices=@()
    foreach ($ClusterNode in $ClusterNodes){
        $devices+=get-pnpdevice -CimSession $ClusterNode | Where-Objectmanufacturer -ne Microsoft | Where-ObjectFriendlyName -NotLike Microsoft* | select -Unique
    }

#Create custom object and add properties
    $Output=@()
    $DevicesCount=$devices.count
    $i=1
    foreach ($Device in $devices){
        Write-Progress -Activity "Processing Devices property" -Completed $i
        $properties=$device | Get-PnpDeviceProperty
        $Output += [PSCustomObject]@{
            "Name"          = $Device.Name
            "ComputerName"  = $Device.PSComputerName
            "DriverVersion" = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_DriverVersion).Data
            "InstallDate"   = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_InstallDate).Data
            "DriverDate"    = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_DriverDate).Data
            "IsPresent"     = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_IsPresent).Data
            "DriverInfPath" = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_DriverInfPath).Data
            "Manufacturer"  = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_Manufacturer).Data
            "HasProblem"    = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_HasProblem).Data
        }
    }

    $devices | foreach-object -begin {$I=0;$Output=@()} -process {
        $properties=$device | Get-PnpDeviceProperty
        $Output += [PSCustomObject]@{
            "Name"          = $Device.Name
            "ComputerName"  = $Device.PSComputerName
            "DriverVersion" = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_DriverVersion).Data
            "InstallDate"   = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_InstallDate).Data
            "DriverDate"    = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_DriverDate).Data
            "IsPresent"     = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_IsPresent).Data
            "DriverInfPath" = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_DriverInfPath).Data
            "Manufacturer"  = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_Manufacturer).Data
            "HasProblem"    = ($properties | Where-Objectkeyname -eq DEVPKEY_Device_HasProblem).Data
        };
        $i++;
        Write-Progress -Activity "GettingPNPDeviceProperty on node $($Device.PSComputerName)" -Status "Progress:" -PercentComplete ($I/$devices.count*100)}

$Output | select * | ogv

<# list of available properties

DEVPKEY_Device_DeviceDesc
DEVPKEY_Device_HardwareIds
DEVPKEY_Device_Service
DEVPKEY_Device_Class
DEVPKEY_Device_ClassGuid
DEVPKEY_Device_Driver
DEVPKEY_Device_ConfigFlags
DEVPKEY_Device_Manufacturer
DEVPKEY_Device_Capabilities
DEVPKEY_Device_EnumeratorName
DEVPKEY_Device_Address
DEVPKEY_Device_BaseContainerId
DEVPKEY_NAME
DEVPKEY_Device_InstanceId
DEVPKEY_Device_Parent
DEVPKEY_Device_Siblings
DEVPKEY_Device_SafeRemovalRequired
DEVPKEY_Device_ContainerId
DEVPKEY_Device_IsPresent
DEVPKEY_Device_HasProblem
DEVPKEY_Device_IsRebootRequired
DEVPKEY_Device_InLocalMachineContainer
DEVPKEY_Device_ConfigurationId
DEVPKEY_Device_InstallDate
DEVPKEY_Device_FirstInstallDate
DEVPKEY_Device_LastArrivalDate
DEVPKEY_Device_LastRemovalDate
DEVPKEY_Device_DriverDate
DEVPKEY_Device_DriverVersion
DEVPKEY_Device_DriverDesc
DEVPKEY_Device_DriverInfPath
DEVPKEY_Device_DriverInfSection
DEVPKEY_Device_MatchingDeviceId
DEVPKEY_Device_DriverProvider
DEVPKEY_Device_DriverRank
#>
````