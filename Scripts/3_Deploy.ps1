# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (-not $isAdmin) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1

    if($PSVersionTable.PSEdition -eq "Core") {
        Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } else {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    }

    exit
}

#region Functions
. $PSScriptRoot\0_Shared.ps1 # [!build-include-inline]

    Function CreateUnattendFileBlob{
        #Create Unattend (parameter is Blob)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Blob,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous
        )

        if ( Test-Path "$PSScriptRoot\Temp\unattend.xml" ) {
            Remove-Item "$PSScriptRoot\Temp\unattend.xml"
        }
        $unattendFile = New-Item "$PSScriptRoot\Temp\unattend.xml" -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <OfflineIdentification>
           <Provisioning>
             <AccountData>$Blob</AccountData>
           </Provisioning>
         </OfflineIdentification>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
       <HideEULAPage>true</HideEULAPage>
       <SkipMachineOOBE>true</SkipMachineOOBE>
       <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      $oeminformation
      <RegisteredOwner>PFE</RegisteredOwner>
      <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile
    }

    Function CreateUnattendFileNoDjoin{
        #Create Unattend(without domain join)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $ComputerName,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous,
            [parameter(Mandatory=$false)]
            [string]
            $AdditionalAccount
        )

            if ( Test-Path "$PSScriptRoot\Temp\unattend.xml" ) {
                Remove-Item "$PSScriptRoot\Temp\unattend.xml"
            }
            $unattendFile = New-Item "$PSScriptRoot\Temp\unattend.xml" -type File
            $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        $oeminformation
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        $AdditionalAccount
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile
    }

    Function CreateUnattendFileWin2012{
        #Create Unattend(traditional Djoin with username/pass)
        param (
            [parameter(Mandatory=$true)]
            [string]
            $ComputerName,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone,
            [parameter(Mandatory=$false)]
            [string]
            $RunSynchronous,
            [parameter(Mandatory=$true)]
            [string]
            $DomainName
        )
        if ( Test-Path "$PSScriptRoot\Temp\unattend.xml" ) {
            Remove-Item "$PSScriptRoot\Temp\unattend.xml"
        }
        $unattendFile = New-Item "$PSScriptRoot\Temp\unattend.xml" -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        $oeminformation
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>PFE Inc.</RegisteredOrganization>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <RunSynchronous>
            $RunSynchronous
        </RunSynchronous>
    </component>
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Identification>
                <Credentials>
                    <Domain>$DomainName</Domain>
                    <Password>$AdminPassword</Password>
                    <Username>Administrator</Username>
                </Credentials>
                <JoinDomain>$DomainName</JoinDomain>
        </Identification>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content $unattendFile $fileContent
        #return the file object
        $unattendFile
    }

    Function AdditionalLocalAccountXML{
        #Creates Additional local account unattend piece
        param (
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $AdditionalAdminName
        )
@"
<LocalAccounts>
    <LocalAccount wcm:action="add">
        <Password>
            <Value>$AdminPassword</Value>
            <PlainText>true</PlainText>
        </Password>
        <Description>$AdditionalAdminName admin account</Description>
        <DisplayName>$AdditionalAdminName</DisplayName>
        <Group>Administrators</Group>
        <Name>$AdditionalAdminName</Name>
    </LocalAccount>
</LocalAccounts>
"@
    }

    function  Get-WindowsBuildNumber {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        return [int]($os.BuildNumber)
    }

    Function Set-VMNetworkConfiguration {
        #source:http://www.ravichaganti.com/blog/?p=2766 with some changes
        #example use: Get-VMNetworkAdapter -VMName Demo-VM-1 -Name iSCSINet | Set-VMNetworkConfiguration -IPAddress 192.168.100.1 00 -Subnet 255.255.0.0 -DNSServer 192.168.100.101 -DefaultGateway 192.168.100.1
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,
                    Position=1,
                    ParameterSetName='DHCP',
                    ValueFromPipeline=$true)]
            [Parameter(Mandatory=$true,
                    Position=0,
                    ParameterSetName='Static',
                    ValueFromPipeline=$true)]
            [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$NetworkAdapter,

            [Parameter(Mandatory=$true,
                    Position=1,
                    ParameterSetName='Static')]
            [String[]]$IPAddress=@(),

            [Parameter(Mandatory=$false,
                    Position=2,
                    ParameterSetName='Static')]
            [String[]]$Subnet=@(),

            [Parameter(Mandatory=$false,
                    Position=3,
                    ParameterSetName='Static')]
            [String[]]$DefaultGateway = @(),

            [Parameter(Mandatory=$false,
                    Position=4,
                    ParameterSetName='Static')]
            [String[]]$DNSServer = @(),

            [Parameter(Mandatory=$false,
                    Position=0,
                    ParameterSetName='DHCP')]
            [Switch]$Dhcp
        )

        $VM = Get-CimInstance -Namespace "root\virtualization\v2" -ClassName "Msvm_ComputerSystem" | Where-Object ElementName -eq $NetworkAdapter.VMName
        $VMSettings = Get-CimAssociatedInstance -InputObject $vm -ResultClassName "Msvm_VirtualSystemSettingData" | Where-Object VirtualSystemType -EQ "Microsoft:Hyper-V:System:Realized"
        $VMNetAdapters = Get-CimAssociatedInstance -InputObject $VMSettings -ResultClassName "Msvm_SyntheticEthernetPortSettingData"

        $networkAdapterConfiguration = @()
        foreach ($netAdapter in $VMNetAdapters) {
            if ($netAdapter.ElementName -eq $NetworkAdapter.Name) {
                $networkAdapterConfiguration = Get-CimAssociatedInstance -InputObject $netAdapter -ResultClassName "Msvm_GuestNetworkAdapterConfiguration"
                break
            }
        }

        $networkAdapterConfiguration.PSBase.CimInstanceProperties["IPAddresses"].Value = $IPAddress
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["Subnets"].Value = $Subnet
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["DefaultGateways"].Value = $DefaultGateway
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["DNSServers"].Value = $DNSServer
        $networkAdapterConfiguration.PSBase.CimInstanceProperties["ProtocolIFType"].Value = 4096

        if ($dhcp) {
            $networkAdapterConfiguration.PSBase.CimInstanceProperties["DHCPEnabled"].Value = $true
        } else {
            $networkAdapterConfiguration.PSBase.CimInstanceProperties["DHCPEnabled"].Value = $false
        }

        $cimSerializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
        $serializedInstance = $cimSerializer.Serialize($networkAdapterConfiguration, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
        $serializedInstanceString = [System.Text.Encoding]::Unicode.GetString($serializedInstance)

        $service = Get-CimInstance -ClassName "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
        $setIp = Invoke-CimMethod -InputObject $service -MethodName "SetGuestNetworkAdapterConfiguration" -Arguments @{
            ComputerSystem = $VM
            NetworkConfiguration = @($serializedInstanceString)
        }
        if($setIp.ReturnValue -eq 0) { # completed
            WriteInfo "`t`t Success"
        } else {
            # unexpected response
            $setIp
        }
    }

    function WrapProcess{
        #Using this function you can run legacy program and search in output string
        #Example: WrapProcess -filename fltmc.exe -arguments "attach svhdxflt e:" -outputstring "Success"
        [CmdletBinding()]
        [Alias()]
        [OutputType([bool])]
        Param (
            # process name. For example fltmc.exe
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
            $filename,

            # arguments. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $arguments,

            # string to search. for example "attach svhdxflt e:"
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=1)]
            $outputstring
        )
        Process {
            $procinfo = New-Object System.Diagnostics.ProcessStartInfo
            $procinfo.FileName = $filename
            $procinfo.Arguments = $arguments
            $procinfo.UseShellExecute = $false
            $procinfo.CreateNoWindow = $true
            $procinfo.RedirectStandardOutput = $true
            $procinfo.RedirectStandardError = $true


            # Create a process object using the startup info
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $procinfo
            # Start the process
            $process.Start() | Out-Null

            # test if process is still running
            if(!$process.HasExited){
                do{
                   Start-Sleep 1
                }until ($process.HasExited -eq $true)
            }

            # get output
            $out = $process.StandardOutput.ReadToEnd()

            if ($out.Contains($outputstring)) {
                $output=$true
            } else {
                $output=$false
            }
            return, $output
        }
    }

    function New-LinuxVM {
        [cmdletbinding()]
        param(
            [PSObject]$VMConfig,
            [PSObject]$LabConfig,
            [string]$LabFolder
        )
        WriteInfoHighlighted "Creating VM $($VMConfig.VMName)"
        WriteInfo "`t Looking for Parent Disk"
        $serverparent = Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $VMConfig.ParentVHD

        if ($serverparent -eq $null) {
            WriteErrorAndExit "Server parent disk $($VMConfig.ParentVHD) not found."
        }else{
            WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
        }

        $VMname=$Labconfig.Prefix+$VMConfig.VMName
        if ($serverparent.Extension -eq ".vhdx"){
            $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhdx"
        }elseif($serverparent.Extension -eq ".vhd"){
            $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhd"
        }
        WriteInfo "`t Creating OS VHD"
        New-VHD -ParentPath $serverparent.fullname -Path $vhdpath

        $VMTemp = New-VM -Path "$LabFolder\VMs" -Name $VMname -Generation 2 -MemoryStartupBytes $VMConfig.MemoryStartupBytes -SwitchName $SwitchName  -VHDPath $vhdPath

        #Set dynamic memory
        if ($VMConfig.StaticMemory -eq $false){
            WriteInfo "`t Configuring DynamicMemory"
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
        } else {
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
        }

        $VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
        if ($VMTemp.AutomaticCheckpointsEnabled -eq $True){
            $VMTemp | Set-VM -AutomaticCheckpointsEnabled $False
        }
        $VMTemp | Set-VMFirmware -EnableSecureBoot Off

        # only Debian Buster supports Secure Boot
        #$vm | Set-VMFirmware -EnableSecureBoot On -SecureBootTemplateId "272e7447-90a4-4563-a4b9-8e4ab00526ce" # -SecureBootTemplate MicrosoftUEFICertificateAuthority

        Start-VM $VMTemp

        # wait for the IP address
        Write-Host "`t Waiting for network connectivity to the VM..." -NoNewLine
        $count = 0
        do {
            $ip = $VMTemp | Get-VMNetworkAdapter | Select-Object -ExpandProperty IPAddresses
            Start-Sleep -Seconds 1

            Write-Host -ForegroundColor Gray -NoNewline "."
            $count += 1
        } while (-not $ip -and $count -le 60)

        if(-not $ip) {
            WriteErrorAndExit "Unable to detect IP for a VM $vmName"
        } else {
            WriteInfo "OK"
        }

        $sshKeyPath = $LabConfig.SshKeyPath
        if(-not $sshKeyPath) {
            $sshKeyPath = "$LabFolder\.ssh\lab_rsa"
        }
        if(-not (Test-Path $sshKeyPath)) {
            WriteErrorAndExit "`t Cannot find SSH key $sshKeyPath."
        }

        if($LabConfig.LinuxAdminName) {
            $username = $LabConfig.LinuxAdminName
        } else {
            $username = $LabConfig.DomainAdminName
        }
        $username = $username.ToLower()

        # set the hostname
        WriteInfo "`t Configuring guest OS hostname..."
        hvc ssh -oLogLevel=ERROR -oStrictHostKeyChecking=no -i $sshKeyPath "$username@$vmName" "echo '$($LabConfig.AdminPassword)' | sudo -p '' -S sh -c 'sed -i `"s/```hostname```/$($VMConfig.VMName)/g`" /etc/hosts; hostnamectl set-hostname `"$($VMConfig.VMName)`" > /etc/hostname;'"

        $linuxCommandsToExecute = ""
        if(-not $VMConfig.LinuxDomainJoin -or $VMConfig.LinuxDomainJoin.ToLower() -eq "sssd") {
            WriteInfo "`t Creating AD Computer object..."
            Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $VMConfig.VMName,$path,$Labconfig -ScriptBlock {
                param($Name,$path,$Labconfig);

                New-ADComputer -Name $Name -Path "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"
                $password = ConvertTo-SecureString -String $Name -AsPlainText -Force
                Get-ADComputer -Identity $Name | Set-ADAccountPassword -NewPassword:$password -Reset:$true
            }

            WriteInfo "`t Joining to AD..."
            $upn = ("$(($LabConfig.DomainAdminName).ToLower())@$($LabConfig.DomainName)")
            $linuxCommandsToExecute = "realm join --one-time-password $($VMConfig.VMName) $($LabConfig.DomainName); mkdir -p /home/$($upn)/.ssh/; chown $upn /home/$upn/; cp /home/$username/.ssh/authorized_keys /home/$upn/.ssh/authorized_keys; sed -i -E `"`"s/use_fully_qualified_names = .+/use_fully_qualified_names = False/g`"`" /etc/sssd/sssd.conf;"
            hvc ssh -oLogLevel=ERROR -oStrictHostKeyChecking=no -i $sshKeyPath "$username@$vmName" "echo '$($LabConfig.AdminPassword)' | sudo -p '' -S sh -c '$linuxCommandsToExecute'"
        }

        WriteInfo "`t Shutting down VM..."
        hvc ssh -oLogLevel=ERROR -oStrictHostKeyChecking=no -i $sshKeyPath "$username@$vmName" "echo '$($LabConfig.AdminPassword)' | sudo -p '' -S sh -c 'poweroff'"

        # Wait for vm to shut down
        $count = 0
        do {
            $vm = $VMTemp | Get-VM
            Start-Sleep -Seconds 1
            $count += 1
        } while ($vm.State -ne "Off" -and $count -le 60)

        if($vm.State -ne "Off") {
            $VMTemp | Stop-VM
        }

        # return info
        [PSCustomObject]@{
            OSDiskPath = $vhdpath
            VM = $VMTemp
        }
    }

    Function BuildVM {
        [cmdletbinding()]
        param(
            [PSObject]$VMConfig,
            [PSObject]$LabConfig,
            [string]$LabFolder
        )
        WriteInfoHighlighted "Creating VM $($VMConfig.VMName)"
        WriteInfo "`t Looking for Parent Disk"
        $serverparent=Get-ChildItem "$PSScriptRoot\ParentDisks\" -Recurse | Where-Object Name -eq $VMConfig.ParentVHD

        if ($serverparent -eq $null){
            WriteErrorAndExit "Server parent disk $($VMConfig.ParentVHD) not found."
        }else{
            WriteInfo "`t`t Server parent disk $($serverparent.Name) found"
        }

        $VMname=$Labconfig.Prefix+$VMConfig.VMName
        if ($serverparent.Extension -eq ".vhdx"){
            $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhdx"
        }elseif($serverparent.Extension -eq ".vhd"){
            $vhdpath="$LabFolder\VMs\$VMname\Virtual Hard Disks\$VMname.vhd"
        }
        WriteInfoHighlighted "`t Creating OS VHD"
        New-VHD -ParentPath $serverparent.fullname -Path $vhdpath

        #Get VM Version
        [System.Version]$VMVersion=(Get-WindowsImage -ImagePath $VHDPath -Index 1).Version
        WriteInfo "`t VM Version is $($VMVersion.Build).$($VMVersion.Revision)"

        WriteInfo "`t Creating VM"
        if ($VMConfig.Generation -eq 1){
            $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$LabFolder\VMs" -SwitchName $SwitchName -Generation 1
        }else{
            $VMTemp=New-VM -Name $VMname -VHDPath $vhdpath -MemoryStartupBytes $VMConfig.MemoryStartupBytes -path "$LabFolder\VMs" -SwitchName $SwitchName -Generation 2
        }
        $VMTemp | Set-VMMemory -DynamicMemoryEnabled $true
        $VMTemp | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
        if ($VMTemp.AutomaticCheckpointsEnabled -eq $True){
            $VMTemp | Set-VM -AutomaticCheckpointsEnabled $False
        }

        $MGMTNICs=$VMConfig.MGMTNICs
        If($MGMTNICs -eq $null){
            $MGMTNICs = 2
        }

        If($MGMTNICs -gt 8){
            $MGMTNICs=8
        }

        If($MGMTNICs -ge 2){
            2..$MGMTNICs | ForEach-Object {
                WriteInfo "`t Adding Network Adapter Management$_"
                $VMTemp | Add-VMNetworkAdapter -Name "Management$_"
            }
        }
        WriteInfo "`t Connecting vNIC to $switchname"
        $VMTemp | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

        if ($LabConfig.Secureboot -eq $False) {
            WriteInfo "`t Disabling Secureboot"
            $VMTemp | Set-VMFirmware -EnableSecureBoot Off
        }

        if ($VMConfig.AdditionalNetworks -eq $True){
            WriteInfo "`t Configuring Additional networks"
            foreach ($AdditionalNetworkConfig in $Labconfig.AdditionalNetworksConfig){
                WriteInfo "`t`t Adding Adapter $($AdditionalNetworkConfig.NetName) with IP $($AdditionalNetworkConfig.NetAddress)$global:IP"
                $VMTemp | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $AdditionalNetworkConfig.NetName
                $VMTemp | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName  | Set-VMNetworkConfiguration -IPAddress "$($AdditionalNetworkConfig.NetAddress)$global:IP" -Subnet $AdditionalNetworkConfig.Subnet
                if($AdditionalNetworkConfig.NetVLAN -ne 0){ $VMTemp | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName | Set-VMNetworkAdapterVlan -VlanId $AdditionalNetworkConfig.NetVLAN -Access }
            }
            $global:IP++
        }

        if($VMConfig.AdditionalNetworkAdapters) {
            $networks = $VMConfig.AdditionalNetworkAdapters
            if($networks -isnot [array]) {
                $networks = @($networks)
            }

            foreach ($network in $networks) {
                $switch = Get-VMSwitch -Name $network.VirtualSwitchName -ErrorAction SilentlyContinue
                if(-not $switch) {
                    WriteErrorAndExit "Hyper-V switch $($network.VirtualSwitchName) not found."
                }

                $adapter = $vmtemp | Add-VMNetworkAdapter -SwitchName $network.VirtualSwitchName -Passthru

                if($network.Mac -and $network.Mac -match "^([0-9A-F][0-9A-F]-){5}[0-9A-F][0-9A-F]$") {
                    $adapter | Set-VMNetworkAdapter -StaticMacAddress $network.Mac
                }

                if($network.VlanId -and $network.VlanId -ne 0) {
                    $adapter | Set-VMNetworkAdapterVlan -VlanId $network.VlanId -Access
                }

                if($network.IpConfiguration -and $network.IpConfiguration -ne "DHCP" -and $network.IpConfiguration -is [Hashtable]) {
                    $adapter | Set-VMNetworkConfiguration -IPAddress $network.IpConfiguration.IpAddress -Subnet $network.IpConfiguration.Subnet
                }
            }
        }

        #Generate DSC Config
        if ($VMConfig.DSCMode -eq 'Pull'){
            WriteInfo "`t Setting DSC Mode to Pull"
            PullClientConfig -ComputerName $VMConfig.VMName -DSCConfig $VMConfig.DSCConfig -OutputPath "$PSScriptRoot\temp\dscconfig" -DomainName $LabConfig.DomainName
        }

        #configure nested virt
        if ($VMConfig.NestedVirt -eq $True){
            WriteInfo "`t Enabling NestedVirt"
            $VMTemp | Set-VMProcessor -ExposeVirtualizationExtensions $true
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $False
        }

        #configure vTPM
        if ($VMConfig.vTPM -eq $True){
            if ($VMConfig.Generation -eq 1){
                WriteError "`t vTPM requested. But vTPM is not compatible with Generation 1"
            }else{
                WriteInfo "`t Enabling vTPM"
                $keyprotector = New-HgsKeyProtector -Owner $guardian -AllowUntrustedRoot
                Set-VMKeyProtector -VM $VMTemp -KeyProtector $keyprotector.RawData
                Enable-VMTPM -VM $VMTemp
            }
        }

        #set MemoryMinimumBytes
        if ($VMConfig.MemoryMinimumBytes -ne $null){
            WriteInfo "`t Configuring MemoryMinimumBytes to $($VMConfig.MemoryMinimumBytes/1MB)MB"
            if ($VMConfig.NestedVirt){
                "`t`t Skipping! NestedVirt configured"
            }else{
                Set-VM -VM $VMTemp -MemoryMinimumBytes $VMConfig.MemoryMinimumBytes
            }
        }

        #Set static Memory
        if ($VMConfig.StaticMemory -eq $true){
            WriteInfo "`t Configuring StaticMemory"
            $VMTemp | Set-VMMemory -DynamicMemoryEnabled $false
        }

        #configure number of processors
        if ($VMConfig.VMProcessorCount){
            if ($VMConfig.VMProcessorCount -eq "Max"){
                if ($NumberOfLogicalProcessors -gt 64){
                    WriteInfo "`t Processors Count $NumberOfLogicalProcessors and Max is specified. Configuring VM Processor Count to 64"
                    $VMTemp | Set-VMProcessor -Count 64
                }else{
                    WriteInfo "`t Configuring VM Processor Count to Max ($NumberOfLogicalProcessors)"
                    $VMTemp | Set-VMProcessor -Count $NumberOfLogicalProcessors
                }
            }elseif ($VMConfig.VMProcessorCount -le $NumberOfLogicalProcessors){
                WriteInfo "`t Configuring VM Processor Count to $($VMConfig.VMProcessorCount)"
                $VMTemp | Set-VMProcessor -Count $VMConfig.VMProcessorCount
            }else{
                WriteError "`t`t Number of processors specified in VMProcessorCount is greater than Logical Processors available in Host!"
                WriteInfo  "`t`t Number of logical Processors in Host $NumberOfLogicalProcessors"
                WriteInfo  "`t`t Number of Processors provided in labconfig $($VMConfig.VMProcessorCount)"
                WriteInfo  "`t`t Will configure maximum processors possible instead ($NumberOfLogicalProcessors)"
                $VMTemp | Set-VMProcessor -Count $NumberOfLogicalProcessors
            }
        }else{
            $VMTemp | Set-VMProcessor -Count 2
        }

        #Disable Time Integration Components
        If ($VMConfig.DisableTimeIC){
            WriteInfo  "`t`t Disabling Time Synchronization Integration Service"
            $VMTemp | Disable-VMIntegrationService -Name "Time Synchronization"
        }

        $Name=$VMConfig.VMName
        #add run synchronous commands
        WriteInfo "`t Adding Sync Commands"
        $RunSynchronous=""
        if ($VMConfig.EnableWinRM){
            $RunSynchronous+=@'
            <RunSynchronousCommand wcm:action="add">
                <Path>cmd.exe /c winrm quickconfig -q -force</Path>
                <Description>enable winrm</Description>
                <Order>1</Order>
            </RunSynchronousCommand>

'@
            WriteInfo "`t`t WinRM will be enabled"
        }

        if ($VMConfig.DisableWCF){
            $RunSynchronous+=@'
            <RunSynchronousCommand wcm:action="add">
                <Path>reg add HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f</Path>
                <Description>disable consumer features</Description>
                <Order>2</Order>
            </RunSynchronousCommand>

'@
            WriteInfo "`t`t WCF will be disabled"
        }
        if ($VMConfig.CustomPowerShellCommands){
            $Order=3
            foreach ($CustomPowerShellCommand in $VMConfig.CustomPowerShellCommands){
                $RunSynchronous+=@"
                <RunSynchronousCommand wcm:action="add">
                    <Path>powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "$CustomPowerShellCommand"</Path>
                    <Description>run custom powershell</Description>
                    <Order>$Order</Order>
                </RunSynchronousCommand>

"@
                $Order++
            }
            WriteInfo "`t`t Custom PowerShell command will be added"
        }

        if (-not $RunSynchronous){
            WriteInfo "`t`t No sync commands requested"
        }

        if ($VMVersion.Build -ge 17763){
            $oeminformation=@"
            <OEMInformation>
             <SupportProvider>MSLab</SupportProvider>
             <SupportURL>https://aka.ms/mslab</SupportURL>
           </OEMInformation>
"@
        }else{
            $oeminformation=$null
        }
        #configure native VLAN and AllowedVLANs
            $AllowedVLANs=$($LabConfig.AllowedVLANs)
            WriteInfo "`t`t Subnet ID is 0 with NativeVLAN 0. AllowedVlanIDList is $($LabConfig.AllowedVLANs)"
            $VMTemp | Set-VMNetworkAdapterVlan -VMNetworkAdapterName "Management*" -Trunk -NativeVlanId 0 -AllowedVlanIdList "$AllowedVLANs"

        #Create Unattend file
        if ($VMConfig.Unattend -eq "NoDjoin" -or $VMConfig.SkipDjoin){
            WriteInfo "`t Skipping Djoin"
            if ($VMConfig.AdditionalLocalAdmin){
                WriteInfo "`t Additional Local Admin $($VMConfig.AdditionalLocalAdmin) will be added"
                $AdditionalLocalAccountXML=AdditionalLocalAccountXML -AdditionalAdminName $VMConfig.AdditionalLocalAdmin -AdminPassword $LabConfig.AdminPassword
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -AdditionalAccount $AdditionalLocalAccountXML -TimeZone $TimeZone
            }else{
                $unattendfile=CreateUnattendFileNoDjoin -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
            }
        }elseif($VMConfig.Win2012Djoin -or $VMConfig.Unattend -eq "DjoinCred"){
            WriteInfoHighlighted "`t Creating Unattend with win2012-ish domain join"
            $unattendfile=CreateUnattendFileWin2012 -ComputerName $Name -AdminPassword $LabConfig.AdminPassword -DomainName $Labconfig.DomainName -RunSynchronous $RunSynchronous -TimeZone $TimeZone

        }elseif($VMConfig.Unattend -eq "DjoinBlob" -or -not ($VMConfig.Unattend)){
            WriteInfoHighlighted "`t Creating Unattend with djoin blob"
            $path="c:\$vmname.txt"
            Invoke-Command -VMGuid $DC.id -Credential $cred  -ScriptBlock {param($Name,$path,$Labconfig); djoin.exe /provision /domain $labconfig.DomainNetbiosName /machine $Name /savefile $path /machineou "OU=$($Labconfig.DefaultOUName),$($Labconfig.DN)"} -ArgumentList $Name,$path,$Labconfig
            $blob=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); get-content $path} -ArgumentList $path
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {param($path); Remove-Item $path} -ArgumentList $path
            $unattendfile=CreateUnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword $LabConfig.AdminPassword -RunSynchronous $RunSynchronous -TimeZone $TimeZone
        }elseif($VMConfig.Unattend -eq "None"){
            $unattendFile=$Null
        }

        #adding unattend to VHD
        if ($unattendFile){
            WriteInfo "`t Adding unattend to VHD"
            Mount-WindowsImage -Path $mountdir -ImagePath $VHDPath -Index 1
            Use-WindowsUnattend -Path $mountdir -UnattendPath $unattendFile
            #&"$PSScriptRoot\Tools\dism\dism" /mount-image /imagefile:$vhdpath /index:1 /MountDir:$mountdir
            #&"$PSScriptRoot\Tools\dism\dism" /image:$mountdir /Apply-Unattend:$unattendfile
            New-item -type directory "$mountdir\Windows\Panther" -ErrorAction Ignore
            Copy-Item $unattendfile "$mountdir\Windows\Panther\unattend.xml"
        }

        if ($VMConfig.DSCMode -eq 'Pull'){
            WriteInfo "`t Adding metaconfig.mof to VHD"
            Copy-Item "$PSScriptRoot\temp\dscconfig\$name.meta.mof" -Destination "$mountdir\Windows\system32\Configuration\metaconfig.mof"
        }

        if ($unattendFile){
            Dismount-WindowsImage -Path $mountdir -Save
            #&"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$mountdir /Commit
        }

        #add toolsdisk
        if ($VMConfig.AddToolsVHD -eq $True){
            $VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\tools.vhdx"
            WriteInfoHighlighted "`t Adding Virtual Hard Disk $($VHD.Path)"
            $VMTemp | Add-VMHardDiskDrive -Path $vhd.Path
        }

        # return info
        [PSCustomObject]@{
            OSDiskPath = $vhdpath
            VM = $VMTemp
        }
    }
#endregion

#region Initialization

    Start-Transcript -Path "$PSScriptRoot\Deploy.log"

    $StartDateTime = Get-Date
    WriteInfoHighlighted "Script started at $StartDateTime"
    WriteInfo "`nMSLab Version $mslabVersion"


    ##Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

    # Telemetry
        if(-not (Get-TelemetryLevel)) {
            $telemetryLevel = Read-TelemetryLevel
            $LabConfig.TelemetryLevel = $telemetryLevel
            $LabConfig.TelemetryLevelSource = "Prompt"
            $promptShown = $true
        }

        if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
            if(-not $promptShown) {
                WriteInfo "Telemetry is set to $(Get-TelemetryLevel) level from $(Get-TelemetryLevelSource)"
            }
            Send-TelemetryEvent -Event "Deploy.Start" -NickName $LabConfig.TelemetryNickName | Out-Null
        }
#endregion

#region Set variables

    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

    If (!$LabConfig.DefaultOUName){
        $LabConfig.DefaultOUName="Workshop"
    }

    if (!$Labconfig.AllowedVLANs){
        $Labconfig.AllowedVLANs="1-10"
    }

    $DN=$null
    $LabConfig.DomainName.Split(".") | ForEach-Object {
        $DN+="DC=$_,"
    }
    $LabConfig.DN=$DN.TrimEnd(",")

    $global:IP=1

    if (!$LabConfig.Prefix){
        $labconfig.prefix="$($PSScriptRoot | Split-Path -Leaf)-"
    }

    if (!$LabConfig.SwitchName){
        $LabConfig.SwitchName = 'LabSwitch'
    }

    WriteInfoHighlighted "List of variables used"
    WriteInfo "`t Prefix used in lab is $($labconfig.prefix)"

    $SwitchName=($labconfig.prefix+$LabConfig.SwitchName)
    WriteInfo "`t Switchname is $SwitchName"

    WriteInfo "`t Workdir is $PSScriptRoot"

    $LABfolder="$PSScriptRoot\LAB"
    WriteInfo "`t LabFolder is $LabFolder"

    $LABfolderDrivePath=$LABfolder.Substring(0,3)

    $ExternalSwitchName="$($Labconfig.Prefix)$($LabConfig.Switchname)-External"

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

    #Grab number of processors
    Get-CimInstance -ClassName "win32_processor" | ForEach-Object { $global:NumberOfLogicalProcessors += $_.NumberOfLogicalProcessors }

    #Calculate highest VLAN (for additional subnets)
    [int]$HighestVLAN=$LabConfig.AllowedVLANs -split "," -split "-" | Select-Object -Last 1

#endregion

#region Some Additional checks and prereqs configuration

    # Checking if not running in root folder
    if (($PSScriptRoot).Length -eq 3) {
        WriteErrorAndExit "`t MSLab canot run in root folder. Please put MSLab scripts into a folder. Exiting"
    }

    # Checking for Compatible OS
        WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"
        $BuildNumber=Get-WindowsBuildNumber
        if ($BuildNumber -ge 10586){
            WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
        }else{
            WriteErrorAndExit "`t Windows 10/ Server 2016 not detected. Exiting"
        }

    # Checking for NestedVirt
        if ($LABConfig.VMs.NestedVirt -contains $True){
            $BuildNumber=Get-WindowsBuildNumber
            if ($BuildNumber -ge 14393){
                WriteSuccess "`t Windows is build greater than 14393. NestedVirt will work"
            }else{
                WriteErrorAndExit "`t Windows build older than 14393 detected. NestedVirt will not work. Exiting"
            }
        }

    # Checking for vTPM support
        if ($LABConfig.VMs.vTPM -contains $true){
            $BuildNumber=Get-WindowsBuildNumber
            if ($BuildNumber -ge 14393){
                WriteSuccess "`t Windows is build greater than 14393. vTPM will work"
            }else{
                WriteErrorAndExit "`t Windows build older than 14393 detected. vTPM will not work Exiting"
            }
            <# Not needed anymore as VBS is automatically enabled since 14393 when vTPM is used
            if (((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus -ne 0) -and ((Get-Process "secure system") -ne $null )){
                WriteSuccess "`t Virtualization Based Security is running. vTPM can be enabled"
            }else{
                WriteErrorAndExit "`t Virtualization based security is not running. Enable VBS, or remove vTPM from configuration"
            }
            #>
            #load Guardian
            $guardian=Get-HgsGuardian | Select-Object -first 1
            if($guardian -eq $null){
                $guardian=New-HgsGuardian -Name LabGuardian -GenerateCertificates
                WriteInfo "`t HGS with name LabGuardian created"
            }
        }

    #Check support for shared disks + enable if possible
        if ($LABConfig.VMs.Configuration -contains "Shared" -or $LABConfig.VMs.Configuration -contains "Replica"){
            WriteInfoHighlighted "Configuration contains Shared or Replica scenario"

            WriteInfo "Checking support for shared disks"
            $OS = Get-CimInstance -ClassName "win32_operatingsystem"
            if (($OS.caption -like "*Server*") -and $OS.version -gt 10){
                WriteInfo "`t Installing Failover Clustering Feature"
                $FC=Install-WindowsFeature Failover-Clustering
                If ($FC.Success -eq $True){
                    WriteSuccess "`t`t Failover Clustering Feature installed with exit code: $($FC.ExitCode)"
                }else{
                    WriteError "`t`t Failover Clustering Feature was not installed with exit code: $($FC.ExitCode)"
                }
            }

            WriteInfoHighlighted "`t Attaching svhdxflt filter driver to drive $LABfolderDrivePath"
            if (WrapProcess -filename fltmc.exe -arguments "attach svhdxflt $LABfolderDrivePath" -outputstring "successful"){
                WriteSuccess "`t Svhdx filter driver was successfully attached"
            }else{
                if (WrapProcess -filename fltmc.exe -arguments "attach svhdxflt $LABfolderDrivePath" -outputstring "0x801f0012"){
                    WriteSuccess "`t Svhdx filter driver was already attached"
                }else{
                    WriteErrorAndExit "`t unable to load svhdx filter driver. Exiting Please use Server SKU or figure out how to install svhdx into the client SKU"
                }
            }

            WriteInfoHighlighted "Adding svhdxflt to registry for autostart"
            if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters)){
                New-Item HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters
            }
            New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\svhdxflt\Parameters -Name AutoAttachOnNonCSVVolumes -PropertyType DWORD -Value 1 -force
        }

    #Check if Hyper-V is installed
        WriteInfoHighlighted "Checking if Hyper-V is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V not installed. Please install hyper-v feature including Hyper-V management tools. Exiting"
        }

        WriteInfoHighlighted "Checking if Hyper-V Powershell module is installed"
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -eq "Enabled"){
            WriteSuccess "`t Hyper-V is Installed"
        }else{
            WriteErrorAndExit "`t Hyper-V tools are not installed. Please install Hyper-V management tools. Exiting"
        }

    #Check if at least 2GB (+200Mb just to be sure) memory is available
        WriteInfoHighlighted "Checking if at least 2GB RAM is available"
        $MemoryAvailableMB=(Get-Ciminstance Win32_OperatingSystem).FreePhysicalMemory/1KB
        if ($MemoryAvailableMB -gt (2048+200)){
            WriteSuccess "`t $("{0:n0}" -f $MemoryAvailableMB) MB RAM Available"
        }else{
            WriteErrorAndExit "`t Please make sure you have at least 2 GB available memory. Exiting"
        }

    #check if filesystem on volume is NTFS or ReFS
    WriteInfoHighlighted "Checking if volume filesystem is NTFS or ReFS"
    $driveletter=$PSScriptRoot -split ":" | Select-Object -First 1
    if ($PSScriptRoot -like "c:\ClusterStorage*"){
        WriteSuccess "`t Volume Cluster Shared Volume. Mountdir will be $env:Temp\MSLabMountdir"
        $mountdir="$env:Temp\MSLabMountDir"
        $VolumeFileSystem="CSVFS"
    }else{
        $mountdir="$PSScriptRoot\Temp\MountDir"
        $VolumeFileSystem=(Get-Volume -DriveLetter $driveletter).FileSystemType
        if ($VolumeFileSystem -match "NTFS"){
            WriteSuccess "`t Volume filesystem is $VolumeFileSystem"
        }elseif ($VolumeFileSystem -match "ReFS") {
            WriteSuccess "`t Volume filesystem is $VolumeFileSystem"
        }else {
            WriteErrorAndExit "`t Volume filesystem is $VolumeFileSystem. Must be NTFS or ReFS. Exiting"
        }
    }

    #enable EnableEnhancedSessionMode if not enabled
    if (-not (Get-VMHost).EnableEnhancedSessionMode){
        WriteInfoHighlighted "Enhanced session mode was disabled. Enabling."
        Set-VMHost -EnableEnhancedSessionMode $true
    }

    #Create Switches
        WriteInfoHighlighted "Creating Switch"
        WriteInfo "`t Checking if $SwitchName already exists..."

        if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction Ignore)){
            WriteInfo "`t Creating $SwitchName..."
            if ($LabConfig.SwitchNICs){
                #test if NICs are not already connected to another switch
                $VMSComponentStatus=Get-NetAdapterBinding -Name $LabConfig.SwitchNICs -ComponentID vms_pp
                if (($VMSComponentStatus).Enabled -contains $true){
                    $BoundNICs=$VMSComponentStatus | Where-Object Enabled -eq $true
                    $InterfaceGUIDs=(Get-NetAdapter -Name $BoundNICs.Name).InterfaceGUID
                    $vSwitches=ForEach ($InterfaceGUID in $InterfaceGUIDs){Get-VMSwitch | Where-Object NetAdapterInterfaceGuid -Contains $InterfaceGuid}
                    WriteError "Following NICs are already bound to a Virtual Switch:"
                    $BoundNICs
                    WriteError "Virtual Switch list:"
                    $vSwitches | Select-Object Name,NetAdapterInterfaceDescriptions
                    WriteErrorAndExit "At least one NIC is connected to existing Virtual Switch, different than specified in Labconfig ($SwitchName)"
                }else{
                    New-VMSwitch -Name $SwitchName -EnableEmbeddedTeaming $true -EnableIov $true -NetAdapterName $LabConfig.SwitchNics -AllowManagementOS $False
                }
            }else{
                New-VMSwitch -SwitchType Private -Name $SwitchName
            }
        }else{
            $SwitchNameExists=$True
            WriteInfo "`t $SwitchName exists. Looks like lab with same prefix exists. "
        }

    #connect lab to internet if specified in labconfig
        if ($Labconfig.Internet){
            WriteInfoHighlighted "Internet connectivity requested"

            if (!$LabConfig.CustomDnsForwarders){
                $LabConfig.CustomDnsForwarders=@("8.8.8.8","1.1.1.1") # Google DNS, Cloudfare
            }

            WriteInfo "`t Detecting default vSwitch"
            #$DefaultSwitch=Get-VMSwitch -ID c08cb7b8-9b3c-408e-8e30-5e16a3aeb444 -ErrorAction Ignore
            $DefaultSwitch=Get-VMSwitch -Name "Default Switch" -ErrorAction Ignore
            if ($DefaultSwitch){WriteInfo "`t Default switch detected"}

            #if running in Azure and default switch is not present, create InternalNAT Switch
            If ((Get-CimInstance win32_systemenclosure).SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3286-77" -and !$DefaultSwitch){
                #https://docs.microsoft.com/en-us/azure/virtual-machines/windows/nested-virtualization#set-up-internet-connectivity-for-the-guest-virtual-machine
                WriteInfoHighlighted "`t Lab is running in Azure and default switch not detected"
                if (Get-VMSwitch -name "InternalNat" -ErrorAction Ignore){
                    WriteInfo "`t vSwitch InternalNat detected, skipping creation"
                    $DefaultSwitch=Get-VMSwitch -Name "InternalNAT"
                }else{
                    WriteInfo "`t Creating vSwitch `"InternalNat`""
                    $DefaultSwitch=New-VMSwitch -Name "InternalNAT" -SwitchType Internal
                    WriteInfo "`t Assigning IP address 192.168.0.1 to interface `"vEthernet (InternalNAT)`""
                    New-NetIPAddress -IPAddress 192.168.0.1 -PrefixLength 24 -InterfaceAlias "vEthernet (InternalNAT)"
                    WriteInfo "`t Assigning IP address 192.168.0.1 to interface `"vEthernet (InternalNAT)`""
                    New-NetNat -Name "InternalNat" -InternalIPInterfaceAddressPrefix 192.168.0.0/24
                }
            }

            if (-not $DefaultSwitch){
                WriteInfo "`t Default switch not present, detecting external vSwitch $ExternalSwitchName"
                $ExternalSwitch=Get-VMSwitch -SwitchType External -Name $ExternalSwitchName -ErrorAction Ignore
                if ($ExternalSwitch){
                    WriteSuccess "`t External vSwitch  $ExternalSwitchName detected"
                }else{
                    WriteInfo "`t Detecting external VMSwitch"
                    $ExtSwitch=Get-VMSwitch -SwitchType External | Where-Object Name -NotLike $SwitchName
                    if (!$ExtSwitch){
                        WriteInfoHighlighted "`t No External Switch detected. Will create one "
                        $TempNetAdapters=get-netadapter | Where-Object Name -NotLike vEthernet* | Where-Object status -eq up
                        if (!$TempNetAdapters){
                            WriteErrorAndExit "No Adapters with Status -eq UP detected. Exitting"
                        }
                        if ($TempNetAdapters.name.count -eq 1){
                            WriteInfo "`t Just one connected NIC detected ($($TempNetAdapters.name)). Will create vSwitch connected to it"
                            $ExternalSwitch=New-VMSwitch -NetAdapterName $TempNetAdapters.name -Name $ExternalSwitchName -AllowManagementOS $true
                        }
                        if ($TempNetAdapters.name.count -gt 1){
                            WriteInfo "`t More than 1 NIC detected"
                            WriteInfoHighlighted "`t Please select NetAdapter you want to use for vSwitch"
                            $tempNetAdapter=get-netadapter | Where-Object Name -NotLike vEthernet* | Where-Object status -eq up | Out-GridView -OutputMode Single -Title "Please select adapter you want to use for External vSwitch"
                            if (!$tempNetAdapter){
                                WriteErrorAndExit "You did not select any net adapter. Exitting."
                            }
                            $ExternalSwitch=New-VMSwitch -NetAdapterName $tempNetAdapter.name -Name $ExternalSwitchName -AllowManagementOS $true
                        }
                    }
                    if ($ExtSwitch.count -eq 1){
                        WriteSuccess "`t External vswitch $($ExtSwitch.name) found. Will be used for connecting lab to internet"
                        $ExternalSwitch=$ExtSwitch
                    }
                    if ($ExtSwitch.count -gt 1){
                        WriteInfoHighlighted "`t More than 1 External Switch found. Please chose what switch you want to use for internet connectivity"
                        $ExternalSwitch=Get-VMSwitch -SwitchType External | Out-GridView -OutputMode Single -Title 'Please Select External Switch you want to use for Internet Connectivity'
                    }
                }
            }
        }

    #Testing if lab already exists.
        WriteInfoHighlighted "Checking if lab already exists."
        $LABExists=$false
        if ($SwitchNameExists){
            if ((Get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue) -ne $null){
                $LABExists=$true
                WriteInfo "`t Lab already exists. If labconfig contains additional VMs, they will be added."
            }else{
                WriteInfo "`t Lab does not exist, will be created"
            }
        }

    #If lab exists, correct starting IP will be calculated
        if (($LABExists) -and ($labconfig.AdditionalNetworksInDC)) {
            $global:IP++
        }

        $Labconfig.VMs | ForEach-Object {
            if (((Get-VM -Name ($labconfig.prefix+$_.vmname) -ErrorAction SilentlyContinue) -ne $null) -and ($_.AdditionalNetworks -eq $True)){
                $global:IP++
            }
        }

        WriteInfo "`t Starting IP for AdditionalNetworks is $global:IP"

    #Create Mount nd VMs directories
        WriteInfoHighlighted "Creating Mountdir"
        New-Item $mountdir -ItemType Directory -Force

        WriteInfoHighlighted "Creating VMs dir"
        New-Item "$PSScriptRoot\LAB\VMs" -ItemType Directory -Force

    #get path for Tools disk
        WriteInfoHighlighted "Looking for Tools Parent Disks"
        $toolsparent=Get-ChildItem "$PSScriptRoot\ParentDisks" -Recurse | Where-Object name -eq tools.vhdx
        if ($toolsparent -eq $null){
            WriteInfo "`t Tools parent disk not found. Will create one."
            WriteInfoHighlighted "Creating Tools.vhdx"
            $toolsVHD=New-VHD -Path "$PSScriptRoot\ParentDisks\tools.vhdx" -SizeBytes 30GB -Dynamic
            #mount and format VHD
                $VHDMount = Mount-VHD $toolsVHD.Path -Passthru
                $vhddisk = $VHDMount| get-disk
                $vhddisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |Format-Volume -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel ToolsDisk
            #dismount VHD
                Dismount-VHD $vhddisk.Number
        }else{
            WriteInfo "`t Tools parent disk $($toolsparent.fullname) found"
        }

#endregion

#region Import DC (if not already present) or just grab it and start
    WriteInfoHighlighted "Configuring DC"
    $dcCandidate = (get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue)
    if($dcCandidate -and !$dcCandidate.ConfigurationLocation.StartsWith($LabFolder)) {
        WriteErrorAndExit "DC with name $($labconfig.prefix+"DC") already exists on this system in the different lab folder [$($dcCandidate.ConfigurationLocation)]..."
    }

    if (!(get-vm -Name ($labconfig.prefix+"DC") -ErrorAction SilentlyContinue)){
        #import DC
            WriteInfo "`t Looking for DC to be imported"
            $dcCandidates = [array](Get-ChildItem $LABFolder -Recurse | Where-Object {($_.extension -eq '.vmcx' -and $_.directory -like '*Virtual Machines*') -or ($_.extension -eq '.xml' -and $_.directory -like '*Virtual Machines*')})
            $dcCandidates | ForEach-Object -Process {
                # If the VM ID is already used create a copy of the DC VM configuration instead of in-place registration
                $vm = Get-VM -Id $_.BaseName -ErrorAction SilentlyContinue
                if($vm -and $dcCandidates.Length -eq 1) { # allow duplicating of the DC VM only if it is the only one VM in lab folder (as if more than one exists, probably just labprefix was changed after the deployment)
                    WriteInfoHighlighted "You are trying to deploy a previously deployed lab from a different location as there is another DC VM with a same VM ID (is this a copied lab folder?) -> this DC VM will be registered with new VM ID."
                    $directory = $_.Directory.FullName.replace("\Virtual Machines", "")
                    $DC = Import-VM -Path $_.FullName -GenerateNewId -Copy -VirtualMachinePath $directory -VhdDestinationPath "$directory\Virtual Hard Disks"
                    WriteInfo "`t`t Virtual Machine $($DC.Name) registered with a new VM ID $($DC.Id)"
                } else {
                    $DC = Import-VM -Path $_.FullName
                }
            }
            if ($DC -eq $null){
                    WriteErrorAndExit "DC was not imported successfully Press any key to continue ..."
            }else{
                WriteInfo "`t`t Virtual Machine $($DC.name) located in folder $($DC.Path) imported"
            }

        #create checkpoint to be able to return to consistent state when cleaned with cleanup.ps1
            $DC | Checkpoint-VM -SnapshotName Initial
            WriteInfo "`t Virtual Machine $($DC.name) checkpoint created"
            Start-Sleep -Seconds 5

        #rename network adapters and add another
            WriteInfo "`t Configuring Network"

            $DC | Get-VMNetworkAdapter | Rename-VMNetworkAdapter -NewName Management1
            If($labconfig.MGMTNICsInDC -gt 8){
                $labconfig.MGMTNICsInDC=8
            }

            If($labconfig.MGMTNICsInDC -ge 2){
                2..$labconfig.MGMTNICsInDC | ForEach-Object {
                    WriteInfo "`t Adding Network Adapter Management$_"
                    $DC | Add-VMNetworkAdapter -Name Management$_
                }
            }

            $DC | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $SwitchName

        #add aditional networks
            if ($labconfig.AdditionalNetworksInDC -eq $True){
                WriteInfo "`t Configuring Additional networks"
                foreach ($AdditionalNetworkConfig in $Labconfig.AdditionalNetworksConfig){
                    $DC | Add-VMNetworkAdapter -SwitchName $SwitchName -Name $AdditionalNetworkConfig.NetName
                    WriteInfo "`t`t Adding Adapter $($AdditionalNetworkConfig.NetName) with IP $($AdditionalNetworkConfig.NetAddress)$global:IP"
                    $DC | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName | Set-VMNetworkConfiguration -IPAddress "$($AdditionalNetworkConfig.NetAddress)$global:IP" -Subnet $AdditionalNetworkConfig.Subnet
                    if($AdditionalNetworkConfig.NetVLAN -ne 0){
                        $DC | Get-VMNetworkAdapter -Name $AdditionalNetworkConfig.NetName  | Set-VMNetworkAdapterVlan -VlanId $AdditionalNetworkConfig.NetVLAN -Access
                    }
                }
                $global:IP++
            }

        #Enable VMNics device naming
            WriteInfo "`t Enabling DC VMNics device naming"
            $DC | Set-VMNetworkAdapter -DeviceNaming On

        #add tools disk
            WriteInfo "`t Adding Tools disk to DC machine"
            $VHD=New-VHD -ParentPath "$($toolsparent.fullname)" -Path "$LABFolder\VMs\ToolsDiskDC.vhdx"
            WriteInfo "`t`t Adding Virtual Hard Disk $($VHD.Path)"
            $DC | Add-VMHardDiskDrive -Path $vhd.Path

        #modify number of CPUs
            if ($Labconfig.DCVMProcessorCount){
                WriteInfo "`t Configuring VM Processor Count for DC VM to $($labconfig.DCVMProcessorCount)"
                If ($labconfig.DCVMProcessorCount -le $NumberOfLogicalProcessors){
                    $DC | Set-VMProcessor -Count $Labconfig.DCVMProcessorCount
                }else{
                    WriteError "`t`t Number of processors specified in DCVMProcessorCount is greater than Logical Processors available in Host!"
                    WriteInfo  "`t`t Number of logical Processors in Host $NumberOfLogicalProcessors"
                    WriteInfo  "`t`t Number of Processors provided in labconfig $($labconfig.DCVMProcessorCount)"
                    WriteInfo  "`t`t Will configure maximum processors possible instead ($NumberOfLogicalProcessors)"
                    $DC | Set-VMProcessor -Count $NumberOfLogicalProcessors
                }
            }

        #start DC
            WriteInfo  "`t Starting Virtual Machine $($DC.name)"
            $DC | Start-VM

        #rename DC VM
            WriteInfo "`t Renaming $($DC.name) to $($labconfig.Prefix+$DC.name)"
            $DC | Rename-VM -NewName ($labconfig.Prefix+$DC.name)
    }else{
        #if DC was present, just grab it
            $DC=get-vm -Name ($labconfig.prefix+"DC")
    }

    #add VLANs to DC
            WriteInfo "`t Configuring VLANs on DC"
            $AllowedVLANs=$($LabConfig.AllowedVLANs)
            WriteInfo "`t`t Subnet ID is 0 with NativeVLAN 0. AllowedVlanIDList is $($LabConfig.AllowedVLANs)"
            $DC | Set-VMNetworkAdapterVlan -VMNetworkAdapterName "Management*" -Trunk -NativeVlanId 0 -AllowedVlanIdList "$AllowedVLANs"

    #Start DC if it is not running
    if ($DC.State -ne "Running"){
        WriteInfo "DC was not started. Starting now..."
        $DC | Start-VM
    }

    #connect to internet
    if ($labconfig.internet){
        if (-not ($DC | Get-VMNetworkAdapter -Name Internet -ErrorAction SilentlyContinue)){
            WriteInfo "`t Adding Network Adapter Internet"
            $DC | Add-VMNetworkAdapter -Name Internet -DeviceNaming On

            if ($DefaultSwitch){
                $internetSwitch = $DefaultSwitch
            }else{
                $internetSwitch = $ExternalSwitch
            }
            WriteInfo "`t Connecting Network Adapter Internet to $($internetSwitch.Name)"
            $DC | Get-VMNetworkAdapter -Name Internet | Connect-VMNetworkAdapter -VMSwitch $internetSwitch
        }
    }

    #connect add VLAN to internet adapter if requested
        if ($Labconfig.Internet -and $LabConfig.InternetVLAN){
            WriteInfo "`t Configuring Internet VLAN for DC"
            $DC | Get-VMNetworkAdapter -Name Internet | Set-VMNetworkAdapterVlan -Access -VlanId $LabConfig.InternetVLAN
        }

#endregion

#region Test DC to come up

    #Credentials for Session
        $username = "$($Labconfig.DomainNetbiosName)\Administrator"
        $password = $LabConfig.AdminPassword
        $secstr = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

    #wait for DC to start
        WriteInfoHighlighted "`t Waiting for Active Directory on $($DC.name) to be Started."
        do{
            $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction Ignore -ScriptBlock {
                param($labconfig);
                Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction Ignore
            }
            Start-Sleep 5
        }until ($test -ne $Null)
        WriteSuccess "`t Active Directory on $($DC.name) is up."

    #if DC was just created, configure additional settings with PowerShell direct
         if (!$LABExists){
            WriteInfoHighlighted "`t Performing some actions against DC with powershell Direct"
            #Configure IP address on Internet NIC for Windows Server on Azure
            if ($DefaultSwitch.Name -eq "InternalNAT"){
                $startIP=(Get-VMNetworkAdapter -ManagementOS -SwitchName "InternalNat").Count+1
                $IP="192.168.0.$startIP"
                WriteInfo "`t Configure static IP $IP on Internet NIC"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    $NetAdapterName=(Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq Internet).Name
                    New-NetIPAddress -InterfaceAlias $NetAdapterName -IPAddress $using:IP -PrefixLength 24 -DefaultGateway "192.168.0.1"
                }
            }
            #make tools disk online
                WriteInfo "`t Making tools disk online"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | Where-Object operationalstatus -eq offline | Set-Disk -IsReadOnly $false}
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {get-disk | Where-Object operationalstatus -eq offline | Set-Disk -IsOffline $false}

            #authorize DHCP (if more networks added, then re-authorization is needed. Also if you add multiple networks once, it messes somehow even with parent VM for DC)
                WriteInfo "`t Authorizing DHCP"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ScriptBlock {
                    param($labconfig);
                    Get-DhcpServerInDC | Remove-DHCPServerInDC
                    Add-DhcpServerInDC -DnsName "DC.$($Labconfig.DomainName)" -IPAddress 10.0.0.1
                }
        }

    #configure NAT on DC
        If ($labconfig.internet){
            $cmd=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {Get-WindowsFeature -Name Routing}
            if ($cmd.installed -eq $False){
                WriteInfoHighlighted "`t Configuring NAT on DC"
                WriteInfo "`t Installing Routing and RSAT-RemoteAccess features"
                $cmd=Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Install-WindowsFeature -Name Routing,RSAT-RemoteAccess -IncludeAllSubFeature -WarningAction Ignore
                }
                if ($cmd.restartneeded -eq "Yes"){
                    WriteInfo "`t Restart of DC is requested"
                    WriteInfo "`t Restarting DC"
                    $DC | Restart-VM -Force
                    Start-Sleep 10
                    WriteInfoHighlighted "`t Waiting for Active Directory on $($DC.name) to be Started."
                    do{
                        $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $Labconfig -ErrorAction SilentlyContinue -ScriptBlock {
                            param($labconfig);
                            Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue
                        }
                        Start-Sleep 5
                    }until ($test -ne $Null)
                    WriteSuccess "`t Active Directory on $($DC.name) is up."
                }

                $DNSServers=@()

                if($LabConfig.UseHostDnsAsForwarder){
                    WriteInfo "`t Requesting DNS settings from Host"
                    if($internetSwitch.Name -eq "Default Switch"){
                        # Host's IP of Default Switch acts also as DNS resolver
                        $DNSServers+=(Get-HnsNetwork | Where-Object { $_.Name -eq "Default Switch" }).Subnets[0].GatewayAddress
                    }
                    else{
                        $vNICName=(Get-VMNetworkAdapter -ManagementOS -SwitchName $internetSwitch.Name).Name | Select-Object -First 1 #in case multiple adapters are in managementos
                        $DNSServers+=(Get-NetIPConfiguration -InterfaceAlias "vEthernet ($vNICName)").DNSServer.ServerAddresses #grab DNS IP from vNIC
                    }
                }

                $DNSServers+=$LabConfig.CustomDnsForwarders

                WriteInfo "`t Configuring NAT with netSH and starting services"
                Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                    Set-Service -Name RemoteAccess -StartupType Automatic
                    Start-Service -Name RemoteAccess
                    netsh.exe routing ip nat install
                    netsh.exe routing ip nat add interface (Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq "Internet").Name
                    netsh.exe routing ip nat set interface (Get-NetAdapterAdvancedProperty | Where-Object displayvalue -eq "Internet").Name mode=full
                    netsh.exe ras set conf confstate = enabled
                    netsh.exe routing ip dnsproxy install
                    Write-Output "`t Restarting service RemoteAccess..."
                    Restart-Service -Name RemoteAccess -WarningAction SilentlyContinue
                    Add-DnsServerForwarder $Using:DNSServers
                }
            }
        }

#endregion

#region Provision VMs
    $vmDeploymentEvents = @()
    #DSC config for LCM (in case Pull configuration is specified)
        WriteInfoHighlighted "Creating DSC config to configure DC as pull server"

        [DSCLocalConfigurationManager()]
        Configuration PullClientConfig
        {
            param
                (
                    [Parameter(Mandatory=$true)]
                    [string[]]$ComputerName,

                    [Parameter(Mandatory=$true)]
                    [string[]]$DSCConfig,

                    [Parameter(Mandatory=$true)]
                    [string[]]$DomainName
                )
            Node $ComputerName {
                Settings{

                    AllowModuleOverwrite = $True
                    ConfigurationMode = 'ApplyAndAutoCorrect'
                    RefreshMode = 'Pull'
                    RebootNodeIfNeeded = $True
                    ActionAfterReboot = 'ContinueConfiguration'
                    }

                    ConfigurationRepositoryWeb PullServerWeb {
                    ServerURL = "http://dc.$($DomainName):8080/PSDSCPullServer.svc"
                    AllowUnsecureConnection = $true
                    RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
                    ConfigurationNames = $DSCConfig
                    }

                    ReportServerWeb PullServerReports {
                    ServerURL = "http://dc.$($DomainName):8080/PSDSCPullServer.svc"
                    RegistrationKey = '14fc8e72-5036-4e79-9f89-5382160053aa'
                    }

                    $DSCConfig | ForEach-Object {
                        PartialConfiguration $_
                        {
                        RefreshMode = 'Pull'
                        ConfigurationSource = '[ConfigurationRepositoryWeb]PullServerWeb'
                        }
                    }
            }
        }

    #process $labconfig.VMs and create VMs (skip if machine already exists)
        WriteInfoHighlighted 'Processing $LabConfig.VMs, creating VMs'
        $provisionedVMs = @()
        foreach ($VMConfig in $LABConfig.VMs.GetEnumerator()){
            if (!(Get-VM -Name "$($labconfig.prefix)$($VMConfig.vmname)" -ErrorAction SilentlyContinue)){
                $vmProvisioningStartTime = Get-Date

                # Ensure that Configuration is set and use Simple as default
                if(-not $VMConfig.configuration) {
                    $VMConfig.configuration = "Simple"
                }
                # Ensure that MemoryStartupBytes is set to use 2048MB as default
                if(-not $VMConfig.MemoryStartupBytes) {
                    $VMConfig.MemoryStartupBytes = 2048MB
                }

                #create VM with Shared configuration
                    if ($VMConfig.configuration -eq 'Shared'){
                        #create disks (if not already created)
                            $VMSet=$VMConfig.VMSet
                            if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
                                $SharedSSDs=$null
                                $SharedHDDs=$null
                                If (($VMConfig.SSDNumber -ge 1) -and ($VMConfig.SSDNumber -ne $null)){
                                    $SharedSSDs= 1..$VMConfig.ssdnumber | ForEach-Object {New-vhd -Path "$LABfolder\VMs\SharedSSD-$VMSet-$_.VHDS" -Dynamic -Size $VMConfig.SSDSize}
                                    $SharedSSDs | ForEach-Object {WriteInfo "`t Disk SSD $($_.path) size $($_.size /1GB)GB created"}
                                }
                                If (($VMConfig.HDDNumber -ge 1) -and ($VMConfig.HDDNumber -ne $null)){
                                    $SharedHDDs= 1..$VMConfig.hddnumber | ForEach-Object {New-VHD -Path "$LABfolder\VMs\SharedHDD-$VMSet-$_.VHDS" -Dynamic -Size $VMConfig.HDDSize}
                                    $SharedHDDs | ForEach-Object {WriteInfo "`t Disk HDD $($_.path) size $($_.size /1GB)GB created"}
                                }
                            }else{
                                $SharedSSDs=Get-VHD -Path "$LABfolder\VMs\SharedSSD-$VMSet-*.VHDS" -ErrorAction SilentlyContinue
                                $SharedHDDs=Get-VHD -Path "$LABfolder\VMs\SharedHDD-$VMSet-*.VHDS" -ErrorAction SilentlyContinue
                            }
                        #Build VM
                        $createdVm = BuildVM -VMConfig $VMConfig -LabConfig $labconfig -LabFolder $LABfolder
                        #Compose VMName
                            $VMname=$Labconfig.Prefix+$VMConfig.VMName
                        #Add disks
                            WriteInfoHighlighted "`t Attaching Shared Disks to $VMname"
                            $SharedSSDs | ForEach-Object {
                                $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
                                WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                            }
                            $SharedHDDs | ForEach-Object {
                                $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
                                WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                            }
                    }

                #create Linux VM
                    if ($VMConfig.configuration -eq 'Linux'){
                        $createdVm = New-LinuxVM -VMConfig $($VMConfig) -LabConfig $labconfig -LabFolder $LABfolder
                    }

                #create VM with Simple configuration
                    if ($VMConfig.configuration -eq 'Simple'){
                        $createdVm = BuildVM -VMConfig $($VMConfig) -LabConfig $labconfig -LabFolder $LABfolder
                    }

                #create VM with S2D configuration
                    if ($VMConfig.configuration -eq 'S2D'){
                        #build VM
                        $createdVm = BuildVM -VMConfig $VMConfig -LabConfig $labconfig -LabFolder $LABfolder
                        #compose VM name
                            $VMname=$Labconfig.Prefix+$VMConfig.VMName

                        #Add disks
                            #add "SSDs"
                                If (($VMConfig.SSDNumber -ge 1) -and ($VMConfig.SSDNumber -ne $null)){
                                    $SSDs= 1..$VMConfig.SSDNumber | ForEach-Object { New-vhd -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\SSD-$_.VHDX" -Dynamic -Size $VMConfig.SSDSize}
                                    WriteInfoHighlighted "`t Adding Virtual SSD Disks"
                                    $SSDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                            #add "HDDs"
                                If (($VMConfig.HDDNumber -ge 1) -and ($VMConfig.HDDNumber -ne $null)) {
                                    $HDDs= 1..$VMConfig.HDDNumber | ForEach-Object { New-VHD -Path "$LabFolder\VMs\$VMname\Virtual Hard Disks\HDD-$_.VHDX" -Dynamic -Size $VMConfig.HDDSize}
                                    WriteInfoHighlighted "`t Adding Virtual HDD Disks"
                                    $HDDs | ForEach-Object {
                                        $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                        Add-VMHardDiskDrive -Path $_.path -VMName $VMname
                                        WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                    }
                                }
                    }

                #create VM with Replica configuration
                    if ($VMConfig.configuration -eq 'Replica'){
                        #create shared drives if not already created
                            $VMSet=$VMConfig.VMSet
                            if (!(Test-Path -Path "$LABfolder\VMs\*$VMSet*.VHDS")){
                                $ReplicaHDD= New-vhd -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS" -Dynamic -Size $VMConfig.ReplicaHDDSize
                                $ReplicaHDD | ForEach-Object {WriteInfo "`t`t ReplicaHDD $($_.path) size $($_.size /1GB)GB created"}
                                $ReplicaLog= New-vhd -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS" -Dynamic -Size $VMConfig.ReplicaLogSize
                                $ReplicaLog | ForEach-Object {WriteInfo "`t`t ReplicaLog $($_.path) size $($_.size /1GB)GB created"}
                            }else{
                                $ReplicaHDD=Get-VHD -Path "$LABfolder\VMs\ReplicaHDD-$VMSet.VHDS"
                                $ReplicaLog=Get-VHD -Path "$LABfolder\VMs\ReplicaLog-$VMSet.VHDS"
                            }
                        #build VM
                            $createdVm = BuildVM -VMConfig $VMConfig -LabConfig $labconfig -LabFolder $LABfolder

                        #Add disks
                            $VMname=$Labconfig.Prefix+$VMConfig.VMName
                            WriteInfoHighlighted "`t Attaching Shared Disks..."
                            #Add HDD
                                $ReplicaHdd | ForEach-Object {
                                    $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                    Add-VMHardDiskDrive -Path $_.path -VMName $VMname -SupportPersistentReservations
                                    WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                }
                            #add Log Disk
                                $ReplicaLog | ForEach-Object {
                                    $filename=$_.Path.Substring($_.Path.LastIndexOf("\")+1,$_.Path.Length-$_.Path.LastIndexOf("\")-1)
                                    Add-VMHardDiskDrive -Path $_.Path -VMName $VMname -SupportPersistentReservations
                                    WriteInfo "`t`t $filename size $($_.size /1GB)GB added to $VMname"
                                }
                    }

                # Telemetry Report
                if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
                    $properties = @{
                        'vm.configuration' = $VMConfig.Configuration
                        'vm.unattend' = $VMConfig.Unattend
                    }
                    if((Test-Path -Path $createdVm.OSDiskPath) -and $VMConfig.configuration -ne "Linux") {
                        $osInfo = Get-WindowsImage -ImagePath $createdVm.OSDiskPath -Index 1

                        $properties.'vm.os.installationType' = $osInfo.InstallationType
                        $properties.'vm.os.editionId' = $osInfo.EditionId
                        $properties.'vm.os.version' = $osInfo.Version
                    }

                    $metrics = @{
                        'vm.deploymentDuration' = ((Get-Date) - $vmProvisioningStartTime).TotalSeconds
                    }
                    $vmInfo = Initialize-TelemetryEvent -Event "Deploy.VM" -Properties $properties -Metrics $metrics -NickName $LabConfig.TelemetryNickName
                    $vmDeploymentEvents += $vmInfo
                }

                $provisionedVMs += $createdVm.VM
            }
        }

#endregion

#region Finishing
    WriteInfoHighlighted "Finishing..."

    #a bit cleanup
        Remove-Item -Path "$PSScriptRoot\temp" -Force -Recurse

        #set MacSpoofing and AllowTeaming (for SET switch in VMs to work properly with vNICs)
        WriteInfo "`t Setting MacSpoofing On and AllowTeaming On"
        Set-VMNetworkAdapter -VMName "$($labconfig.Prefix)*" -MacAddressSpoofing On -AllowTeaming On

    #list VMs
        $AllVMs = Get-VM | Where-Object name -like "$($labconfig.Prefix)*"
        $AllVMs | ForEach-Object { WriteSuccess "Machine $($_.VMName) provisioned" }

    #configure HostResourceProtection on all VM CPUs
        WriteInfo "`t Configuring EnableHostResourceProtection on all VM processors"
        Set-VMProcessor -EnableHostResourceProtection $true -VMName "$($labconfig.Prefix)*" -ErrorAction SilentlyContinue

    #Enable Guest services on all VMs if integration component if configured
    if ($labconfig.EnableGuestServiceInterface){
        WriteInfo "`t Enabling Guest Service Interface"
        $vms = Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object {$_.state -eq "Running" -or $_.state -eq "Off"}
        foreach ($vm in $vms) {
            $guestServiceId = 'Microsoft:{0}\6C09BB55-D683-4DA0-8931-C9BF705F6480' -f $vm.Id
            $guestService = $vm | Get-VMIntegrationService | Where-Object -FilterScript {$_.Id -eq $guestServiceId}
            $guestService | Enable-VMIntegrationService
        }
        $TempVMs=Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object {$_.state -ne "Running" -and $_.state -ne "Off"}
        if ($TempVMs){
            WriteInfoHighlighted "`t`t Following VMs cannot be configured, as the state is not running or off"
            $TempVMs.Name
        }
    }

    #Enable VMNics device naming
        WriteInfo "`t Enabling VMNics device naming"
        Get-VM -VMName "$($labconfig.Prefix)*" | Where-Object Generation -eq 2 | Set-VMNetworkAdapter -DeviceNaming On

    #Autostart VMs
        $startVMs = 0
        if($LabConfig.AutoStartAfterDeploy -eq $true -or $LabConfig.AutoStartAfterDeploy -eq "All") {
            $startVMs = 1
        } elseif($LabConfig.AutoStartAfterDeploy -eq "DeployedOnly") {
            $startVMs = 2
        }

        $CheckPointTime=Get-Date

        if(-not $LabConfig.ContainsKey("AutoStartAfterDeploy") -and $AllVMs.Count -gt 0) {
            $options = [System.Management.Automation.Host.ChoiceDescription[]] @(
                <# 0 #> New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No VM will be started."
                <# 1 #> New-Object System.Management.Automation.Host.ChoiceDescription "&All", "All VMs in the lab will be started."
            )

            if($provisionedVMs.Count -gt 0) {
                <# 2 #> $options += New-Object System.Management.Automation.Host.ChoiceDescription "&Deployed only", "Only newly deployed VMs will be started."
            }
            $startVMs = $host.UI.PromptForChoice("Start VMs", "Would you like to start lab virtual machines?", $options, 0 <#default option#>)
        }
        #Starting VMs
        $toStart = @()
        switch($startVMs) {
            1 {
                $toStart = $AllVMs
            }
            2 {
                $toStart = $provisionedVMs
            }
        }

        if(($toStart | Measure-Object).Count -gt 0) {
            WriteInfoHighlighted "Starting VMs"
            $toStart | ForEach-Object {
                WriteInfo "`t $($_.Name)"
                Start-VM -VM $_ -WarningAction SilentlyContinue
            }
        }

    # Telemetry Event
    if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
        WriteInfo "Sending telemetry info"
        $metrics = @{
            'script.duration' = [Math]::Round(($CheckPointTime - $StartDateTime).TotalSeconds, 2)
            'lab.vmsCount.active' = ($AllVMs | Measure-Object).Count # how many VMs are running
            'lab.vmsCount.provisioned' = ($provisionedVMs | Measure-Object).Count # how many VMs were created by this script run
        }
        $properties = @{
            'lab.internet' = [bool]$LabConfig.Internet
            'lab.isncrementalDeployment' = $LABExists
            'lab.autostartmode' = $startVMs
        }
        $telemetryEvent = Initialize-TelemetryEvent -Event "Deploy.End" -Metrics $metrics -Properties $properties -NickName $LabConfig.TelemetryNickName
        $vmDeploymentEvents += $telemetryEvent

        Send-TelemetryEvents -Events $vmDeploymentEvents | Out-Null
    }

#write how much it took to deploy
WriteInfo "Script finished at $CheckPointTime and took $(($CheckPointTime - $StartDateTime).TotalMinutes) Minutes"

Stop-Transcript

If (!$LabConfig.AutoClosePSWindows) {
    WriteSuccess "Press enter to continue..."
    Read-Host | Out-Null
}
#endregion
