#region CreateUnattendFileVHD

#Create Unattend for VHD
    Function CreateUnattendFileVHD {
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Computername,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $Path,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone
        )

        if ( Test-Path "$path\Unattend.xml" ) {
            Remove-Item "$Path\Unattend.xml"
        }
        $unattendFile = New-Item "$Path\Unattend.xml" -type File

        $fileContent =  @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <settings pass="offlineServicing">
   <component
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        language="neutral"
        name="Microsoft-Windows-PartitionManager"
        processorArchitecture="amd64"
        publicKeyToken="31bf3856ad364e35"
        versionScope="nonSxS"
        >
      <SanPolicy>1</SanPolicy>
    </component>
 </settings>
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        $oeminformation
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
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

        Set-Content -path $unattendFile -value $fileContent

        #return the file object
        Return $unattendFile
    }
#endregion

#region Hydrate DC
function Hydrate-DC {

    param(
        [parameter(Mandatory=$true)]
        [string]$DCName,

        [parameter(Mandatory=$true)]
        [string]$VhdPath,

        [parameter(Mandatory=$true)]
        [string]$VmPath,

        [parameter(Mandatory=$true)]
        [string]$SwitchName,

        [parameter(Mandatory=$true)]
        [string]$TimeZone,

        [parameter(Mandatory=$true)]
        [string]$DhcpScope,

        [parameter(Mandatory=$true)]
        [string]$AdminPassword)
    
    WriteInfoHighlighted "Starting DC Hydration"
    $dcHydrationStartTime = Get-Date

    #DCHP scope
    $ReverseDnsRecord = $DhcpScope -replace '^(\d+)\.(\d+)\.\d+\.(\d+)$','$3.$2.$1.in-addr.arpa'
    $DhcpScope = $DhcpScope.Substring(0,$DhcpScope.Length-1)
    
    #If the switch does not already exist, then create a switch with the name $SwitchName
        if (-not [bool](Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
            WriteInfoHighlighted "`t Creating temp hydration switch $SwitchName"
            New-VMSwitch -SwitchType Private -Name $SwitchName
        }

    #create VM DC
        WriteInfoHighlighted "`t Creating DC VM"
        if ($LabConfig.DCVMVersion){
            $DC=New-VM -Name $DCName -VHDPath $VhdPath -MemoryStartupBytes 2GB -path $VmPath -SwitchName $SwitchName -Generation 2 -Version $LabConfig.DCVMVersion
        }else{
            $DC=New-VM -Name $DCName -VHDPath $VhdPath -MemoryStartupBytes 2GB -path $VmPath -SwitchName $SwitchName -Generation 2
        }
        $DC | Set-VMProcessor -Count 2
        $DC | Set-VMMemory -DynamicMemoryEnabled $true -MinimumBytes 2GB
        if ($LabConfig.Secureboot -eq $False) {$DC | Set-VMFirmware -EnableSecureBoot Off}
        if ($DC.AutomaticCheckpointsEnabled -eq $True){
            $DC | Set-VM -AutomaticCheckpointsEnabled $False
        }
        if ($LabConfig.InstallSCVMM -eq "Yes"){
            #SCVMM 2022 requires 4GB of memory
            $DC | Set-VMMemory -StartupBytes 4GB -MinimumBytes 4GB
        }

    #Apply Unattend to VM
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

        WriteInfoHighlighted "`t Applying Unattend and copying Powershell DSC Modules"
        if (Test-Path $mountdir){
            Remove-Item -Path $mountdir -Recurse -Force
        }
        if (Test-Path "$PSScriptRoot\Temp\unattend"){
            Remove-Item -Path "$PSScriptRoot\Temp\unattend.xml"
        }
        $unattendfile=CreateUnattendFileVHD -Computername $DCName -AdminPassword $AdminPassword -path "$PSScriptRoot\temp\" -TimeZone $TimeZone
        New-item -type directory -Path $mountdir -force
        [System.Version]$VMVersion=(Get-WindowsImage -ImagePath $VHDPath -Index 1).Version
        Mount-WindowsImage -Path $mountdir -ImagePath $VHDPath -Index 1
        Use-WindowsUnattend -Path $mountdir -UnattendPath $unattendFile
        #&"$PSScriptRoot\Temp\dism\dism" /mount-image /imagefile:$VhdPath /index:1 /MountDir:$mountdir
        #&"$PSScriptRoot\Temp\dism\dism" /image:$mountdir /Apply-Unattend:$unattendfile
        New-item -type directory -Path "$mountdir\Windows\Panther" -force
        Copy-Item -Path $unattendfile -Destination "$mountdir\Windows\Panther\unattend.xml" -force
        Copy-Item -Path "$PSScriptRoot\Temp\DSC\*" -Destination "$mountdir\Program Files\WindowsPowerShell\Modules\" -Recurse -force
        WriteInfoHighlighted "`t Adding Hyper-V feature into DC"
        #Install Hyper-V feature
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Path "$mountdir"

    #Create credentials for DSC

        $username = "$($LabConfig.DomainNetbiosName)\Administrator"
        $password = $AdminPassword
        $secstr = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

    #Create DSC configuration
        configuration DCHydration
        {
            param
            ( 
                [Parameter(Mandatory)]
                [pscredential]$safemodeAdministratorCred,
        
                [Parameter(Mandatory)]
                [pscredential]$domainCred,

                [Parameter(Mandatory)]
                [pscredential]$NewADUserCred

            )

            Import-DscResource -ModuleName ActiveDirectoryDsc -ModuleVersion "6.3.0"
            Import-DscResource -ModuleName DnsServerDsc -ModuleVersion "3.0.0"
            Import-DSCResource -ModuleName NetworkingDSC -ModuleVersion "9.0.0"
            Import-DSCResource -ModuleName xDHCPServer -ModuleVersion "3.1.1"
            Import-DSCResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion "9.1.0"
            Import-DSCResource -ModuleName xHyper-V -ModuleVersion "3.18.0"
            Import-DscResource -ModuleName PSDesiredStateConfiguration

            Node $AllNodes.Where{$_.Role -eq "Parent DC"}.Nodename

            {
                WindowsFeature ADDSInstall
                { 
                    Ensure = "Present"
                    Name = "AD-Domain-Services"
                }

                WindowsFeature FeatureGPMC
                {
                    Ensure = "Present"
                    Name = "GPMC"
                    DependsOn = "[WindowsFeature]ADDSInstall"
                }

                WindowsFeature FeatureADPowerShell
                {
                    Ensure = "Present"
                    Name = "RSAT-AD-PowerShell"
                    DependsOn = "[WindowsFeature]ADDSInstall"
                } 

                WindowsFeature FeatureADAdminCenter
                {
                    Ensure = "Present"
                    Name = "RSAT-AD-AdminCenter"
                    DependsOn = "[WindowsFeature]ADDSInstall"
                } 

                WindowsFeature FeatureADDSTools
                {
                    Ensure = "Present"
                    Name = "RSAT-ADDS-Tools"
                    DependsOn = "[WindowsFeature]ADDSInstall"
                } 

                WindowsFeature Hyper-V-PowerShell
                {
                    Ensure = "Present"
                    Name = "Hyper-V-PowerShell"
                }

                xVMSwitch VMSwitch
                {
                    Ensure = "Present"
                    Name = "vSwitch"
                    Type = "External"
                    AllowManagementOS = $true
                    NetAdapterName = "Ethernet"
                    EnableEmbeddedTeaming = $true
                    DependsOn = "[WindowsFeature]Hyper-V-PowerShell"
                }
        
                ADDomain FirstDS 
                { 
                    DomainName = $Node.DomainName
                    Credential = $domainCred
                    SafemodeAdministratorPassword = $safemodeAdministratorCred
                    DomainNetbiosName = $node.DomainNetbiosName
                    DependsOn = "[WindowsFeature]ADDSInstall"
                }
            
                WaitForADDomain DscForestWait
                { 
                    DomainName = $Node.DomainName
                    Credential = $domainCred
                    DependsOn = "[ADDomain]FirstDS"
                }
                
                ADOrganizationalUnit DefaultOU
                {
                    Name = $Node.DefaultOUName
                    Path = $Node.DomainDN
                    ProtectedFromAccidentalDeletion = $true
                    Description = 'Default OU for all user and computer accounts'
                    Ensure = 'Present'
                    DependsOn = "[ADDomain]FirstDS"
                }

                ADUser SQL_SA
                {
                    DomainName = $Node.DomainName
                    Credential = $domainCred
                    UserName = "SQL_SA"
                    Password = $NewADUserCred
                    Ensure = "Present"
                    DependsOn = "[ADOrganizationalUnit]DefaultOU"
                    Description = "SQL Service Account"
                    Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                    PasswordNeverExpires = $true
                }

                ADUser SQL_Agent
                {
                    DomainName = $Node.DomainName
                    Credential = $domainCred
                    UserName = "SQL_Agent"
                    Password = $NewADUserCred
                    Ensure = "Present"
                    DependsOn = "[ADOrganizationalUnit]DefaultOU"
                    Description = "SQL Agent Account"
                    Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                    PasswordNeverExpires = $true
                }

                ADUser Domain_Admin
                {
                    DomainName = $Node.DomainName
                    Credential = $domainCred
                    UserName = $Node.DomainAdminName
                    Password = $NewADUserCred
                    Ensure = "Present"
                    DependsOn = "[ADOrganizationalUnit]DefaultOU"
                    Description = "DomainAdmin"
                    Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                    PasswordNeverExpires = $true
                }

                ADUser VMM_SA
                {
                    DomainName = $Node.DomainName
                    Credential = $domainCred
                    UserName = "VMM_SA"
                    Password = $NewADUserCred
                    Ensure = "Present"
                    DependsOn = "[ADUser]Domain_Admin"
                    Description = "VMM Service Account"
                    Path = "OU=$($Node.DefaultOUName),$($Node.DomainDN)"
                    PasswordNeverExpires = $true
                }

                ADGroup DomainAdmins
                {
                    GroupName = "Domain Admins"
                    DependsOn = "[ADUser]VMM_SA"
                    MembersToInclude = "VMM_SA",$Node.DomainAdminName
                }

                ADGroup SchemaAdmins
                {
                    GroupName = "Schema Admins"
                    GroupScope = "Universal"
                    DependsOn = "[ADUser]VMM_SA"
                    MembersToInclude = $Node.DomainAdminName
                }

                ADGroup EntAdmins
                {
                    GroupName = "Enterprise Admins"
                    GroupScope = "Universal"
                    DependsOn = "[ADUser]VMM_SA"
                    MembersToInclude = $Node.DomainAdminName
                }

                ADUser AdministratorNeverExpires
                {
                    DomainName = $Node.DomainName
                    UserName = "Administrator"
                    Ensure = "Present"
                    DependsOn = "[ADDomain]FirstDS"
                    PasswordNeverExpires = $true
                }

                IPaddress IP
                {
                    IPAddress = ($DhcpScope+"1/24")
                    AddressFamily = "IPv4"
                    InterfaceAlias = "vEthernet (vSwitch)"
                    DependsOn = "[xVMSwitch]VMSwitch"
                }

                WindowsFeature DHCPServer
                {
                    Ensure = "Present"
                    Name = "DHCP"
                    DependsOn = "[ADDomain]FirstDS"
                }

                Service DHCPServer #since insider 17035 dhcpserver was not starting for some reason
                {
                    Name = "DHCPServer"
                    State = "Running"
                    DependsOn =  "[WindowsFeature]DHCPServer"
                }

                WindowsFeature DHCPServerManagement
                {
                    Ensure = "Present"
                    Name = "RSAT-DHCP"
                    DependsOn = "[WindowsFeature]DHCPServer"
                } 

                xDhcpServerScope ManagementScope
                {
                    Ensure = 'Present'
                    ScopeId = ($DhcpScope+"0")
                    IPStartRange = ($DhcpScope+"10")
                    IPEndRange = ($DhcpScope+"254")
                    Name = 'ManagementScope'
                    SubnetMask = '255.255.255.0'
                    LeaseDuration = '00:08:00'
                    State = 'Active'
                    AddressFamily = 'IPv4'
                    DependsOn = "[Service]DHCPServer"
                }

                # Setting scope gateway
                DhcpScopeOptionValue 'ScopeOptionGateway'
                {
                    OptionId      = 3
                    Value         = ($DhcpScope+"1")
                    ScopeId       = ($DhcpScope+"0")
                    VendorClass   = ''
                    UserClass     = ''
                    AddressFamily = 'IPv4'
                    DependsOn = "[xDhcpServerScope]ManagementScope"
                }

                # Setting scope DNS servers
                DhcpScopeOptionValue 'ScopeOptionDNS'
                {
                    OptionId      = 6
                    Value         = ($DhcpScope+"1")
                    ScopeId       = ($DhcpScope+"0")
                    VendorClass   = ''
                    UserClass     = ''
                    AddressFamily = 'IPv4'
                    DependsOn = "[xDhcpServerScope]ManagementScope"
                }

                # Setting scope DNS domain name
                DhcpScopeOptionValue 'ScopeOptionDNSDomainName'
                {
                    OptionId      = 15
                    Value         = $Node.DomainName
                    ScopeId       = ($DhcpScope+"0")
                    VendorClass   = ''
                    UserClass     = ''
                    AddressFamily = 'IPv4'
                    DependsOn = "[xDhcpServerScope]ManagementScope"
                }
                
                xDhcpServerAuthorization LocalServerActivation
                {
                    IsSingleInstance = 'Yes'
                    Ensure = 'Present'
                }

                WindowsFeature DSCServiceFeature
                {
                    Ensure = "Present"
                    Name   = "DSC-Service"
                }

                DnsServerADZone addReverseADZone
                {
                    Name = $ReverseDnsRecord
                    DynamicUpdate = "Secure"
                    ReplicationScope = "Forest"
                    Ensure = "Present"
                    DependsOn = "[DhcpScopeOptionValue]ScopeOptionGateway"
                }

                If ($LabConfig.PullServerDC){
                    xDscWebService PSDSCPullServer
                    {
                        UseSecurityBestPractices = $false
                        Ensure                  = "Present"
                        EndpointName            = "PSDSCPullServer"
                        Port                    = 8080
                        PhysicalPath            = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
                        CertificateThumbPrint   = "AllowUnencryptedTraffic"
                        ModulePath              = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
                        ConfigurationPath       = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
                        State                   = "Started"
                        DependsOn               = "[WindowsFeature]DSCServiceFeature"
                    }
                    
                    File RegistrationKeyFile
                    {
                        Ensure = 'Present'
                        Type   = 'File'
                        DestinationPath = "$env:ProgramFiles\WindowsPowerShell\DscService\RegistrationKeys.txt"
                        Contents        = $Node.RegistrationKey
                    }
                }
            }
        }

        $ConfigData = @{ 
        
            AllNodes = @( 
                @{ 
                    Nodename = $DCName
                    Role = "Parent DC"
                    DomainAdminName=$LabConfig.DomainAdminName
                    DomainName = $LabConfig.DomainName
                    DomainNetbiosName = $LabConfig.DomainNetbiosName
                    DomainDN = $LabConfig.DN
                    DefaultOUName=$LabConfig.DefaultOUName
                    RegistrationKey='14fc8e72-5036-4e79-9f89-5382160053aa'
                    PSDscAllowPlainTextPassword = $true
                    PsDscAllowDomainUser= $true
                    RetryCount = 50
                    RetryIntervalSec = 30
                }         
            ) 
        } 

    #create LCM config
        [DSCLocalConfigurationManager()]
        configuration LCMConfig
        {
            Node DC
            {
                Settings
                {
                    RebootNodeIfNeeded = $true
                    ActionAfterReboot = 'ContinueConfiguration'
                }
            }
        }

    #create DSC MOF files
        WriteInfoHighlighted "`t Creating DSC Configs for DC"
        LCMConfig       -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData
        DCHydration     -OutputPath "$PSScriptRoot\Temp\config" -ConfigurationData $ConfigData -safemodeAdministratorCred $cred -domainCred $cred -NewADUserCred $cred
    
    #copy DSC MOF files to DC
        WriteInfoHighlighted "`t Copying DSC configurations (pending.mof and metaconfig.mof)"
        New-item -type directory -Path "$PSScriptRoot\Temp\config" -ErrorAction Ignore
        Copy-Item -path "$PSScriptRoot\Temp\config\dc.mof"      -Destination "$mountdir\Windows\system32\Configuration\pending.mof"
        Copy-Item -Path "$PSScriptRoot\Temp\config\dc.meta.mof" -Destination "$mountdir\Windows\system32\Configuration\metaconfig.mof"

    #close VHD and apply changes
        WriteInfoHighlighted "`t Applying changes to VHD"
        Dismount-WindowsImage -Path $mountdir -Save
        #&"$PSScriptRoot\Temp\dism\dism" /Unmount-Image /MountDir:$mountdir /Commit

    #Start DC VM and wait for configuration
        WriteInfoHighlighted "`t Starting DC"
        $DC | Start-VM

        $VMStartupTime = 250
        WriteInfoHighlighted "`t Configuring DC using DSC takes a while."
        WriteInfo "`t `t Initial configuration in progress. Sleeping $VMStartupTime seconds"
        Start-Sleep $VMStartupTime
        $i=1
        do{
            $test=Invoke-Command -VMGuid $DC.id -ScriptBlock {Get-DscConfigurationStatus} -Credential $cred -ErrorAction SilentlyContinue
            if ($test -eq $null) {
                WriteInfo "`t `t Configuration in Progress. Sleeping 10 seconds"
                Start-Sleep 10
            }elseif ($test.status -ne "Success" -and $i -eq 1) {
                WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                WriteInfoHighlighted "`t `t Invoking DSC Configuration again"
                Invoke-Command -VMGuid $DC.id -ScriptBlock {Start-DscConfiguration -UseExisting} -Credential $cred
                $i++
            }elseif ($test.status -ne "Success" -and $i -gt 1) {
                WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                WriteInfoHighlighted "`t `t Restarting DC"
                Invoke-Command -VMGuid $DC.id -ScriptBlock {Restart-Computer} -Credential $cred
            }elseif ($test.status -eq "Success" ) {
                WriteInfo "`t `t Current DSC state: $($test.status), ResourncesNotInDesiredState: $($test.resourcesNotInDesiredState.count), ResourncesInDesiredState: $($test.resourcesInDesiredState.count)."
                WriteInfoHighlighted "`t `t DSC Configured DC Successfully"
            }
        }until ($test.Status -eq 'Success' -and $test.rebootrequested -eq $false)
        $test

    #configure default OU where new Machines will be created using redircmp and add reverse lookup zone (as setting reverse lookup does not work with DSC)
        Invoke-Command -VMGuid $DC.id -Credential $cred -ErrorAction SilentlyContinue -ArgumentList $LabConfig -ScriptBlock {
            Param($LabConfig);
            redircmp "OU=$($LabConfig.DefaultOUName),$($LabConfig.DN)"
            Add-DnsServerPrimaryZone -NetworkID ($DhcpScope+"/24") -ReplicationScope "Forest"
        }
    #install SCVMM or its prereqs if specified so
        if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
            $DC | Add-VMHardDiskDrive -Path $toolsVHD.Path
        }

        if ($LabConfig.InstallSCVMM -eq "Yes"){
            WriteInfoHighlighted "Installing System Center Virtual Machine Manager and its prerequisites"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                d:\scvmm\1_SQL_Install.ps1
                d:\scvmm\2_ADK_Install.ps1
                #install prereqs
                if (Test-Path "D:\SCVMM\SCVMM\Prerequisites\VCRedist\amd64\vcredist_x64.exe"){
                    Start-Process -FilePath "D:\SCVMM\SCVMM\Prerequisites\VCRedist\amd64\vcredist_x64.exe" -ArgumentList "/passive /quiet /norestart" -Wait
                }
                Restart-Computer
            }
            Start-Sleep 10

            WriteInfoHighlighted "$($DC.name) was restarted, waiting for Active Directory on $($DC.name) to be started."
            do{
            $test=Invoke-Command -VMGuid $DC.id -Credential $cred -ArgumentList $LabConfig -ErrorAction SilentlyContinue -ScriptBlock {
                param($LabConfig);
                Get-ADComputer -Filter * -SearchBase "$($LabConfig.DN)" -ErrorAction SilentlyContinue}
                Start-Sleep 5
            }
            until ($test -ne $Null)
            WriteSuccess "Active Directory on $($DC.name) is up."

            Start-Sleep 30 #Wait as sometimes VMM failed to install without this.
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                d:\scvmm\3_SCVMM_Install.ps1
            }
        }

        if ($LabConfig.InstallSCVMM -eq "SQL"){
            WriteInfoHighlighted "Installing SQL"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                d:\scvmm\1_SQL_Install.ps1
            }
        }

        if ($LabConfig.InstallSCVMM -eq "ADK"){
            WriteInfoHighlighted "Installing ADK"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                d:\scvmm\2_ADK_Install.ps1
            }
        }

        if ($LabConfig.InstallSCVMM -eq "Prereqs"){
            WriteInfoHighlighted "Installing System Center VMM Prereqs"
            Invoke-Command -VMGuid $DC.id -Credential $cred -ScriptBlock {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
                d:\scvmm\1_SQL_Install.ps1
                d:\scvmm\2_ADK_Install.ps1
            }
        }

        if (($LabConfig.InstallSCVMM -eq "Yes") -or ($LabConfig.InstallSCVMM -eq "SQL") -or ($LabConfig.InstallSCVMM -eq "ADK") -or ($LabConfig.InstallSCVMM -eq "Prereqs")){
            $DC | Get-VMHardDiskDrive | Where-Object path -eq $toolsVHD.Path | Remove-VMHardDiskDrive
        }

        WriteInfo "`t Disconnecting VMNetwork Adapter from DC"
        $DC | Get-VMNetworkAdapter | Disconnect-VMNetworkAdapter

        $dcHydrationEndTime = Get-Date
}
#endregion
