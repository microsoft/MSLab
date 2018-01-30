# Scenario Introduction

**Work in progress**

In this scenario will be VBS deployed to remote servers. It is just a demonstration on how to lockdown remote servers from Management machine. You don't have to spin Win10 machine (you can use DC), but since I want to demonstrate security best practices, all is done from there.


## LabConfig Windows Server 1709

````PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab1709-'; SwitchName = 'LabSwitch'; DCEdition='SERVERDATACENTERACORE'; CreateClientParent=$True ; ClientEdition='Enterprise' ; PullServerDC=$false; Internet=$true; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@()}
$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'WinServer1709_G2.vhdx'  ; MemoryStartupBytes= 512MB} }

$LABConfig.ServerVHDs += @{
    Edition="SERVERDATACENTERACORE";
    VHDName="WinServer1709_G2.vhdx";
    Size=40GB
}
 
````
## LabConfig Windows Server 2016

**Note:** If you dont have Win10, you can use CreateParentDisk.ps1 in tools folder to create Win10 VHD without creating all parent disks

````PowerShell

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'ws2016lab-'; SwitchName = 'LabSwitch'; DCEdition='DataCenter'; AdditionalNetworksConfig=@(); VMs=@(); ServerVHDs=@(); Internet=$True ; CreateClientParent=$true}

$LabConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple' ; ParentVHD = 'Win10_G2.vhdx'  ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True ; DisableWCF=$True }
1..3 | % {"Server$_"}  | % { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple' ; ParentVHD = 'Win2016Core_G2.vhdx'  ; MemoryStartupBytes= 512MB} }
 
````

# The lab

The lab is same as for LAPS. therefore we will be configuring 3 servers... 

````PowerShell
    $Servers=1..3 | Foreach-Object {"Server$_"}

    #configure VBS & Cred Guard
        if ($VBS){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                #Device Guard
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 1 /f 
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 3 /f
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d 1 /f

                #Cred Guard  
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

                #HVCI
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 1 /f
                REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d 1 /f
            }
        }

    #Configure UMCI policy (User Mode Code Integrity)
        $session=New-PSSession -ComputerName ($servers | Select-Object -last 1)
        Invoke-Command -Session $session -ScriptBlock {
            $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
            If (($WindowsInstallationType -eq "Server")-or($WindowsInstallationType -eq "Client")){
                #usually more applications are present on GUI servers (as it serves as application server, therefore -Level Publisher)
                New-CIPolicy -Level Publisher -Fallback Hash -UserPEs -FilePath .\CIPolicy.xml
            }elseif($WindowsInstallationType -eq "Server Core"{
                New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -FilePath .\CIPolicy.xml
            }
            Set-RuleOption -FilePath .\CIPolicy.xml -Option 3 -Delete 
            ConvertFrom-CIPolicy .\CIPolicy.xml .\CIPolicy.bin
            Copy-Item .\CIPolicy.bin -Destination C:\Windows\System32\CodeIntegrity\SiPolicy.p7b
            ".\CIPolicy.xml",".\CIPolicy.bin" | ForEach-Object {Remove-Item -Path $_}
        }

        #copy CI to other servers 
            $sessions=New-PSSession ($Servers | Select-Object -SkipLast 1)
            Copy-Item -FromSession $session -Path C:\Windows\System32\CodeIntegrity\SiPolicy.p7b -Destination .\
            $sessions | ForEach-Object {
                Copy-Item .\SiPolicy.p7b -ToSession $_ -Destination C:\Windows\System32\CodeIntegrity\
            }
            Remove-Item .\SiPolicy.p7b

        #close sessions
            $session,$sessions | Remove-PSSession
    
    #Alternatively you can use built in policies that are available in 1709
        <#
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $PolicyPath="C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
            Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\MyCustomPolicy.xml
            Set-RuleOption -FilePath .\MyCustomPolicy.xml -Option 3 -Delete
            ConvertFrom-CIPolicy .\MyCustomPolicy.xml .\MyCustomPolicy.bin
            Copy-Item .\MyCustomPolicy.bin -Destination C:\Windows\System32\CodeIntegrity\SiPolicy.p7b
            ".\MyCustomPolicy.xml",".\MyCustomPolicy.bin" | ForEach-Object {Remove-Item -Path $_}
        }
        #>
    
    #reboot
        Restart-Computer -ComputerName $servers -Protocol WSMan -Wait -For PowerShell
````