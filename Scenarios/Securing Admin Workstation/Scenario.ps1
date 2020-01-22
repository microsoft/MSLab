#region Create Admin user and Groups

#OU path where Groups User will be created
$ServerAdminName="ServerAdmin01"
$ServerAdminPassword="LS1Setup!"
$ServerAdminGroupName="ServerAdmins"
$AdminWorkstationName="AdminStation"
$AdminWorkstationGroupName="AdminWorkstationGroup"
$OUPath="ou=workshop,dc=corp,dc=contoso,dc=com"

#create groups
New-ADGroup -Name $AdminWorkstationGroupName -GroupScope Global -Path $OUPath
New-ADGroup -Name $ServerAdminGroupName      -GroupScope Global -Path $OUPath

#create ServerAdmin
New-ADUser -Name $ServerAdminName -UserPrincipalName $ServerAdminName -Path $OUPath -Enabled $true -AccountPassword (ConvertTo-SecureString $ServerAdminPassword -AsPlainText -Force)

#add ServerAdmin to ServerAdmins Group
Add-ADGroupMember -Identity $ServerAdminGroupName -Members $ServerAdminName

#add AdminWorkstation to AdminWorkstations group
$WorkstationObject=Get-ADComputer -Identity $AdminWorkstationName
Add-ADGroupMember -Identity $AdminWorkstationGroupName -Members $WorkstationObject

#endregion

#region setup auditing

$AdminWorkstationName="AdminStation"

#download sysmon and sysmonconfig
Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
    #Download Sysmon
    Invoke-WebRequest -UseBasicParsing -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:USERPROFILE\Downloads\Sysmon.zip

    #unzip
    Expand-Archive -Path $env:USERPROFILE\Downloads\Sysmon.zip -DestinationPath $env:USERPROFILE\Downloads\Sysmon\ -Force

    #download sysmon config
    [xml]$XML=Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
    $xml.Save("$env:USERPROFILE\Downloads\Sysmon\Sysmonconfig-export.xml")
}

#install sysmon
Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
    Start-Process -Wait -FilePath sysmon.exe -ArgumentList "-accepteula -i sysmonconfig-export.xml" -WorkingDirectory "$env:USERPROFILE\Downloads\Sysmon\"
}

#validate if it's running
Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
    Get-Service Sysmon
}

#add posh transcript
#https://devblogs.microsoft.com/powershell/powershell-the-blue-team/
Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
    md c:\Transcripts
    ## Kill all inherited permissions
    $acl = Get-Acl c:\Transcripts
    $acl.SetAccessRuleProtection($true, $false)
    ## Grant Administrators full control
    $administrators = [System.Security.Principal.NTAccount] "Administrators"
    $permission = $administrators,"FullControl","ObjectInherit,ContainerInherit","None","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    ## Grant everyone else Write and ReadAttributes. This prevents users from listing
    ## transcripts from other machines on the domain.
    $everyone = [System.Security.Principal.NTAccount] "Everyone"
    $permission = $everyone,"Write,ReadAttributes","ObjectInherit,ContainerInherit","None","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    ## Deny "Creator Owner" everything. This prevents users from
    ## viewing the content of previously written files.
    $creatorOwner = [System.Security.Principal.NTAccount] "Creator Owner"
    $permission = $creatorOwner,"FullControl","ObjectInherit,ContainerInherit","InheritOnly","Deny"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.AddAccessRule($accessRule)
    ## Set the ACL
    $acl | Set-Acl c:\Transcripts\
}

#endregion

#region add RSAT tools to Admin Workstation using scheduled task (as invoke does not work)
$AdminStationName="AdminStation"
$TaskName="OneTimeTask"

$scriptblock={
        $Capabilities=Get-WindowsCapability -Name RSAT* -Online
        foreach ($capability in $Capabilities){
            $capability | Add-WindowsCapability -Online
        }
}
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -command `"& {$ScriptBlock}`""
$task=Register-ScheduledTask -Action $action -TaskName $TaskName -CimSession $AdminStationName -User "NT Authority\System"
$task.Settings.DisallowStartIfOnBatteries=$false
$settings=$task.settings
Set-ScheduledTask -CimSession $AdminStationName -TaskName $TaskName -Settings $settings
Start-ScheduledTask -CimSession $AdminStationName -TaskName $TaskName
$task=Get-ScheduledTask -CimSession $AdminStationName -TaskName $TaskName
while ($task.State -ne "Ready"){
    $task=Get-ScheduledTask -CimSession $AdminStationName -TaskName $TaskName
    Start-Sleep 1
    Write-Host "." -NoNewline
}
Unregister-ScheduledTask -CimSession $AdminStationName -TaskName $TaskName -Confirm:0
#endregion

#region setup Windows Firewall
$AdminWorkstationName=@("AdminStation")
$ManagedServers="Server01","Server02"
$AdminWorkstationGroupName="AdminWorkstationGroup"

#create Connection Security Rule (notice that I'm also adding local machine)
$Computers=$AdminWorkstationName+$ManagedServers+"$env:COMPUTERNAME"
Invoke-Command -ComputerName $Computers -ScriptBlock {
    if (-not (Get-NetIPsecRule -DisplayName "Default Request Rule" -ErrorAction SilentlyContinue)){
        New-NetIPsecRule -DisplayName "Default Request Rule" -InboundSecurity Request -OutboundSecurity Request
    }
}

#modify WinRM firewall rule to accept connections from AdminWS only
Set-NetFirewallRule -CimSession $managedservers -DisplayGroup "Windows Remote Management" -Authentication NoEncap
    
   #add local computer to remote machines (to not cut yourself)    
       #grab SID
        $SID=(Get-ADComputer -Identity $env:COMPUTERNAME).SID.Value
        #add SID to Firewall rule
        $FWRules=Get-NetFirewallrule -CimSession $managedservers -DisplayGroup "Windows Remote Management"
        #grab current ACLs and add new ones
        foreach ($fwrule in $fwrules){
            $CurrentACL=($fwrule | Get-NetFirewallSecurityFilter).RemoteMachines
            if ((-not($CurrentACL -like "*$SID*"))-or ($CurrentACL -eq $null)){
                if ($CurrentACL){
                    $SDDL=$CurrentACL+"(A;;CC;;;$SID)"
                }else{
                    $SDDL="O:LSD:(A;;CC;;;$SID)"
                }
                $fwrule | Set-NetFirewallRule -RemoteMachine $SDDL
            }
        }

   #add admin workstation group to remote computers
       #grab SID
        $SID=(Get-ADGroup -Identity $AdminWorkstationGroupName).SID.Value
        #add SID to Firewall rule
        $FWRules=Get-NetFirewallrule -CimSession $managedservers -DisplayGroup "Windows Remote Management"
        #grab current ACLs and add new ones
        foreach ($fwrule in $fwrules){
            $CurrentACL=($fwrule | Get-NetFirewallSecurityFilter).RemoteMachines
            if ((-not($CurrentACL -like "*$SID*"))-or ($CurrentACL -eq $null)){
                if ($CurrentACL){
                    $SDDL=$CurrentACL+"(A;;CC;;;$SID)"
                }else{
                    $SDDL="O:LSD:(A;;CC;;;$SID)"
                }
                $fwrule | Set-NetFirewallRule -RemoteMachine $SDDL
            }
        }


#endregion

#region lockdown Admin Workstation

$AdminWorkstationName="AdminStation"

#configure VBS & Cred Guard
    Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
        #Device Guard
        #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 1 /f 
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 3 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d 1 /f

        #Cred Guard  
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

        #HVCI
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f
        #REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 1 /f
        REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d 1 /f
    }


#configure Defender Application Guard
    #copy AllowMicrosoft.xml to Temp\MyPolicy.xml
    Copy-Item "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" "$env:TEMP\MyPolicy.xml"
    #load file into variable as XML
    [xml]$Policy=get-content -Path "$env:TEMP\MyPolicy.xml"
    #add new options
    13..16 | Foreach-Object{
        Set-RuleOption -Option $_ -FilePath "$env:TEMP\MyPolicy.xml"
    }
    #add recommended blocklist
    #grab recommended xml blocklist from GitHub
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $content=Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/master/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md 

    #find start and end
    $XMLStart=$content.Content.IndexOf("<?xml version=")
    $XMLEnd=$content.Content.IndexOf("</SiPolicy>")+11 # 11 is lenght of string
    #create xml
    [xml]$XML=$content.Content.Substring($xmlstart,$XMLEnd-$XMLStart) #find XML part
    $XML.Save("$env:TEMP\blocklist.xml")
    #add to MyPolicy.xml
    $mergedPolicyRules = Merge-CIPolicy -PolicyPaths "$env:TEMP\blocklist.xml","$env:TEMP\MyPolicy.xml" -OutputFilePath "$env:TEMP\MyPolicy.xml"
    Write-Host ('Merged policy contains {0} rules' -f $mergedPolicyRules.Count)
    #remove audit mode option
    Set-RuleOption -Option 3 -FilePath "$env:TEMP\MyPolicy.xml" -Delete
    #create binary policy file
    ConvertFrom-CIPolicy "$env:TEMP\MyPolicy.xml" "$env:TEMP\MyPolicy.bin"

    #copy policy file to Admin workstation
    $session=New-PSSession -ComputerName $AdminWorkstationName
    Copy-Item "$env:TEMP\MyPolicy.bin" -Destination "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b" -Force -ToSession $session

    #update policy
    Invoke-CimMethod -CimSession $AdminWorkstationName -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" }
 
    #configure services
    Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
        #start  applockerfltr,appidsvc,appid services. Alternatively you can run "appidtel start"
        Get-Service -Name applockerfltr | Start-Service
        #make it autostart
        Get-Service -Name applockerfltr | Set-Service -StartupType Automatic
    }

    #restart computer to apply all changes
    Restart-Computer -ComputerName $AdminWorkstationName -Protocol WSMan -Wait -for PowerShell

#endregion

#region Add Server Admin to remote desktop users on Admin Workstation
$AdminWorkstationName="AdminStation"
$ServerAdminName="ServerAdmin01"
Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $using:ServerAdminName
}

#enable remote desktop
Invoke-Command -ComputerName $AdminWorkstationName -ScriptBlock {
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

#endregion

#region Add ServerAdmin01 to Local Admins on managed servers

$ManagedServers="Server01","Server02"
$ServerAdminGroupName="ServerAdmins"
Invoke-Command -ComputerName $ManagedServers -ScriptBlock {
    Add-LocalGroupMember -Group Administrators -Member $using:ServerAdminGroupName
}

#endregion

#region add and lockdown another management options

$DisplayGroups="Performance Logs and Alerts","Remote Service Management","Remote Scheduled Tasks Management","Remote Event Monitor","Remote Event Log Management","Remote Volume Management"#,"Windows Defender Firewall Remote Management"
$ManagedServers="Server01","Server02"
$AdminWorkstationGroupName="AdminWorkstationGroup"

#configure NoEncap Auth for selected rules
Set-NetFirewallRule -CimSession $managedservers -DisplayGroup $DisplayGroups -Authentication NoEncap
#add admin workstation group to remote computers
    #grab SID
    $SID=(Get-ADGroup -Identity $AdminWorkstationGroupName).SID.Value
    #add SID to Firewall rule
    $FWRules=Get-NetFirewallrule -CimSession $managedservers -DisplayGroup $DisplayGroups
    #grab current ACLs and add new ones
    foreach ($fwrule in $fwrules){
        $CurrentACL=($fwrule | Get-NetFirewallSecurityFilter).RemoteMachines
        if ((-not($CurrentACL -like "*$SID*"))-or ($CurrentACL -eq $null)){
            if ($CurrentACL){
                $SDDL=$CurrentACL+"(A;;CC;;;$SID)"
            }else{
                $SDDL="O:LSD:(A;;CC;;;$SID)"
            }
            $fwrule | Set-NetFirewallRule -RemoteMachine $SDDL
        }
    }

#enable
Enable-NetFirewallRule -CimSession $managedservers -DisplayGroup $DisplayGroups

#endregion