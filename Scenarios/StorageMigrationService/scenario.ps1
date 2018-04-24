###############
# Run from DC #
###############

# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (!( $isAdmin )) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    exit
}

$StartDateTime = get-date
Write-host "Scripts started at $StartDateTime"

#Set PSScriptRoot
$PSScriptRootFolder = "D:\Scripts"

##### LAB Config #####
#Change the Servers here based on the servers you need to deploy

$WAC = 'WAC'
$SMS_2008R2 = 'SMS2008R2'
$SMS_2012R2 = 'SMS_2012R2'
$SMS_2019 = 'SMS_2019'

$Servers = ($WAC, $SMS_2008R2, $SMS_2012R2, $SMS_2019)

#Enable firewall rules for servers
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-NetFirewallRule -Name *FPS* | Enable-NetFirewallRule ; Enable-PSRemoting -Force -Confirm:$false }
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-NetFirewallRule -Name *rpc* | Enable-NetFirewallRule }
Invoke-Command -ComputerName $Servers -ScriptBlock { Get-NetFirewallRule -Name *wmi* | Enable-NetFirewallRule } 

#Upgrade Powershell on 2008R2 server
IF ($SMS_2008R2) {    
    #Install requierd Roles on 2008R2 Server
    Write-host "Installing IIS on 2008R2 Server"
    Invoke-Command -ComputerName $SMS_2008R2 -ScriptBlock {
        Import-Module Servermanager
        Add-WindowsFeature Web-server -IncludeAllSubFeature
    }

    #Wait for servers to come online before resuming
    Write-host "Waiting for SMS2008R2 to come online again"
    Restart-Computer -ComputerName $SMS_2008R2 -Protocol wsman -Wait -Force
    Start-Sleep -Seconds 30

    ##Copy IIS files Hello World
    Write-host "Copy IIS files to SMS2008R2"
    Copy-Item "D:\Scripts\iisstart.htm" -Destination "\\$SMS_2008R2\c$\inetpub\wwwroot"
        
}
IF ($SMS_2019) {
    ##Install required roles on SMS server
    Write-host "Installing SMS services on SMS_2019"
    Invoke-Command -ComputerName $SMS_2019 -ScriptBlock {Install-WindowsFeature SMS, SMS-Proxy -IncludeAllSubFeature -IncludeManagementTools}

    #Wait for SMS server to come online before resuming
    Write-host "Waiting for SMS Server to come online again"
    Restart-Computer -ComputerName $SMS_2019 -Protocol wsman -Wait -Force
}


##Install Windows Admin Center
Write-host "Installing Windows Admin Center on WAC"
Invoke-Command -Computername $WAC -ScriptBlock {

    mkdir C:\Scripts\
}

Copy-Item "D:\Scripts\WindowsAdminCenter1804.msi" -Destination "\\WAC\c$\Scripts"

Invoke-Command -Computername $WAC -ScriptBlock {

    Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Scripts\WindowsAdminCenter1804.msi /qn /L*v log.txt SME_PORT=9999 SSL_CERTIFICATE_OPTION=generate'
    New-NetFirewallRule -Name WAC -DisplayName WAC -Enabled True -Profile any -Action Allow -Direction Inbound -Protocol tcp -LocalPort 9999
}

#Install Chrome on DC
Write-host "Install Chrome on DC"
D:\Scripts\installchrome.ps1
