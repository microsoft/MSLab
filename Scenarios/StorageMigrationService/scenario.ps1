###############
# Run from DC #
###############

$StartDateTime = get-date
Write-host "Scripts started at $StartDateTime"

##### LAB Config #####
#Change the Servers here based on the servers you need to deploy

$SMS_2019 = 'SMS_2019'
$WAC = 'WAC'
$SMS_2008R2 = 'SMS2008R2'

$Servers = ($SMS_2019,$Honolulu)

#Enable firewall rules for servers
Invoke-Command -ComputerName $Servers -ScriptsBlock { Get-NetFirewallRule -Name *FPS* | Enable-NetFirewallRule ; Enable-PSRemoting -Force -Confirm:$false }
Invoke-Command -ComputerName $Servers -ScriptsBlock { Get-NetFirewallRule -Name *rpc* | Enable-NetFirewallRule }
Invoke-Command -ComputerName $Servers -ScriptsBlock { Get-NetFirewallRule -Name *wmi* | Enable-NetFirewallRule }  

#Enable remote powershell for Windows Server 2008R2


##Install required roles
Invoke-Command -ComputerName $SMS_2019 -ScriptsBlock {Install-WindowsFeature SMS,SMS-Proxy -IncludeAllSubFeature -IncludeManagementTools -Restart}
Invoke-Command -ComputerName $SMS_2008R2 -ScriptsBlock {
    Import-Module Servermanager
    Add-WindowsFeature Web-server -IncludeAllSubFeature -norestart 
    Add-WindowsFeature MicrosoftWindowsPowerShell -norestart 
    Restart-Computer
}

#Wait for servers to come online before resuming

Start-Sleep -Seconds 60

##Install Honolulu
Invoke-Command -computername $WAC -ScriptsBlock {

mkdir C:\Scripts
}

Copy-Item "D:\Scripts\WindowsAdminCenter1804.msi" -Destination "\\WAC\c$\Scripts"

Invoke-Command -computername $WAC -ScriptsBlock {

Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Scripts\WindowsAdminCenter1804.msi /qn /L*v log.txt SME_PORT=9999 SSL_CERTIFICATE_OPTION=generate'
New-NetFirewallRule -Name honolulu -DisplayName honolulu -Enabled True -Profile any -Action Allow -Direction Inbound -Protocol tcp -LocalPort 9999
}

##Copy IIS files Hello World
Copy-Item "D:\Scripts\iisstart.htm" -Destination "C:\inetpub\wwwroot"

#Install Chrome on DC

D:\Scripts\installchrome.ps1
