###############
# Run from DC #
###############

$StartDateTime = get-date
Write-host "Scripts started at $StartDateTime"

#Set PSScriptRoot
$PSScriptRootFolder = "D:\Scripts"

##### LAB Config #####
#Change the Servers here based on the servers you need to deploy

$SMS_2019 = 'SMS_2019'
$WAC = 'WAC'
$SMS_2008R2 = 'SMS2008R2'

$Servers = ($SMS_2019,$Honolulu,$SMS_2008R2)

#Enable firewall rules for servers
Invoke-Command -ComputerName $Servers -ScriptsBlock { Get-NetFirewallRule -Name *FPS* | Enable-NetFirewallRule ; Enable-PSRemoting -Force -Confirm:$false }
Invoke-Command -ComputerName $Servers -ScriptsBlock { Get-NetFirewallRule -Name *rpc* | Enable-NetFirewallRule }
Invoke-Command -ComputerName $Servers -ScriptsBlock { Get-NetFirewallRule -Name *wmi* | Enable-NetFirewallRule } 

#Upgrade Powershell on 2008R2 server
IF ($SMS_2008R2){
        #Download .net 4.51
        WriteInfoHighlighted "Testing .net 4.51 presence"
        If ( Test-Path -Path "$PSScriptRootFolder\NDP451-KB2858728-x86-x64-AllOS-ENU.ex" ) {
            WriteSuccess "`t .net 4.51 is present, skipping download"
        }else{ 
            WriteInfo "`t Downloading .net 4.51"
            try{
            Invoke-WebRequest -UseBasicParsing -Uri https://download.microsoft.com/download/1/6/7/167F0D79-9317-48AE-AEDB-17120579F8E2/NDP451-KB2858728-x86-x64-AllOS-ENU.exe -OutFile "$PSScriptRootFolder\NDP451-KB2858728-x86-x64-AllOS-ENU.exe"
            }catch{
            WriteError "`t Failed to download .net 4.51!"
                }
            }

        #Download Powershell 4.0
        If (!(Test-Path "$PSScriptRootFolder\Windows6.1-KB2819745-x64-MultiPkg.msu")){
            WriteSuccess "`t .net 4.51 is present, skipping download"
        }else{     
            WriteInfo "`t Downloading PowerShell 4.0"
            try{
            Invoke-WebRequest -UseBasicParsing -Uri https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu -OutFile "$PSScriptRootFolder\Windows6.1-KB2819745-x64-MultiPkg.msu"
            }catch{
            WriteError "`t Failed to download PowerShell 4.0!"
                }
            }
        #Installing .net 4.51 and Powershell 4.0
        Invoke-Command -computername $SMS_2008R2 -ScriptsBlock {

        mkdir C:\Temp
        }
    
        Copy-Item "D:\Scripts\NDP451-KB2858728-x86-x64-AllOS-ENU.exe" -Destination "\\$SMS_2008R2\c$\Temp"
        Copy-Item "D:\Scripts\Windows6.1-KB2819745-x64-MultiPkg.msu" -Destination "\\$SMS_2008R2\c$\Temp"
    
        Invoke-Command -computername $SMS_2008R2 -ScriptsBlock {
    
        Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Temp\NDP451-KB2858728-x86-x64-AllOS-ENU.exe /quiet /norestart'
        Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu /quiet'
        }

        #Wait for servers to come online before resuming
        Write-host "Waiting for SMS2008R2 to come online again"
        restart-computer -computername $SMS_2008R2 -protocol wsman -wait

        #Install requierd Roles on 2008R2 Server
        Write-host "Installing IIS on 2008R2 Server"
        Invoke-Command -ComputerName $SMS_2008R2 -ScriptsBlock {
            Import-Module Servermanager
            Add-WindowsFeature Web-server -IncludeAllSubFeature -norestart 
            Add-WindowsFeature MicrosoftWindowsPowerShell -norestart 
        }
        #Wait for servers to come online before resuming
        Write-host "Waiting for SMS2008R2 to come online again"
        restart-computer -computername $SMS_2008R2 -protocol wsman -wait

        Copy-Item "D:\Scripts\iisstart.htm" -Destination "\\$SMS_2008R2\c$\inetpub\wwwroot"
        
    }
IF($SMS_2019){
    ##Install required roles on SMS server
    Invoke-Command -ComputerName $SMS_2019 -ScriptsBlock {Install-WindowsFeature SMS,SMS-Proxy -IncludeAllSubFeature -IncludeManagementTools}

    #Wait for SMS server to come online before resuming
    Write-host "Waiting for SMS Server to come online again"
    restart-computer -computername $SMS_2019 -protocol wsman -wait
}
    else{Write-host "No Roles installed on servers in Lab"}

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
