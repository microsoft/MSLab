#region (optional) Install Windows Admin Center in a GW mode 
$GatewayServerName="WACGW"
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
    $ProgressPreference='Continue' #return progress preference back
}
#Create PS Session and copy install files to remote server
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SSL_CERTIFICATE_OPTION=generate"
}

$Session | Remove-PSSession

#add certificate to trusted root certs
start-sleep 10
$cert = Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My\ |where subject -eq "CN=Windows Admin Center"}
$cert | Export-Certificate -FilePath $env:TEMP\WACCert.cer
Import-Certificate -FilePath $env:TEMP\WACCert.cer -CertStoreLocation Cert:\LocalMachine\Root\

#Configure Resource-Based constrained delegation
$gatewayObject = Get-ADComputer -Identity $GatewayServerName
$computers = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name

foreach ($computer in $computers){
    $computerObject = Get-ADComputer -Identity $computer
    Set-ADComputer -Identity $computerObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
#endregion

#region (optional) Install Edge
#install edge for azure portal and authentication (if code is running from DC)
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/40e309b4-5d46-4AE8-b839-bd74b4cff36e/MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#Install Edge Beta
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
#endregion

#region prepare file servers (create some dummy files and folders)
$Servers="FS1","FS2","FS3"
Invoke-Command -ComputerName $Servers -ScriptBlock {
    Install-WindowsFeature -Name FS-FileServer
}

Invoke-Command -ComputerName "FS1","FS2","FS3" -ScriptBlock {
    #create folder for shares
    New-Item -Name Shares -Path c:\ -ItemType Directory
    $shares=1..10 | ForEach-Object {"Share$_"}

    foreach ($share in $shares) {
        New-Item -Name $share -Path c:\Shares -ItemType Directory
        #create some files
        1..1000 | ForEach-Object {
            New-Item -Path c:\Shares\$share\MyFile$_.txt -ItemType File
        }
        #CreateFileShare
        New-SMBShare -Name $share -path c:\Shares\$share
    }
}
#endregion

#Install Storage Migration Service
$SMSServerName="SMS"
Install-WindowsFeature -ComputerName $SMSServerName -Name "SMS","RSAT-SMS","SMS-Proxy"

#region migrate servers
$Servers="FS1","FS2","FS3"
$DestinationServers="FSNew1","FSNew2","FSNew3"
#install management tools
Install-WindowsFeature -Name "RSAT-SMS"

#crete password object
$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

#Create SMS Inventory tasks (same names as servers)
foreach ($Server in $Servers){
    New-SmsInventory -Name $Server -Force -ComputerName $Server -OrchestratorComputerName $SMSServerName -SourceCredential $Credentials
}

#start inventory
foreach ($server in $servers){
    Start-SmsInventory -OrchestratorComputerName $SMSServerName -Name $server -Force
}

Get-SmsState -OrchestratorComputerName $SMSServerName

#install proxy feature to destination servers
Invoke-Command -ComputerName $DestinationServers -ScriptBlock {
    Install-WindowsFeature -Name "SMS-Proxy"
}

#endregion

