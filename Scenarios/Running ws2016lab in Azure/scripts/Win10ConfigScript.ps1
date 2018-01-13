#Download and unzip ws2016lab scripts
New-Item -Type Directory -Name ws2016lab -Path d:
Invoke-WebRequest -UseBasicParsing -Uri https://github.com/Microsoft/ws2016lab/blob/master/scripts.zip?raw=true -OutFile d:\scripts.zip
Expand-Archive d:\scripts.zip -DestinationPath d:\ws2016lab -Force

#enable Hyper-V
Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online

#disable WCF in start menu
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -value 1 

#restart computer
#Restart-Computer