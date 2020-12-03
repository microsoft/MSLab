$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}

#3 servers
1..3 | ForEach-Object {$LABConfig.VMs += @{VMName = "Server$_" ; ParentVHD = 'Win2019Core_G2.vhdx'}}