#Labconfig with telemetry enabled
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; <#Prefix = 'MSLab-' ;#> DCEdition='4'; Internet=$true ; InstallSCVMM='Yes'; TelemetryLevel='Full' ; TelemetryNickname='AzSHCISCVMMBareMetal' ; AdditionalNetworksConfig=@(); VMs=@()}
 