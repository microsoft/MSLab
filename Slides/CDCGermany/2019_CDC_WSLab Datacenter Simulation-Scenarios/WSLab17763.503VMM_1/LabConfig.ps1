#basic config for Windows Server 2016, that creates VMs for S2D Hyperconverged scenario https://github.com/Microsoft/WSLab/tree/master/Scenarios/S2D%20Hyperconverged

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab17763.503VMM_1-'; InstallSCVMM='Yes'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$true ; AdditionalNetworksConfig=@(); VMs=@()}
