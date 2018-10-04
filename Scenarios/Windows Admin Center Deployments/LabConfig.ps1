$LabConfig = @{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WacDeployments-'; SwitchName = 'WacDeploymentsSwitch'; DCEdition='4'; Internet=$True; AdditionalNetworksConfig=@(); VMs=@() }

# Management Client Node
$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win10RS4_G2.vhdx'; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }

# Single Gateway
$LabConfig.VMs += @{ VMName = 'WacGateway'; Configuration = 'Simple'; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }

# SAN Failover cluster nodes
1..3 | ForEach-Object { $VMNames = "WacSan-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'Shared'; VMSet = 'WacSan'; HDDNumber = 1; HDDSize = 40GB; } }

# Storage Spaces Direct nodes
1..3 | ForEach-Object { $VMNames = "WacS2D-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'S2D'; HDDNumber = 2; HDDSize = 40GB;  } }
