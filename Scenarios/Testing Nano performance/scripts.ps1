##############################
# LabConfig in variables.ps1 #
##############################

$LabConfig=@{AdminPassword='LS1setup!'; DomainAdminName='Jaromirk'; Prefix = 'PerfTest-'; SecureBoot='ON'; CreateClientParent='No';DCEdition='ServerDataCenter'}
$NetworkConfig=@{SwitchName = 'LabSwitch' ; StorageNet1='172.16.1.'; StorageNet2='172.16.2.'} 
$LAbVMs = @()
$LAbVMs += @{ VMName = 'Win2016'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2.vhdx'          ; MemoryStartupBytes= 1GB }
$LAbVMs += @{ VMName = 'Win2016_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'      ; MemoryStartupBytes= 1GB }
$LAbVMs += @{ VMName = 'Win2016_Nano' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Nano_G2.vhdx'      ; MemoryStartupBytes= 1GB }
$LAbVMs += @{ VMName = 'Win2012'      ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2.vhdx'        ; MemoryStartupBytes= 1GB ; Unattend='DjoinCred' }
$LAbVMs += @{ VMName = 'Win2012_Core' ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2.vhdx'    ; MemoryStartupBytes= 1GB ; Unattend='DjoinCred' }

#################################
# Scripts for converting images #
#################################

#loading convert-windowsimage into the memory (notice . in front of command)
. .\Tools\convert-windowsimage.ps1
 
#win 2012r2
Convert-WindowsImage -SourcePath X:\sources\install.wim -DiskLayout UEFI -VHDPath .\ParentDisks\win2012r2_G2.vhdx `
-Edition datacenter -SizeBytes 40GB -Package .\Packages\Windows8.1-KB2919355-x64.msu,.\Packages\Windows8.1-KB3156418-x64.msu
 
#win 2012r2 core
Convert-WindowsImage -SourcePath X:\sources\install.wim -DiskLayout UEFI -VHDPath .\ParentDisks\win2012r2Core_G2.vhdx `
-Edition datacentercore -SizeBytes 40GB -Package .\Packages\Windows8.1-KB2919355-x64.msu,.\Packages\Windows8.1-KB3156418-x64.msu 
 
#win 2016
Convert-WindowsImage -SourcePath x:\sources\install.wim -DiskLayout UEFI -VHDPath .\ParentDisks\win2016_G2.vhdx `
-Edition datacenter -SizeBytes 40GB -Package .\Packages\AMD64-all-windows10.0-kb3158987-x64_6b363d8ecc6ac98ca26396daf231017a258bfc94.msu


