# Host Guardian Service !WORK IN PROGRESS!

## LabConfig for Windows Server 2019

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$false ;AdditionalNetworksConfig=@(); VMs=@()}

1..3 | % { $VMNames="HGS" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2019Core_G2.vhdx'    ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; Unattend="NoDjoin" ; vTPM=$True ; MGMTNICs=1 } }

1..2 | % { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2019Core_G2.vhdx'    ; MemoryStartupBytes= 2GB ; NestedVirt=$True ; vTPM=$True } }
 
```

## About the lab

Following lab will setup 3 node HGS cluster and then it will configure those 2 compute servers to be shielded.

## The lab

Run all scripts from Hyper-V host (not DC!)

```PowerShell
#Start all VMs
Start-VM *HGS*,*Compute*

#Variables
$FabricPlainPassword="LS1setup!" #password to access fabric nodes Compute1 and Compute2
$HGSPlainPassword   ="LS1setup!" #password to access HGS cluster nodes. In production environments it should be different

$SafeModeAdministratorPlainPassword="LS1setup!" #SafeModePassword for HGS Domain
$HGSDomainName='bastion.local'
$HGSServiceName = 'MyHGS'

#Create creds
$FabricPassword = ConvertTo-SecureString $FabricPlainPassword -AsPlainText -Force
$HGSPassword = ConvertTo-SecureString $HGSPlainPassword -AsPlainText -Force

$FabricCreds = New-Object System.Management.Automation.PSCredential ("corp\LabAdmin", $FabricPassword)
$HGSCreds = New-Object System.Management.Automation.PSCredential ("Administrator", $HGSPassword)
$HGSDomainCreds = New-Object System.Management.Automation.PSCredential ("$HGSDomainName\Administrator", $HGSPassword)

#wait until machines are up and grab IPs
do{
    $HGSServerIPs=Invoke-Command -VMName *HGS1, *HGS2, *HGS3 -Credential $HGSCreds -ScriptBlock {(Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress} -ErrorAction SilentlyContinue
    Start-Sleep 5
}until ($HGSServerIPs.count -eq 3)

#Install required HGS feature on HGS VMs
Invoke-Command -VMName *HGS1,*HGS2,*HGS3 -Credential $HGSCreds -ScriptBlock {
    Install-WindowsFeature -Name HostGuardianServiceRole -IncludeManagementTools
}

#restart VMs
Restart-VM -VMName *HGS* -Type Reboot -Force -Wait -For HeartBeat

#Install HGS on first node
Invoke-Command -VMName *HGS1 -Credential $HGSCreds -scriptblock {
    $SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $using:SafeModeAdministratorPlainPassword -Force
    Install-HgsServer -HgsDomainName $using:HGSDomainName -SafeModeAdministratorPassword $SafeModeAdministratorPassword
}

#restart HGS1
Restart-VM -VMName *HGS1 -Type Reboot -Force -Wait -For HeartBeat

#Set the DNS forwarder on the fabric DC so other nodes can find the new domain
Invoke-Command -VMName *DC -Credential $FabricCreds -ScriptBlock {
    Add-DnsServerConditionalForwarderZone -Name $using:HGSDomainName -ReplicationScope Forest -MasterServers $using:HgsServerIPs
}

#add HGS2 and HGS3
Invoke-Command -VMName *HGS2,*HGS3 -Credential $HGSCreds -ScriptBlock {
    $SafeModeAdministratorPassword = ConvertTo-SecureString -AsPlainText $using:SafeModeAdministratorPlainPassword -Force
    Install-HgsServer -HgsDomainName $using:HGSDomainName -HgsDomainCredential $using:HGSDomainCreds -SafeModeAdministratorPassword $SafeModeAdministratorPassword
}

#restart HGS2 and HGS3
Restart-VM -VMName *HGS2,*HGS3 -Type Reboot -Force -Wait -For HeartBeat

#you can create CA in Bastion forest https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-obtain-certs#request-certificates-from-your-certificate-authority

#or just create self signed cert
Invoke-Command -VMName *HGS1 -Credential $HGSDomainCreds -ScriptBlock {
    $certificatePassword = ConvertTo-SecureString -AsPlainText -String "LS1setup!" -Force

    $signCert = New-SelfSignedCertificate -Subject "CN=HGS Signing Certificate"
    Export-PfxCertificate -FilePath $env:temp\signCert.pfx -Password $certificatePassword -Cert $signCert
    Remove-Item $signCert.PSPath

    $encCert = New-SelfSignedCertificate -Subject "CN=HGS Encryption Certificate"
    Export-PfxCertificate -FilePath $env:temp\encCert.pfx -Password $certificatePassword -Cert $encCert
    Remove-Item $encCert.PSPath

    Initialize-HgsServer -HgsServiceName $using:HGSServiceName -SigningCertificatePath "$env:temp\signCert.pfx" -SigningCertificatePassword $certificatePassword -EncryptionCertificatePath "$env:Temp\encCert.pfx" -EncryptionCertificatePassword $certificatePassword -TrustTpm -hgsversion V1
}

# Wait for HGS2, HGS3 to finish dcpromo
# todo: add magic here to check for DC status
Start-sleep 30

# Join HGS2 and HGS3 to the cluster
Invoke-Command -VMName *HGS2,*HGS3 -Credential $HGSDomainCreds -ScriptBlock {
    Initialize-HgsServer -HgsServerIPAddress $using:HGSServerIPs[0]
}

# Set HGS configuration to support VMs (disable IOMMU requirement)
Invoke-Command -VMName *HGS1 -Credential $HGSCreds -ScriptBlock {
    Disable-HgsAttestationPolicy Hgs_IommuEnabled
}

# Install HostGuardian Hyper-V Support on compute nodes
Invoke-Command -VMName *Compute1,*Compute2 -Credential $FabricCreds -ScriptBlock {
    Install-WindowsFeature HostGuardian -IncludeManagementTools
}

# Restart compute nodes
Restart-VM -Name *Compute1, *Compute2 -Type Reboot -Force

# Wait for installation to complete
Start-Sleep 60

# Set registry key to not require IOMMU for VBS in VMs and apply default CI policy
# Also generate attestation artifacts (CI policy, TPM EK, and TPM baseline)
Invoke-Command -VMName *Compute1, *Compute2 -Credential $FabricCreds -ScriptBlock {
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name RequirePlatformSecurityFeatures -Value 0
    md C:\attestationdata
    $cipolicy = "C:\attestationdata\CI_POLICY_AUDIT.xml"
    Copy-Item "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" $cipolicy -Force
    # For testing, convert the policy to an audit policy to avoid constrained language mode in PS
    Set-RuleOption -FilePath $cipolicy -Option 3
    # Allowing a CI policy to be updated without a reboot can allow someone to pass attestation and replace with a bad policy, so we disallow that
    Set-RuleOption -FilePath $cipolicy -Option 16 -Delete
    ConvertFrom-CIPolicy -XmlFilePath $cipolicy -BinaryFilePath "C:\attestationdata\CI_POLICY_AUDIT.bin"
    Copy-Item "C:\attestationdata\CI_POLICY_AUDIT.bin" "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b" -Force
    Initialize-Tpm
    (Get-PlatformIdentifier -Name $env:COMPUTERNAME).Save("C:\attestationdata\TPM_EK_$env:COMPUTERNAME.xml")
    Get-HgsAttestationBaselinePolicy -Path "C:\attestationdata\TPM_Baseline_$env:COMPUTERNAME.xml" -SkipValidation
}

# Reboot VMs again for setting to take effect
Restart-VM -Name *Compute1, *Compute2 -Type Reboot -Force -Wait -For IPAddress

# Collect attestation artifacts from hosts
# todo: need some magic to copy the files to HGS

# Import the attestation policies on HGS
Invoke-Command -VMName *HGS1 -Credential $HGSCreds -ScriptBlock {
    # Every individual EK needs to be added
    Add-HgsAttestationTpmHost -Path C:\attestationdata\TPM_EK_COMPUTE1.xml -Force
    Add-HgsAttestationTpmHost -Path C:\attestationdata\TPM_EK_Compute2.xml -Force
    
    # But only one copy of the baseline and CI policy, since they should be identical on both hosts
    Add-HgsAttestationTpmPolicy -Path C:\attestationdata\TPM_Baseline_COMPUTE1.xml -Name "Hyper-V TPM Baseline"
    Add-HgsAttestationCIPolicy -Path C:\attestationdata\CI_POLICY_AUDIT.bin -Name "AllowMicrosoft-AUDIT-CI"
}

# Now, have the hosts try to attest
Invoke-Command -VMName *Compute1, *Compute2 -Credential $FabricCreds -ScriptBlock {
    Set-HgsClientConfiguration -AttestationServerUrl "http://$using:HGSServiceName.$using:HGSDomainName/Attestation" -KeyProtectionServerUrl "http://$using:HGSServiceName.$using:HGSDomainName/KeyProtection"
}
 
```