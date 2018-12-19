<!-- TOC -->

- [S2D and SDN](#s2d-and-sdn)
    - [LabConfig for Windows Server 2019 !!! WORK IN PROGRESS !!!](#labconfig-for-windows-server-2019--work-in-progress-)
    - [Prereq](#prereq)
    - [Finish S2D HC scenario](#finish-s2d-hc-scenario)
        - [Make sure management features are installed](#make-sure-management-features-are-installed)
    - [Configure Certificates](#configure-certificates)
        - [Install and configure ADCS on the CA Server](#install-and-configure-adcs-on-the-ca-server)
        - [Create certificate templates](#create-certificate-templates)
        - [Set permissions on NetworkController certificate template and Nodes Cert template and publish it](#set-permissions-on-networkcontroller-certificate-template-and-nodes-cert-template-and-publish-it)
    - [Deploy Network Controller](#deploy-network-controller)
        - [Add machine certs](#add-machine-certs)
        - [Generate and Export NCClus Certificate](#generate-and-export-ncclus-certificate)
        - [Add Cert to network controller nodes](#add-cert-to-network-controller-nodes)
        - [Install NC](#install-nc)

<!-- /TOC -->

# S2D and SDN

## LabConfig for Windows Server 2019 !!! WORK IN PROGRESS !!!

```PowerShell
#Labconfig is same as default for Windows Server 2019, just with nested virtualization and 4GB for startup memory
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

#S2D Cluster
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$true }}

#Certification Authority
$LabConfig.VMs += @{ VMName = 'CA' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; vTPM=$True ; MGMTNICs=1 }

#SDN Cluster
1..3 | % {$VMNames="NC"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx';MemoryStartupBytes= 1GB ; MGMTNICs=1}}

# Management machine
$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win10RS5_G2.vhdx' ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True ; DisableWCF=$true ; MGMTNICs=1 }
 
```

## Prereq

## Finish S2D HC scenario

Run first 9 regions of S2D [Hyperconverged scenario](https://raw.githubusercontent.com/Microsoft/WSLab/master/Scenarios/S2D%20Hyperconverged/Scenario.ps1). Run all code from DC

Collapse all regions with ctrl+m, select first 9 regions and paste into elevated PowerShell (right-click)

![](/Scenarios/S2D%20and%20Diskspd/Screenshots/Regions.png)

Note: Enable-ClusterS2D in Windows Server 2019 requires you to reach support to get steps to make it work on 2019 RTM as WSSD programme will be officially launched starting 2019. You will need similar info for SDN.

```PowerShell
#Sample
Invoke-Command -ComputerName $servers -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\SYSTEM\XYZ" -Name XYZ -value 1
}
 
```

### Make sure management features are installed

```PowerShell
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name "RSAT-ADDS","RSAT-AD-PowerShell","RSAT-ADCS","RSAT-NetworkController","RSAT-Clustering","RSAT-Hyper-V-Tools","Web-Mgmt-Console","Web-Scripting-Tools"
    }elseif ($WindowsInstallationType -eq "Client"){
        $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.NetworkController.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.CertificateServices.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        foreach ($Capability in $Capabilities){
            Add-WindowsCapability -Name $Capability -Online
        }
        #install iis management tools
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole","IIS-WebServerManagementTools","IIS-ManagementConsole","IIS-ManagementScriptingTools" 
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -NoRestart
    }
 
```

Since this is not script-able to install only subfeatures (due to nature of Enable-WindowsOptionalFeature that requires parent features enabled) Above script installs parent features and removes features that are not needed in Windows 10.

![](/Scenarios/S2D%20and%SDN/Screenshots/win10features.png)

## Configure Certificates

### Install and configure ADCS on the CA Server

On `CA` install ADCS role, and after role installation we will create custom `NCRestEndPoint` template. Steps are the same as in Certification Authority WSLab Scenario.

```PowerShell
$CAServer="CA"
$CAServerFQDN="CA.corp.contoso.com"
$CAAdminUsername="CORP\LabAdmin"
$CAAdminPass="LS1setup!"
$CompanyName="Contoso"

#Install IIS
Install-WindowsFeature Web-WebServer -ComputerName $CAServer -IncludeManagementTools

#Create a CertData Folder and CPS Text File
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    New-Item -Path C:\inetpub\wwwroot\CertData -Type Directory
    Write-Output "Placeholder for Certificate Policy Statement (CPS). Modify as needed by your organization." | Out-File C:\inetpub\wwwroot\CertData\cps.txt
}

#New IIS Virtual Directory
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    $vDirProperties = @{
        Site         = "Default Web Site"
        Name         = "CertData"
        PhysicalPath = 'C:\inetpub\wwwroot\CertData'
    }
    New-WebVirtualDirectory @vDirProperties
}

#Allow IIS Directory Browsing & Double Escaping
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProperties.site)\$($vDirProperties.name)"
    Set-WebConfigurationProperty -filter /system.webServer/Security/requestFiltering -name allowDoubleEscaping -value $true -PSPath "IIS:\Sites\$($vDirProperties.site)"
}

#New Share for the CertData Directory
New-SmbShare -CimSession $CAServer -Name CertData -Path C:\inetpub\wwwroot\CertData -ReadAccess "Corp\domain users" -ChangeAccess "corp\cert publishers"
#configure NTFS Permissions
Invoke-Command -ComputerName $CAServer -ScriptBlock {(Get-SmbShare CertData).PresetPathAcl | Set-Acl}

#Create CA Policy file
$Content=@"
[Version]
Signature="$Windows NT$"

[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=False

[AllIssuancePolicy]
OID=2.5.29.32.0
URL=http://$CAServerFQDN/certdata/cps.txt

[BasicConstraintsExtension]
PathLength=0
Critical=True

[certsrv_server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=0
"@

Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Set-Content -Value $using:Content -Path C:\windows\CAPolicy.inf
}

#Install ADCS
Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools -ComputerName $CAServer

#Enable CredSSP
# Temporarily enable CredSSP delegation to avoid double-hop issue
Enable-PSRemoting -Force  #Win10 has remoting disabled by default
Enable-WSManCredSSP -Role "Client" -DelegateComputer $CAServer -Force
Invoke-Command -ComputerName $CAServer -ScriptBlock { Enable-WSManCredSSP Server -Force }

$password = ConvertTo-SecureString $CAAdminPass -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ($CAAdminUsername, $password)

#Install ADCS Certification Authority Role Services
Invoke-Command -ComputerName $CAServer -Credential $Credentials -Authentication Credssp -ScriptBlock {
    $CaProperties = @{
        CACommonName        = "$($Using:CompanyName)-Root-CA"
        CAType              = "EnterpriseRootCA"
        CryptoProviderName  = "ECDSA_P256#Microsoft Software Key Storage Provider"
        HashAlgorithmName   = "SHA256"
        KeyLength           = 256
        ValidityPeriod      = "Years"
        ValidityPeriodUnits = 10
    }
    Install-AdcsCertificationAuthority @CaProperties -force
}

# Disable CredSSP
Disable-WSManCredSSP -Role Client
Invoke-Command -ComputerName $CAServer -ScriptBlock { Disable-WSManCredSSP Server }

#Configure Max Validity Period of Certificates Issued by this CA
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Certutil -setreg ca\ValidityPeriodUnits 5
    Certutil -setreg ca\ValidityPeriod "Years"
}

#Configure the CRL Validity Periods
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Certutil -setreg CA\CRLPeriodUnits 6
    Certutil -setreg CA\CRLPeriod "Days"
    Certutil -setreg CA\CRLDeltaPeriodUnits 0
    Certutil -setreg CA\CRLDeltaPeriod "Hours"
    Certutil -setreg CA\CRLOverlapUnits 3
    Certutil -setreg ca\CRLOverlapPeriod "Days"
}

#Configure the CDP Locations
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    ## Remove Existing CDP URIs
    $CrlList = Get-CACrlDistributionPoint
    ForEach ($Crl in $CrlList) { Remove-CACrlDistributionPoint $Crl.uri -Force }

    ## Add New CDP URIs
    Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri C:\inetpub\wwwroot\CertData\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri "http://$using:CAServerFQDN/certdata/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force
}

#Configure the AIA Locations
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    ## Remove Existing AIA URIs
    $AiaList = Get-CAAuthorityInformationAccess
    ForEach ($Aia in $AiaList) { Remove-CAAuthorityInformationAccess $Aia.uri -Force }
    ## Add New AIA URIs
    Certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt"
    Add-CAAuthorityInformationAccess -AddToCertificateAia -uri "http://$using:CAServerFQDN/certdata/%3%4.crt" -Force
}

#Restart the CA Service & Publish a New CRL
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Restart-Service certsvc
    Start-Sleep 10
    Certutil -crl
}

#Copy the Root Certificate File to the CertData Folder
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Copy-Item "C:\Windows\System32\Certsrv\CertEnroll\$($using:CAServerFQDN)_$($using:CompanyName)-Root-CA.crt" "C:\inetpub\wwwroot\CertData\$($using:CAServerFQDN)_$($using:CompanyName)-Root-CA.crt"
}

#Rename the Root Certificate File
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    Rename-Item "C:\inetpub\wwwroot\CertData\$($using:CAServerFQDN)_$($using:CompanyName)-Root-CA.crt" "$($using:CompanyName)-Root-CA.crt"
}

#Export the Root Certificate in PEM Format
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *$($using:CompanyName)-Root-CA* | select -First 1
    $CACert |Export-Certificate -Type CERT -FilePath C:\inetpub\wwwroot\CertData\$($using:CompanyName)-Root-CA.cer
    Rename-Item "C:\inetpub\wwwroot\CertData\$($using:CompanyName)-Root-CA.cer" "$($using:CompanyName)-Root-CA.pem"
}

#Add mime type
Invoke-Command -ComputerName $CAServer -ScriptBlock {
    #& $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /-"[fileExtension='.pem']"
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /+"[fileExtension='.pem',mimeType='text/plain']"
}

#configure IIS remote management
Invoke-Command -ComputerName $CAServer -ScriptBlock{
    Install-WindowsFeature  Web-Mgmt-Service
    Set-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1
    Set-Service -name WMSVC  -StartupType Automatic
    Start-Service WMSVC
}
 
```

### Create certificate templates

```PowerShell
# Create and Publish Template
#region initial functions

Function Get-RandomHex {
param ([int]$Length)
    $Hex = '0123456789ABCDEF'
    [string]$Return = $null
    For ($i=1;$i -le $length;$i++) {
        $Return += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16),1)
    }
    Return $Return
}

Function IsUniqueOID {
param ($cn,$TemplateOID,$Server,$ConfigNC)
    $Search = Get-ADObject -Server $Server `
        -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
        -Filter {cn -eq $cn -and msPKI-Cert-Template-OID -eq $TemplateOID}
    If ($Search) {$False} Else {$True}
}

Function New-TemplateOID {
Param($Server,$ConfigNC)
    <#
    OID CN/Name                    [10000000-99999999].[32 hex characters]
    OID msPKI-Cert-Template-OID    [Forest base OID].[1000000-99999999].[10000000-99999999]  <--- second number same as first number in OID name
    #>
    do {
        $OID_Part_1 = Get-Random -Minimum 1000000  -Maximum 99999999
        $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Part_3 = Get-RandomHex -Length 32
        $OID_Forest = Get-ADObject -Server $Server `
            -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
            -Properties msPKI-Cert-Template-OID |
            Select-Object -ExpandProperty msPKI-Cert-Template-OID
        $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
        $Name = "$OID_Part_2.$OID_Part_3"
    } until (IsUniqueOID -cn $Name -TemplateOID $msPKICertTemplateOID -Server $Server -ConfigNC $ConfigNC)
    Return @{
        TemplateOID  = $msPKICertTemplateOID
        TemplateName = $Name
    }
}

Function New-Template {
Param($DisplayName,$TemplateOtherAttributes)

    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext
    #Create OID
        $OID = New-TemplateOID -Server $Server -ConfigNC $ConfigNC
        $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
        $OIDOtherAttributes = @{
                'DisplayName' = $DisplayName
                'flags' = [System.Int32]'1'
                'msPKI-Cert-Template-OID' = $OID.TemplateOID
        }
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $OIDOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server
    #Create Template itself
        $TemplateOtherAttributes+= @{
            'msPKI-Cert-Template-OID' = $OID.TemplateOID
        }
        $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        New-ADObject -Path $TemplatePath -OtherAttributes $TemplateOtherAttributes -Name $DisplayName -DisplayName $DisplayName -Type pKICertificateTemplate -Server $Server
}

#endregion

#region Create Templates

Import-Module ActiveDirectory

#Create NCRestEndPoint template (legacy key storage provider)

$DisplayName="NCRestEndPoint"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'msPKI-Certificate-Name-Flag' = [System.Int32]'9'
        'msPKI-Enrollment-Flag' = [System.Int32]'0'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056912'
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'pKIKeyUsage' = [System.Byte[]]@('160')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

<# Key Storage Provider, ECDH, does not work
$DisplayName="NCRestEndPoint"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'msPKI-Certificate-Name-Flag' = [System.Int32]'9'
        'msPKI-Enrollment-Flag' = [System.Int32]'32'
        'msPKI-Minimal-Key-Size' = [System.Int32]'521'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056656'
        'msPKI-RA-Application-Policies' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`ECDH_P521`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`')
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultCSPs' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft Software Key Storage Provider')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes
#>

#Create NCNodes template (Legacy provider)

$DisplayName="NCNodes"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1073741824'
        'msPKI-Enrollment-Flag' = [System.Int32]'0'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056912'
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes


<#Key Storage Provider, ECDH
$DisplayName="NCNodes"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1073741824'
        'msPKI-Enrollment-Flag' = [System.Int32]'32'
        'msPKI-Minimal-Key-Size' = [System.Int32]'521'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056512'
        'msPKI-RA-Application-Policies' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`ECDH_P521`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`')
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultCSPs' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2,Microsoft Smart Card Key Storage Provider','1,Microsoft Software Key Storage Provider')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes
#>

#endregion
 
```

### Set permissions on NetworkController certificate template and Nodes Cert template and publish it

To set permissions is PSPKI module needed. You can find more info here https://www.sysadmins.lv/projects/pspki/default.aspx

```PowerShell
# Install PSPKI module for managing Certification Authority
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name PSPKI -Force
    If ((Get-ExecutionPolicy) -eq "restricted"){
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
    }
    Import-Module PSPKI

#Set permissions on NCNodes template
    $Computers="NC1","NC2","NC3"
    foreach ($Computer in $Computers){
        Get-CertificateTemplate -Name "NCNodes" | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$Computer$" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl
    }

#Publish Certificates
    $DisplayNames="NCRestEndPoint","NCNodes"
    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext

    ### WARNING: Issues on all available CAs. Test in your environment.
    $EnrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    $CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter * -Server $Server
    ForEach ($CA in $CAs) {
        foreach ($DisplayName in $DisplayNames){
            Set-ADObject -Identity $CA.DistinguishedName -Add @{certificateTemplates=$DisplayName} -Server $Server
        }
    }
 
```

## Deploy Network Controller

### Add machine certs

```PowerShell
    #Set Autoenrollment policy and enroll certs
    $Computers="NC1","NC2","NC3"
    Invoke-Command -ComputerName $Computers -ScriptBlock {
        Set-CertificateAutoEnrollmentPolicy -StoreName MY -PolicyState Enabled -ExpirationPercentage 10 -EnableTemplateCheck -EnableMyStoreManagement -context Machine
        certutil -pulse
    }
 
```

### Generate and Export NCClus Certificate

```PowerShell
#First set permissions, so Machine Management can enroll certificate
    Get-CertificateTemplate -Name "NCRestEndPoint" | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$env:ComputerName$" -AccessType Allow -AccessMask Read, Enroll | Set-CertificateTemplateAcl

#Generate Certificate to local machine store
Get-Certificate -Template NCRestEndPoint -SubjectName "CN=ncclus.corp.contoso.com" -CertStoreLocation Cert:\LocalMachine\My

#Export Certificate
$Password = "LS1setup!"
$SecurePassword = ConvertTo-SecureString -String $Password -Force –AsPlainText
$Certificate=Get-ChildItem -Path cert:\LocalMachine\My | where-object {$_.SubjectName.Name -eq "CN=ncclus.corp.contoso.com"}
Export-PfxCertificate -Cert $Certificate -FilePath $env:USERPROFILE\Downloads\NCCert.pfx -Password $SecurePassword -Verbose
 
```

### Add Cert to network controller nodes

```PowerShell
#Copy certificate to remote servers
$Computers="NC1","NC2","NC3"
$sessions=New-PSSession -ComputerName $computers
foreach ($Session in $sessions){
    Copy-Item -Path $env:USERPROFILE\Downloads\NCCert.pfx -Destination $env:USERPROFILE\Downloads\NCCert.pfx -ToSession $session
}

#import certificate
$CertPassword="LS1setup!"

Invoke-Command -Session $Sessions -ScriptBlock {
    Import-PfxCertificate -Exportable -FilePath $env:USERPROFILE\Downloads\NCCert.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String $using:CertPassword -Force –AsPlainText) -Verbose
}
 
```

### Install NC

```PowerShell
$Servers="NC1","NC2","NC3"
$ManagementSecurityGroupName="NCManagementAdmins" #Group for users with permission to configure Network Controller
$ClientSecurityGroupName="NCRESTClients"          #Group for users with configure and manage networks permission using NC
$LOGFileShareName="SDN_Logs"
$LogAccessAccountName="NCLog"
$LogAccessAccountPassword="LS1setup!"

#Create ManagementSecurityGroup
New-ADGroup -Name $ManagementSecurityGroupName -GroupScope Global -Path "ou=workshop,dc=corp,dc=contoso,dc=com"
Add-ADGroupMember -Identity $ManagementSecurityGroupName -Members "Domain Admins"

#Create NCRestClients group
New-ADGroup -Name $ClientSecurityGroupName -GroupScope Global -Path "ou=workshop,dc=corp,dc=contoso,dc=com"
Add-ADGroupMember -Identity $ClientSecurityGroupName -Members "Domain Admins"

#Create account for log access
New-ADUser -Name $LogAccessAccountName -AccountPassword  (ConvertTo-SecureString "LS1setup!" -AsPlainText -Force) -Enabled $True -Path  "ou=workshop,dc=corp,dc=contoso,dc=com"

#Create file share for logs
Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:LOGFileShareName -ItemType Directory}
$accounts=@()
$accounts+="corp\$LogAccessAccountName"
New-SmbShare -Name $LOGFileShareName -Path "c:\Shares\$LOGFileShareName" -FullAccess $accounts -CimSession DC


#Install NC Role
Invoke-Command -ComputerName $servers -ScriptBlock {
    Install-WindowsFeature -Name NetworkController -IncludeManagementTools
}

#region Kerberos based authentication (Recommended)
    #Create Node Objects
    $NodeObject1=New-NetworkControllerNodeObject -Name "NC1" -Server "NC1.corp.contoso.com" -FaultDomain "fd:/rack1/host1" -RestInterface "Ethernet"
    $NodeObject2=New-NetworkControllerNodeObject -Name "NC2" -Server "NC2.corp.contoso.com" -FaultDomain "fd:/rack2/host2" -RestInterface "Ethernet"
    $NodeObject3=New-NetworkControllerNodeObject -Name "NC3" -Server "NC3.corp.contoso.com" -FaultDomain "fd:/rack3/host3" -RestInterface "Ethernet"

    #Grab certificate
    $Certificate = Invoke-Command -ComputerName $Servers[0] -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My | where Subject -eq "CN=ncclus.corp.contoso.com"}

    #Install NC Cluster
    $password = ConvertTo-SecureString $LogAccessAccountPassword -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ("CORP\$LogAccessAccountName", $password)
    Install-NetworkControllerCluster -Node @($NodeObject1,$NodeObject2,$NodeObject3) -ClusterAuthentication kerberos -ManagementSecurityGroup $ManagementSecurityGroupName -DiagnosticLogLocation "\\DC\$LOGFileShareName" -LogLocationCredential $cred -CredentialEncryptionCertificate $Certificate
#endregion

<# 
#region Certificate based authentication example
    #Create Node Objects
    $Cert1=Invoke-Command -ComputerName "NC1" -ScriptBlock {Get-ChildItem cert:\LocalMachine\My | where Subject -eq "CN=NC1.corp.contoso.com"}
    $NodeObject1=New-NetworkControllerNodeObject -Name "NC1" -Server "NC1.corp.contoso.com" -FaultDomain "fd:/rack1/host1" -RestInterface "Ethernet" -NodeCertificate $Cert1
    $Cert2=Invoke-Command -ComputerName "NC2" -ScriptBlock {Get-ChildItem cert:\LocalMachine\My | where Subject -eq "CN=NC2.corp.contoso.com"}
    $NodeObject2=New-NetworkControllerNodeObject -Name "NC2" -Server "NC2.corp.contoso.com" -FaultDomain "fd:/rack2/host2" -RestInterface "Ethernet" -NodeCertificate $Cert2
    $Cert3=Invoke-Command -ComputerName "NC3" -ScriptBlock {Get-ChildItem cert:\LocalMachine\My | where Subject -eq "CN=NC3.corp.contoso.com"}
    $NodeObject3=New-NetworkControllerNodeObject -Name "NC3" -Server "NC3.corp.contoso.com" -FaultDomain "fd:/rack3/host3" -RestInterface "Ethernet" -NodeCertificate $Cert3

    #Grab Rest certificate
    $Certificate = Invoke-Command -ComputerName $Servers[0] -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My | where Subject -eq "CN=ncclus.corp.contoso.com"}

    #Install NC Cluster
    $password = ConvertTo-SecureString $LogAccessAccountPassword -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ("CORP\$LogAccessAccountName", $password)
    Install-NetworkControllerCluster -Node @($NodeObject1,$NodeObject2,$NodeObject3) -ClusterAuthentication X509 -ManagementSecurityGroup $ManagementSecurityGroupName -DiagnosticLogLocation "\\DC\$LOGFileShareName" -LogLocationCredential $cred -CredentialEncryptionCertificate $Certificate

#>
#endregion

```