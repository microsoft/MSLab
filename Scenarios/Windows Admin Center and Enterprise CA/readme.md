# Windows Admin Center and Enterprise CA

<!-- TOC -->

- [Windows Admin Center and Enterprise CA](#windows-admin-center-and-enterprise-ca)
    - [Sample LabConfig for Windows Server 2016](#sample-labconfig-for-windows-server-2016)
    - [Sample LabConfig for Windows Server 2019](#sample-labconfig-for-windows-server-2019)
    - [Desktop mode installation on Windows 10](#desktop-mode-installation-on-windows-10)
    - [Server Scenarios prerequisites](#server-scenarios-prerequisites)
        - [Install RSAT on Management machine](#install-rsat-on-management-machine)
        - [Install and configure ADCS on the CA Server](#install-and-configure-adcs-on-the-ca-server)
    - [Gateway mode installation on single Windows Server](#gateway-mode-installation-on-single-windows-server)
        - [Generate a certificate](#generate-a-certificate)
        - [Install Windows Admin Center](#install-windows-admin-center)
        - [Run Windows Admin Center](#run-windows-admin-center)

<!-- /TOC -->

## Sample LabConfig for Windows Server 2016

```PowerShell
$LabConfig = @{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$True; AdditionalNetworksConfig=@(); VMs=@() }

# Management Client Node
$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win10RS5_G2.vhdx'   ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }
# Single Gateway
$LabConfig.VMs += @{ VMName = 'WacGateway'; Configuration = 'Simple'; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }
# Certification Authority
$LabConfig.VMs += @{ VMName = 'CA'        ; Configuration = 'Simple'; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB }
# SAN Failover cluster nodes
1..3 | ForEach-Object { $VMNames = "WacSan-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'Shared'; VMSet = 'WacSan'; HDDNumber = 1; HDDSize = 40GB; } }
# Storage Spaces Direct nodes
1..3 | ForEach-Object { $VMNames = "WacS2D-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2016Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'S2D'; HDDNumber = 2; HDDSize = 40GB;  } }
 
```

## Sample LabConfig for Windows Server 2019

```PowerShell
$LabConfig = @{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab2019-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$True; AdditionalNetworksConfig=@(); VMs=@() }

# Management Client Node
$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win10RS5_G2.vhdx'; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }
# Single Gateway
$LabConfig.VMs += @{ VMName = 'WacGateway'; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True }
# Certification Authority
$LabConfig.VMs += @{ VMName = 'CA'        ; Configuration = 'Simple'; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 1GB; MemoryMinimumBytes = 1GB }
# SAN Failover cluster nodes
1..3 | ForEach-Object { $VMNames = "WacSan-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'Shared'; VMSet = 'WacSan'; HDDNumber = 1; HDDSize = 40GB; } }
# Storage Spaces Direct nodes
1..3 | ForEach-Object { $VMNames = "WacS2D-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'S2D'; HDDNumber = 2; HDDSize = 40GB;  } }
 
```

> **Note:** All commands below should be executed from the `Management` virtual machine that runs Windows 10.

## Desktop mode installation on Windows 10

```PowerShell
#Download Windows Admin Center to downloads
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

#Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

#Open Windows Admin Center
    Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
 
```

## Server Scenarios prerequisites

### Install RSAT on Management machine

First, we will install RSAT (it's necessary to work with servers remotely).

```PowerShell
Get-WindowsCapability -Online -Name RSAT* | Add-WindowsCapability -Online
 
```

### Install and configure ADCS on the CA Server

Certification Authority would be used to issue signed certificates for the Windows Admin Center instances.

On `CA` install ADCS role, and after role installation we will create custom `Computer2019` template. The CA install does not follow all best practices. For more details visit Certification Authority WSLab Scenario.

```PowerShell
#Create CA Policy file
$Content=@"
[Version]
Signature="$Windows NT$"

[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=False

[AllIssuancePolicy]
OID=2.5.29.32.0
URL=http://ca.corp.contoso.com/certdata/cps.txt

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

Invoke-Command -ComputerName CA -ScriptBlock {
    Set-Content -Value $using:Content -Path C:\windows\CAPolicy.inf
}

#Install ADCS
Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools -ComputerName CA

#Enable CredSSP
# Temporarily enable CredSSP delegation to avoid double-hop issue
Enable-WSManCredSSP -Role "Client" -DelegateComputer CA -Force
Invoke-Command -ComputerName CA -ScriptBlock { Enable-WSManCredSSP Server -Force }

$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

#Install ADCS Certification Authority Role Services
Invoke-Command -ComputerName CA -Credential $Credentials -Authentication Credssp -ScriptBlock {
    $CaProperties = @{
        CACommonName        = "Contoso-Root-CA"
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
Invoke-Command -ComputerName CA -ScriptBlock { Disable-WSManCredSSP Server }

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

#CreateTemplate
Import-Module ActiveDirectory
$DisplayName="Computer2016"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1207959552'
        'msPKI-Enrollment-Flag' = [System.Int32]'32'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056512'
        'msPKI-RA-Application-Policies' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`')
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultCSPs' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft Software Key Storage Provider','2,Microsoft Platform Crypto Provider')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

#endregion

#Publish Computer2016 Certificate
    $DisplayName="Computer2016"
    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext

    ### WARNING: Issues on all available CAs. Test in your environment.
    $EnrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    $CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter * -Server $Server
    ForEach ($CA in $CAs) {
        Set-ADObject -Identity $CA.DistinguishedName -Add @{certificateTemplates=$DisplayName} -Server $Server
    }
 
```

## Gateway mode installation on single Windows Server

### Generate a certificate

In order to use own certificate instead of default self-signed one, certificate needs to be generated before actually installing Windows Admin Center and certificate needs to be imported in Computer store of that machine. Let's do it using Autoenrollment.

```PowerShell
# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
Import-Module PSPKI

#Set Cert Template permission
Get-CertificateTemplate -Name "Computer2016" | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "WacGateway$" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

#Configure AutoEnrollment policy and enroll cert on WacGateway
Invoke-Command -ComputerName WacGateway -ScriptBlock {
    Set-CertificateAutoEnrollmentPolicy -StoreName MY -PolicyState Enabled -ExpirationPercentage 10 -EnableTemplateCheck -EnableMyStoreManagement -context Machine
    certutil -pulse
}
 
```

### Install Windows Admin Center

> **Note:** If you don't want to download installer over the Internet, copy MSI file over to virtual machine manually.

```PowerShell
#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
}

#Create PS Session
$Session=New-PSSession -ComputerName "WacGateway"
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Grab Certificate Thumbprint
$Cert=Invoke-Command -Session $session -ScriptBlock {
    Get-ChildItem -Path Cert:\LocalMachine\My\ | where Subject -eq CN=WacGateway.Corp.contoso.com
}

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SME_THUMBPRINT=$($using:cert.Thumbprint) SSL_CERTIFICATE_OPTION=installed"
}
 
```

### Run Windows Admin Center

After the installation on `WacGateway` Windows Admin Center's network service is started automatically. In order to access it you need to just open the web browser from the `Management` virtual machine, navigate to http://wacgateway.corp.contoso.com/ and you can log in to the Windows Admin Center.