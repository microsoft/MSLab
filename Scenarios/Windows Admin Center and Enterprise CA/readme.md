# Windows Admin Center and Enterprise CA

<!-- TOC -->

- [Windows Admin Center and Enterprise CA](#windows-admin-center-and-enterprise-ca)
    - [Sample LabConfig for Windows Server 2019](#sample-labconfig-for-windows-server-2019)
    - [Desktop mode installation on Windows 10](#desktop-mode-installation-on-windows-10)
    - [GW mode installation with Self-Signed cert](#gw-mode-installation-with-self-signed-cert)
        - [Install Windows Admin Center in a GW mode](#install-windows-admin-center-in-a-gw-mode)
        - [Install Edge](#install-edge)
    - [Server Scenarios with Certs prerequisites](#server-scenarios-with-certs-prerequisites)
        - [Install prerequisites on Win10 or DC machine](#install-prerequisites-on-win10-or-dc-machine)
        - [Install and configure ADCS on the CA Server](#install-and-configure-adcs-on-the-ca-server)
    - [Gateway mode installation on single Windows Server](#gateway-mode-installation-on-single-windows-server)
        - [Create Computer Template](#create-computer-template)
        - [Generate a certificate](#generate-a-certificate)
        - [Install Windows Admin Center](#install-windows-admin-center)
        - [Run Windows Admin Center](#run-windows-admin-center)
    - [Clustered Windows Admin Center installations](#clustered-windows-admin-center-installations)
        - [Prereq - Create custom certificate template](#prereq---create-custom-certificate-template)
        - [Gateway mode installation on Cluster with Shared storage](#gateway-mode-installation-on-cluster-with-shared-storage)
            - [Install Failover Cluster](#install-failover-cluster)
            - [Grab Certificate](#grab-certificate)
            - [Download Windows Admin Center files](#download-windows-admin-center-files)
            - [Install Windows Admin Center on cluster](#install-windows-admin-center-on-cluster)
            - [Navigate to Windows Admin Center console](#navigate-to-windows-admin-center-console)
        - [Gateway mode installation on Cluster with Storage Spaces Direct](#gateway-mode-installation-on-cluster-with-storage-spaces-direct)
            - [Install Failover Cluster](#install-failover-cluster-1)
            - [Grab Certificate](#grab-certificate-1)
            - [Download Windows Admin Center files](#download-windows-admin-center-files-1)
            - [Install Windows Admin Center on cluster](#install-windows-admin-center-on-cluster-1)
            - [Navigate to Windows Admin Center console](#navigate-to-windows-admin-center-console-1)
    - [Operate Windows Admin Center](#operate-windows-admin-center)
        - [Generate list of computers to import](#generate-list-of-computers-to-import)
        - [Configure Resource-Based constrained delegation](#configure-resource-based-constrained-delegation)

<!-- /TOC -->

## Sample LabConfig for Windows Server 2019

```PowerShell
$LabConfig = @{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLab-'; SwitchName = 'LabSwitch'; DCEdition='4'; Internet=$True; AdditionalNetworksConfig=@(); VMs=@() }

## Without Certs Machines
# Win10 Client Node
$LabConfig.VMs += @{ VMName = 'Win10' ; ParentVHD = 'Win1019H1_G2.vhdx'   ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True ; DisableWCF=$True ; MGMTNICs=1}
# Single Gateway (NoCert from CA)
$LabConfig.VMs += @{ VMName = 'WACGW' ; ParentVHD = 'Win2019Core_G2.vhdx'; MGMTNICs=1}

## Machines for Cert scenario

# Certification Authority
$LabConfig.VMs += @{ VMName = 'CA' ; ParentVHD = 'Win2019Core_G2.vhdx'; MGMTNICs=1}
# Single Gateway
$LabConfig.VMs += @{ VMName = 'WACGWCert' ; ParentVHD = 'Win2019Core_G2.vhdx'; MGMTNICs=1}
# SAN Failover cluster nodes
1..2 | ForEach-Object { $VMNames = "WacSan-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'Shared'; VMSet = 'WacSan'; SSDNumber=1 ; SSDSize=1GB ; HDDNumber = 1; HDDSize = 40GB ; MGMTNICs=1 } }
# Storage Spaces Direct nodes
1..2 | ForEach-Object { $VMNames = "WacS2D-Node0"; $LABConfig.VMs += @{ VMName = "$VMNames$_"; ParentVHD = 'Win2019Core_G2.vhdx'; MemoryStartupBytes = 512MB; Configuration = 'S2D'; HDDNumber = 2; HDDSize = 40GB ; MGMTNICs=1} }
 
```

## Desktop mode installation on Windows 10

> **Note:** All commands below should be executed from the `Win10` virtual machine that runs Windows 10.

```PowerShell
$ProgressPreference='SilentlyContinue' #for faster download
#Download Windows Admin Center to downloads
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

#Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate"

#Open Windows Admin Center
    Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"
 
```

## GW mode installation with Self-Signed cert

> **Note:** All commands below should be executed from the `DC` virtual machine

This just a quick way to setup WAC in GW mode for testing

### Install Windows Admin Center in a GW mode

```PowerShell
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
```

### Install Edge

```PowerShell
#Install Edge
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/07367ab9-ceee-4409-a22f-c50d77a8ae06/MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
 
```

## Server Scenarios with Certs prerequisites

### Install prerequisites on Win10 or DC machine

Run following code from Win10 machine or from DC

First, we will install RSAT (it's necessary to work with servers remotely).

```PowerShell
#Detect if code is running on server or Win10 and install necessary features
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
if ($WindowsInstallationType -eq "Server"){
    Install-WindowsFeature -Name "RSAT-ADDS","RSAT-AD-PowerShell","RSAT-ADCS","RSAT-Clustering","RSAT-Hyper-V-Tools"
}elseif ($WindowsInstallationType -eq "Client"){
    $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.NetworkController.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.CertificateServices.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    foreach ($Capability in $Capabilities){
        Add-WindowsCapability -Name $Capability -Online
    }
}
 
```

### Install and configure ADCS on the CA Server

Certification Authority would be used to issue signed certificates for the Windows Admin Center instances.

On `CA` install ADCS role, and after role installation we will create custom `Computer2019` template. The CA install does not follow all best practices. For more details visit Certification Authority WSLab Scenario.

```PowerShell
$CAServerName="CA"

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

Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Set-Content -Value $using:Content -Path C:\windows\CAPolicy.inf
}

#Install ADCS
Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools -ComputerName $CAServerName

#Enable CredSSP
# Temporarily enable CredSSP delegation to avoid double-hop issue
Enable-PSRemoting -Force  #Win10 has remoting disabled by default
Enable-WSManCredSSP -Role "Client" -DelegateComputer $CAServerName -Force
Invoke-Command -ComputerName $CAServerName -ScriptBlock { Enable-WSManCredSSP Server -Force }

$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

#Install ADCS Certification Authority Role Services
Invoke-Command -ComputerName $CAServerName -Credential $Credentials -Authentication Credssp -ScriptBlock {
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
Invoke-Command -ComputerName $CAServerName -ScriptBlock { Disable-WSManCredSSP Server }
 
```

## Gateway mode installation on single Windows Server

### Create Computer Template

```PowerShell
# Create and Publish "WACGW" Template
$TemplateName = "WACGW"

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
$DisplayName=$TemplateName
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1207959552'
        'msPKI-Enrollment-Flag' = [System.Int32]'32'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056640'
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

#Publish WACGW Template
    $DisplayName=$TemplateName
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

### Generate a certificate

In order to use own certificate instead of default self-signed one, certificate needs to be generated before actually installing Windows Admin Center and certificate needs to be imported in Computer store of that machine. Let's do it using Autoenrollment.

```PowerShell
$GatewayServerName="WACGWCert"
$TemplateName = "WACGW"

# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
Import-Module PSPKI

#Set Cert Template permission
Get-CertificateTemplate -Name $TemplateName | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$GatewayServerName$" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

#Configure AutoEnrollment policy and enroll cert on WACGW
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {
    Set-CertificateAutoEnrollmentPolicy -StoreName MY -PolicyState Enabled -ExpirationPercentage 10 -EnableTemplateCheck -EnableMyStoreManagement -context Machine
    certutil -pulse
}
 
```

### Install Windows Admin Center

> **Note:** If you don't want to download installer over the Internet, copy MSI file over to virtual machine manually.

```PowerShell
$GatewayServerName="WACGWCert"

#Download Windows Admin Center if not present
if (-not (Test-Path -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi")){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
}

#Create PS Session and copy install files to remote server
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Session=New-PSSession -ComputerName $GatewayServerName
Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -ToSession $Session

#Grab Certificate Thumbprint
$Cert=Invoke-Command -Session $session -ScriptBlock {
    Get-ChildItem -Path Cert:\LocalMachine\My\ | where Subject -eq "CN=$env:ComputerName.$((Get-WmiObject win32_computersystem).Domain)"
}

#Install Windows Admin Center
Invoke-Command -Session $session -ScriptBlock {
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SME_THUMBPRINT=$($using:cert.Thumbprint) SSL_CERTIFICATE_OPTION=installed"
}

$Session | Remove-PSSession
 
```

### Run Windows Admin Center

After the installation on `WACGW` Windows Admin Center's network service is started automatically. In order to access it you need to just open the web browser from the `Win10` virtual machine, navigate to http://WACGW.corp.contoso.com/ and you can log in to the Windows Admin Center.

```PowerShell
start microsoft-edge:http://WACGW.corp.contoso.com
 
```

## Clustered Windows Admin Center installations

### Prereq - Create custom certificate template

```PowerShell
# Create and Publish Template
$TemplateName = "WebCustomRSA"

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
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'9'
        'msPKI-Enrollment-Flag' = [System.Int32]'0'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056656'
        'msPKI-RA-Application-Policies' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`')
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15','2.5.29.7')
        'pKIDefaultCSPs' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft Software Key Storage Provider','2,Microsoft Platform Crypto Provider')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $TemplateName -TemplateOtherAttributes $TemplateOtherAttributes

#endregion

#Publish Template
    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext

    ### WARNING: Issues on all available CAs. Test in your environment.
    $EnrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    $CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter * -Server $Server
    ForEach ($CA in $CAs) {
        Set-ADObject -Identity $CA.DistinguishedName -Add @{certificateTemplates=$TemplateName} -Server $Server
    }
 
```

### Gateway mode installation on Cluster with Shared storage

#### Install Failover Cluster

```PowerShell
# Cluster Configuration
$clusterName = "Wac-Cluster-SAN"
$volumeName = "VolumeWac"
$nodesSan = "WacSan-Node01","WacSan-Node02"

# Install failover clustering on all nodes
$result= Invoke-Command -ComputerName $nodesSan -ScriptBlock {
  Install-WindowsFeature -Name "Failover-Clustering", "RSAT-Clustering-PowerShell"
}
$result

# Restart computers if needed (as 2019 requires restart after failover clustering is installed)
$ComputersToRestart=($result |where restartneeded -ne "No").PSComputerName
if ($ComputersToRestart){
    Restart-Computer -ComputerName $ComputersToRestart -Protocol WSMan -Wait -For PowerShell
}

# Form a cluster
New-Cluster -Name $clusterName -Node $nodesSan

# Ensure that DNS name of the cluster would be accessible
Start-Sleep 5
Clear-DnsClientCache

# Set up disk witness
    $witness_disk = get-disk -cimsession $nodesSan[0]  | where {$_.PartitionStyle -eq 'RAW' -and $_.Size -le 2GB}
    $witness_disk  | Initialize-Disk -PartitionStyle GPT
    Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $witness_disk) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel witness_disk -CimSession $nodesSan[0] -Confirm:$false
    $witness_disk | Set-Disk -IsOffline $true
    $ClusterDisk = Get-ClusterAvailableDisk -Cluster $clusterName
    $clusterDisk=Add-ClusterDisk -Cluster $clusterName -InputObject $ClusterDisk
    $clusterDisk.name = "Witness Disk"
    Set-ClusterQuorum -DiskWitness $ClusterDisk -Cluster $clusterName

# Configure volume
$csvDisks = Get-Disk -CimSession $clusterName | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.Size -gt 10GB } | Sort-Object Number

$csvDisk = $csvDisks | Select -First 1
$csvDisk | Initialize-Disk -PartitionStyle GPT

Format-Volume -Partition (New-Partition -UseMaximumSize -InputObject $csvDisk ) -FileSystem NTFS -AllocationUnitSize 8kb -NewFileSystemLabel $volumeName -CimSession $clusterName -Confirm:$false
$csvDisk | Set-Disk -IsOffline $true
$clusterDisk = Get-ClusterAvailableDisk -Cluster $clusterName
$clusterDisk = Add-ClusterDisk -Cluster $clusterName -InputObject $clusterDisk
$clusterDisk.name = $volumename
$clusterSharedVolume = Add-ClusterSharedVolume -Cluster $clusterName -InputObject $clusterDisk
$clusterSharedVolume.Name = $volumeName

# Rename the volume
$currentPath = $clusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
$currentVolumeName = Split-Path $currentPath -Leaf
$fullPath = Join-Path -Path "C:\ClusterStorage\" -ChildPath $currentVolumeName
Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ScriptBlock {
    Rename-Item -Path $Using:fullPath -NewName $Using:volumeName -PassThru
}
 
```

#### Grab Certificate

```PowerShell
$TemplateName="WebCustomRSA"
$SubjectName="CN=wac-san.corp.contoso.com"
$DNSName="wac-san.corp.contoso.com"
$ExportPath="$env:USERPROFILE\Downloads\wac-san.pfx"
$Password = "LS1setup!"

#make sure PSPKI is installed
    if (-not (Get-Module PSPKI)){
        Install-PackageProvider -Name NuGet -Forcet
        Install-Module -Name PSPKI -Force
        If ((Get-ExecutionPolicy) -eq "restricted"){
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
        }
        Import-Module PSPKI
    }

#First set permissions, so Machine Win10 can enroll certificate
Get-CertificateTemplate -Name $TemplateName | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$env:ComputerName$" -AccessType Allow -AccessMask Read, Enroll | Set-CertificateTemplateAcl

#Generate Certificate to local machine store
Get-Certificate -Template $TemplateName -SubjectName $SubjectName -DNSName $DNSName -CertStoreLocation Cert:\LocalMachine\My

#Export Certificate
$SecurePassword = ConvertTo-SecureString -String $Password -Force –AsPlainText
$Certificate=Get-ChildItem -Path cert:\LocalMachine\My | where-object {$_.SubjectName.Name -eq $SubjectName}
Export-PfxCertificate -Cert $Certificate -FilePath $ExportPath -Password $SecurePassword -Verbose
 
```

#### Download Windows Admin Center files

```PowerShell
#Download Windows Admin Center if not present
$Path="$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
if (-not (Test-Path -Path $Path)){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile $Path
}

<#
#Download setup scripts
$Path="$env:USERPROFILE\Downloads\WindowsAdminCenterHA-SetupScripts.zip"
if (-not (Test-Path -Path $Path)){
    Invoke-WebRequest -UseBasicParsing -Uri http://aka.ms/WACHASetupScripts -OutFile $Path
}
Expand-Archive -LiteralPath $Path -DestinationPath "$env:USERPROFILE\Downloads" -Force
#> 
```

#### Install Windows Admin Center on cluster

Following code is reverse engineered HA Setup script just for education purposes. For production deployments please use setup script

```PowerShell
$ClientAccessPoint="wac-san"
$ClientAccessPointIP="" #empty or something like "10.0.0.112" or even multiple "10.0.0.112","10.0.0.113"
$ClusterName="Wac-Cluster-SAN"
$CertificatePath="$env:USERPROFILE\Downloads\wac-san.pfx"
$CertPassword="LS1setup!"
$msipath="$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
$CSVPath="C:\ClusterStorage\VolumeWac"

#generate another variables
$ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
#Increase MaxEvelope size to transfer files
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Sessions=New-PSSession -ComputerName $ClusterNodes
$CertName=$CertificatePath | Split-Path -Leaf
$msiname=$msipath | Split-Path -Leaf

#Copy certificate and MSI to CSV
#Create Temp folder on CSV
Invoke-Command -ComputerName $ClusterNodes[0] -ScriptBlock {New-Item -Name "Temp" -Path $using:CSVPath -ItemType Directory}
$CertificatePath,$MSIPath | Foreach-Object {
    foreach ($Session in $Sessions){
        Copy-Item -Path $_ -Destination "$CSVPath\Temp\" -ToSession $Session
    }
}

#import cert on nodes
Invoke-Command -Session $Sessions -ScriptBlock {
    Import-PfxCertificate -FilePath $using:CSVPath\Temp\$using:CertName -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String $using:CertPassword -Force –AsPlainText) -Verbose
}

#install Windows Admin Center to each node
$StartDate=Get-Date
Invoke-Command -Session $sessions -ScriptBlock {
    $cert=Get-ChildItem -Path cert:\LocalMachine\My | where Subject -eq "CN=$using:ClientAccessPoint.$((Get-WmiObject win32_computersystem).Domain)"
    Start-Process msiexec.exe -Wait -ArgumentList "/i $using:CSVPath\Temp\$using:msiname /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SME_THUMBPRINT=$($cert.Thumbprint) SSL_CERTIFICATE_OPTION=installed"
}

#wait for some time
Start-Sleep 5

#close sessions and create new
$sessions | Remove-PSSession
$Sessions=New-PSSession -ComputerName $ClusterNodes

#wait until WAC is installed
foreach ($session in $sessions){
    Write-Verbose "Waiting till Windows Admin Center is Installed on $($session.ComputerName)" -Verbose
    do{
        Start-Sleep 3
    }until (
        Invoke-Command -Session $session -ScriptBlock {
            Get-WinEvent -FilterHashtable @{"LogName"="Application";Id=1033} | where TimeCreated -gt $using:StartDate |where Message -like "*Windows Admin Center*"
        }
    )
}

#Check results
$events=invoke-command -session $sessions -scriptblock {
    $events=Get-WinEvent -FilterHashtable @{"LogName"="Application";Id=1033} | where TimeCreated -gt $using:StartDate |where Message -like "*Windows Admin Center*"
    $msilog=@()
    ForEach ($Event in $Events) {
        # Convert the event to XML
        $eventXML = [xml]$Event.ToXml()
        # create custom object for all values
        $msilog += [PSCustomObject]@{
            "ProductName" = $eventxml.Event.EventData.data[0]
            "ProductVersion" = $eventxml.Event.EventData.data[1]
            "ProductLanguage" = $eventxml.Event.EventData.data[2]
            "Result" = $eventxml.Event.EventData.data[3]
            "TimeCreated" = $event.TimeCreated
        }
    }
    return $msilog
}
$events | ft PSComputerName,Result

#Stop Windows Admin Center service and set manual startup
Invoke-Command -session $sessions {
    Stop-Service ServerManagementGateway
    Set-Service ServerManagementGateway -StartupType Manual
}

#Configure cluster role
$WAC_PRODUCT_NAME = 'Windows Admin Center'
$WAC_SETTINGS_REG_KEY = 'HKLM:\Software\Microsoft\ServerManagementGateway'
$HA_SETTINGS_REG_KEY = "$WAC_SETTINGS_REG_KEY\Ha"
$smePath = "$CSVPath\Server Management Experience"
$portnumber="443"
$HACheckpointKey="SOFTWARE\Microsoft\ServerManagementGateway\Ha"

#Copy SME files to CSV
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    $uxFolder = "$using:smePath\Ux"
    if (Test-Path $uxFolder) {
        Remove-Item $uxFolder -Force -Recurse
    }
    New-Item -Path $uxFolder -ItemType Directory | Out-Null
    Copy-Item -Path "$env:programdata\Server Management Experience\Ux" -Destination $using:smePath -Recurse -Container -Force
}

#populate registry
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
    $CertThumbprint = (Get-ChildItem -Path cert:\LocalMachine\My | where Subject -eq "CN=$using:ClientAccessPoint.$((Get-WmiObject win32_computersystem).Domain)").ThumbPrint
    $registryPath = $using:HA_SETTINGS_REG_KEY
    $null = New-Item -Path $registryPath -Force
    New-ItemProperty -Path $registryPath -Name IsHaEnabled -Value "true" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name StoragePath -Value $using:smePath -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name Thumbprint -Value $certThumbprint -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name Port -Value $using:PortNumber -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name ClientAccessPoint -Value $Using:ClientAccessPoint -PropertyType String -Force | Out-Null
    $StaticAddressValue = $using:ClientAccessPointIP -join ','
    New-ItemProperty -Path $registryPath -Name StaticAddress -Value $StaticAddressValue -PropertyType String -Force | Out-Null
}

#Grant permissions to Network Service for the UX folder
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        $uxFolder = "$using:smePath\Ux"
        $Acl = Get-Acl $uxFolder
        $sID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-20")
        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($sID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.SetAccessRule($Ar)
        Set-Acl $uxFolder $Acl
}

#Create Cluster Role
if ($ClientAccessPointIP){
    Add-ClusterGenericServiceRole -Cluster $ClusterName -ServiceName ServerManagementGateway -Name $ClientAccessPoint -CheckpointKey $HACheckpointKey -StaticAddress $ClientAccessPointIP
}else{
    Add-ClusterGenericServiceRole -Cluster $ClusterName -ServiceName ServerManagementGateway -Name $ClientAccessPoint -CheckpointKey $HACheckpointKey
}
 
```

#### Navigate to Windows Admin Center console

Open the web browser from the `Win10` virtual machine, navigate to http://wac-san.corp.contoso.com/ and you can log in to the Windows Admin Center.

```PowerShell
start microsoft-edge:http://wac-san.corp.contoso.com
 
```

### Gateway mode installation on Cluster with Storage Spaces Direct

#### Install Failover Cluster

```PowerShell
# Cluster Configuration
$clusterName = "Wac-Cluster-S2D"
$volumeName = "VolumeWac"
$nodesS2D = "WacS2D-Node01","WacS2D-Node02"

# Install failover clustering on all nodes
$result= Invoke-Command -ComputerName $nodesS2D -ScriptBlock {
  Install-WindowsFeature -Name "Failover-Clustering", "RSAT-Clustering-PowerShell"
}
$result

# Restart computers if needed (as 2019 requires restart after failover clustering is installed)
$ComputersToRestart=($result |where restartneeded -ne "No").PSComputerName
if ($ComputersToRestart){
    Restart-Computer -ComputerName $ComputersToRestart -Protocol WSMan -Wait -For PowerShell
}

#Test-Cluster –Node $nodesS2D –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"
New-Cluster –Name $clusterName –Node $nodesS2D –NoStorage

# Ensure that DNS name of the cluster would be accessible
Start-Sleep 5
Clear-DnsClientCache

# Set up file share witness
$witnessName = "S2D-ClusterWitness"

Invoke-Command -ComputerName "DC" -ScriptBlock {
    New-Item -Path "C:\Shares" -Name $Using:witnessName -ItemType Directory

    # Generate account list
    $accounts = @()
    $accounts += "Corp\$($Using:clusterName)$"

    # Create file share
    New-SmbShare -Name $Using:witnessName -Path "C:\Shares\$Using:witnessName" -FullAccess $accounts
    (Get-SmbShare $Using:witnessName).PresetPathAcl | Set-Acl
}

Set-ClusterQuorum -Cluster $clusterName -FileShareWitness "\\DC\$($witnessName)"

# Now enable the cluster. This step takes a few minutes to complete.
Enable-ClusterS2D -CimSession $clusterName -confirm:0 -Verbose

# And in last step we will create a volume where Windows Admin Center files will be stored.
New-Volume -FriendlyName $volumeName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 40GB -CimSession $clusterName

# Rename the volume
$clusterSharedVolume = Get-ClusterSharedVolume -Cluster $clusterName -Name "Cluster Virtual Disk ($volumeName)"
$currentPath = $clusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
$currentVolumeName = Split-Path $currentPath -Leaf
$fullPath = Join-Path -Path "C:\ClusterStorage\" -ChildPath $volumeName

if($fullPath -ne $currentPath){ # On Windows 2019 volume name is already as we expect
    Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ScriptBlock {
        Rename-Item -Path $Using:currentPath -NewName $Using:volumeName -PassThru
    }
}
 
```

#### Grab Certificate

```PowerShell
$TemplateName="WebCustomRSA"
$SubjectName="CN=wac-s2d.corp.contoso.com"
$DNSName="wac-s2d.corp.contoso.com"
$ExportPath="$env:USERPROFILE\Downloads\wac-s2d.pfx"
$Password = "LS1setup!"

#make sure PSPKI is installed
    if (-not (Get-Module PSPKI)){
        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name PSPKI -Force
        If ((Get-ExecutionPolicy) -eq "restricted"){
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
        }
        Import-Module PSPKI
    }

#First set permissions, so Machine Management can enroll certificate
Get-CertificateTemplate -Name $TemplateName | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$env:ComputerName$" -AccessType Allow -AccessMask Read, Enroll | Set-CertificateTemplateAcl

#Generate Certificate to local machine store
Get-Certificate -Template $TemplateName -SubjectName $SubjectName -DNSName $DNSName -CertStoreLocation Cert:\LocalMachine\My

#Export Certificate
$SecurePassword = ConvertTo-SecureString -String $Password -Force –AsPlainText
$Certificate=Get-ChildItem -Path cert:\LocalMachine\My | where-object {$_.SubjectName.Name -eq $SubjectName}
Export-PfxCertificate -Cert $Certificate -FilePath $ExportPath -Password $SecurePassword -Verbose
 
```

#### Download Windows Admin Center files

```PowerShell
#Download Windows Admin Center if not present
$Path="$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
if (-not (Test-Path -Path $Path)){
    $ProgressPreference='SilentlyContinue' #for faster download
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile $Path
}

<#
#Download setup scripts
$Path="$env:USERPROFILE\Downloads\WindowsAdminCenterHA-SetupScripts.zip"
if (-not (Test-Path -Path $Path)){
    Invoke-WebRequest -UseBasicParsing -Uri http://aka.ms/WACHASetupScripts -OutFile $Path
}
Expand-Archive -LiteralPath $Path -DestinationPath "$env:USERPROFILE\Downloads" -Force
#>
 
```

#### Install Windows Admin Center on cluster

Following code is reverse engineered HA Setup script just for education purposes. For production deployments please use setup script

```PowerShell
$ClientAccessPoint="wac-s2d"
$ClientAccessPointIP="" #empty or something like "10.0.0.112" or even multiple "10.0.0.112","10.0.0.113"
$ClusterName="Wac-Cluster-S2D"
$CertificatePath="$env:USERPROFILE\Downloads\wac-s2d.pfx"
$CertPassword="LS1setup!"
$msipath="$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
$CSVPath="C:\ClusterStorage\VolumeWac"

#generate another variables
$ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
#Increase MaxEvelope size to transfer files
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
$Sessions=New-PSSession -ComputerName $ClusterNodes
$CertName=$CertificatePath | Split-Path -Leaf
$msiname=$msipath | Split-Path -Leaf

#Copy certificate and MSI to CSV
#Create Temp folder on CSV
Invoke-Command -ComputerName $ClusterNodes[0] -ScriptBlock {New-Item -Name "Temp" -Path $using:CSVPath -ItemType Directory}
$CertificatePath,$MSIPath | Foreach-Object {
    foreach ($Session in $Sessions){
        Copy-Item -Path $_ -Destination "$CSVPath\Temp\" -ToSession $Session
    }
}

#import cert on nodes
Invoke-Command -Session $Sessions -ScriptBlock {
    Import-PfxCertificate -FilePath $using:CSVPath\Temp\$using:CertName -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String $using:CertPassword -Force –AsPlainText) -Verbose
}

#install Windows Admin Center to each node
$StartDate=Get-Date
Invoke-Command -Session $sessions -ScriptBlock {
    $cert=Get-ChildItem -Path cert:\LocalMachine\My | where Subject -eq "CN=$using:ClientAccessPoint.$((Get-WmiObject win32_computersystem).Domain)"
    Start-Process msiexec.exe -Wait -ArgumentList "/i $using:CSVPath\Temp\$using:msiname /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SME_THUMBPRINT=$($cert.Thumbprint) SSL_CERTIFICATE_OPTION=installed"
}

#wait for some time
Start-Sleep 5

#close sessions and create new
$sessions | Remove-PSSession
$Sessions=New-PSSession -ComputerName $ClusterNodes

#wait until WAC is installed
foreach ($session in $sessions){
    Write-Verbose "Waiting till Windows Admin Center is Installed on $($session.ComputerName)" -Verbose
    do{
        Start-Sleep 3
    }until (
        Invoke-Command -Session $session -ScriptBlock {
            Get-WinEvent -FilterHashtable @{"LogName"="Application";Id=1033} | where TimeCreated -gt $using:StartDate |where Message -like "*Windows Admin Center*"
        }
    )
}

#Check results
$events=invoke-command -session $sessions -scriptblock {
    $events=Get-WinEvent -FilterHashtable @{"LogName"="Application";Id=1033} | where TimeCreated -gt $using:StartDate |where Message -like "*Windows Admin Center*"
    $msilog=@()
    ForEach ($Event in $Events) {
        # Convert the event to XML
        $eventXML = [xml]$Event.ToXml()
        # create custom object for all values
        $msilog += [PSCustomObject]@{
            "ProductName" = $eventxml.Event.EventData.data[0]
            "ProductVersion" = $eventxml.Event.EventData.data[1]
            "ProductLanguage" = $eventxml.Event.EventData.data[2]
            "Result" = $eventxml.Event.EventData.data[3]
            "TimeCreated" = $event.TimeCreated
        }
    }
    return $msilog
}
$events | ft PSComputerName,Result

#Stop Windows Admin Center service and set manual startup
Invoke-Command -session $sessions {
    Stop-Service ServerManagementGateway
    Set-Service ServerManagementGateway -StartupType Manual
}

#Configure cluster role
$WAC_PRODUCT_NAME = 'Windows Admin Center'
$WAC_SETTINGS_REG_KEY = 'HKLM:\Software\Microsoft\ServerManagementGateway'
$HA_SETTINGS_REG_KEY = "$WAC_SETTINGS_REG_KEY\Ha"
$smePath = "$CSVPath\Server Management Experience"
$portnumber="443"
$HACheckpointKey="SOFTWARE\Microsoft\ServerManagementGateway\Ha"

#Copy SME files to CSV
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
    $uxFolder = "$using:smePath\Ux"
    if (Test-Path $uxFolder) {
        Remove-Item $uxFolder -Force -Recurse
    }
    New-Item -Path $uxFolder -ItemType Directory | Out-Null
    Copy-Item -Path "$env:programdata\Server Management Experience\Ux" -Destination $using:smePath -Recurse -Container -Force
}

#populate registry
Invoke-Command -ComputerName $ClusterNodes -ScriptBlock {
    $CertThumbprint = (Get-ChildItem -Path cert:\LocalMachine\My | where Subject -eq "CN=$using:ClientAccessPoint.$((Get-WmiObject win32_computersystem).Domain)").ThumbPrint
    $registryPath = $using:HA_SETTINGS_REG_KEY
    $null = New-Item -Path $registryPath -Force
    New-ItemProperty -Path $registryPath -Name IsHaEnabled -Value "true" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name StoragePath -Value $using:smePath -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name Thumbprint -Value $certThumbprint -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name Port -Value $using:PortNumber -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name ClientAccessPoint -Value $Using:ClientAccessPoint -PropertyType String -Force | Out-Null
    $StaticAddressValue = $using:ClientAccessPointIP -join ','
    New-ItemProperty -Path $registryPath -Name StaticAddress -Value $StaticAddressValue -PropertyType String -Force | Out-Null
}

#Grant permissions to Network Service for the UX folder
Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        $uxFolder = "$using:smePath\Ux"
        $Acl = Get-Acl $uxFolder
        $sID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-20")
        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($sID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.SetAccessRule($Ar)
        Set-Acl $uxFolder $Acl
}

#Create Cluster Role
if ($ClientAccessPointIP){
    Add-ClusterGenericServiceRole -Cluster $ClusterName -ServiceName ServerManagementGateway -Name $ClientAccessPoint -CheckpointKey $HACheckpointKey -StaticAddress $ClientAccessPointIP
}else{
    Add-ClusterGenericServiceRole -Cluster $ClusterName -ServiceName ServerManagementGateway -Name $ClientAccessPoint -CheckpointKey $HACheckpointKey
}
 
```

#### Navigate to Windows Admin Center console

Open the web browser from the `Win10` virtual machine, navigate to http://wac-s2d.corp.contoso.com/ and you can log in to the Windows Admin Center.


```PowerShell
start microsoft-edge:http://wac-s2d.corp.contoso.com
 
```

## Operate Windows Admin Center

### Generate list of computers to import

```PowerShell
#generate Servers list into Downloads
(Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name | Out-GridView -OutputMode Multiple | Out-File "$env:userprofile\Downloads\Servers.txt"
 
```

### Configure Resource-Based constrained delegation

```PowerShell
$gateway = "WACGW" # Machine where Windows Admin Center is installed
$gatewayObject = Get-ADComputer -Identity $gateway
$nodes = (Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"}).Name | Out-GridView -OutputMode Multiple # Machines that you want to manage

foreach ($Node in $Nodes){
    $nodeObject = Get-ADComputer -Identity $node
    Set-ADComputer -Identity $nodeObject -PrincipalsAllowedToDelegateToAccount $gatewayObject
}
 
```