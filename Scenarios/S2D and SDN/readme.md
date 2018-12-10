<!-- TOC -->

- [S2D and SDN](#s2d-and-sdn)
    - [LabConfig for Windows Server 2019 !!! WORK IN PROGRESS !!!](#labconfig-for-windows-server-2019--work-in-progress-)
    - [Prereq](#prereq)
    - [Finish S2D HC scenario](#finish-s2d-hc-scenario)
        - [Make sure management features are installed](#make-sure-management-features-are-installed)
    - [Configure Certificates](#configure-certificates)
        - [Install and configure ADCS on the CA Server](#install-and-configure-adcs-on-the-ca-server)
        - [Set permissions on NetworkController certificate template and publish it](#set-permissions-on-networkcontroller-certificate-template-and-publish-it)
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
1..4 | % {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 8GB ; NestedVirt=$true }}

#Certification Authority
$LabConfig.VMs += @{ VMName = 'CA' ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; vTPM=$True ; MGMTNICs=1 }

#SDN Cluster
1..3 | % {$VMNames="NC"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2019Core_G2.vhdx';MemoryStartupBytes= 1GB ; MGMTNICs=1}}

# Management machine
$LabConfig.VMs += @{ VMName = 'Management'; Configuration = 'Simple'; ParentVHD = 'Win10RS5_G2.vhdx' ; MemoryStartupBytes = 2GB; MemoryMinimumBytes = 1GB; AddToolsVHD = $True ; MGMTNICs=1 }
 
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
        Install-WindowsFeature -Name "RSAT-ADDS","RSAT-AD-PowerShell","RSAT-ADCS","RSAT-NetworkController","RSAT-Clustering","RSAT-Hyper-V-Tools"
    }elseif ($WindowsInstallationType -eq "Client"){
        $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.NetworkController.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.CertificateServices.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        foreach ($Capability in $Capabilities){
            Add-WindowsCapability -Name $Capability -Online
        }
    }
 
```

## Configure Certificates

### Install and configure ADCS on the CA Server

On `CA` install ADCS role, and after role installation we will create custom `NCRestEndPoint` template. The CA install does not follow all best practices. For more details visit Certification Authority WSLab Scenario.

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
Invoke-Command -ComputerName CA -ScriptBlock {
    Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
}

#Enable CredSSP
# Temporarily enable CredSSP delegation to avoid double-hop issue
Enable-PSRemoting #Win10 has remoting disabled by default
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

Import-Module ActiveDirectory

#Create NCRestEndPoint template

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
        'pKIExpirationPeriod' = [System.Byte[]]@('0','128','060','072','209','203','244','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

<#
#Create NCRestEndPointRSA template

$DisplayName="NCRestEndPointRSA"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131649'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1'
        'msPKI-Enrollment-Flag' = [System.Int32]'8'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'16842768'
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultCSPs' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','128','060','072','209','203','244','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.95.1.1.1') #https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs
        'pKIKeyUsage' = [System.Byte[]]@('136')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
}
New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes
#>

#Create NCNodes template

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

#endregion
 
```

### Set permissions on NetworkController certificate template and publish it

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

$NodeObject1=Invoke-Command -ComputerName NC1 -ScriptBlock {New-NetworkControllerNodeObject -Name "NC1" -Server "NC1.corp.contoso.com" -FaultDomain "fd:/rack1/host1" -RestInterface "Ethernet" -NodeCertificate (Get-ChildItem Cert:\LocalMachine\My |Where-Object {$_.Subject -like "*$env:ComputerName*"})}
$NodeObject2=Invoke-Command -ComputerName NC2 -ScriptBlock {New-NetworkControllerNodeObject -Name "NC2" -Server "NC2.corp.contoso.com" -FaultDomain "fd:/rack2/host2" -RestInterface "Ethernet" -NodeCertificate (Get-ChildItem Cert:\LocalMachine\My |Where-Object {$_.Subject -like "*$env:ComputerName*"})}
$NodeObject3=Invoke-Command -ComputerName NC3 -ScriptBlock {New-NetworkControllerNodeObject -Name "NC3" -Server "NC3.corp.contoso.com" -FaultDomain "fd:/rack3/host3" -RestInterface "Ethernet" -NodeCertificate (Get-ChildItem Cert:\LocalMachine\My |Where-Object {$_.Subject -like "*$env:ComputerName*"})}

$CertPassword="LS1setup!"
$CertPath="$env:USERPROFILE\Downloads\NCCert.pfx"
$certificate=Import-PfxCertificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String $CertPassword -Force –AsPlainText)

$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ("CORP\$LogAccessAccountName", $password)
Install-NetworkControllerCluster -Node @($NodeObject1,$NodeObject2,$NodeObject3) -ClusterAuthentication X509 -ManagementSecurityGroup $ManagementSecurityGroupName -DiagnosticLogLocation "\\DC\$LOGFileShareName" -LogLocationCredential $cred -CredentialEncryptionCertificate $Certificate



########## TBD

#$Certificate = Get-ChildItem -Path cert:\LocalMachine\My | where-object {$_.SubjectName.Name -eq "CN=ncclus.corp.contoso.com"}
#$Certificate = Get-Item Cert:\LocalMachine\My | Get-ChildItem | where-object {$_.SubjectName.Name -eq "CN=ncclus.corp.contoso.com"}
$Certificate = Invoke-Command -ComputerName $Servers[0] -ScriptBlock {Get-Item Cert:\LocalMachine\My | Get-ChildItem | where-object {$_.SubjectName.Name -eq "CN=ncclus.corp.contoso.com"}}

$password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ("CORP\$LogAccessAccountName", $password)
Install-NetworkControllerCluster -Node @($NodeObject1,$NodeObject2,$NodeObject3) -ClusterAuthentication Kerberos -ManagementSecurityGroup $ManagementSecurityGroupName -DiagnosticLogLocation "\\DC\$LOGFileShareName" -LogLocationCredential $cred -CredentialEncryptionCertificate $Certificate

Install-NetworkController -Node @($NodeObject1,$NodeObject2,$NodeObject3) -ClientAuthentication Kerberos -ClientSecurityGroup $ClientSecurityGroupName -ServerCertificate $cert -RestIpAddress 10.0.0.112/24
 
```