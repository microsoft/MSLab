<!-- TOC -->

- [Certification Authority !!!WORK IN PROGRESS!!!](#certification-authority-work-in-progress)
    - [LabConfig](#labconfig)
    - [Scenario](#scenario)

<!-- /TOC -->

# Certification Authority !!!WORK IN PROGRESS!!!

## LabConfig

```PowerShell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'WSLabInsider-'; SwitchName = 'LabSwitch'; DCEdition='4' ; Internet=$true ;AdditionalNetworksConfig=@(); VMs=@()}

$LabConfig.VMs += @{ VMName = 'CA'    ; Configuration = 'Simple' ; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 1GB ; MemoryMinimumBytes=1GB ; vTPM=$True }

$LabConfig.VMs += @{ VMName = 'Server1'     ; Configuration = 'Simple'; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True }
$LabConfig.VMs += @{ VMName = 'Server2'     ; Configuration = 'Simple'; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True }
$LabConfig.VMs += @{ VMName = 'Server3'     ; Configuration = 'Simple'; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True }

$LabConfig.VMs += @{ VMName = 'ServerExt1'     ; Configuration = 'Simple'; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True ; Unattend="NoDjoin"}
$LabConfig.VMs += @{ VMName = 'ServerExt2'     ; Configuration = 'Simple'; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True ; Unattend="NoDjoin"}
$LabConfig.VMs += @{ VMName = 'ServerExt3'     ; Configuration = 'Simple'; ParentVHD = 'WinSrvInsiderCore_17744.vhdx' ; MemoryStartupBytes= 512MB ; vTPM=$True ; Unattend="NoDjoin"}
 
```

## Scenario

Inspired by https://itpro.outsidesys.com/2017/10/28/lab-deploy-adcs-enterprise-root-ca/ , https://mcpmag.com/articles/2014/10/21/enabling-iis-remote-management.aspx and https://www.sysadmins.lv/blog-en/export-and-import-certificate-templates-with-powershell.aspx


```PowerShell
#Install Management Tools
Install-WindowsFeature -Name "RSAT-ADCS","Web-Mgmt-Console","Web-Scripting-Tools"

#Install IIS
Install-WindowsFeature Web-WebServer -ComputerName CA -IncludeManagementTools

#Create a CertData Folder and CPS Text File
Invoke-Command -ComputerName CA -ScriptBlock {
    New-Item -Path C:\inetpub\wwwroot\CertData -Type Directory
    Write-Output "Placeholder for Certificate Policy Statement (CPS). Modify as needed by your organization." | Out-File C:\inetpub\wwwroot\CertData\cps.txt
}

#New IIS Virtual Directory
Invoke-Command -ComputerName CA -ScriptBlock {
    $vDirProperties = @{
        Site         = "Default Web Site"
        Name         = "CertData"
        PhysicalPath = 'C:\inetpub\wwwroot\CertData'
    }
    New-WebVirtualDirectory @vDirProperties
}

#Allow IIS Directory Browsing & Double Escaping
Invoke-Command -ComputerName CA -ScriptBlock {
    Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProperties.site)\$($vDirProperties.name)"
    Set-WebConfigurationProperty -filter /system.webServer/Security/requestFiltering -name allowDoubleEscaping -value $true -PSPath "IIS:\Sites\$($vDirProperties.site)"
}

#New Share for the CertData Directory
New-SmbShare -CimSession CA -Name CertData -Path C:\inetpub\wwwroot\CertData -ReadAccess "Corp\domain users" -ChangeAccess "corp\cert publishers"
#configure NTFS Permissions
Invoke-Command -ComputerName CA -ScriptBlock {(Get-SmbShare CertData).PresetPathAcl | Set-Acl}

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

#Configure Max Validity Period of Certificates Issued by this CA
Invoke-Command -ComputerName CA -ScriptBlock {
    Certutil -setreg ca\ValidityPeriodUnits 5
    Certutil -setreg ca\ValidityPeriod "Years"
}

#Configure the CRL Validity Periods
Invoke-Command -ComputerName CA -ScriptBlock {
    Certutil -setreg CA\CRLPeriodUnits 6
    Certutil -setreg CA\CRLPeriod "Days"
    Certutil -setreg CA\CRLDeltaPeriodUnits 0
    Certutil -setreg CA\CRLDeltaPeriod "Hours"
    Certutil -setreg CA\CRLOverlapUnits 3
    Certutil -setreg ca\CRLOverlapPeriod "Days"
}

#Configure the CDP Locations
Invoke-Command -ComputerName CA -ScriptBlock {
    ## Remove Existing CDP URIs
    $CrlList = Get-CACrlDistributionPoint
    ForEach ($Crl in $CrlList) { Remove-CACrlDistributionPoint $Crl.uri -Force }

    ## Add New CDP URIs
    Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri C:\inetpub\wwwroot\CertData\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri "http://ca.corp.contoso.com/certdata/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force
}

#Configure the AIA Locations
Invoke-Command -ComputerName CA -ScriptBlock {
    ## Remove Existing AIA URIs
    $AiaList = Get-CAAuthorityInformationAccess
    ForEach ($Aia in $AiaList) { Remove-CAAuthorityInformationAccess $Aia.uri -Force }
    ## Add New AIA URIs
    Certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt"
    Add-CAAuthorityInformationAccess -AddToCertificateAia -uri "http://ca.corp.contoso.com/certdata/%3%4.crt" -Force
}

#Restart the CA Service & Publish a New CRL
Invoke-Command -ComputerName CA -ScriptBlock {
    Restart-Service certsvc
    Start-Sleep 10
    Certutil -crl
}

#Copy the Root Certificate File to the CertData Folder
Invoke-Command -ComputerName CA -ScriptBlock {
    Copy-Item "C:\Windows\System32\Certsrv\CertEnroll\CA.Corp.contoso.com_Contoso-Root-CA.crt" "C:\inetpub\wwwroot\CertData\CA.Corp.contoso.com_Contoso-Root-CA.crt"
}

#Rename the Root Certificate File
Invoke-Command -ComputerName CA -ScriptBlock {
    Rename-Item "C:\inetpub\wwwroot\CertData\CA.Corp.contoso.com_Contoso-Root-CA.crt" "Contoso-Root-CA.crt"
}

#Export the Root Certificate in PEM Format
Invoke-Command -ComputerName ca -ScriptBlock {
    $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *Contoso-Root-CA* | select -First 1
    $CACert |Export-Certificate -Type CERT -FilePath C:\inetpub\wwwroot\CertData\Contoso-Root-CA.cer
    Rename-Item "C:\inetpub\wwwroot\CertData\Contoso-Root-CA.cer" "Contoso-Root-CA.pem"
}

#Add mime type
Invoke-Command -ComputerName ca -ScriptBlock {
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /-"[fileExtension='.pem']"
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /+"[fileExtension='.pem',mimeType='text/plain']"
}

#configure remote management (inspired by https://mcpmag.com/articles/2014/10/21/enabling-iis-remote-management.aspx )
Invoke-Command -ComputerName CA -ScriptBlock{
    Install-WindowsFeature  Web-Mgmt-Service
    Set-ItemProperty -Path  HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1
    Set-Service -name WMSVC  -StartupType Automatic
    Start-Service WMSVC
}


#region Add templates

#inspired by https://blogs.technet.microsoft.com/ashleymcglone/2017/08/29/function-to-create-certificate-template-in-active-directory-certificate-services-for-powershell-dsc-and-cms-encryption/

#initial functions

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

#CreateTPMAttestedTemplate

$DisplayName="Computer2016TPM"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1207959552'
        'msPKI-Enrollment-Flag' = [System.Int32]'32'
        'msPKI-Minimal-Key-Size' = [System.Int32]'521'
        'msPKI-Private-Key-Flag' = [System.Int32]'101058560'
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

#CreateNormalTemplate
$DisplayName="Computer2016"
$TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131680'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'1207959552'
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

# Install PSPKI module for managing Certification Authority
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name PSPKI -Force
    Import-Module PSPKI

#Set permissions on TPM Templates so all computers can autoenroll it
    Get-CertificateTemplate -Name "Computer2016TPM" | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "Domain Computers" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

#Publish Computer2016TPM Certificate
    $DisplayName="Computer2016TPM"
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

#Create Certificate stores on CA
Invoke-Command -ComputerName CA -ScriptBlock {
    New-Item -Path Cert:\LocalMachine\ -Name EKROOT
    New-Item -Path Cert:\LocalMachine\ -Name EKCA
    New-Item -Path c:\ -Name EKPub -Type Directory
    New-Item -Path c:\EKPub -Name ComputersList.txt -Type File
}

#Setup EKPUB List for EK attestation type
certutil.exe -setreg CA\EndorsementKeyListDirectories +"c:\EKPub"

#restart CA to apply above change
Invoke-Command -computername CA -scriptblock {
    Restart-Service -Name CertSvc
}

#Initialize TPMs and extract Cert info (we will do it only on one machine as all certs are the same as it's hyper-v)
$Computers="CA","Server1","Server2"

Invoke-Command -ComputerName "CA","Server1","Server2" -ScriptBlock {
    Initialize-TPM
}

#Generate EKPub files to CA
Foreach ($computer in $computers){
    $EKHash=Invoke-Command -ComputerName $computer -scriptblock {
        Get-TpmEndorsementKeyInfo -hashalgorithm sha256
    }
    Invoke-Command -ComputerName CA -ScriptBlock {
        if (-not (test-path c:\EKPub\$($using:EKHash).PublicKeyHash)){
            new-item -Path c:\EKPub -Name $($using:EKHash).PublicKeyHash -ItemType file -force
            #add info to cert list file
            Add-Content -Path c:\EKPub\ComputersList.txt -Value "$($using:Computer),$($($using:EKHash).PublicKeyHash)"
        }
    }
}

#Add AutoEnrollment policy
    #Download AutoEnrollGPO policy from GitHub
    Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/Certification%20Authority/Resources/EAutoEnrollGPO.zip -OutFile "$env:UserProfile\Downloads\AutoEnrollGPO.zip"
    Expand-Archive -Path "$env:UserProfile\Downloads\AutoEnrollGPO.zip" -DestinationPath "$env:UserProfile\Downloads\AutoEnrollGPO\"

    #create GPOs
    New-GPO -Name AutoEnroll  | New-GPLink -Target "dc=corp,dc=contoso,dc=com"
    Import-GPO -BackupGpoName AutoEnroll -TargetName AutoEnroll -path "$env:UserProfile\Downloads\AutoEnrollGPO\"

    #Update GPO and enroll certs
    $Computers="CA","Server1","Server2"
    Invoke-Command -ComputerName $Computers -ScriptBlock {
        gpupdate /force
        certutil -pulse
    }

<#TBD
#configure cert for remote management (different cert is needed than Root)
    Invoke-Command -ComputerName CA -ScriptBlock {
        Import-Module WebAdministration
        Remove-Item -Path IIS:\SslBindings\0.0.0.0!8172
        $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *Contoso-Root-CA* | select -first 1
        New-Item -Path IIS:\SslBindings\0.0.0.0!8172 -value $CACert
    }

#>


```
