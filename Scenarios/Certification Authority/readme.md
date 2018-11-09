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

#Add Templates
#Download Import,Export script, and Templates
"Export-CertificateTemplate.ps1","Import-CertificateTemplate.ps1","CertTemplates.dat" | Foreach-Object {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/Certification%20Authority/Resources/$_" -OutFile "$env:UserProfile\Downloads\$_"
}

# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Import-Module PSPKI

#Install "Certificate Enrollment Policy Web Server" and "Certificate Enrollment Web Server"
Install-WindowsFeature -Name "ADCS-Enroll-Web-Svc","ADCS-Enroll-Web-Pol" -ComputerName CA

#Configure "Certificate Enrollment Policy Web Server" and "Certificate Enrollment Web Server" (Needs some work around figuring out cert first...)

    #Enable CredSSP
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    Enable-WSManCredSSP -Role "Client" -DelegateComputer CA -Force
    Invoke-Command -ComputerName CA -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    Invoke-Command -ComputerName CA -Credential $Credentials -Authentication Credssp -ScriptBlock {
        $ThumbPrint=(Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *Contoso-Root-CA* | select -First 1).Thumbprint
        Install-AdcsEnrollmentPolicyWebService -AuthenticationType Kerberos -SSLCertThumbprint $ThumbPrint -Confirm:0
        Install-AdcsEnrollmentWebService -ApplicationPoolIdentity -CAConfig "CA.corp.contoso.com\Contoso-Root-CA" -SSLCertThumbprint $ThumbPrint -AuthenticationType Certificate -Confirm:0
    }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName CA -ScriptBlock { Disable-WSManCredSSP Server }


# Add Certificate Template Import/Export script
Invoke-WebRequest -Uri  https://gallery.technet.microsoft.com/scriptcenter/Certificate-Templatre-f53ecebe/file/129706/1/CertificateTemplate-Configuration.ps1 -OutFile "$env:UserProfile\Downloads\CertificateTemplate-Configuration.ps1"

#Export templates (Was done just to export manually created templates) so you can download it now)
<#
    Import-Module PSPKI
    $Templates = Get-CertificateTemplate -Name "Computer2016","Computer2016TPM"
    #Load Export function
    . "$env:UserProfile\Downloads\Export-CertificateTemplate.ps1"
    Export-CertificateTemplate -Template $templates -Path $env:UserProfile\Downloads\CertTemplates.dat
#>

#Import templates
    Import-Module PSPKI
    #Load Import function
    . "$env:UserProfile\Downloads\Import-CertificateTemplate.ps1"
    Import-CertificateTemplate -Path $env:UserProfile\Downloads\CertTemplates.dat
    
#Set permissions on TPM Template
Get-CertificateTemplate -Name "Computer 2016 TPM" | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "Domain Computers" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

<#TBD
#configure cert for remote management (different cert is needed than Root)
    Invoke-Command -ComputerName CA -ScriptBlock {
        Import-Module WebAdministration
        Remove-Item -Path IIS:\SslBindings\0.0.0.0!8172
        $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *Contoso-Root-CA* | select -first 1
        New-Item -Path IIS:\SslBindings\0.0.0.0!8172 -value $CACert
    }
#>


#Add AutoEnrollment policy
#Add Templates
 
```
