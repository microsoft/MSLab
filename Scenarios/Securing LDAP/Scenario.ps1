#region install management tools
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
$CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
if ($WindowsInstallationType -eq "Server"){
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-AD-PowerShell,RSAT-ADCS,Web-Mgmt-Console,Web-Scripting-Tools
}elseif ($WindowsInstallationType -eq "Server Core"){
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-AD-PowerShell
}elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
    #Validate RSAT Installed
        if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
            Write-Host "Please install RSAT, Exitting in 5s"
            Start-Sleep 5
            Exit
        }
}elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
    #Install RSAT tools
        $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0","Rsat.CertificateServices.Tools~~~~0.0.1.0"
        foreach ($Capability in $Capabilities){
            Add-WindowsCapability -Name $Capability -Online
        }
        $FeatureNames="IIS-ManagementConsole","IIS-ManagementScriptingTools"
        foreach ($FeatureName in $FeatureNames){
            Enable-WindowsOptionalFeature -FeatureName $FeatureName -Online
        }
}
#endregion

#region setup Certification Authority
#Certification Authority
$CAServerName="CA"

#Install IIS
Install-WindowsFeature Web-WebServer -ComputerName $CAServerName -IncludeManagementTools

#Create a CertData Folder and CPS Text File
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    New-Item -Path C:\inetpub\wwwroot\CertData -Type Directory
    Write-Output "Placeholder for Certificate Policy Statement (CPS). Modify as needed by your organization." | Out-File C:\inetpub\wwwroot\CertData\cps.txt
}

#New IIS Virtual Directory
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    $vDirProperties = @{
        Site         = "Default Web Site"
        Name         = "CertData"
        PhysicalPath = 'C:\inetpub\wwwroot\CertData'
    }
    New-WebVirtualDirectory @vDirProperties
}

#Allow IIS Directory Browsing & Double Escaping
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProperties.site)\$($vDirProperties.name)"
    Set-WebConfigurationProperty -filter /system.webServer/Security/requestFiltering -name allowDoubleEscaping -value $true -PSPath "IIS:\Sites\$($vDirProperties.site)"
}

#New Share for the CertData Directory
New-SmbShare -CimSession $CAServerName -Name CertData -Path C:\inetpub\wwwroot\CertData -ReadAccess "Corp\domain users" -ChangeAccess "corp\cert publishers"
#configure NTFS Permissions
Invoke-Command -ComputerName $CAServerName -ScriptBlock {(Get-SmbShare CertData).PresetPathAcl | Set-Acl}

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
Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools -ComputerName CA

#Enable CredSSP
# Temporarily enable CredSSP delegation to avoid double-hop issue
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

#Configure Max Validity Period of Certificates Issued by this CA
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Certutil -setreg ca\ValidityPeriodUnits 5
    Certutil -setreg ca\ValidityPeriod "Years"
}

#Configure the CRL Validity Periods
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Certutil -setreg CA\CRLPeriodUnits 6
    Certutil -setreg CA\CRLPeriod "Days"
    Certutil -setreg CA\CRLDeltaPeriodUnits 0
    Certutil -setreg CA\CRLDeltaPeriod "Hours"
    Certutil -setreg CA\CRLOverlapUnits 3
    Certutil -setreg ca\CRLOverlapPeriod "Days"
}

#Configure the CDP Locations
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    ## Remove Existing CDP URIs
    $CrlList = Get-CACrlDistributionPoint
    ForEach ($Crl in $CrlList) { Remove-CACrlDistributionPoint $Crl.uri -Force }

    ## Add New CDP URIs
    Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri C:\inetpub\wwwroot\CertData\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACRLDistributionPoint -Uri "http://ca.corp.contoso.com/certdata/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force
}

#Configure the AIA Locations
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    ## Remove Existing AIA URIs
    $AiaList = Get-CAAuthorityInformationAccess
    ForEach ($Aia in $AiaList) { Remove-CAAuthorityInformationAccess $Aia.uri -Force }
    ## Add New AIA URIs
    Certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt"
    Add-CAAuthorityInformationAccess -AddToCertificateAia -uri "http://ca.corp.contoso.com/certdata/%3%4.crt" -Force
}

#Restart the CA Service & Publish a New CRL
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Restart-Service certsvc
    Start-Sleep 10
    Certutil -crl
}

#Copy the Root Certificate File to the CertData Folder
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Copy-Item "C:\Windows\System32\Certsrv\CertEnroll\CA.Corp.contoso.com_Contoso-Root-CA.crt" "C:\inetpub\wwwroot\CertData\CA.Corp.contoso.com_Contoso-Root-CA.crt"
}

#Rename the Root Certificate File
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    Rename-Item "C:\inetpub\wwwroot\CertData\CA.Corp.contoso.com_Contoso-Root-CA.crt" "Contoso-Root-CA.crt"
}

#Export the Root Certificate in PEM Format
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *Contoso-Root-CA* | select -First 1
    $CACert |Export-Certificate -Type CERT -FilePath C:\inetpub\wwwroot\CertData\Contoso-Root-CA.cer
    Rename-Item "C:\inetpub\wwwroot\CertData\Contoso-Root-CA.cer" "Contoso-Root-CA.pem"
}

#Add mime type
Invoke-Command -ComputerName $CAServerName -ScriptBlock {
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /-"[fileExtension='.pem']"
    & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /+"[fileExtension='.pem',mimeType='text/plain']"
}
#endregion

#region Add Exportable certificate template for Grafana
#First import ActiveDirectory module to be able to create [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection] type
Import-Module ActiveDirectory
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

$DisplayName="WebServerKSP_RSAExportable"
$TemplateOtherAttributes = @{
    'flags' = [System.Int32]'131680'
    'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
    'msPKI-Certificate-Name-Flag' = [System.Int32]'1207959552'
    'msPKI-Enrollment-Flag' = [System.Int32]'32'
    'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
    'msPKI-Private-Key-Flag' = [System.Int32]'101056528'
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

#Publish Templates
$TemplateNames="WebServerKSP_RSAExportable"
#grab DC
$Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
#grab Naming Context
$ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext

### WARNING: Issues on all available CAs. Test in your environment.
$EnrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
$CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter * -Server $Server
foreach ($TemplateName in $TemplateNames){
    ForEach ($CA in $CAs) {
        Set-ADObject -Identity $CA.DistinguishedName -Add @{certificateTemplates=$TemplateName} -Server $Server
    }
}
#endregion

#region Download and Install Edge
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/07367ab9-ceee-4409-a22f-c50d77a8ae06/MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"
$ProgressPreference='Continue' #to set it back
#start install
Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"
#start Edge
start-sleep 5
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
 
#endregion

#region download files for Grafana
$ProgressPreference='SilentlyContinue' #for faster download
#Grafana
Invoke-WebRequest -UseBasicParsing -Uri https://dl.grafana.com/oss/release/grafana-6.6.0.windows-amd64.zip -OutFile "$env:USERPROFILE\Downloads\grafana.zip"
#NSSM - the Non-Sucking Service Manager
Invoke-WebRequest -UseBasicParsing -Uri https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip -OutFile "$env:USERPROFILE\Downloads\NSSM.zip"
$ProgressPreference='Continue' #to set it back
#endregion

#region Install Grafana
$GrafanaServerName="Grafana"

#increase MaxEnvelopeSize to transfer files
Invoke-Command -ComputerName $GrafanaServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}

$GrafanaSession=New-PSSession -ComputerName $GrafanaServerName

Copy-Item -Path "$env:USERPROFILE\Downloads\grafana.zip" -Destination "$env:temp\grafana.zip" -tosession $GrafanaSession
Copy-Item -Path "$env:USERPROFILE\Downloads\NSSM.zip" -Destination "$env:temp\NSSM.zip" -tosession $GrafanaSession

invoke-command -Session $GrafanaSession -scriptblock {
    Expand-Archive -Path "$env:temp\grafana.zip" -DestinationPath "$env:temp" -Force
    Expand-Archive -Path "$env:temp\NSSM.zip" -DestinationPath "$env:temp" -Force
    #rename folder to remove version
    Get-ChildItem -Path $env:temp  | Where-Object name -like grafana-* | Rename-Item -NewName Grafana
    Get-ChildItem -Path $env:temp  | Where-Object name -like nssm-* | Rename-Item -NewName NSSM
    #move to program files
    Move-Item -Path $env:temp\Grafana -Destination $env:ProgramFiles -Force
    #copy nssm to system32
    get-childitem -Path "$env:temp\NSSM" -recurse | Where-Object FullName -like "*win64*nssm.exe" | copy-item -destination "$env:SystemRoot\system32"
    #remove nssm folder
    Remove-Item -Path "$env:temp\NSSM" -Recurse -Force
    #remove zips
    Remove-Item -Path "$env:temp\*.zip" -Force
}

#Install Grafana as Service
Invoke-command -Session $GrafanaSession -scriptblock {
    #install as service
    Start-Process -FilePath nssm.exe -ArgumentList "install Grafana ""$env:ProgramFiles\Grafana\bin\grafana-server.exe""" -Wait
    Start-Service Grafana
}
#endregion

#region Configure LDAP for Grafana
$GrafanaServerName="Grafana"
$LDAP_servers = "dc.corp.contoso.com" #for multiple "10.0.0.2 10.0.0.3"
$OU_For_User_And_Group = "OU=Workshop,DC=Corp,DC=contoso,DC=com"
$Grafana_LDAPuser = "GrafanaUser" #account to query LDAP
$Grafana_LDAPuserpwd = "LS1setup!"
$Grafana_AdminsGroupName = "GrafanaAdmins" #Grafana Admins Group
$Grafana_Admins_To_Add = "LabAdmin"

#validate if AD Posh is installed (or install it)
$WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
$CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
if ($WindowsInstallationType -like "Server*"){
    Install-WindowsFeature -Name "RSAT-AD-PowerShell"
}elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
    #Validate RSAT Installed
    if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
        Write-Host "Please install RSAT, Exitting in 5s"
        Start-Sleep 5
        Exit
    }
}elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
    #install AD RSAT
    Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online
}

#Create Users and Groups
#create Grafana LDAP User
New-ADUser -Name $Grafana_LDAPuser -UserPrincipalName $Grafana_LDAPuser -Path $OU_For_User_And_Group -Enabled $true -AccountPassword (ConvertTo-SecureString $Grafana_LDAPuserpwd -AsPlainText -Force)

#create group for Grafana Admins
New-ADGroup -Name $Grafana_AdminsGroupName -GroupScope Global -Path $OU_For_User_And_Group

#Add members to AD Group
Add-ADGroupMember -Identity $Grafana_AdminsGroupName -Members $Grafana_Admins_To_Add

### setup LDAP Authentication - https://grafana.com/docs/auth/ldap/
### Source: Grafana, InfluxDB und Windows PowerShell - https://www.zueschen.eu/grafana-influxdb-und-windows-powershell-teil-7/
Write-Host -ForegroundColor Cyan "Configuring Grafana for LDAP Authentication ..." 

$GrafanaLDAPuser = (Get-ADUser $Grafana_LDAPuser).DistinguishedName
$GrafanaLDAPuserpwd = $Grafana_LDAPuserpwd
$GrafanaBaseDomain = (Get-ADDomain).DistinguishedName
$GrafanaAdmins = (Get-ADGroup $Grafana_AdminsGroupName).DistinguishedName
Invoke-command -computername $GrafanaServerName -scriptblock {
    Stop-Service -Name Grafana
    #region Configure LDAP authentication in Grafane server config file
    #Load Grafana Server config file - LDAP to be anabled there
    $configfile = "$($env:ProgramFiles)\Grafana\conf\defaults.ini"
    $GrafanaServerConfigLDAPstring = Select-String -Path $configfile -Pattern 'Auth LDAP'
    $GrafanaServerConfig = Get-Content -Path $configfile

    #Replace the default values with the new ones
    $GrafanaServerConfig[$GrafanaServerConfigLDAPstring.LineNumber + 1] = 'enabled = true'
    $GrafanaServerConfig[$GrafanaServerConfigLDAPstring.LineNumber + 2] = 'config_file = C:\Program Files\Grafana\conf\ldap.toml'
    $GrafanaServerConfig[$GrafanaServerConfigLDAPstring.LineNumber + 3] = 'allow_sign_up = true'

    # Set the new content
    $GrafanaServerConfig | Set-Content -Path "$($env:ProgramFiles)\Grafana\conf\defaults.ini"
    #endregion

    #region Configure LDAP authentication in Grafane LDAP config file
    #Load Grafana LDAP config file
    $LDAPconfigfile = "C:\Program Files\Grafana\conf\ldap.toml"
    $GrafanaLDAPConfig = Get-Content -Path $LDAPconfigfile
    #Define config file lines to be changed
    $GrafanaLDAP_host = Select-String -Path $LDAPconfigfile -Pattern "Ldap server host"
    $GrafanaLDAP_SearchUserBind = Select-String -Path $LDAPconfigfile -Pattern "Search user bind dn"
    $GrafanaLDAP_UserSearchFilter = Select-String -Path $LDAPconfigfile -Pattern "User search filter, for example"
    $GrafanaLDAP_BaseDNSSearch = Select-String -Path $LDAPconfigfile -Pattern "An array of base dns to search through"
    $GrafanaLDAP_Attributes = Select-String -Path $LDAPconfigfile -Pattern "Specify names of the ldap attributes your ldap uses"
    $GrafanaLDAP_AdminMapping = Select-String -Path $LDAPconfigfile -Pattern "Map ldap groups to grafana org roles"
    #Set LDAP servers
    $GrafanaLDAPConfig[$GrafanaLDAP_host.LineNumber] = "host = $('"')$($using:LDAP_servers)$('"')"
    #Set Grafana search bind account
    $GrafanaLDAPConfig[$GrafanaLDAP_SearchUserBind.LineNumber] = "bind_dn = $('"')$($using:GrafanaLDAPuser)$('"')"
    $GrafanaLDAPConfig[$GrafanaLDAP_SearchUserBind.LineNumber + 3] = "bind_password = '$using:GrafanaLDAPuserpwd'"
    #Set user search filter
    $GrafanaLDAPConfig[$GrafanaLDAP_UserSearchFilter.LineNumber] = 'search_filter = "(|(sAMAccountName=%s)(userPrincipalName=%s))"'
    #Set base dns search
    $GrafanaLDAPConfig[$GrafanaLDAP_BaseDNSSearch.LineNumber] = "search_base_dns = [$('"')$($using:GrafanaBaseDomain)$('"')]"
    #Set LDAP attributes
    $GrafanaLDAPConfig[$GrafanaLDAP_Attributes.LineNumber + 3] = 'username = "sAMAccountName"'
    #Set Admin role mapping
    $GrafanaLDAPConfig[$GrafanaLDAP_AdminMapping.LineNumber + 1] = "group_dn = $('"')$($using:GrafanaAdmins)$('"')"

    # Set the new content
    $GrafanaLDAPConfig | Set-Content -Path "C:\Program Files\Grafana\conf\ldap.toml"
    #endregion

    Set-Service -Name Grafana -StartupType Automatic  
    Start-Service -Name Grafana
}
#endregion

#region distribute certificates to Grafana
#Enroll Computer2016 template to DC to enable LDAPs
$CertsToEnrollList=@()
$CertsToEnrollList+=@{ServerName="Grafana";TemplateName="WebServerKSP_RSAExportable"}

# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
Import-Module PSPKI

foreach ($List in $CertsToEnrollList){
    #Set Cert Template permission
    Get-CertificateTemplate -Name $List.TemplateName | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$($List.ServerName)$" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

    #Configure AutoEnrollment policy and enroll cert
    Invoke-Command -ComputerName $List.ServerName -ScriptBlock {
        Set-CertificateAutoEnrollmentPolicy -StoreName MY -PolicyState Enabled -ExpirationPercentage 10 -EnableTemplateCheck -EnableMyStoreManagement -context Machine
        certutil -pulse
        while (-not (Get-ChildItem -Path Cert:\LocalMachine\My)){
            Start-Sleep 1
            certutil -pulse
        }
    }
}
#endregion

#region Configure Grafana Certificate
$GrafanaServerName="Grafana"
#Grab DN
$CAcert=(Get-CertificationAuthority).certificate
#download OpenSSL and transfer to GrafanaServer
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri https://indy.fulgan.com/SSL/openssl-1.0.2t-x64_86-win64.zip -OutFile $env:USERPROFILE\Downloads\OpenSSL.zip -UseBasicParsing
#transfer OpenSSL to $GrafanaServer
$GrafanaSession=New-PSSession -ComputerName $GrafanaServerName
Copy-Item -Path $env:USERPROFILE\Downloads\OpenSSL.zip -Destination $env:USERPROFILE\Downloads\OpenSSL.zip -ToSession $GrafanaSession
#Unzip OpenSSL
Invoke-Command -ComputerName $GrafanaServerName -ScriptBlock {
    Expand-Archive -Path "$env:USERPROFILE\Downloads\OpenSSL.zip" -DestinationPath $env:USERPROFILE\Downloads\OpenSSL -Force
}
Invoke-Command -ComputerName $GrafanaServerName -ScriptBlock {
    Stop-Service -Name Grafana
    #region Configure Cert for HTTP
    #export certificate from local store
    $Cert=Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object Subject -like *$env:COMPUTERNAME* |Select-Object -First 1
    $bytes = $Cert.Export("Pfx")
    [System.IO.File]::WriteAllBytes("C:/Program Files/Grafana/conf/Cert.pfx", $bytes)
    #convert pfx to pem
    #private
    Start-Process -FilePath $env:USERPROFILE\Downloads\OpenSSL\openssl.exe -ArgumentList 'pkcs12 -in "C:/Program Files/Grafana/conf/Cert.pfx" -nocerts -nodes -out "C:/Program Files/Grafana/conf/Private.key" -password pass:""' -Wait
    #public
    Start-Process -FilePath $env:USERPROFILE\Downloads\OpenSSL\openssl.exe -ArgumentList 'pkcs12 -in "C:/Program Files/Grafana/conf/Cert.pfx" -clcerts -nokeys -out "C:/Program Files/Grafana/conf/Public.key" -password pass:""' -Wait
    $GrafanaConfigFileContent=Get-Content -Path "C:\Program Files\Grafana\conf\defaults.ini"
    $GrafanaConfigFileContent=$GrafanaConfigFileContent.Replace("protocol = http","protocol = https")
    $GrafanaConfigFileContent=$GrafanaConfigFileContent.Replace("http_port = 3000","http_port = 443")
    $GrafanaConfigFileContent=$GrafanaConfigFileContent.Replace("cert_file =","cert_file = C:/Program Files/Grafana/conf/Public.key")
    $GrafanaConfigFileContent=$GrafanaConfigFileContent.Replace("cert_key =","cert_key = C:/Program Files/Grafana/conf/Private.key")
    $GrafanaConfigFileContent | Set-Content -Path "C:\Program Files\Grafana\conf\defaults.ini"
    #endregion
    Start-Service -Name Grafana
}
#endregion

#region Add Firewall Rule for Grafana
$GrafanaServerName="Grafana"

New-NetFirewallRule -CimSession $GrafanaServerName `
-Action Allow `
-Name "Grafana-HTTP-In-TCP" `
-DisplayName "Grafana (HTTP-In)" `
-Description "Inbound rule for Grafana web. [TCP-443]" `
-Enabled True `
-Direction Inbound `
-Program "%ProgramFiles%\Grafana\bin\grafana-server.exe" `
-Protocol TCP `
-LocalPort 443 `
-Profile Any `
-Group "Grafana" `
-RemoteAddress Any
#endregion

#region create custom event log on collector
$CollectorServerName="Collector"
$CustomEventChannelsFileName="CustomEventChannels"
$CustomEventsFilesLocation="$env:UserProfile\Downloads\ECMan"

#Download SDK
$ProgressPreference='SilentlyContinue' #for faster download
#Download Windows 10 RS5 SDK
Invoke-WebRequest -UseBasicParsing -Uri https://go.microsoft.com/fwlink/p/?LinkID=2033908 -OutFile "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe"
$ProgressPreference='Continue' #switching back
#Install SDK RS5
Start-Process -Wait -FilePath "$env:USERPROFILE\Downloads\SDKRS5_Setup.exe" -ArgumentList "/features OptionId.DesktopCPPx64 /quiet"

#Create Man file or run setup
#Variables
$CustomEventChannelsFileName="CustomEventChannels"
$OutputFolder="$env:UserProfile\Downloads\ECMan"

#some neccessaries
$ManifestFileName = '{0}.man' -f $CustomEventChannelsFileName
$ResourceFileName = 'C:\Windows\system32\{0}.dll' -f $CustomEventChannelsFileName
$message = '$(string.Custom Forwarded Events.event.100.message)' 

#Events definition
$EventsArray = @(
    @{
        EventProviderName = 'LDAPSigning'
        EventGuid = New-Guid
        EventSymbol = 'LDAPSigning_EVENTS'
        EventResourceFileName = $ResourceFileName
        ImportChannelID='C1'
        Channels = @(
            @{
                ChannelName = 'LDAPSNotRequired'
                ChannelchID = 'LDAPSNotRequired'
                ChannelSymbol = 'LDAPSNotRequired'
            },
            @{
                ChannelName = 'LDAPBindsStats'
                ChannelchID = 'LDAPBindsStats'
                ChannelSymbol = 'LDAPBindsStats'
            },
            @{
                ChannelName = 'LDAPBindsComputers'
                ChannelchID = 'LDAPBindsComputers'
                ChannelSymbol = 'LDAPBindsComputers'
            },
            @{
                ChannelName = 'LDAPBindsRejectStats'
                ChannelchID = 'LDAPBindsRejectStats'
                ChannelSymbol = 'LDAPBindsRejectStats'
            }
        )
    },
    @{
        EventProviderName = 'LDAPChannelBinding'
        EventGuid = New-Guid
        EventSymbol = 'LDAPChannelBinding_EVENTS'
        EventResourceFileName = $ResourceFileName
        ImportChannelID='C2'
        Channels = @(
            @{
                ChannelName = 'TokenValidationFails'
                ChannelchID = 'TokenValidationFails'
                ChannelSymbol = 'TokenValidationFails'
            },
            @{
                ChannelName = 'ChannelBindingNotEnforced'
                ChannelchID = 'ChannelBindingNotEnforced'
                ChannelSymbol = 'ChannelBindingNotEnforced'
            }
        )
    }
)

#Generate XML
$EventsArrayFinal = foreach ($Event in $EventsArray) {
    $channels = foreach ($channel in $Event.Channels) {
    @"
                    <channel name="$($Channel.ChannelName)" chid="$($Channel.ChannelchID)" symbol="$($Channel.ChannelSymbol)" type="Operational" enabled="true"></channel>
"@
    }
    @"

            <provider name="$($Event.EventProviderName)" guid="{$($Event.EventGUID)}" symbol="$($Event.EventSymbol)" resourceFileName="$($Event.EventResourceFileName)" messageFileName="$($Event.EventResourceFileName)">
                <events>
                    <event symbol="DUMMY_EVENT" value="100" version="0" template="DUMMY_TEMPLATE" message="$message"></event>
                </events>
                <channels>
                    <importChannel name="System" chid="$($Event.ImportChannelID)"></importChannel>$channels
                </channels>
                <templates>
                    <template tid="DUMMY_TEMPLATE">
                        <data name="Prop_UnicodeString" inType="win:UnicodeString" outType="xs:string"></data>
                        <data name="PropUInt32" inType="win:UInt32" outType="xs:unsignedInt"></data>
                    </template>
                </templates>
            </provider>
"@
}
$Content=@"
<?xml version="1.0"?>
<instrumentationManifest xsi:schemaLocation="http://schemas.microsoft.com/win/2004/08/events eventman.xsd" xmlns="http://schemas.microsoft.com/win/2004/08/events" xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:trace="http://schemas.microsoft.com/win/2004/08/events/trace">
    <instrumentation>
        <events>$EventsArrayFinal
        </events>
    </instrumentation>
    <localization>
        <resources culture="en-US">
            <stringTable>
                <string id="level.Informational" value="Information"></string>
                <string id="channel.System" value="System"></string>
                <string id="Publisher.EventMessage" value="Prop_UnicodeString=%1;%n&#xA;                  Prop_UInt32=%2;%n"></string>
                <string id="Custom Forwarded Events.event.100.message" value="Prop_UnicodeString=%1;%n&#xA;                  Prop_UInt32=%2;%n"></string>
            </stringTable>
        </resources>
    </localization>
</instrumentationManifest>
"@

#Create output folder if does not exist
if(-not (Test-Path $OutputFolder)) { 
    New-Item -Path $OutputFolder -ItemType Directory
}

#write XML
Set-Content -Value $content -Path (Join-Path -Path $OutputFolder -ChildPath $ManifestFileName) -Encoding ASCII
 
#Compile manifest https://docs.microsoft.com/en-us/windows/desktop/WES/compiling-an-instrumentation-manifest
$CustomEventChannelsFileName="CustomEventChannels"
$OutputFolder="$env:UserProfile\Downloads\ECMan"
$ToolsPath="C:\Program Files (x86)\Windows Kits\10\bin\10.0.17763.0\x64"
$dotNetPath="C:\Windows\Microsoft.NET\Framework64\v4.0.30319"
 
Start-Process -Wait -FilePath "$ToolsPath\mc.exe" -ArgumentList "$OutputFolder\$CustomEventChannelsFileName.man" -WorkingDirectory $OutputFolder
Start-Process -Wait -FilePath "$ToolsPath\mc.exe" -ArgumentList "-css CustomEventChannels.DummyEvent  $OutputFolder\$CustomEventChannelsFileName.man" -WorkingDirectory $OutputFolder
Start-Process -Wait -FilePath "$ToolsPath\rc.exe" -ArgumentList "$OutputFolder\$CustomEventChannelsFileName.rc"
Start-Process -Wait -FilePath "$dotNetPath\csc.exe" -ArgumentList "/win32res:$OutputFolder\$CustomEventChannelsFileName.res /unsafe /target:library /out:$OutputFolder\$CustomEventChannelsFileName.dll"
 

#create session for managed computer (ComputerName is Collector in this case)
$CollectorSession=New-PSSession -ComputerName $CollectorServerName
 
#configure Event Forwarding on collector server
Invoke-Command -Session $CollectorSession -ScriptBlock {
    WECUtil qc /q
}
 
#Create custom event forwarding logs
Invoke-Command -Session $CollectorSession -ScriptBlock {
    Stop-Service Wecsvc
    #unload current event channnel (commented as there is no custom manifest)
    #wevtutil um C:\windows\system32\CustomEventChannels.man
}
 
#copy new man and dll
$files="$CustomEventChannelsFileName.dll","$CustomEventChannelsFileName.man"
$Path="$CustomEventsFilesLocation"
foreach ($file in $files){
    Copy-Item -Path "$path\$file" -Destination C:\Windows\system32 -ToSession $CollectorSession -Force
}
#load new event channel file and start Wecsvc service
Invoke-Command -Session $CollectorSession -ScriptBlock {
    wevtutil im "C:\windows\system32\$using:CustomEventChannelsFileName.man"
    Start-Service Wecsvc
}

#enable firewall rule
Enable-NetFirewallRule -CimSession $CollectorServerName -DisplayGroup "Remote Event Log Management"
eventvwr
 
#endregion

#region configure event forwarding on collector server
$CollectorServerName="Collector"
#Events definition
$Definitions=@()
$Definitions+=@{Name="LDAPSNotRequired"         ; Description="DCs not requiring LDAP signing"                                                 ; Query='<Select Path="Directory Service">*[System[(EventID=2886)]]</Select>'}
$Definitions+=@{Name="LDAPBindsStats"           ; Description="How many binds not requiring LDAP occurred"                                     ; Query='<Select Path="Directory Service">*[System[(EventID=2887)]]</Select>'}
$Definitions+=@{Name="LDAPBindsComputers"       ; Description="Detailed information on Who/When/From Where"                                    ; Query='<Select Path="Directory Service">*[System[(EventID=2889)]]</Select>'}
$Definitions+=@{Name="LDAPBindsRejectStats"     ; Description="Reject unsigned SASL LDAP binds or LDAP simple binds Stats"                     ; Query='<Select Path="Directory Service">*[System[(EventID=2888)]]</Select>'}
$Definitions+=@{Name="TokenValidationFails"     ; Description="LDAP bind over SSL/TLS and failed the channel binding token validation"         ; Query='<Select Path="Directory Service">*[System[(EventID=3039)]]</Select>'}
$Definitions+=@{Name="ChannelBindingNotEnforced"; Description="During the previous 24 hours period, %1 unprotected LDAPS binds were performed" ; Query='<Select Path="Directory Service">*[System[(EventID=3040)]]</Select>'}


#configure Event Forwarding on collector server
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    WECUtil qc /q
}

foreach ($Definition in $Definitions){
    #Create XML Parameters
    $Name=$Definition.Name
    $Description=$Definition.Description
    $DestinationLogPath=$Definition.Name
    $Query=@"
<QueryList>
  <Query Id="0">
    $($Definition.Query)
  </Query>
</QueryList>
"@

    #Generate AllowedSourceDomainComputers parameter
    $SID=(Get-ADGroup -Identity "Domain Controllers").SID.Value
    $AllowedSourceDomainComputers="O:NSG:BAD:P(A;;GA;;;$SID)S:"


    #Create XML
    [xml]$xml=@"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>$Name</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>$Description</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>

    <!-- Use Normal (default), Custom, MinLatency, MinBandwidth -->
    <ConfigurationMode>Custom</ConfigurationMode>

    <Delivery Mode="Push">
        <Batching>
            <MaxItems>1</MaxItems>
            <MaxLatencyTime>1000</MaxLatencyTime>
        </Batching>
        <PushSettings>
            <Heartbeat Interval="40000"/>
        </PushSettings>
    </Delivery>

    <Query>
        <![CDATA[
$Query
        ]]>
    </Query>

    <ReadExistingEvents>true</ReadExistingEvents>
    <TransportName>http</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>$DestinationLogPath</LogFile>
    <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
    <AllowedSourceDomainComputers>$AllowedSourceDomainComputers</AllowedSourceDomainComputers>
</Subscription>
"@

    #Configure subscription on Collector Server
    Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
        $($using:xml).Save("$env:TEMP\temp.xml")
        wecutil cs "$env:TEMP\temp.xml"
    }
}

#endregion

#region validate subscriptions
$CollectorServerName="Collector"

$subscriptions=Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    #enumerate subscriptions
    $subs=wecutil es
    $subscriptionXMLs= foreach ($sub in $subs){
        [xml]$xml=wecutil gs $sub /f:xml
        $xml.subscription
    }
    $Subscriptions = foreach ($subXML in $subscriptionXMLs) {
        New-Object PSObject -Property @{
            SubscriptionId = $subXML.SubscriptionId
            SubscriptionType = $subXML.SubscriptionType
            Description = $subXML.Description
            Enabled = $subXML.Enabled
            Uri = $subXML.Uri
            ConfigurationMode = $subXML.ConfigurationMode
            Delivery = $subXML.Delivery
            Query = $subXML.Query."#cdata-section"
            ReadExistingEvents = $subXML.ReadExistingEvents
            TransportName = $subXML.TransportName
            ContentFormat = $subXML.ContentFormat
            Locale = $subXML.Locale
            LogFile = $subXML.LogFile
            AllowedSourceNonDomainComputers = $subXML.AllowedSourceNonDomainComputers
            AllowedSourceDomainComputers = $subXML.AllowedSourceDomainComputers
            AllowedSourceDomainComputersFriendly = (ConvertFrom-SddlString $subXML.AllowedSourceDomainComputers).DiscretionaryAcl
        }
    }
    return $subscriptions
}

$subscriptions | Format-Table SubscriptionId,AllowedSourceDomainComputersFriendly,LogFile -AutoSize

#endregion

#region configure controllers to send logs to collector
$DCs=(Get-ADDomainController).Name
$CollectorServerName="Collector"

#configure DCs
Invoke-Command -ComputerName $DCs -ScriptBlock {
    #add NT AUTHORITY\NETWORK SERVICE to "Directory Service" log
    wevtutil set-log "Directory Service" /ca:'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)'

    #add network service toEvent Log Readers
    #Add-LocalGroupMember -Group "Event Log Readers" -Member "Network Service"
    
    #configure registry
    $Path="hklm:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    if(!(Test-Path $Path)){
        New-Item $Path -Force
    }
    New-ItemProperty -Path $Path -Name 1 -Value "Server=http://$($using:CollectorServerName):5985/wsman/SubscriptionManager/WEC,Refresh=30" -PropertyType String -force
    #refresh GPO to kick in event subscription
    gpupdate /force
}

#apply network service permissions to be able to read logs
Invoke-Command -ComputerName $DCs -ScriptBlock {
    #create new svchost process
    Sc.exe config WinRM type= own
    restart-service WinRM
}
 
#endregion

#region check if DCs are registered
$CollectorServerName="Collector"
$SubscriptionNames="LDAPSNotRequired","LDAPBindsStats","LDAPBindsComputers","LDAPBindsRejectStats","TokenValidationFails","ChannelBindingNotEnforced"
Invoke-Command -ComputerName $CollectorServerName -ScriptBlock {
    foreach ($SubscriptionName in $Using:SubscriptionNames){
        wecutil gs $SubscriptionName
    }
}
 
#endregion