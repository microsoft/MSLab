#region variables
    #grafana and influxdb variables
    $GrafanaServerName="Grafana"
    $InfluxDBServerName="InfluxDB"
    $InfluxDBPath="E:\InfluxDB\" #path for DB and config. In lab is D drive drive that is not initialized and will be formatted
    $InfluxDBConfigPath=$InfluxDBPath+"influxdb.conf"

    #Certification Authority
    $CSServerName="CA"

    #SSL cert will be reloaded there
    $DomainControllerName="DC"

    #grafana variables
    $LDAP_servers = "dc.corp.contoso.com" #for multiple "10.0.0.2 10.0.0.3"
    $OU_For_User_And_Group = "OU=Workshop,DC=Corp,DC=contoso,DC=com"
    $Grafana_LDAPuser = "GrafanaUser" #account to query LDAP
    $Grafana_LDAPuserpwd = "LS1setup!"
    $Grafana_AdminsGroupName = "GrafanaAdmins" #Grafana Admins Group
    $Grafana_Admins_To_Add = "LabAdmin"

    #firewall vars
    $IPSecEnabledServers="DC",$GrafanaServerName,$InfluxDBServerName,"S2D1","S2D2","S2D3","S2D4"
    $InfluxDBAuthorizedServers="DC",$GrafanaServerName,"S2D1","S2D2","S2D3","S2D4"

    #telegraf - monitored servers
    $clusters=@("S2D-Cluster")
    #$clusters=(Get-Cluster -Domain $env:USERDOMAIN | Where-Object S2DEnabled -eq 1).Name

#endregion

#region download required files to downloads folder
$ProgressPreference='SilentlyContinue' #for faster download
#influxDB and telegraph
Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/influxdb/releases/influxdb-1.7.8_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\influxdb.zip"
Invoke-WebRequest -UseBasicParsing -Uri https://dl.influxdata.com/telegraf/releases/telegraf-1.12.2_windows_amd64.zip -OutFile "$env:USERPROFILE\Downloads\telegraf.zip"
#Grafana
Invoke-WebRequest -UseBasicParsing -Uri https://dl.grafana.com/oss/release/grafana-6.6.0.windows-amd64.zip -OutFile "$env:USERPROFILE\Downloads\grafana.zip"
#NSSM - the Non-Sucking Service Manager
Invoke-WebRequest -UseBasicParsing -Uri https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip -OutFile "$env:USERPROFILE\Downloads\NSSM.zip"
#endregion

#region Download and Install Edge Dev
$ProgressPreference='SilentlyContinue' #for faster download
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2069324&Channel=Dev&language=en-us&Consent=1" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe"
#Install Edge Dev
Start-Process -FilePath "$env:USERPROFILE\Downloads\MicrosoftEdgeSetup.exe" -Wait

#endregion

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
    #Install IIS
    Install-WindowsFeature Web-WebServer -ComputerName $CSServerName -IncludeManagementTools

    #Create a CertData Folder and CPS Text File
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        New-Item -Path C:\inetpub\wwwroot\CertData -Type Directory
        Write-Output "Placeholder for Certificate Policy Statement (CPS). Modify as needed by your organization." | Out-File C:\inetpub\wwwroot\CertData\cps.txt
    }

    #New IIS Virtual Directory
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        $vDirProperties = @{
            Site         = "Default Web Site"
            Name         = "CertData"
            PhysicalPath = 'C:\inetpub\wwwroot\CertData'
        }
        New-WebVirtualDirectory @vDirProperties
    }

    #Allow IIS Directory Browsing & Double Escaping
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -Value $true -PSPath "IIS:\Sites\$($vDirProperties.site)\$($vDirProperties.name)"
        Set-WebConfigurationProperty -filter /system.webServer/Security/requestFiltering -name allowDoubleEscaping -value $true -PSPath "IIS:\Sites\$($vDirProperties.site)"
    }

    #New Share for the CertData Directory
    New-SmbShare -CimSession $CSServerName -Name CertData -Path C:\inetpub\wwwroot\CertData -ReadAccess "Corp\domain users" -ChangeAccess "corp\cert publishers"
    #configure NTFS Permissions
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {(Get-SmbShare CertData).PresetPathAcl | Set-Acl}

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

    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Set-Content -Value $using:Content -Path C:\windows\CAPolicy.inf
    }

    #Install ADCS
    Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools -ComputerName CA

    #Enable CredSSP
    # Temporarily enable CredSSP delegation to avoid double-hop issue
    Enable-WSManCredSSP -Role "Client" -DelegateComputer $CSServerName -Force
    Invoke-Command -ComputerName $CSServerName -ScriptBlock { Enable-WSManCredSSP Server -Force }

    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    #Install ADCS Certification Authority Role Services
    Invoke-Command -ComputerName $CSServerName -Credential $Credentials -Authentication Credssp -ScriptBlock {
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
    Invoke-Command -ComputerName $CSServerName -ScriptBlock { Disable-WSManCredSSP Server }

    #Configure Max Validity Period of Certificates Issued by this CA
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Certutil -setreg ca\ValidityPeriodUnits 5
        Certutil -setreg ca\ValidityPeriod "Years"
    }

    #Configure the CRL Validity Periods
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Certutil -setreg CA\CRLPeriodUnits 6
        Certutil -setreg CA\CRLPeriod "Days"
        Certutil -setreg CA\CRLDeltaPeriodUnits 0
        Certutil -setreg CA\CRLDeltaPeriod "Hours"
        Certutil -setreg CA\CRLOverlapUnits 3
        Certutil -setreg ca\CRLOverlapPeriod "Days"
    }

    #Configure the CDP Locations
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        ## Remove Existing CDP URIs
        $CrlList = Get-CACrlDistributionPoint
        ForEach ($Crl in $CrlList) { Remove-CACrlDistributionPoint $Crl.uri -Force }

        ## Add New CDP URIs
        Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
        Add-CACRLDistributionPoint -Uri C:\inetpub\wwwroot\CertData\%3%8.crl -PublishToServer -PublishDeltaToServer -Force
        Add-CACRLDistributionPoint -Uri "http://ca.corp.contoso.com/certdata/%3%8.crl" -AddToCertificateCDP -AddToFreshestCrl -Force
    }

    #Configure the AIA Locations
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        ## Remove Existing AIA URIs
        $AiaList = Get-CAAuthorityInformationAccess
        ForEach ($Aia in $AiaList) { Remove-CAAuthorityInformationAccess $Aia.uri -Force }
        ## Add New AIA URIs
        Certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\System32\CertSrv\CertEnroll\%3%4.crt"
        Add-CAAuthorityInformationAccess -AddToCertificateAia -uri "http://ca.corp.contoso.com/certdata/%3%4.crt" -Force
    }

    #Restart the CA Service & Publish a New CRL
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Restart-Service certsvc
        Start-Sleep 10
        Certutil -crl
    }

    #Copy the Root Certificate File to the CertData Folder
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Copy-Item "C:\Windows\System32\Certsrv\CertEnroll\CA.Corp.contoso.com_Contoso-Root-CA.crt" "C:\inetpub\wwwroot\CertData\CA.Corp.contoso.com_Contoso-Root-CA.crt"
    }

    #Rename the Root Certificate File
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        Rename-Item "C:\inetpub\wwwroot\CertData\CA.Corp.contoso.com_Contoso-Root-CA.crt" "Contoso-Root-CA.crt"
    }

    #Export the Root Certificate in PEM Format
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        $CACert=Get-ChildItem -Path Cert:\LocalMachine\CA | where Subject -Like *Contoso-Root-CA* | select -First 1
        $CACert |Export-Certificate -Type CERT -FilePath C:\inetpub\wwwroot\CertData\Contoso-Root-CA.cer
        Rename-Item "C:\inetpub\wwwroot\CertData\Contoso-Root-CA.cer" "Contoso-Root-CA.pem"
    }

    #Add mime type
    Invoke-Command -ComputerName $CSServerName -ScriptBlock {
        & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /-"[fileExtension='.pem']"
        & $Env:WinDir\system32\inetsrv\appcmd.exe set config /section:staticContent /+"[fileExtension='.pem',mimeType='text/plain']"
    }

#endregion

#region Add certificate templates for Computers (to secure LDAP) and Exportable for Grafana
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

    $DisplayName="DomainControllerLegacyCSP_RSA"
    $TemplateOtherAttributes = @{
        'flags' = [System.Int32]'131692'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
        'msPKI-Certificate-Name-Flag' = [System.Int32]'150994944'
        'msPKI-Enrollment-Flag' = [System.Int32]'41'
        'msPKI-Minimal-Key-Size' = [System.Int32]'2048'
        'msPKI-Private-Key-Flag' = [System.Int32]'101056768'
        'msPKI-RA-Signature' = [System.Int32]'0'
        'msPKI-Template-Minor-Revision' = [System.Int32]'1'
        'msPKI-Template-Schema-Version' = [System.Int32]'4'
        'pKIMaxIssuingDepth' = [System.Int32]'0'
        'ObjectClass' = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
        'pKIDefaultKeySpec' = [System.Int32]'1'
        'pKIExpirationPeriod' = [System.Byte[]]@('0','64','57','135','46','225','254','255')
        'pKIExtendedKeyUsage' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage' = [System.Byte[]]@('160')
        'pKIOverlapPeriod' = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        'revision' = [System.Int32]'100'
    }
    New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

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
    $TemplateNames="DomainControllerLegacyCSP_RSA","WebServerKSP_RSAExportable"
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

#region distribute certificates to Domain Controller and Grafana
    #Enroll Computer2016 template to DC to enable LDAPs
    $CertsToEnrollList=@()
    $CertsToEnrollList+=@{ServerName="DC";TemplateName="DomainControllerLegacyCSP_RSA"}
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

#region Reload AD SSL certificate
    Invoke-Command -ComputerName $DomainControllerName -ScriptBlock {
        $content=@'
dn:
changetype: modify
add: renewServerCertificate
renewServerCertificate: 1
-
'@
        $content | Out-File -FilePath $env:temp\ldap-renewservercert.txt
        & ldifde -i -f $env:temp\ldap-renewservercert.txt
    }
#endregion

#region Copy NSSM, InfluxDB and Grafana to servers
    #increase MaxEnvelopeSize to transfer files
    Invoke-Command -ComputerName $GrafanaServerName,$InfluxDBServerName -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}

    $GrafanaSession=New-PSSession -ComputerName $GrafanaServerName
    $InfluxDBSession=New-PSSession -ComputerName $InfluxDBServerName

    Copy-Item -Path "$env:USERPROFILE\Downloads\influxdb.zip" -Destination "$env:temp\influxdb.zip" -tosession $InfluxDBSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\grafana.zip" -Destination "$env:temp\grafana.zip" -tosession $GrafanaSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\NSSM.zip" -Destination "$env:temp\NSSM.zip" -tosession $GrafanaSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\NSSM.zip" -Destination "$env:temp\NSSM.zip" -tosession $InfluxDBSession

    #extract zip files and copy to destination folder
    invoke-command -Session $InfluxDBSession -scriptblock {
        Expand-Archive -Path "$env:temp\influxdb.zip" -DestinationPath "$env:temp" -Force
        Expand-Archive -Path "$env:temp\NSSM.zip" -DestinationPath "$env:temp" -Force
        #rename folder to remove version
        Get-ChildItem -Path $env:temp  | Where-Object name -like influxdb-* | Rename-Item -NewName InfluxDB
        Get-ChildItem -Path $env:temp  | Where-Object name -like nssm-* | Rename-Item -NewName NSSM
        #move to program files
        Move-Item -Path $env:temp\InfluxDB -Destination $env:ProgramFiles -Force
        #copy nssm to system32
        get-childitem -Path "$env:temp\NSSM" -recurse | Where-Object FullName -like "*win64*nssm.exe" | copy-item -destination "$env:SystemRoot\system32"
        #remove nssm folder
        Remove-Item -Path "$env:temp\NSSM" -Recurse -Force
        #remove zips
        Remove-Item -Path "$env:temp\*.zip" -Force
    }

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
#endregion

#region Configure InfluxDB to exist in different folder
    #Format raw Disk on InfluxDB Server
    Get-Disk -CimSession $InfluxDBServerName | Where-Object partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter E -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false

    #Create folders for DB
    Invoke-command -computername $InfluxDBServerName -scriptblock {   
        if (-not(Test-Path -Path $using:InfluxDBPath)){New-Item -Path $using:InfluxDBPath -ItemType Directory}
        "data","meta","wal" | Foreach-Object {
            New-Item -Type Directory -Path $using:InfluxDBPath -Name $_
        }
    }

    #replace path for database and copy config to DB folder
    $InfluxDBPathForeSlash=$InfluxDBPath.Replace("\","/")
    Invoke-command -computername $InfluxDBServerName -scriptblock {
        $content=Get-Content -Path $env:ProgramFiles\InfluxDB\InfluxDB.conf
        $content=$content.Replace("/var/lib/influxdb/",$using:InfluxDBPathForeSlash)
        Set-Content -Value $Content -Path $using:InfluxDBConfigPath -Encoding UTF8
    }
 
#endregion

#region Configure Grafana and Influx DB services
    Invoke-command -computername $GrafanaServerName -scriptblock {
        #install as service
        Start-Process -FilePath nssm.exe -ArgumentList "install Grafana ""$env:ProgramFiles\Grafana\bin\grafana-server.exe""" -Wait
        Start-Service Grafana
    }
    Invoke-command -computername $InfluxDBServerName -scriptblock {
        Start-Process -FilePath nssm.exe -ArgumentList "install InfluxDB ""$env:ProgramFiles\InfluxDB\influxd.exe""" -Wait
        Start-Process -FilePath nssm.exe -ArgumentList "set InfluxDB AppParameters -config $('"""""""')$using:InfluxDBConfigPath$('"""""""')" -Wait
        Start-Service InfluxDB
    }
    #remove
    #Start-Process -FilePath nssm.exe -ArgumentList "remove Grafana confirm" -Wait
    #Start-Process -FilePath nssm.exe -ArgumentList "remove InfluxDB confirm" -Wait
#endregion

#region Secure communication to InfluxDB with IPSec
    #Create IPSec rule locally and on machines to secure traffic between endpoints
    Invoke-Command -ComputerName $IPSecEnabledServers -ScriptBlock {
        if (-not (Get-NetIPsecRule -DisplayName "Default Request Rule" -ErrorAction SilentlyContinue)){
            New-NetIPsecRule -DisplayName "Default Request Rule" -InboundSecurity Request -OutboundSecurity Request
        }
    }

    New-NetFirewallRule -CimSession $InfluxDBServerName `
        -Action Allow `
        -Name "InfluxDB-HTTP-In-TCP" `
        -DisplayName "InfluxDB (HTTP-In)" `
        -Description "Inbound rule for Grafana DB. [TCP-8086]" `
        -Enabled True `
        -Direction Inbound `
        -Program "%ProgramFiles%\InfluxDB\influxd.exe" `
        -Protocol TCP `
        -LocalPort 8086 `
        -Profile Any `
        -Group "InfluxDB" `
        -RemoteAddress Any `
        -Authentication Required `
        -Encryption Dynamic


    New-NetFirewallRule -CimSession $InfluxDBServerName `
        -Action Allow `
        -Name "InfluxDBBackup-HTTP-In-TCP" `
        -DisplayName "InfluxDBBackup (HTTP-In)" `
        -Description "Inbound rule for Grafana DB. [TCP-8088]" `
        -Enabled True `
        -Direction Inbound `
        -Program "%ProgramFiles%\InfluxDB\influxd.exe" `
        -Protocol TCP `
        -LocalPort 8088 `
        -Profile Any `
        -Group "InfluxDB" `
        -RemoteAddress Any `
        -Authentication Required `
        -Encryption Dynamic
 
#endregion

#region Add computer to InfluxDB rule to authorize access to Influx DB Database
foreach ($server in $InfluxDBAuthorizedServers){
    #grab SID
    $SID=(Get-ADComputer -Identity $server).SID.Value
    #add SID to Firewall rule
    $FWRules=Get-NetFirewallrule -CimSession $InfluxDBServerName -Name InfluxDB*
    #grab current ACLs and add new ones
    foreach ($fwrule in $fwrules){
        $CurrentACL=($fwrule | Get-NetFirewallSecurityFilter).RemoteMachines
        if ((-not($CurrentACL -like "*$SID*")) -or ($CurrentACL -eq $null)){
            if ($CurrentACL){
                $SDDL=$CurrentACL+"(A;;CC;;;$SID)"
            }else{
                $SDDL="O:LSD:(A;;CC;;;$SID)"
            }
            $fwrule | Set-NetFirewallRule -RemoteMachine $SDDL
        }
    }
}

#endregion

#region Configure LDAP for Grafana
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

#region Secure LDAP to use SSL and Configure Grafana Certificate
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
            #region Configure SSL for LDAP
                #export RootCA.crt
                $content = @(
'-----BEGIN CERTIFICATE-----'
[System.Convert]::ToBase64String((get-item "Cert:\LocalMachine\CA\$($using:CACert.Thumbprint)").Export("Cert"), 'InsertLineBreaks')
'-----END CERTIFICATE-----'
)
                $content | Out-File -FilePath "C:\RootCA.crt" -Encoding ascii #as I did not find a way how to specify space in "C:/Program Files" in ldap.toml file
                #load toml file
                $tomlfilecontent=Get-Content -Path "C:\Program Files\Grafana\conf\ldap.toml"
                #configure RootCA
                $tomlfilecontent=$tomlfilecontent.Replace('# root_ca_cert = "/path/to/certificate.crt"','root_ca_cert = "C:/RootCA.crt"')
                #configure port
                $tomlfilecontent=$tomlfilecontent.Replace("port = 389","port = 636")
                #configure SSL
                $tomlfilecontent=$tomlfilecontent.Replace("use_ssl = false","use_ssl = true")
                #configure disable CA validation as it root ca is not trusted even all is configured right (fixed in latest release, commenting)
                #$tomlfilecontent=$tomlfilecontent.Replace("ssl_skip_verify = false","ssl_skip_verify = true")
                #set content to Toml file
                $tomlfilecontent | Set-Content -Path "C:\Program Files\Grafana\conf\ldap.toml"
            #endregion
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

#region push telegraf agent to nodes
    #expand telegraf
    Expand-Archive -Path "$env:USERPROFILE\Downloads\Telegraf.zip" -DestinationPath "$env:temp" -Force

    #download telegraf configuration from WSLab Github and configure grafana URL
    $InfluxDBServerURL="http://InfluxDB.corp.contoso.com:8086"
    $config=invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.conf
    $posh=(invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.ps1).content.substring(1)
    $config=$config.content.substring(1).replace("PlaceInfluxDBUrlHere",$InfluxDBServerURL) #| Out-File -FilePath "$env:temp\telegraf\telegraf.conf" -Encoding UTF8 -Force
    <#
    #reuse default telegraf config and replace server name in config
    $config=get-content -path "$env:temp\telegraf\telegraf.conf"
    $config=$config.replace("127.0.0.1","grafana.corp.contoso.com")
    $config | Set-Content -Path "$env:temp\telegraf\telegraf.conf" -Encoding UTF8
    #>

    foreach ($Cluster in $Clusters){
        $servers=(Get-ClusterNode -Cluster $Cluster).Name
        #increase MaxEnvelopeSize to transfer foles
        Invoke-Command -ComputerName $servers -ScriptBlock {Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 4096}
        #create sessions
        $sessions=New-PSSession -ComputerName $servers
        #copy telegraf
        foreach ($session in $sessions){
            Copy-Item -Path "$env:temp\Telegraf" -Destination "$env:ProgramFiles" -tosession $session -recurse -force
        }
        #replace telegraf conf and drop posh script
        Invoke-command -Session $sessions -ScriptBlock {
            $config=$using:config
            $config.replace("# clustername = ","clustername = $('"')$using:Cluster$('"')") | Out-File -FilePath "$env:ProgramFiles\telegraf\telegraf.conf" -Encoding UTF8 -Force
            $using:posh | Out-File -FilePath "$env:ProgramFiles\telegraf\telegraf.ps1" -Encoding UTF8 -Force
        }
        #install telegraf
        invoke-command -session $sessions -scriptblock {
            Start-Process -FilePath "$env:ProgramFiles\telegraf\telegraf.exe" -ArgumentList "--service install" -Wait
            Start-Service Telegraf
        }
    }

    #Example - Just replace telegraf conf on already deployed nodes
    <#
    $clusters=@("S2D-Cluster")
    $InfluxDBServerURL="http://InfluxDB.corp.contoso.com:8086"
    $config=invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.conf
    $posh=(invoke-webrequest -usebasicparsing -uri https://raw.githubusercontent.com/Microsoft/WSLab/dev/Scenarios/S2D%20and%20Grafana/telegraf.ps1).content.substring(1)
    $config=$config.content.substring(1).replace("PlaceInfluxDBUrlHere",$InfluxDBServerURL) #| Out-File -FilePath "$env:temp\telegraf\telegraf.conf" -Encoding UTF8 -Force

    foreach ($Cluster in $Clusters){
        $servers=(Get-ClusterNode -Cluster $Cluster).Name
        #replace telegraf conf and drop posh script
        Invoke-command -ComputerName $servers -ScriptBlock {
            Stop-Service Telegraf
            $config=$using:config
            $config.replace("# clustername = ","clustername = $('"')$using:Cluster$('"')") | Out-File -FilePath "$env:ProgramFiles\telegraf\telegraf.conf" -Encoding UTF8 -Force
            $using:posh | Out-File -FilePath "$env:ProgramFiles\telegraf\telegraf.ps1" -Encoding UTF8 -Force
            Start-Service Telegraf
        }
    }
    #>
 
#endregion