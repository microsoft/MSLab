#####################################################################
# Export-CertificateTemplate.ps1
# Version 1.0
#
# Exports certificate templates to a serialized format.
#
# Vadims Podans (c) 2013
# http://en-us.sysadmins.lv/
#####################################################################
#requires -Version 2.0

function Export-CertificateTemplate {
    <#
    .Synopsis
        Exports certificate templates to a serialized format.
    .Description
        Exports certificate templates to a serialized format. Exported templates can be distributed
        and imported in another forest.
    .Parameter Template
        A collection of certificate templates to export. A collection can be retrieved by running
        Get-CertificateTemplate that is a part of PSPKI module: https://pspki.codeplex.com
    .Parameter Path
        Specifies the path to export.
    .Example
        $Templates = Get-CertificateTemplate -Name SmartCardV2, WebServerV3
        PS C:\> Export-CertificateTemplate $templates c:\temp\templates.dat
    #>
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [PKI.CertificateTemplates.CertificateTemplate[]]$Template,
            [Parameter(Mandatory = $true)]
            [IO.FileInfo]$Path
        )
        if ($Template.Count -lt 1) {throw "At least one template must be specified in the 'Template' parameter."}
        $ErrorActionPreference = "Stop"

    #region enums
        $HashAlgorithmGroup = 1
        $EncryptionAlgorithmGroup = 2
        $PublicKeyIdGroup = 3
        $SigningAlgorithmIdGroup = 4
        $RDNIdGroup = 5
        $ExtensionAttributeGroup = 6
        $EKUGroup = 7
        $CertificatePolicyGroup = 8
        $EnrollmentObjectGroup = 9
    #endregion

    #region funcs
        function Get-OIDid ($OID,$group) {
            $found = $false
            :outer for ($i = 0; $i -lt $oids.Count; $i++) {
                if ($script:oids[$i].Value -eq $OID.Value) {
                    $ID = ++$i
                    $found = $true
                    break outer
                }
            }
            if (!$found) {
                $script:oids += New-Object psobject -Property @{
                    Value = $OID.Value;
                    Group = $group;
                    Name = $OID.FriendlyName;
                }
                $ID = $script:oids.Count
            }
            $ID
        }
        function Get-Seconds ($str) {
            [void]("$str" -match "(\d+)\s(\w+)")
            $period = $matches[1] -as [int]
            $units = $matches[2]
            switch ($units) {
                "hours" {$period * 3600}
                "days" {$period * 3600 * 24}
                "weeks" {$period * 3600 * 168}
                "months" {$period * 3600 * 720}
                "years" {$period * 3600 * 8760}
            }
        }
    #endregion

        $SB = New-Object Text.StringBuilder
        [void]$SB.Append(
@"
<GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
    <response>
        <policyID/>
        <policyFriendlyName/>
        <nextUpdateHours>8</nextUpdateHours>
        <policiesNotChanged a:nil="true" xmlns:a="http://www.w3.org/2001/XMLSchema-instance"/>
        <policies>
"@)
        $script:oids = @()
        foreach ($temp in $Template) {
                [void]$SB.Append("<policy>")
            $OID = New-Object Security.Cryptography.Oid $temp.OID.Value, $temp.DisplayName
            $tempID = Get-OIDid $OID $EnrollmentObjectGroup
            # validity/renewal
            $validity = Get-Seconds $temp.Settings.ValidityPeriod
            $renewal = Get-Seconds $temp.Settings.RenewalPeriod
            # key usages
            $KU = if ([int]$temp.Settings.Cryptography.CNGKeyUsage -eq 0) {
                '<keyUsageProperty xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                "<keyUsageProperty>$([int]$temp.Settings.CNGKeyUsage)</keyUsageProperty>"
            }
            # private key security
            $PKS = if ([string]::IsNullOrEmpty($temp.Settings.Cryptography.PrivateKeySecuritySDDL)) {
                '<permissions xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                "<permissions>$($temp.Settings.PrivateKeySecuritySDDL)</permissions>"
            }
            # public key algorithm
            $KeyAlgorithm = if ($temp.Settings.Cryptography.KeyAlgorithm.Value -eq "1.2.840.113549.1.1.1") {
                '<algorithmOIDReference xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $kalgID = Get-OIDid $temp.Settings.Cryptography.KeyAlgorithm $PublicKeyIdGroup
                "<algorithmOIDReference>$kalgID</algorithmOIDReference>"
            }
            # superseded templates
            $superseded = if ($temp.Settings.SupersededTemplates.Length -eq 0) {
                '<supersededPolicies xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'    
            } else {
                $str = "<supersededPolicies>"
                $temp.Settings.SupersededTemplates | ForEach-Object {$str += "<commonName>$_</commonName>"}
                $str + "</supersededPolicies>"
            }
            # list of CSPs
            $CSPs = if ($temp.Settings.Cryptography.CSPList.Count -eq 0) {
                '<cryptoProviders xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $str = "<cryptoProviders>`n"
                $temp.Settings.Cryptography.CSPList | ForEach-Object {
                    $str += "<provider>$_</provider>`n"
                }
                $str + "</cryptoProviders>"
            }
            # version
            [void]($temp.Version -match "(\d+)\.(\d+)")
            $major = $matches[1]
            $minor = $matches[2]
            # hash algorithm
            $hash = if ($temp.Settings.Cryptography.HashAlgorithm.Value -eq "1.3.14.3.2.26") {
                '<hashAlgorithmOIDReference xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $hashID = Get-OIDid $temp.Settings.Cryptography.HashAlgorithm $HashAlgorithmGroup
                "<hashAlgorithmOIDReference>$hashID</hashAlgorithmOIDReference>"
            }
            # enrollment agent
            $RAR = if ($temp.Settings.RegistrationAuthority.SignatureCount -eq 0) {
                '<rARequirements xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $str = @"
<rARequirements>
<rASignatures>$($temp.Settings.RegistrationAuthority.SignatureCount)</rASignatures>
"@
                if ([string]::IsNullOrEmpty($temp.Settings.RegistrationAuthority.ApplicationPolicy.Value)) {
                    $str += '<rAEKUs xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
                } else {
                    $raapID = Get-OIDid $temp.Settings.RegistrationAuthority.ApplicationPolicy $EKUGroup
                    $str += @"
<rAEKUs>
    <oIDReference>$raapID</oIDReference>
</rAEKUs>
"@
                }
                if ($temp.Settings.RegistrationAuthority.CertificatePolicies.Count -eq 0) {
                    $str += '<rAPolicies xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
                } else {
                    $str += "                       <rAPolicies>"
                    $temp.Settings.RegistrationAuthority.CertificatePolicies | ForEach-Object {
                        $raipID = Get-OIDid $_ $CertificatePolicyGroup
                        $str += "<oIDReference>$raipID</oIDReference>`n"
                    }
                    $str += "</rAPolicies>`n"
                }
                $str += "</rARequirements>`n"
                $str
            }
            # key archival
            $KAS = if (!$temp.Settings.KeyArchivalSettings.KeyArchival) {
                '<keyArchivalAttributes xmlns:a="http://www.w3.org/2001/XMLSchema-instance" a:nil="true"/>'
            } else {
                $kasID = Get-OIDid $temp.Settings.KeyArchivalSettings.EncryptionAlgorithm $EncryptionAlgorithmGroup
@"
<keyArchivalAttributes>
    <symmetricAlgorithmOIDReference>$kasID</symmetricAlgorithmOIDReference>
    <symmetricAlgorithmKeyLength>$($temp.Settings.KeyArchivalSettings.KeyLength)</symmetricAlgorithmKeyLength>
</keyArchivalAttributes>
"@
            }
            $sFlags = [Convert]::ToUInt32($("{0:x2}" -f [int]$temp.Settings.SubjectName),16)
            [void]$SB.Append(
@"
<policyOIDReference>$tempID</policyOIDReference>
<cAs>
    <cAReference>0</cAReference>
</cAs>
<attributes>
    <commonName>$($temp.Name)</commonName>
    <policySchema>$($temp.SchemaVersion)</policySchema>
    <certificateValidity>
        <validityPeriodSeconds>$validity</validityPeriodSeconds>
        <renewalPeriodSeconds>$renewal</renewalPeriodSeconds>
    </certificateValidity>
    <permission>
        <enroll>false</enroll>
        <autoEnroll>false</autoEnroll>
    </permission>
    <privateKeyAttributes>
        <minimalKeyLength>$($temp.Settings.Cryptography.MinimalKeyLength)</minimalKeyLength>
        <keySpec>$([int]$temp.Settings.Cryptography.KeySpec)</keySpec>
        $KU
        $PKS
        $KeyAlgorithm
        $CSPs
    </privateKeyAttributes>
    <revision>
        <majorRevision>$major</majorRevision>
        <minorRevision>$minor</minorRevision>
    </revision>
    $superseded
    <privateKeyFlags>$([int]$temp.Settings.Cryptography.PrivateKeyOptions)</privateKeyFlags>
    <subjectNameFlags>$sFlags</subjectNameFlags>
    <enrollmentFlags>$([int]$temp.Settings.EnrollmentOptions)</enrollmentFlags>
    <generalFlags>$([int]$temp.Settings.GeneralFlags)</generalFlags>
    $hash
    $rar
    $KAS
<extensions>
"@)
            foreach ($ext in $temp.Settings.Extensions) {
                $extID = Get-OIDid ($ext.Oid) $ExtensionAttributeGroup
                $critical = $ext.Critical.ToString().ToLower()
                $value = [Convert]::ToBase64String($ext.RawData)
                [void]$SB.Append("<extension><oIDReference>$extID</oIDReference><critical>$critical</critical><value>$value</value></extension>")
            }
            [void]$SB.Append("</extensions></attributes></policy>")
        }
        [void]$SB.Append("</policies></response>")
        [void]$SB.Append("<oIDs>")
        $n = 1
        $script:oids | ForEach-Object {
            [void]$SB.Append(@"
<oID>
    <value>$($_.Value)</value>
    <group>$($_.Group)</group>
    <oIDReferenceID>$n</oIDReferenceID>
    <defaultName>$($_.Name)</defaultName>
</oID>
"@)
            $n++
        }
        [void]$SB.Append("</oIDs></GetPoliciesResponse>")
        Set-Content -Path $Path -Value $SB.ToString() -Encoding Ascii
}