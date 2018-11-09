#####################################################################
# Import-CertificateTemplate.ps1
# Version 1.0
#
# Imports and registers certificate templates in Active Directory from a file.
#
# Note: this function supports only Windows 7/Windows Server 2008 R2 and newer systems.
# Vadims Podans (c) 2013
# http://en-us.sysadmins.lv/
#####################################################################
#requires -Version 2.0

function Import-CertificateTemplate {
    <#
    .Synopsis
        Imports and registers certificate templates in Active Directory from a file.
    .Description
        Imports certificate templates from a file that contains serialized templates. Use
        Export-CertificateTemplate command to export and serialize certificate templates.
        
        If certificate template is successfully imported, it is installed to Active Directory.
        The command must be run on a Windows 7/Windows Server 2008 R2 or newer OS. Windows
        Server 2003 and Windows Server 2008 are not supported.
        
        Note: the command generates new object identifier (OID) for the template. Existing
        OID reuse is not supported.
    .Parameter Path
        Specifies the path to a file that contains exported certificate templates.
    .Parameter ServerName
        Specifies the DNS name of the Active Directory server to which the changes will be applied.
        If this value is NULL, the changes will be applied to the default domain controller.
    .Example
        Import-CertificateTemplate c:\temp\templates.dat
    #>
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [IO.FileInfo]$Path,
            [Alias('DNSName','DC','DomainController','DomainControllerName','ComputerName')]
            [string]$ServerName
        )
        if (
            [Environment]::OSVersion.Version.Major -lt 6 -or
            [Environment]::OSVersion.Version.Major -eq 6 -and
            [Environment]::OSVersion.Version.Minor -lt 1
        ) {throw New-Object PlatformNotSupportedException}
        
        $bytes = [IO.File]::ReadAllBytes($Path)
        $pol = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
        $pol.InitializeImport($bytes)
        $templates = $pol.GetTemplates() | ForEach-Object {$_}
        $templates | ForEach-Object {
            $adwt = New-Object -ComObject X509Enrollment.CX509CertificateTemplateADWritable
            $adwt.Initialize($_)
            $adwt.Commit(1,$ServerName)
        }
}