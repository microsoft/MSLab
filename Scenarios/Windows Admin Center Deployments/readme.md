# Windows Admin Center deployments
<!-- TOC -->

- [Windows Admin Center deployments](#windows-admin-center-deployments)
    - [About the lab](#about-the-lab)
        - [Your feedback is welcome](#your-feedback-is-welcome)
    - [LabConfig and lab prerequisites](#labconfig-and-lab-prerequisites)
    - [Scenario prerequisites](#scenario-prerequisites)
        - [Install and configure ADCS role on the domain controller](#install-and-configure-adcs-role-on-the-domain-controller)
    - [Standalone installation](#standalone-installation)
        - [Generate a certificate](#generate-a-certificate)
        - [Install Windows Admin Center](#install-windows-admin-center)
        - [Run Windows Admin Center](#run-windows-admin-center)
            - [If Desktop mode](#if-desktop-mode)
            - [If Gateway mode](#if-gateway-mode)
    - [High Availability installation](#high-availability-installation)
        - [Shared prerequisites](#shared-prerequisites)
            - [Generate PFX certificate](#generate-pfx-certificate)
            - [Failover clustering management](#failover-clustering-management)
            - [Install the failover cluster](#install-the-failover-cluster)
                - [SAN based failover cluster](#san-based-failover-cluster)
                - [Storage Spaces Direct failover cluster](#storage-spaces-direct-failover-cluster)
        - [Install Windows Admin Center within the cluster](#install-windows-admin-center-within-the-cluster)

<!-- /TOC -->

## About the lab
In this lab you will set up basic PKI for Windows Admin Center and install WAC without default self-signed certificate to various environments:
  - Desktop mode on Windows 10
  - Gateway mode on single Windows Server node
  - High Availability installation 
     - Cluster with shared SAN storage
     - Storage Spaces Direct cluster (that can be installed also deployed in Azure)

### Your feedback is welcome
If you run into any issue with this scenario or find anything unclear, please let me know. You can reach me at mail vlmach@microsoft.com or on Twitter [@vladimirmach](https://twitter.com/vladimirmach).

## LabConfig and lab prerequisites
In order to deploy Windows Admin Center in above mentioned modes we will use [LabConfig.ps1](LabConfig.ps1) in this folder.

This configuration will set up these virtual machines:
  - Management machine running Windows 10 to access Windows Admin Center
  - Windows Server for standalone Windows Admin Center in Gateway mode
  - Node servers for Failover cluster using SAN
  - Node servers for Storage Spaces Direct cluster

> Management machine in this LabConfig is based on Windows 10 which requires `Win10RS4_G2.vhdx` image. This VHDX can be created using `CreateParentDisk.ps1` script in the `Tools` folder. That VHDX then needs to be moved to `ParentDisks` folder.

Internet connectivity in this lab is used as we will download additional PowerShell module in oder to configure Certification Authority and Windows Admin Center installation files.

## Scenario prerequisites
### Install and configure ADCS role on the domain controller
Certification Authority would be used to issue signed certificates for the Windows Admin Center instances.

On domain controller `DC` install ADCS role and PowerShell management module using these commands: 

```PowerShell
# Install ADCS role
Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -Force -CAType EnterpriseRootCa -HashAlgorithmName SHA256 -CACommonName "Lab-Root-CA"

# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Import-Module PSPKI
 
```

After installation we need to allow issuing certificates of `WebServer` template. To simplify our lab scenario, with commands below we will allow every computer in lab's Active Directory domain to enroll certificate using `WebServer` template.

```PowerShell
# Allow Domain Computers and Domain Controllers to enroll WebServer certificates
Get-CertificateTemplate -Name WebServer | 
    Get-CertificateTemplateAcl | 
    Add-CertificateTemplateAcl -User "Domain Computers" -AccessType Allow -AccessMask Read, Enroll | 
    Add-CertificateTemplateAcl -User "Domain Controllers" -AccessType Allow -AccessMask Read, Enroll |
    Set-CertificateTemplateAcl
 
```

## Standalone installation
Windows Admin Center supports installation in two modes:
  - Desktop mode when installed on Windows 10
  - Gateway mode when installed on Windows Server

For both modes installation steps are the same, the main differences in our lab is that in desktop mode WAC runs as background process while in Gateway mode WAC runs as a network service.

You can proceed with the installation directly on the `WacGateway` server for gateway mode or on `Management` machine for desktop mode. 
Select one of the mentioned virtual machines and when logged to that virtual machine proceed with following sections.

### Generate a certificate
In order to use own certificate instead of default self-signed one, certificate needs to be generated before actually installing Windows Admin Center and certificate needs to be imported in Computer store of that machine.

```PowerShell
# Create certificate with SAN for both FQDN and hostname
$fqdn = ([System.Net.Dns]::GetHostByName(($env:COMPUTERNAME))).Hostname
$cert = Get-Certificate -Template WebServer -DnsName $env:COMPUTERNAME, $fqdn -CertStoreLocation cert:\LocalMachine\My

# Certificate's thumbprint needs to be specified in the installer later
$cert.Certificate.Thumbprint
 
```

### Install Windows Admin Center
> **Note:** If you don't want to download installer over the Internet, copy MSI file over to virtual machine manually.

```PowerShell
# Download Windows Admin Center to downloads
Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

# Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SME_THUMBPRINT=$($cert.Certificate.Thumbprint) SSL_CERTIFICATE_OPTION=installed"
 
```
### Run Windows Admin Center
Based on which mode you've installed proceed with respective section.

> **Note:** Only Edge and Chrome browsers are officialy supported to work with Windows Admin Center.

#### If Desktop mode
When installed on Windows 10 to start Windows Admin Center we need to manually execute the application. The application will then start as background process with its icon in system tray. When executed it should automatically open the default web browser and navigate to WAC homepage https://management.corp.contoso.com.

```PowerShell
# Open Windows Admin Center
Start-Process "C:\Program Files\Windows Admin Center\SmeDesktop.exe"

```
#### If Gateway mode
After the installation on `WacGateway` Windows Admin Center's network service is started automatically. In order to access it you need to just open the web browser from the `Management` virtual machine, navigate to http://wacgateway.corp.contoso.com/ and you can log in to the Windows Admin Center.

## High Availability installation
In order to install Windows Admin Center in high availability mode Failover Cluster is required. In this Lab we show how to install Failover cluster in two ways:
  1. SAN based cluster that simulates traditional architecture with shared SAN storage between each cluster node. 
  2. Storage Spaces Direct cluster that simulates hyper-converged architecture and can be also deployed in Azure.

Log in to the `DC` virtual machine and run following PowerShell commands from there.

### Shared prerequisites
These steps are needed for both HA variants.

#### Generate PFX certificate
In this installation PFX file containing the certificate is needed, following block of code will request that certificate and save it to `WacHaCert.pfx` file in `Downloads` folder of logged in user. Certificate will be generated both with single name `wac` of the cluster and FQDN `wac.corp.contoso.com`.

```PowerShell
# Function that creates PFX certificate
function Get-WacPfxCertificate {
    Param(
        [parameter(Mandatory = $true)]
        [String]
        $ClientAccessPoint,

        [parameter(Mandatory = $true)]
        [String]
        $CertificateOutputPath,

        [parameter(Mandatory = $true)]
        [SecureString]
        $CertificatePassword 
    )

    # Answer file for certreq
    $fqdn = "{0}.{1}" -f $ClientAccessPoint, $env:USERDNSDOMAIN
    $content = @"
[NewRequest]
Subject = "CN=$($fqdn)" ; Remove to use an empty Subject name.
Exportable = TRUE
KeyLength = 2048
KeySpec = 1 ; Key Exchange – Required for encryption
KeyUsage = 0xA0 ; Digital Signature, Key Encipherment

MachineKeySet = True
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication
OID=1.3.6.1.5.5.7.3.2 ; Client Authentication

[Extensions]
; 2.5.29.17 is the OID for a SAN extension.
2.5.29.17 = "{text}"
_continue_ = "dns=$($fqdn)&"
_continue_ = "dns=$($ClientAccessPoint)&"

[RequestAttributes]
CertificateTemplate = WebServer
"@

    $answerFile = New-TemporaryFile
    Set-Content $answerFile.FullName $content

    $requestFile = New-TemporaryFile
    $publicCertFile = New-TemporaryFile
    Invoke-Expression -Command "certreq -new -q -f $($answerFile.FullName) $($requestFile.FullName)"
    Invoke-Expression -Command "certreq -submit -q -f -config $($env:LOGONSERVER)\Lab-Root-CA $($requestFile.FullName) $($publicCertFile.FullName)"
    Invoke-Expression -Command "certreq -accept $($publicCertFile.FullName)"

    # Get thumbprint of the newly generated certificate
    $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $certPrint.Import($publicCertFile.FullName)
    $thumbprint = $certPrint.Thumbprint

    # Cleanup temporary file
    Remove-Item $answerFile.FullName, $requestFile.FullName, $publicCertFile.FullName -Force

    # And export signed certificate to PFX file
    Get-ChildItem -Path Cert:\LocalMachine\My\$thumbprint | Export-PfxCertificate -FilePath $CertificateOutputPath -Password $CertificatePassword
}

# Generate certificates for both clusters
$certificatePassword = ConvertTo-SecureString -String "LS1setup!" -Force -AsPlainText
Get-WacPfxCertificate -ClientAccessPoint "wac-san" -CertificateOutputPath "$env:USERPROFILE\Downloads\WacHaCertSan.pfx" -CertificatePassword $certificatePassword
Get-WacPfxCertificate -ClientAccessPoint "wac-s2d" -CertificateOutputPath "$env:USERPROFILE\Downloads\WacHaCertS2D.pfx" -CertificatePassword $certificatePassword
 
```
> **Note:** As `Get-Certificate` commandlet currently does not support generating certificate with exportable private key so `certreq` utility is used instead to generate the certificate.

#### Failover clustering management
We need to install RSAT Management tools for Failover clustering to install the cluster.

```PowerShell
# Install features for management on DC
Install-WindowsFeature -Name "RSAT-Clustering", "RSAT-Clustering-Mgmt", "RSAT-Clustering-PowerShell"
 
```

#### Install the failover cluster
Choose on of the Failover cluster options and follow steps:
  1. [SAN based](#san-based-failover-cluster)
  2. [Storage Spaces Direct based](#storage-spaces-direct-failover-cluster)

##### SAN based failover cluster
> **Note:** This scenario requires Shared VHDX feature that is **not** available on Windows 10 Hyper-V.

```PowerShell
# Cluster Configuration
$clusterName = "Wac-Cluster-SAN"
$volumeName = "VolumeWac"
$nodesSan = @()
1..3 | ForEach-Object { $nodesSan += "WacSan-Node0$_" }

# Install failover clustering on all nodes
Invoke-Command -ComputerName $nodesSan -ScriptBlock { Install-WindowsFeature -Name "Failover-Clustering", "RSAT-Clustering-PowerShell" }

# Form a cluster
New-Cluster -Name $clusterName -Node $nodesSan

# Ensure that DNS name of the cluster would be accessible
Start-Sleep 5
Clear-DnsClientCache

# Set up file share witness
$witnessName = "SAN-ClusterWitness"
New-Item -Path "C:\Shares" -Name $witnessName -ItemType Directory

# Generate account list
$accounts = @()
$accounts += "Corp\$($clusterName)$"

# Create file share
New-SmbShare -Name $witnessName -Path "C:\Shares\$witnessName" -FullAccess $accounts
(Get-SmbShare $witnessName).PresetPathAcl | Set-Acl

Set-ClusterQuorum -Cluster $clusterName -FileShareWitness "\\DC\$($witnessName)"

# Configure volumes on "SAN" based Hyper-V
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

##### Storage Spaces Direct failover cluster

```PowerShell
# Cluster Configuration
$clusterName = "Wac-Cluster-S2D"
$volumeName = "VolumeWac"
$nodesS2D = @()
1..3 | ForEach-Object { $nodesS2D += "WacS2D-Node0$_" }

# Install failover clustering on all nodes
Invoke-Command -ComputerName $nodesS2D -ScriptBlock { 
    Install-WindowsFeature -Name "Failover-Clustering", "RSAT-Clustering-PowerShell" 
}
Test-Cluster –Node $nodesS2D –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"
New-Cluster –Name $clusterName –Node $nodesS2D –NoStorage

# Ensure that DNS name of the cluster would be accessible
Start-Sleep 5
Clear-DnsClientCache

# Set up file share witness
$witnessName = "S2D-ClusterWitness"
New-Item -Path "C:\Shares" -Name $witnessName -ItemType Directory

# Generate account list
$accounts = @()
$accounts += "Corp\$($clusterName)$"

# Create file share
New-SmbShare -Name $witnessName -Path "C:\Shares\$witnessName" -FullAccess $accounts
(Get-SmbShare $witnessName).PresetPathAcl | Set-Acl

Set-ClusterQuorum -Cluster $clusterName -FileShareWitness "\\DC\$($witnessName)"

# Now enable the cluster. This step takes a few minutes to complete.
Enable-ClusterS2D -CimSession $clusterName -confirm:0 -Verbose

# And in last step we will create a volume where Windows Admin Center files will be stored.
New-Volume -FriendlyName $volumeName -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 40GB -CimSession $clusterName

# Rename the volume
$clusterSharedVolume = Get-ClusterSharedVolume -Cluster $clusterName -Name "*$volumeName*"
$currentPath = $clusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
$currentVolumeName = Split-Path $currentPath -Leaf
$fullPath = Join-Path -Path "C:\ClusterStorage\" -ChildPath $currentVolumeName

Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ScriptBlock {
    Rename-Item -Path $Using:fullPath -NewName $Using:volumeName -PassThru
}
 
```

### Install Windows Admin Center within the cluster
After the failover cluster is ready we can proceed with the installation of the Windows Admin Center.

Run these PowerShell commands from the `DC` virtual machine as previously.
```PowerShell
# Download Windows Admin Center to downloads
$msiFile = "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile $msiFile

# Download HA scripts
$zipFile = "$env:USERPROFILE\Downloads\WindowsAdminCenterHA-SetupScripts.zip"
Invoke-WebRequest -UseBasicParsing -Uri http://aka.ms/WACHASetupScripts -OutFile $zipFile

# Unzip HA scripts
$zipFile = "$env:USERPROFILE\Downloads\WindowsAdminCenterHA-SetupScripts.zip"
Expand-Archive -LiteralPath $zipfile -DestinationPath "$env:USERPROFILE\Downloads"
 
```
Now when we have downloaded everything on the `DC` node we can copy everything needed to one of the cluster nodes, in our case we will use first node of the cluster. For copying the installation files we will use this function on corresponing failover cluster. 

Let's start by definding the function:
```PowerShell
# Prepare cluster node for the Windows Admin Center installation
function Copy-WacInstallData {
    Param(
        [parameter(Mandatory = $true)]
        [String]
        $ClusterNode,

        [parameter(Mandatory = $true)]
        [String]
        $CertificatePath
    )

    $nodeSession = New-PSSession –ComputerName $ClusterNode
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock { New-Item -Type Directory "C:\Data" -ErrorAction SilentlyContinue }
    Copy-Item -Path $CertificatePath -Destination 'C:\Data\' -ToSession $nodeSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\Install-WindowsAdminCenterHA.ps1" -Destination 'C:\Data\' -ToSession $nodeSession 
    Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination 'C:\Data\' -ToSession $nodeSession
}
 
```
And now execute that function for selected cluster(s).

```PowerShell
# For SAN cluster to WacSan-Node01
Copy-WacInstallData -ClusterNode $nodesSan[0] -CertificatePath "$env:USERPROFILE\Downloads\WacHaCertSan.pfx"
 
```

```PowerShell
# For SAN cluster to WacS2D-Node01
Copy-WacInstallData -ClusterNode $nodesS2D[0] -CertificatePath "$env:USERPROFILE\Downloads\WacHaCertS2D.pfx"
 
```

And now we need to log in to that node of the cluster directly and there in PowerShell window start the installation process.

For **SAN cluster** connect to `WacSan-Node01` virtual machine and run this:
```PowerShell
$certPassword = ConvertTo-SecureString -String "LS1setup!" -Force -AsPlainText
C:\data\Install-WindowsAdminCenterHA.ps1 -ClusterStorage "C:\ClusterStorage\VolumeWac" -ClientAccessPoint "wac-san" -MsiPath "C:\Data\WindowsAdminCenter.msi" -CertPath "C:\Data\WacHaCertSan.pfx" -CertPassword $certPassword
 
```

For **S2D cluster** connect to `WacS2D-Node01` virtual machine and run this:
```PowerShell
$certPassword = ConvertTo-SecureString -String "LS1setup!" -Force -AsPlainText
C:\data\Install-WindowsAdminCenterHA.ps1 -ClusterStorage "C:\ClusterStorage\VolumeWac" -ClientAccessPoint "wac-s2d" -MsiPath "C:\Data\WindowsAdminCenter.msi" -CertPath "C:\Data\WacHaCertS2D.pfx" -CertPassword $certPassword
 
```

After the installation finished (it takes few minutes to complete) you can log in to the `Management` virtual machine and from a web browser navigate to corresponding URL address in the table below to access highly available instance of the Windows Admin Center.

| Cluster Type            | URL                                |
| ----------------------- | ---------------------------------- |
| SAN                     | https://wac-san.corp.contoso.com/  |
| Storage Spaces Direct   | https://wac-s2d.corp.contoso.com/  |
