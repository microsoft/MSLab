# Windows Admin Center deployments

<!-- TOC -->

- [Windows Admin Center deployments](#windows-admin-center-deployments)
    - [About the lab](#about-the-lab)
        - [Your feedback is welcome](#your-feedback-is-welcome)
    - [LabConfig and lab prerequisites](#labconfig-and-lab-prerequisites)
    - [Scenario prerequisites](#scenario-prerequisites)
        - [Install RSAT on Management machine](#install-rsat-on-management-machine)
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
            - [Install the failover clusters](#install-the-failover-clusters)
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

> **Note:** All commands below should be executed from the `Management` virtual machine that runs Windows 10.

### Install RSAT on Management machine

First, we will check if RSAT is installed (it's necessary to work with servers remotelly). If you did not provide RSAT msu (downloaded from http://aka.ms/RSAT) during the lab hydration, we need to install it manually now.

```PowerShell
if ((Get-HotFix).HotFixId -notcontains "KB2693643"){
    Invoke-WebRequest -UseBasicParsing -Uri "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS_1803-x64.msu" -OutFile "$env:USERPROFILE\Downloads\WindowsTH-RSAT_WS_1803-x64.msu"
    Start-Process -Wait -Filepath "$env:USERPROFILE\Downloads\WindowsTH-RSAT_WS_1803-x64.msu" -Argumentlist "/quiet"
}
 
```

### Install and configure ADCS role on the domain controller

Certification Authority would be used to issue signed certificates for the Windows Admin Center instances.

On domain controller `DC` install ADCS role, and after role installation we need to allow issuing certificates of `WebServer` template. To simplify our lab scenario, we will allow every computer in lab's Active Directory domain to enroll a certificate using the `WebServer` template.

```PowerShell
Invoke-Command -ComputerName "DC" -ScriptBlock {
    # Install ADCS role
    Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
    Install-AdcsCertificationAuthority -Force -CAType EnterpriseRootCa -HashAlgorithmName SHA256 -CACommonName "Lab-Root-CA"

    # Install PSPKI module for managing Certification Authority
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name PSPKI -Force
    Import-Module PSPKI

    # Allow Domain Computers and Domain Controllers to enroll WebServer certificates
    Get-CertificateTemplate -Name WebServer |
        Get-CertificateTemplateAcl |
        Add-CertificateTemplateAcl -User "Domain Computers" -AccessType Allow -AccessMask Read, Enroll |
        Add-CertificateTemplateAcl -User "Domain Controllers" -AccessType Allow -AccessMask Read, Enroll |
        Set-CertificateTemplateAcl
}
 
```

## Standalone installation

Windows Admin Center supports installation in two modes:

- Desktop mode when installed on Windows 10
- Gateway mode when installed on Windows Server

For both modes installation steps are the same, the main differences in our lab is that in desktop mode WAC runs as background process while in Gateway mode WAC runs as a network service.

You can proceed with the installation on the `WacGateway` virtual machine for gateway mode or on `Management` machine for desktop mode.
Select one of the mentioned virtual machines and when logged to that virtual machine proceed with following sections.

For GatewayMode run these commands with `Invoke-Command` and for desktop mode just use the inner content of the `Invoke-Command`s.

### Generate a certificate

In order to use own certificate instead of default self-signed one, certificate needs to be generated before actually installing Windows Admin Center and certificate needs to be imported in Computer store of that machine.

```PowerShell
Invoke-Command -ComputerName "WacGateway" -ScriptBlock {
    # Enforce presence of the root certificate
    certutil -pulse

    # Create certificate with SAN for both FQDN and hostname
    $fqdn = (Resolve-DnsName -Name $env:COMPUTERNAME | Select -First 1).Name
    $cert = Get-Certificate -Template WebServer -DnsName $env:COMPUTERNAME, $fqdn -CertStoreLocation cert:\LocalMachine\My

    # Certificate's thumbprint needs to be specified in the installer later
    $cert.Certificate.Thumbprint
}
 
```

### Install Windows Admin Center

> **Note:** If you don't want to download installer over the Internet, copy MSI file over to virtual machine manually.

```PowerShell
Invoke-Command -ComputerName "WacGateway" -ScriptBlock {
    # Download Windows Admin Center to downloads
    Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"

    # Install Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install)
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:USERPROFILE\Downloads\WindowsAdminCenter.msi /qn /L*v log.txt REGISTRY_REDIRECT_PORT_80=1 SME_PORT=443 SME_THUMBPRINT=$($cert.Certificate.Thumbprint) SSL_CERTIFICATE_OPTION=installed"
}

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

In HA installation PFX file containing the certificate is needed, following block of code will request that certificate and save it to `WacHaCert.pfx` file in `Downloads` folder of logged in user.

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

# Ensure Root Certificate presense
certutil -pulse

# Generate certificates for both clusters
$certificatePassword = ConvertTo-SecureString -String "LS1setup!" -Force -AsPlainText
Get-WacPfxCertificate -ClientAccessPoint "wac-san" -CertificateOutputPath "$env:USERPROFILE\Downloads\WacHaCertSan.pfx" -CertificatePassword $certificatePassword
Get-WacPfxCertificate -ClientAccessPoint "wac-s2d" -CertificateOutputPath "$env:USERPROFILE\Downloads\WacHaCertS2D.pfx" -CertificatePassword $certificatePassword
 
```

> **Note:** As `Get-Certificate` commandlet currently does not support generating certificate with exportable private key so `certreq` utility is used instead to generate the certificate.

#### Install the failover clusters

Choose on of the Failover cluster options and follow steps:

  1. [SAN based](#san-based-failover-cluster) (Can be installed only on Hyper-V running Windows Server)
  2. [Storage Spaces Direct based](#storage-spaces-direct-failover-cluster) (Can be installed also on Windows 10)

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
$clusterSharedVolume = Get-ClusterSharedVolume -Cluster $clusterName -Name "*$volumeName*"
$currentPath = $clusterSharedVolume.SharedVolumeInfo.FriendlyVolumeName
$currentVolumeName = Split-Path $currentPath -Leaf
$fullPath = Join-Path -Path "C:\ClusterStorage\" -ChildPath $currentVolumeName

if($fullPath -ne $currentPath){ # On Windows 2019 volume name is already as we expect
    Invoke-Command -ComputerName $ClusterSharedVolume.OwnerNode -ScriptBlock {
        Rename-Item -Path $Using:fullPath -NewName $Using:volumeName -PassThru
    }
}
 
```

### Install Windows Admin Center within the cluster

After the failover cluster is ready we can proceed with the installation of the Windows Admin Center.

Run these PowerShell commands from the `DC` virtual machine as previously.

```PowerShell
# Download Windows Admin Center to downloads
$msiFile = "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi"
Invoke-WebRequest -UseBasicParsing -Uri https://aka.ms/WACDownload -OutFile $msiFile

# Download & unzip HA scripts
$zipFile = "$env:USERPROFILE\Downloads\WindowsAdminCenterHA-SetupScripts.zip"
Invoke-WebRequest -UseBasicParsing -Uri http://aka.ms/WACHASetupScripts -OutFile $zipFile
Expand-Archive -LiteralPath $zipfile -DestinationPath "$env:USERPROFILE\Downloads"
 
```

Now when we have downloaded everything on the `DC` node we can copy everything needed to one of the cluster nodes, in our case we will use first node of the cluster. For copying the installation files we will use this function on corresponing failover cluster. 

Let's start by definding the function:

```PowerShell
# Enable Windows PowerShell remoting on our management machine
Enable-PSRemoting

# Prepare cluster node for the Windows Admin Center installation
function Install-WacCluster {
    Param(
        [parameter(Mandatory = $true)]
        [String]
        $ClusterNode,

        [parameter(Mandatory = $true)]
        [String]
        $CertificatePath,

        [parameter(Mandatory = $true)]
        [String]
        $ClientAccessPoint
    )

    $nodeSession = New-PSSession –ComputerName $ClusterNode
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock { New-Item -Type Directory "C:\Data" -ErrorAction SilentlyContinue }
    Copy-Item -Path $CertificatePath -Destination 'C:\Data\' -ToSession $nodeSession
    Copy-Item -Path "$env:USERPROFILE\Downloads\Install-WindowsAdminCenterHA.ps1" -Destination 'C:\Data\' -ToSession $nodeSession 
    Copy-Item -Path "$env:USERPROFILE\Downloads\WindowsAdminCenter.msi" -Destination 'C:\Data\' -ToSession $nodeSession

    # Temporarily enable CredSSP delegation to avoid double-hop issue
    $memberServer = "WacSan-Node01"
    $password = ConvertTo-SecureString "LS1setup!" -AsPlainText -Force
    $labAdminCredential = New-Object System.Management.Automation.PSCredential ("CORP\LabAdmin", $password)

    Enable-WSManCredSSP -Role "Client" -DelegateComputer $ClusterNode -Force
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Enable-WSManCredSSP Server -Force }

    Invoke-Command -Credential $labAdminCredential -Authentication Credssp -ComputerName $ClusterNode -ScriptBlock {
        $certPassword = ConvertTo-SecureString -String "LS1setup!" -Force -AsPlainText
        $certName = Split-Path $Using:CertificatePath -Leaf
        C:\data\Install-WindowsAdminCenterHA.ps1 -ClusterStorage "C:\ClusterStorage\VolumeWac" -ClientAccessPoint $Using:ClientAccessPoint -MsiPath "C:\Data\WindowsAdminCenter.msi" -CertPath "C:\Data\$($certName)" -CertPassword $certPassword
    }

    # Disable CredSSP
    Disable-WSManCredSSP -Role Client
    Invoke-Command -ComputerName $ClusterNode -ScriptBlock { Disable-WSManCredSSP Server }
}
 
```

And now execute that function for selected cluster(s).

```PowerShell
# For SAN cluster via WacSan-Node01
Install-WacCluster -ClientAccessPoint "wac-san" -ClusterNode $nodesSan[0] -CertificatePath "$env:USERPROFILE\Downloads\WacHaCertSan.pfx"
 
```

```PowerShell
# For SAN cluster via WacS2D-Node01
Install-WacCluster -ClientAccessPoint "wac-s2d" -ClusterNode $nodesS2D[0] -CertificatePath "$env:USERPROFILE\Downloads\WacHaCertS2D.pfx"
 
```

After the installation is finished (it takes few minutes to complete) using the Edge browser navigate to corresponding URL address in the table below to access highly available instance of the Windows Admin Center.

| Cluster Type            | URL                                |
| ----------------------- | ---------------------------------- |
| SAN                     | https://wac-san.corp.contoso.com/  |
| Storage Spaces Direct   | https://wac-s2d.corp.contoso.com/  |
