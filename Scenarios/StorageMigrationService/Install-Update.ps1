<#
  .SYNOPSIS
  Installs an Windows QFE Update from a local or network media source if not already installed.

  .DESCRIPTION
  Installs a Windows QFE Update from a specified media source by executing the update installer (.EXE) or Microsoft Update (.MSU) file.
  
  This script would normally be used with the Windows Server 2012 GPO PowerShell Start up Script feature to install a specific application or update.

  Normally WSUS would be used to distribute and install QFE updates, but some updates are not always available via this method (Windows Management Framework 3.0 and above for example).

  .PARAMETER InstallerPath
  The location of the update executable or MSU. Can be a local or network path. If an MSU file is specified then it will be automatically be installed by the WUSA.EXE with the appropraite parameters to ensure unattended installation. If an EXE file is specified then the appropriate quiet mode parameters are used.

  .PARAMETER KBID
  This is the KB ID for this Windows QFE Update. It must match that of the update specified in the Installer path because it is used to detect if this update has already been installed. The KBID is usually found in the update filename.

  .PARAMETER LogPath
  Optional parameter specifying where the installation log file should be written to. If not specified, an installation log file will not be written.
  The installation log file will be named with the name of the computer being installed to.
  
  .EXAMPLE
  To install the Windows Management Framework 5.0 April 2015 update with no log file creation:
  Install-Update -InstallerPath \\Server\Software$\Updates\WindowsBlue-KB3055381-x64.msu -KBID KB3055381

  .EXAMPLE
  To install the Windows Management Framework 5.0 April 2015 update creating log files for each machine it is installed on in \\Server\Logfiles$\ folder:
  Install-Update -InstallerPath \\Server\Software$\Updates\WindowsBlue-KB3055381-x64.msu -KBID KB3055381 -LogPath \\Server\Logfiles$\

  .OUTPUTS

  .NOTES
#>

# AUTHOR
# Daniel Scott-Raynsford
# http://dscottraynsford.wordpress.com/
#
# VERSION
# 1.0   2015-06-30   Daniel Scott-Raynsford       Initial Version
#

[CmdLetBinding(
    SupportsShouldProcess=$true
    )]

param( 
    [String]
    [Parameter(
        Position=1,
        Mandatory=$true
        )]
    [ValidateScript({ ($_ -ne '') -and ( Test-Path $_ ) })]
    $InstallerPath,
 
    [String]
    [Parameter(
        Position=2
        )]
    [ValidateNotNullOrEmpty()]
    $KBID,

    [String]
    [Parameter(
        Position=3
        )]
    [ValidateScript({ ( $_ -ne '' ) -and ( Test-Path $_ ) })]
    $LogPath,

    [Boolean]
    [Parameter(
        Position=4
        )]
    $Force
) # Param
 
Function Add-LogEntry ( [String]$Path ,[String]$Message)
{
    Write-Verbose -Message $Message
    # Only write log entry if a path was specified
    If ( $Path -ne '' ) {
        Add-Content -Path $Path -Value "$(Get-Date): $Message"
    } # ( $Path -ne '' )
} # Function Add-LogEntry

# If a Log Path was specified get up a log file name to write to.
If (($LogPath -eq '') -or ($LogPath -eq $null)) {
    [String]$LogFile = ''
} else {
    [String]$LogFile = Join-Path -Path $LogPath -ChildPath "$($ENV:computername)_$KBID.txt" 
} # ($LogPath -eq '')

# Has this update already been installed?
[Boolean]$Installed = $False
If ( (get-wmiobject -Class win32_QuickFixEngineering -Filter "HotfixID = '$KBID'" | Measure-Object).Count -gt 0 ) {
    [Boolean]$Installed = $True
} # (  (get-wmiobject -Class win32_QuickFixEngineering -Filter "HotfixID = '$KBID'" | Measure-Object).Count -gt 0 )

# This application or update is not installed - so install it.
If (-not $Installed) { 
    If ([io.path]::GetExtension($InstallerPath) -eq '.msu') {
	    [String]$Command="WUSA.EXE $InstallerPath /quiet /norestart)"
		[String]$Type="MSU $KBID"
	} else {
	    [String]$Command="$InstallerPath /quiet /norestart"
		[String]$Type="EXE $KBID"
	}

    Add-LogEntry -Path $LogFile -Message "Install $Type using $Command started."
    If ($PSCmdlet.ShouldProcess("Install $Type using $Command started")) {
        # Call the product Install.
        & cmd.exe /c "$Command"
        [Int]$ErrorCode = $LASTEXITCODE
    } # ShouldProcess
    Switch ($ErrorCode) {
		0 { Add-LogEntry -Path $LogFile -Message "Install $Type using $Command completed successfully." }
		1641 { Add-LogEntry -Path $LogFile -Message "Install $Type using $Command completed successfully and computer is rebooting." }
		default { Add-LogEntry -Path $LogFile -Message "Install $Type using $Command failed with error code $ErrorCode." }
    } # ($ErrorCode)
} Else {
    Write-Verbose -Message "$Type is already installed."
} # (-not $Installed)
