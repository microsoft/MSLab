<#
Function script to hold all the common fuctions - Longterm this should be a module 
#>
<#
.Synopsis
   Check the supplied path for a single ISO and Mount it. Will display a dialog to prompt for a new path if a ISO is not found in the supplied path. 
.EXAMPLE
   Mount-ISO -path .\OSSever
#>
function Mount-ISO {
    [CmdletBinding()] 
    param (
        #Path
        [parameter(Mandatory=$true)]
        [string]$Path
    )
    Write-Verbose -Message "Test for ISO and if no ISO found, open file dialog to select one"
	If (Test-Path -Path $Path){
		$ISO = Get-ChildItem -Path $Path -Recurse -Include '*.iso' -ErrorAction SilentlyContinue
	}

	if (!($ISO)){
		Write-Verbose -Message "No ISO found in $Path"
		[reflection.assembly]::loadwithpartialname("System.Windows.Forms")
		$openFile = New-Object System.Windows.Forms.OpenFileDialog
        $openFile.Title = "Select a Windows OS install ISO"
		$openFile.Filter = "iso files (*.iso)|*.iso|All files (*.*)|*.*" 
		If($openFile.ShowDialog() -eq "OK")
		{
		   Write-Verbose -Message "File $openfile.name selected"
		} 
        if (!$openFile.FileName){
		        throw "Iso was not selected... Exiting"
		 }
		$ISO = Mount-DiskImage -ImagePath $openFile.FileName -PassThru
	}else {
        If($ISO.count -eq 1){
           Write-Verbose -Message "Found ISO $($ISO.FullName)"
		    Mount-DiskImage -ImagePath $ISO.FullName -PassThru
        }else{
            throw "There can be only one!! Ensure that there is only one iso file in $Path "
        }
	}
}

<#
.Synopsis
   Create a unattened.xml 
.EXAMPLE
   Create-UnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword "NeverUsePasswordAsAPassword"
#> 
Function Create-UnattendFileVHD{
    [CmdletBinding()] 
    param (
        #ComputerName
        [parameter(Mandatory=$true)]
        [string]$Computername,
        #Local Admin Password
        [parameter(Mandatory=$true)]
        [string]$AdminPassword,
        #Path
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    if ( Test-Path "$path\Unattend.xml" ) {
      Remove-Item "$Path\Unattend.xml"
    }
    $unattendFile = New-Item "$Path\Unattend.xml" -type File
    $fileContent =  @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <settings pass="offlineServicing">
   <component
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        language="neutral"
        name="Microsoft-Windows-PartitionManager"
        processorArchitecture="amd64"
        publicKeyToken="31bf3856ad364e35"
        versionScope="nonSxS"
        >
      <SanPolicy>1</SanPolicy>
    </component>
 </settings>
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
    </component>
  </settings>
</unattend>

"@

    Set-Content -path $unattendFile -value $fileContent

    #return the file object
    Return $unattendFile 
}

<#
.Synopsis
   Create a unattened.xml with domain join Blob
.EXAMPLE
   Create-UnattendFileBlob -Blob $blob.Substring(0,$blob.Length-1) -AdminPassword "NeverUsePasswordAsAPassword"
#> 
Function Create-UnattendFileBlob{
    [CmdletBinding()]
    param(
        #Domain join Blob
        [parameter(Mandatory=$true)]
        [string]$Blob,
        #Local Admin Password
        [parameter(Mandatory=$true)]
        [string]$AdminPassword,
        #Path to create Unattend.xml
        [parameter()]
        [string]$Path="Unattend.xml"
    )

        if(Test-Path -Path $Path){remove-item -Path $Path}
        $unattendFile = New-Item -Path $path -type File
        $fileContent = @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

    <settings pass="offlineServicing">
    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <OfflineIdentification>              
            <Provisioning>  
                <AccountData>$Blob</AccountData>
            </Provisioning>  
            </OfflineIdentification>  
    </component>
    </settings>

    <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <UserAccounts>
        <AdministratorPassword>
            <Value>$AdminPassword</Value>
            <PlainText>true</PlainText>
        </AdministratorPassword>
        </UserAccounts>
        <TimeZone>Pacific Standard Time</TimeZone>
    </component>
    </settings>

    <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
    </settings>
</unattend>

"@

    Set-Content -Path $unattendFile -Value $fileContent

    #return the file object
    $unattendFile|Write-Output
}

<#
.Synopsis
   returns current Script Directory
.EXAMPLE
  Get-ScriptDirectory
#> 
Function Get-ScriptDirectory{
    [CmdletBinding()]
    param()
    Split-Path -Path $script:MyInvocation.MyCommand.Path|Write-Output
}

<#
.Synopsis
   returns Windows Build Number
.EXAMPLE
  Get-ScriptDirectory
#> 
function  Get-WindowsBuildNumber {
    [CmdletBinding()]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem 
    [int]($os.BuildNumber)|Write-Output
} 