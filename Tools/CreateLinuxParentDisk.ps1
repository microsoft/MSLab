# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (-not $isAdmin) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1

    if($PSVersionTable.PSEdition -eq "Core") {
        Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    } else {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    }
    
    exit
}

function WriteSuccess($message){
    Write-Host $message -ForegroundColor Green
}

function WriteInfo($message) {
    Write-Host $message
}

function WriteInfoHighlighted($message){
    Write-Host $message -ForegroundColor Cyan
}
function WriteErrorAndExit($message){
    Write-Host $message -ForegroundColor Red
    Write-Host "Press enter to continue ..."
    Read-Host | Out-Null
    Exit
}

$ScriptRoot = $PSScriptRoot
#$ScriptRoot = Resolve-Path "$((pwd).Path)"
$LabRoot = Resolve-Path "$ScriptRoot\..\"
$env:Path += ";$LabRoot\LAB\bin"

##Load LabConfig....
. "$LabRoot\LabConfig.ps1"

Start-Transcript -Path "$ScriptRoot\CreateLinuxParentDisk.log"

$StartDateTime = Get-Date
WriteInfoHighlighted "Script started at $StartDateTime"

#region check prereqs
# Packer
if (-not (Get-Command "packer.exe" -ErrorAction SilentlyContinue)) { 
    WriteErrorAndExit "Packer not found."
}

# Packer templates
$packerTemplatesDirectory = "$ScriptRoot\PackerTemplates\"
$templatesFile = "$packerTemplatesDirectory\templates.json"
if (-not (Test-Path $templatesFile)) {
    WriteErrorAndExit "Packer Templates are not downloaded."
}
$templatesInfo = Get-Content -Path $templatesFile | ConvertFrom-Json
WriteInfoHighlighted "Using templates pack version $($templatesInfo.version)"

# Verify OpenSSH
$capability = Get-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
if($capability.State -ne "Installed") {
    WriteErrorAndExit "OpensSH cabability not found."
}

# SSH Key
if($LabConfig.SshKeyPath) {
    if(-not (Test-Path $LabConfig.SshKeyPath)) {
        WriteErrorAndExit "`t Cannot find SSH key configured in LabConfig: $($LabConfig.SshKeyPath)."
    }

    $private = ssh-keygen.exe -y -e -f $LabConfig.SshKeyPath
    $public = ssh-keygen.exe -y -e -f "$($LabConfig.SshKeyPath).pub"
    $comparison = Compare-Object -ReferenceObject $private -DifferenceObject $public
    if($comparison) {
        WriteErrorAndExit "`t SSH Keypair $($LabConfig.SshKeyPath) does not match."
    }

    $sshKeyPath = $LabConfig.SshKeyPath
} else {
    $sshKeyDir = "$LabRoot\LAB\.ssh" 
    $key = "$sshKeyDir\lab_rsa"

    if(-not (Test-Path $key)) {
        WriteErrorAndExit "`t Cannot find SSH key that prereq created: $($key)."
    }

    $private = ssh-keygen.exe -y -e -f $key
    $public = ssh-keygen.exe -y -e -f "$($key).pub"

    $comparison = Compare-Object -ReferenceObject $private -DifferenceObject $public
    if($comparison) {
        WriteErrorAndExit "`t SSH Keypair $($key) does not match."
    }

    $sshKeyPath = $key
}

WriteInfoHighlighted "SSH key $($sshKeyPath) will be used"

#region Select ISO
$isoUrl = $null
WriteInfo "Please select ISO image with a supported Linux distribution"
[reflection.assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Please select Linux ISO image"
}
$openFile.Filter = "ISO files (*.iso)|*.iso|All files (*.*)|*.*" 
If($openFile.ShowDialog() -eq "OK") {
    WriteInfo "File $($openfile.FileName) selected"
    $isoUrl = $openFile.FileName #.Replace("\", "/")
    $isoName = Split-Path -Leaf $isoUrl
} 

if (-not $openFile.FileName) {
    WriteErrorAndExit  "ISO was not selected... Exitting"
}

$selectedTemplate = $templatesInfo.templates | Where-Object { $isoName -match $_.isoPattern }
if(-not $selectedTemplate) {
    $selectedTemplate = $templatesInfo.templates | Out-GridView -Title "Please select a Packer template to use" -OutputMode Single
}

if(-not $selectedTemplate) {
    WriteErrorAndExit  "Packer template was not selected... Exitting"
}
#endregion

#region Build template
# ask for imagename
$tempVhdName = "$($selectedTemplate.directory).vhdx"
$vhdName = (Read-Host -Prompt "Please type VHD name (if nothing specified, $tempVhdName is used")
if(-not $vhdName) {
    $vhdName = $tempVhdName
}

# ask for size
[int64]$vhdSize = (Read-Host -Prompt "Please type size of the Image in GB. If nothing specified, 20 is used")
$vhdSize = $vhdSize*1GB
if (-not $vhdSize) {
    $vhdSize = 20GB
}

$tempDir = "$LabRoot\Temp"
if (-not (Test-Path $tempDir)) {
    WriteInfo "Creating Directory $tempDir"
    New-Item -Type Directory -Path $tempDir
}
#endregion

$packerTemplatePath = Join-Path $packerTemplatesDirectory $selectedTemplate.directory 
$packerTemplateFilePath = Join-Path $packerTemplatePath $selectedTemplate.templateFile

# for Linuxugging uncomment this line
New-Item -ItemType Directory -Path $tempDir -Name "packer_cache" -Force | Out-Null
New-Item -ItemType Directory -Path $tempDir -Name "packer_temp" -Force | Out-Null

$env:PACKER_LOG = 1
$env:PACKER_CACHE_DIR = Join-Path $tempDir "packer_cache"
$env:TMPDIR = Join-Path $tempDir "packer_temp"
$outputDir = Join-Path $tempDir "packer_output"


WriteInfo "Starting image build"

$publicKey = Get-Content "$($sshKeyPath).pub"

if($LabConfig.LinuxAdminName) {
    $username = $LabConfig.LinuxAdminName
} else {
    $username = $LabConfig.DomainAdminName
}
$username = $username.ToLower()

try {
    packer init $packerTemplateFilePath
    packer build -force -var "osdisk_size=$($vhdSize/1MB)" -var "ssh_key=$($publicKey)" -var "username=$($username)" -var "password=$($LabConfig.AdminPassword)" -var "vm_dir=$($outputDir)" -var "iso_path=$($isoUrl)" -var "iso_name=$($isoName)" $packerTemplateFilePath
}
catch {
    WriteErrorAndExit "Packer build failed"
}

function Cleanup {
    Remove-Item -Path (Join-Path $tempDir "packer_cache") -Recurse -Force
    Remove-Item -Path (Join-Path $tempDir "packer_temp") -Recurse -Force
    Remove-Item -Path $outputDir -Recurse -Force
}

$vhdx = Get-ChildItem -Path $outputDir -Filter "*.vhdx" -Recurse
if($vhdx.Length -eq 0) {
    Cleanup
    WriteErrorAndExit "No VHDX found in output directory $($outputDir). Probably Packer build failed, please check log output above for details."
}


$parentDisk = "$LabRoot\ParentDisks\$vhdName"
Move-Item -Path $vhdx.FullName -Destination $parentDisk

#region Cleanup
Cleanup
#endregion

# finishing 
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) minutes."
Stop-Transcript
WriteSuccess "Press enter to continue..."
Read-Host | Out-Null