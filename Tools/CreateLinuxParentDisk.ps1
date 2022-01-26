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

##Load LabConfig....
. "$LabRoot\LabConfig.ps1"

Start-Transcript -Path "$ScriptRoot\CreateLinuxParentDisk.log"

$StartDateTime = Get-Date
WriteInfoHighlighted "Script started at $StartDateTime"

#region SSH
# Verify OpenSSH
$capability = Get-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
if($capability.State -ne "Installed") {
    WriteInfoHighlighted "`t Enabling OpensSH Client"
    Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
    Set-Service ssh-agent -StartupType Automatic
    Start-Service ssh-agent
}

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
#endregion

"Temp", "LAB/Packer Templates" | ForEach-Object {
    if (!( Test-Path "$LabRoot\$_" )) {
        WriteInfoHighlighted "Creating Directory $_"
        $d = New-Item -Type Directory -Path "$LabRoot\$_" 
    }
}

#region Download packer definitions
$templatesBase = "https://github.com/machv/mslab-templates/releases/latest/download/"
$packerTemplatesDirectory = "$LabRoot\LAB\Packer Templates\"
$templatesFile = "$($packerTemplatesDirectory)\templates.json"

Invoke-WebRequest -Uri "$($templatesBase)/templates.json" -OutFile $templatesFile
$templatesInfo = Get-Content -Path $templatesFile | ConvertFrom-Json
foreach($template in $templatesInfo) {
    $templateZipFile = Join-Path $packerTemplatesDirectory $template.package
    Invoke-WebRequest -Uri "$($templatesBase)/$($template.package)" -OutFile $templateZipFile
    Expand-Archive -Path $templateZipFile -DestinationPath (Join-Path $packerTemplatesDirectory $template.directory)
    Remove-Item -Path $templateZipFile
}
#endregion

#region Select ISO
$isoUrl = $isoHash = $null
WriteInfo "Please select ISO image with Linux"
[reflection.assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$openFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Please select Linux ISO image"
}
$openFile.Filter = "ISO files (*.iso)|*.iso|All files (*.*)|*.*" 
If($openFile.ShowDialog() -eq "OK") {
    WriteInfo "File $($openfile.FileName) selected"
    $isoUrl = $openFile.FileName #.Replace("\", "/")
    $isoHash = (Get-FileHash -Path $isoUrl -Algorithm SHA256).Hash
} 

if($isoUrl) {
    $isoName = Split-Path -Leaf $isoUrl
    $selectedTemplate = $templatesInfo | Where-Object { $isoName -match $_.isoPattern }
}

if(-not $selectedTemplate) {
    $selectedTemplate = $templatesInfo | Out-GridView -Title "Please select a Packer template to use" -OutputMode Single
}
#endregion

#region Build template
$tempDir = "$LabRoot\Temp" 

$packerTemplatePath = Join-Path $packerTemplatesDirectory $selectedTemplate.directory 
$packerTemplateFilePath = Join-Path $packerTemplatePath $selectedTemplate.templateFile

# for Linuxugging uncomment this line
New-Item -ItemType Directory -Path $tempDir -Name "packer_cache" -Force | Out-Null
New-Item -ItemType Directory -Path $tempDir -Name "packer_temp" -Force | Out-Null

$env:PACKER_LOG = 1
$env:PACKER_CACHE_DIR = Join-Path $tempDir "packer_cache"
$env:TMPDIR = Join-Path $tempDir "packer_temp"
$outputDir = Join-Path $tempDir "packer_output"
$env:Path += ";$LabRoot\LAB\bin"

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
    packer build -force -var "ssh_key=$($publicKey)" -var "username=$($username)" -var "password=$($LabConfig.AdminPassword)" -var "vm_dir=$($outputDir)" -var "iso_path=$($isoUrl)" -var "iso_name=$($isoName)" -var "iso_checksum=$($isoHash)" $packerTemplateFilePath
}
catch {
    WriteErrorAndExit "Packer build failed"
}

$vhdx = Get-ChildItem -Path $outputDir -Filter "*.vhdx" -Recurse
if($vhdx.Length -eq 0) {
    WriteErrorAndExit "No VHDX found in output directory $($outputDir)"
}

$vhdName = "$($selectedTemplate.directory).vhdx"
$parentDisk = "$LabRoot\ParentDisks\$vhdName"
Move-Item -Path $vhdx.FullName -Destination $parentDisk

#region Cleanup
Remove-Item -Path (Join-Path $tempDir "packer_cache") -Recurse -Force
Remove-Item -Path (Join-Path $tempDir "packer_temp") -Recurse -Force
Remove-Item -Path $outputDir -Recurse -Force
#endregion

WriteSuccess "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"
WriteSuccess "Press enter to continue..."
Read-Host | Out-Null
