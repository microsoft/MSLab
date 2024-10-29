[CmdletBinding(DefaultParameterSetName = 'BuildOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildOnly')]
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildAndSign')]
    [string]$Version,
    [Parameter(Mandatory = $false, ParameterSetName = 'BuildAndSign')]
    [bool]$SignScripts = $false,
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildAndSign', HelpMessage = "Azure Blob URI to code signing script")]
    [string]$SignScriptUri = "",
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildAndSign', HelpMessage = "Client ID of Code Signing App Registration")]
    [string]$ClientId = ""
)

#region Configuration
$toolsDir = ".\Tools\"
$scriptsDir = ".\Scripts\"
$outputBaseDir = ".\Output\"
$scriptsOutputDir = Join-Path $outputBaseDir "ScriptsCompiled"
$signedScriptsOutputDir = Join-Path $outputBaseDir "Scripts"
$toolsOutputDir = Join-Path $outputBaseDir "ToolsCompiled"
$signedToolsOutputDir = Join-Path $outputBaseDir "Tools"
$scriptsOutputFile = "Release.zip"

# Files that would be skipped by Build function (no replacements)
[array]$scriptsBuildIgnoredFiles = @("0_Shared.ps1", "0_DCHydrate.ps1")
[array]$toolsBuildIgnoredFiles = @()

# Files that won't be signed after build function
[array]$scriptsIgnoredFilesToSign = @() #"LabConfig.ps1"
[array]$toolsIgnoredFilesToSign = @("1_SQL_Install.ps1", "2_ADK_Install.ps1", "3_SCVMM_Install.ps1")
#endregion

#region Init
if($SignScripts) {
    # Download signing script with Managed Identity
    $response = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F" -Headers @{ "Metadata" = "true" }
    Invoke-WebRequest -Headers @{ "x-ms-version" = "2017-11-09"; "Authorization" = "Bearer $($response.access_token)" } -Uri $SignScriptUri -OutFile .\sign.ps1
    
    . .\sign.ps1
}

if(Test-Path -Path $outputBaseDir) {
    Remove-Item -Path $outputBaseDir -Recurse -Force
}
#endregion

#region Functions
function Build-File {
    param (
        [string]$InputFilePath,
        [string]$OutputFilePath
    )

    $content = Get-Content -Path $InputFilePath
    $output = $content | ForEach-Object { 
        $line = $_

        # inline include
        if($line -match "^\s*\.\s+([^#]+)#\s\[!build-include-inline\]") {
           $includeFile = $Matches[1]

           if($includeFile.Contains("`$PSScriptRoot")) {
               $includeFile = $includeFile.Replace("`$PSScriptRoot", ".")
           }

           if($includeFile.StartsWith(".\")) {
               $includeFile = $includeFile.Substring(2)
           }
           $includeFile = Join-Path -Path $scriptsDir -ChildPath $includeFile
           if(-not (Test-Path -Path $includeFile)) {
               throw "Unable to include requested script ($includeFile)"
           }
           $line = Get-Content -Path $includeFile
        }

        # special variable populated with current version
        if($line -match '^\s*\$mslabVersion') { 
            $line = $line -replace '\$mslabVersion\s*=\s*"[^"]*"', "`$mslabVersion = `"$Version`"" 
        }

        $line
    }
    
    Set-Content -Path $OutputFilePath -Value $output
}
#endregion

#region Build (and optionally sign) Scripts
if(Test-Path -Path $scriptsOutputDir) {
    Remove-Item -Path $scriptsOutputDir -Recurse -Force
}

if(Test-Path -Path $signedScriptsOutputDir) {
    Remove-Item -Path $signedScriptsOutputDir -Recurse -Force
}

$scriptsReleaseDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $scriptsOutputDir
$scriptsFiles = Get-ChildItem -Path $scriptsDir
foreach($file in $scriptsFiles) {
    if($file.Name -in $scriptsBuildIgnoredFiles) {
        continue
    }
    
    $outFile = Join-Path -Path $scriptsReleaseDirectory -ChildPath $file.Name
    Build-File -InputFilePath $file.FullName -OutputFilePath $outFile
}

$scriptsSignedDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $signedScriptsOutputDir
$scriptFiles = Get-ChildItem -Path $scriptsReleaseDirectory -File | Where-Object Name -NotIn $scriptsIgnoredFilesToSign 

if($SignScripts) {
    # sign scripts
    Invoke-CodeSign -Files $scriptFiles -OutputPath $scriptsSignedDirectory -ClientId $ClientId
} else {
    # if not signing, just copy files over as is
    $scriptFiles | Select-Object -ExpandProperty FullName | Copy-Item -Destination $scriptsSignedDirectory
}

$signedScriptFiles = Get-ChildItem -Path $scriptsSignedDirectory.FullName
if($scriptFiles.Length -ne $signedScriptFiles.Length) {
    throw "Signing files failed (source count: $($scriptFiles.Length), signedCount: $($signedScriptFiles.Length))"
}
#endregion

#region Build (and optionally sign) Tools
if(Test-Path -Path $toolsOutputDir) {
    Remove-Item -Path $toolsOutputDir -Recurse -Force
}

if(Test-Path -Path $signedToolsOutputDir) {
    Remove-Item -Path $signedToolsOutputDir -Recurse -Force
}

$toolsReleaseDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $toolsOutputDir
$toolsFiles = Get-ChildItem -Path $toolsDir
foreach($file in $toolsFiles) {
    if($file.Name -in $toolsBuildIgnoredFiles) {
        continue
    }
    
    $outFile = Join-Path -Path $toolsReleaseDirectory -ChildPath $file.Name
    Build-File -InputFilePath $file.FullName -OutputFilePath $outFile
}

$toolsSignedDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $signedToolsOutputDir
$toolsFiles = Get-ChildItem -Path $toolsReleaseDirectory -File | Where-Object Name -NotIn $toolsIgnoredFilesToSign

if($SignScripts) {
    # Sign scripts in Tools folder
    Invoke-CodeSign -Files $toolsFiles -OutputPath $toolsSignedDirectory -ClientId $ClientId
} else {
    # or just copy tools scripts over
    $toolsFiles | Select-Object -ExpandProperty FullName | Copy-Item -Destination $toolsSignedDirectory
}

$signedToolsFiles = Get-ChildItem -Path $toolsSignedDirectory.FullName
if($toolsFiles.Length -ne $signedToolsFiles.Length) {
    throw "Signing files failed (source count: $($toolsFiles.Length), signedCount: $($signedToolsFiles.Length))"
}
#endregion

#region Create Scripts release ZIP
$scriptsOutputFullPath = $scriptsSignedDirectory.FullName
Compress-Archive -Path "$($scriptsOutputFullPath)\*" -DestinationPath $scriptsOutputFile -CompressionLevel Optimal -Force
#endregion