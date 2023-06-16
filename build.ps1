[CmdletBinding(DefaultParameterSetName = 'BuildOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildOnly')]
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildAndSign')]
    [string]$Version,
    [Parameter(Mandatory = $false, ParameterSetName = 'BuildAndSign')]
    [bool]$SignScripts = $false,
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildAndSign')]
    [string]$SignScriptUri,
    [Parameter(Mandatory = $true, ParameterSetName = 'BuildAndSign')]
    [string]$ClientId
)

$toolsDir = ".\Tools\"
$baseDir = ".\Scripts\"
$outputBaseDir = ".\Output\"
$outputDir = "$($outputBaseDir)\Compiled"
$signedOutputDir = "$($outputBaseDir)\Signed"
$toolsOutputDir = "$($outputBaseDir)\Tools"
$outputFile = "Release.zip"

[array]$ignoredFiles = "0_Shared.ps1"
[array]$ignoredFilesToSign = @() #"LabConfig.ps1"
[array]$toolsIgnoredFilesToSign = @("1_SQL_Install.ps1", "2_ADK_Install.ps1", "3_SCVMM_Install.ps1")

#region Build (and optionally sign) Scripts
if(Test-Path -Path $outputDir) {
    Remove-Item -Path $outputDir -Recurse -Force
}

$releaseDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $outputDir
$files = Get-ChildItem -Path $baseDir
foreach($file in $files) {
    if($file.Name -in $ignoredFiles) {
        continue
    }
    $content = Get-Content -Path $file.FullName
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
           $includeFile = Join-Path -Path $baseDir -ChildPath $includeFile
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
    $outFile = Join-Path -Path $releaseDirectory -ChildPath $file.Name
    Set-Content -Path $outFile -Value $output
}

$outputFullPath = $releaseDirectory.FullName

if($SignScripts) {
    # Download signing script with Managed Identity
    $token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F" -Headers @{ "Metadata" = "true" }
    Invoke-WebRequest -Headers @{ "x-ms-version" = "2017-11-09"; "Authorization" = "Bearer $($token.access_token)" } -Uri $SignScriptUri -OutFile .\sign.ps1
    
    . .\sign.ps1
}

if(Test-Path -Path $signedOutputDir) {
    Remove-Item -Path $signedOutputDir -Recurse -Force
}

$signedReleaseDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $signedOutputDir
$files = Get-ChildItem -Path $releaseDirectory -File | Where-Object Name -NotIn $ignoredFilesToSign 

if($SignScripts) {
    # sign scripts
    Invoke-CodeSign -Files $files -OutputPath $signedReleaseDirectory -ClientId $ClientId
} else {
    # if not signing, just copy files over as is
    $files | Select-Object -ExpandProperty FullName | Copy-Item -Destination $signedReleaseDirectory
}

$signedFiles = Get-ChildItem -Path $signedReleaseDirectory.FullName
if($files.Length -ne $signedFiles.Length) {
    throw "Signing files failed (source count: $($files.Length), signedCount: $($signedFiles.Length))"
}
#endregion

#region Build (and optionally sign) Tools
if(Test-Path -Path $ToolsOutputDir) {
    Remove-Item -Path $ToolsOutputDir -Recurse -Force
}
# and copy scripts that are ignored from signing
Get-ChildItem -Path $releaseDirectory -File | Where-Object Name -In $ignoredFilesToSign | Copy-Item -Destination $signedReleaseDirectory.FullName

$outputFullPath = $signedReleaseDirectory.FullName

$toolsSignedDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $toolsOutputDir
$toolsFiles = Get-ChildItem -Path $toolsDir -File | Where-Object Name -NotIn $toolsIgnoredFilesToSign

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

Compress-Archive -Path "$($outputFullPath)\*" -DestinationPath $outputFile -CompressionLevel Optimal -Force
