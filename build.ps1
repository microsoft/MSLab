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

$baseDir = ".\Scripts\"
$outputDir = ".\Output"
$outputFile = "Release.zip"
[array]$ignoredFiles = "0_Shared.ps1"
[array]$ignoredFilesToSign = @() #"LabConfig.ps1"

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
    # Download signing script
    Invoke-WebRequest -Uri $SignScriptUri -OutFile .\sign.ps1

    . .\sign.ps1

    $signedOutputDir = "$($outputDir)\Signed"
    if(Test-Path -Path $signedOutputDir) {
        Remove-Item -Path $signedOutputDir -Recurse -Force
    }

    $signedReleaseDirectory = New-Item -ItemType "Directory" -Path ".\" -Name $signedOutputDir
    $files = Get-ChildItem -Path $releaseDirectory -File | Where-Object Name -NotIn $ignoredFilesToSign 

    # sign scripts
    Invoke-CodeSign -Files $files -OutputPath $signedReleaseDirectory -ClientId $ClientId

    $signedFiles = Get-ChildItem -Path $signedReleaseDirectory.FullName
    if($files.Length -ne $signedFiles.Length) {
        throw "Signing files failed (source count: $($files.Length), signedCount: $($signedFiles.Length))"
    }

    # and copy scripts that are ignored from signing
    Get-ChildItem -Path $releaseDirectory -File | Where-Object Name -In $ignoredFilesToSign | Copy-Item -Destination $signedReleaseDirectory.FullName

    $outputFullPath = $signedReleaseDirectory.FullName
}

Compress-Archive -Path "$($outputFullPath)\*" -DestinationPath $outputFile -CompressionLevel Optimal -Force
