param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$baseDir = ".\Scripts\"
$outputDir = ".\Output"
$outputFile = "Release.zip"
[array]$ignoredFiles = "0_Shared.ps1"

if(Test-Path -Path $outputDir) {
    Remove-Item -Path $outputDir -Recurse
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

Compress-Archive -Path "$($releaseDirectory.FullName)\*" -DestinationPath $outputFile -CompressionLevel Optimal -Force
