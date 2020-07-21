param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$baseDir = ".\Scripts\"
[array]$ignoredFiles = "0_Shared.ps1"

$releaseDirectory = New-Item -ItemType "Directory" -Path ".\" -Name "Output"
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
        if($line -match '^\s*\$wslabVersion') { 
            $line = $line -replace '\$wslabVersion\s*=\s*"[^"]*"', "`$wslabVersion = `"$Version`"" 
        }

        $line
    }
    $outFile = Join-Path -Path $releaseDirectory -ChildPath $file.Name
    Set-Content -Path $outFile -Value $output
}
Compress-Archive -Path "$($releaseDirectory.FullName)\*" -DestinationPath Release.zip -CompressionLevel Optimal
