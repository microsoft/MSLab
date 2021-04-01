If ((Get-ExecutionPolicy) -ne "RemoteSigned"){
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
}

#region variables

#grab folder to download to
$folder=Read-Host -Prompt "Please type path to download. For example `"c:\temp`" (if nothing specified, $PSScriptRoot is used)"
if(!$folder){$folder=$PSScriptRoot}

#do you want preview?
$preview=Read-Host -Prompt "Do you want to download preview updates? Y/N, default N"
if($preview -eq "y"){
    $preview = $true
}else{
    $preview=$false
}

#URLs with list of latest updates
$URLs=@()
$URLs+=@{Product="AzureStackHCI";URL="https://support.microsoft.com/en-us/topic/release-notes-for-azure-stack-hci-64c79b7f-d536-015d-b8dd-575f01090efd"}
$URLs+=@{Product="Windows10";URL="https://support.microsoft.com/en-us/topic/windows-10-update-history-7dd3071a-3906-fa2c-c342-f7f86728a6e3"}

$UpdatesList=@()
$Titles=@()
#endregion

#region process
#download content
Write-Output "Downloading content of latest update sites"
foreach ($url in $urls){
    $content=Invoke-WebRequest -Uri $url.url
    $UpdatesList+=($content.ParsedHtml.getElementsByClassName("supLeftNavArticle") | Select-Object OuterText).OuterText
    $Titles+=$content.ParsedHtml.getElementsByClassName("supLeftNavCategoryTitle") | Select-Object textcontent
}

#clean white space
$CleanedList=@()
Foreach ($item in $UpdatesList){
    $item=$item.Replace(" "," ")
    $CleanedList+=$item.Trim()
}

#clean white space
$CleanedListTitles=@()
Foreach ($Title in $Titles){
    $Title=$Title.textcontent.Replace(" "," ")
    $CleanedListTitles+=$Title.Trim()
}

#Process data
Write-Output "Processing data"
$i=0
$Output=@()
foreach ($item in $CleanedList){
    if ($item -eq $CleanedListTitles[$i]){
        $Title=$CleanedListTitles[$i]
        $i++
    }else{
        $DateString=([Regex]::Match($item,'\w*\ \d*,\ \d*')).Value
        if (($DateString -split " ")[1].Length -eq 3){
            $format="MMMM dd, yyyy"
        }else{
            $format="MMMM d, yyyy"
        }
        $Date=([datetime]::ParseExact($DateString,$format,[Globalization.CultureInfo]::CreateSpecificCulture('en-US')))
        if ($item -like "*Preview*"){
            $ReleaseType="Preview"
        }elseif ($item -like "*Out-Of-Band*"){
            $ReleaseType="Out-Of-Band"
        }elseif ($item -like "*servicing*"){
            $ReleaseType="ServicingStackUpdate"
        }else{
            $ReleaseType="Standard"
        }
        if ($title -like "*initial*"){
            $Version="Initial Release"
        }else{
            $Version=([Regex]::Match($Title,"(?<=version\ )\w{4}")).Value
        }
        $Product=$Title.Replace(", version $version and Windows Server, version $version update history"," $Version").Replace(", version 1809, Windows Server, version 1809,"," 1809").Replace(", version $version"," $version").Replace(" update history","")
        #$Product="$(([Regex]::Match($Title,'^.+?(?=,)')).Value)$(([Regex]::Match($Title,'\ and\ .+?(?=,)')).value) $(([Regex]::Match($Title,"(?<=version\ )\w{4}")).Value)"
        #skip mobile
        if ($item -notlike "*Windows 10 Mobile*"){
            $Output += [PSCustomObject]@{
                "Product"=$Product
                "Version"=$Version
                "Date"= $Date
                "KB" = ([Regex]::Match($item,'KB\d*')).Value
                "Build" = ([Regex]::Match($item,'\d*\.\d*')).Value
                "ReleaseType" = $ReleaseType
                "NavCategoryTitle"=$Title
                "NavArticle"=$item
            }
        }
    }
}


$Products=$Output | Select-Object Product -Unique | Out-GridView -Title "Please select Products you want to download latest updates for" -OutputMode Multiple

$Result=@()
Foreach ($Product in $products){
    if ($preview -eq $true){
        $result+=$Output | Where-Object {$_.Product -eq $Product.Product -and $_.ReleaseType -notlike "ServicingStackUpdate"} | Select-Object -First 1
        $result+=$Output | Where-Object {$_.Product -eq $Product.Product -and $_.ReleaseType -eq "ServicingStackUpdate"} | Select-Object -First 1
    }else{
        $result+=$Output | Where-Object {$_.Product -eq $Product.Product -and $_.ReleaseType -eq "Standard"} | Select-Object -First 1
        $result+=$Output | Where-Object {$_.Product -eq $Product.Product -and $_.ReleaseType -eq "ServicingStackUpdate"} | Select-Object -First 1
    }
}
#endregion

#region download MSCatalog module
Write-Output "Checking if MSCatalog PS Module is Installed"
if (!(Get-InstalledModule -Name MSCatalog -ErrorAction Ignore)){
    # Verify Running as Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If (!( $isAdmin )) {
        Write-Host "-- Restarting as Administrator to install Modules" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
        exit
    }
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name MSCatalog -Force
}

#endregion

#region Download update
Write-Output "Downloading Updates"
Foreach ($item in $Result){
    $DateFolderName=($result | Where-Object Product -eq $item.Product | where ReleaseType -ne ServicingStackUpdate).Date | Get-Date -Format "dd-MMM-yy"
    $Path="$folder\$($item.Product)\$DateFolderName"
    New-Item -Path $Path -ItemType Directory -ErrorAction Ignore
    $UpdateCandidate=Get-MSCatalogUpdate -Search $item.kb | Where-Object Title -Like "*x64*"
    if ($UpdateCandidate.count -eq 1){
        $UpdateCandidate | Save-MSCatalogUpdate -UseBits -Destination $Path
    }elseif ($item.Product -like "Azure Stack*"){
        $UpdateCandidate | Where-Object Products -Like "*Azure Stack*" | Save-MSCatalogUpdate -UseBits -Destination $Path
    }elseif ($item.Product -like "*Windows Server*"){
        $update=$UpdateCandidate | Where-Object Title -Like "*Windows Server*"
        if ($update.count -eq 1){
            $update | Save-MSCatalogUpdate -UseBits -Destination $Path
        }else{
            $update | Where-Object Title -Like "*$($item.Version)*" | Save-MSCatalogUpdate -UseBits -Destination $Path
        }
    }
}

#endregion

Write-Host "Job finished. Press enter to continue" -ForegroundColor Green
Read-Host