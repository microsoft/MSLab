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

$Products=@()
$Products+=@{Product="Azure Stack HCI 20H2";SearchString="Cumulative Update for Azure Stack HCI, version 20H2"                ;SSUSearchString="Servicing Stack Update for Azure Stack HCI, version 20H2 for x64-based Systems" ; ID="Azure Stack HCI"}
$Products+=@{Product="Windows Server 2019" ;SearchString="Cumulative Update for Windows Server 2019 for x64-based Systems"    ;SSUSearchString="Servicing Stack Update for Windows Server 2019 for x64-based Systems"           ; ID="Windows Server 2019"}
$Products+=@{Product="Windows Server 2016" ;SearchString="Cumulative Update for Windows Server 2016 for x64-based Systems"    ;SSUSearchString="Servicing Stack Update for Windows Server 2016 for x64-based Systems"           ; ID="Windows Server 2016"}
$Products+=@{Product="Windows 10 21H1"     ;SearchString="Cumulative Update for Windows 10 Version 21H1 for x64-based Systems";SSUSearchString="Servicing Stack Update for Windows 10 Version 21H1 for x64-based Systems"       ; ID="Windows 10, version 1903 and later"}
$Products+=@{Product="Windows 10 20H2"     ;SearchString="Cumulative Update for Windows 10 Version 20H2 for x64-based Systems";SSUSearchString="Servicing Stack Update for Windows 10 Version 20H2 for x64-based Systems"       ; ID="Windows 10, version 1903 and later"}
$Products+=@{Product="Windows 10 2004"     ;SearchString="Cumulative Update for Windows 10 Version 2004 for x64-based Systems";SSUSearchString="Servicing Stack Update for Windows 10 Version 2004 for x64-based Systems"       ; ID="Windows 10, version 1903 and later"}
$Products+=@{Product="Windows 10 1909"     ;SearchString="Cumulative Update for Windows 10 Version 1909 for x64-based Systems";SSUSearchString="Servicing Stack Update for Windows 10 Version 1909 for x64-based Systems"       ; ID="Windows 10, version 1903 and later"}

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

#let user choose products
$SelectedProducts=$Products.Product | Out-GridView -OutputMode Multiple -Title "Please select products to download Cumulative Updates and Servicing Stack Updates"

#region download products
Foreach($SelectedProduct in $SelectedProducts){
    $item=$Products | Where-Object product -eq $SelectedProduct
    #Download CU
    If ($preview){
        $update=Get-MSCatalogUpdate -Search $item.searchstring | Where-Object Products -eq $item.ID | Select-Object -First 1
    }else{
        $update=Get-MSCatalogUpdate -Search $item.searchstring | Where-Object Products -eq $item.ID | Where-Object Title -like "*$($item.SearchString)*" | Select-Object -First 1
    }
    $DestinationFolder="$folder\$SelectedProduct\$($update.title.Substring(0,7))"
    New-Item -Path $DestinationFolder -ItemType Directory -ErrorAction Ignore | Out-Null
    Write-Output "Downloading $($update.title) to $destinationFolder"
    $update | Save-MSCatalogUpdate -Destination "$DestinationFolder" #-UseBits

    #Download SSU
    $update=Get-MSCatalogUpdate -Search $item.SSUSearchString | Where-Object Products -eq $item.ID | Select-Object -First 1
    Write-Output "Downloading $($update.title) to $destinationFolder"
    $update | Save-MSCatalogUpdate -Destination $DestinationFolder #-UseBits
}
#endregion

Write-Host "Job finished. Press enter to continue" -ForegroundColor Green
Read-Host