<!-- TOC -->

- [Get-SDDCDiagnosticInfo](#get-sddcdiagnosticinfo)
    - [About the lab](#about-the-lab)
    - [Prereq](#prereq)
    - [Download and install module](#download-and-install-module)
        - [From GitHub (Most up-to-date version)](#from-github-most-up-to-date-version)
        - [From Gallery (Offline environment)](#from-gallery-offline-environment)
        - [From Gallery (Online environment)](#from-gallery-online-environment)
    - [Collect data from cluster](#collect-data-from-cluster)

<!-- /TOC -->

# Get-SDDCDiagnosticInfo

## About the lab

If your S2D cluster is in trouble and you will create case with our customer support, the first thing you will be asked for is logs.

You can find more information here https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/data-collection

Let's try it out. I'll intentionally write script to download and import module a little bit different way than it's described in Docs, just to give you an idea how to work with PowerShell modules

## Prereq

[S2D hyperconverged scenario](/Scenarios/S2D%20Hyperconverged/)

## Download and install module

### From GitHub (Most up-to-date version)

As you can see, there are multiple ways to install SDDCDiagnosticInfo. Let's use modified docs script. If your lab is not connected to internet (Internet=$true), then download ZIP on your host and ctrl+c/ctrl+v it into your management machine.

````PowerShell
#Download ZIP from GitHub to d:\SDDCDiag.zip
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$module = 'PrivateCloud.DiagnosticInfo'
Invoke-WebRequest -Uri https://github.com/PowerShell/$module/archive/master.zip -OutFile d:\SDDCDiag.zip

#Expand ZIP
Expand-Archive -Path d:\SDDCDiag.zip -DestinationPath d:\ -Force
 
````

As you can see, you can find PowerShell module in D drive now.

![](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/Screenshots/ExpandedZip.png)

The only thing we need is having PrivateCloud.DiagnosticInfo folder in our PowerShell modules folder inside program files and import. So let's copy it.

````PowerShell
#Copy Module
Copy-Item -Path D:\PrivateCloud.DiagnosticInfo-master\PrivateCloud.DiagnosticInfo -Recurse -Destination "C:\Program Files\WindowsPowerShell\Modules"
#Import Module
Import-Module PrivateCloud.DiagnosticInfo -Force
 
````

You will see following error. It's because module is not signed.

![](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/Screenshots/ImportModuleError.png)

Let's lower execution policy and import it

````PowerShell
#Grab current ExecutionPolicy and lower it
$executionpolicy=Get-ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy remotesigned -Force
#import module
Import-Module PrivateCloud.DiagnosticInfo -Force
#Return ExecutionPolicy to previous state
Set-ExecutionPolicy -ExecutionPolicy $executionpolicy -force
 
````

### From Gallery (Offline environment)

It is little bit more straightforward with PowerShell Gallery

````PowerShell
#download SDDC module to c:\Temp\PrivateCloud.DiagnosticInfo
Save-Module -Name PrivateCloud.DiagnosticInfo -Path "C:\Temp"

#Copy to destination machine (lets-say c:\Temp) and Import
    Copy-Item -Path c:\Temp\PrivateCloud.DiagnosticInfo -Recurse -Destination "C:\Program Files\WindowsPowerShell\Modules" -Force
    #grab current state of executionpolicy
    $executionpolicy=Get-ExecutionPolicy
    #lower execution policy
    Set-ExecutionPolicy -ExecutionPolicy remotesigned -Force
    Import-Module PrivateCloud.DiagnosticInfo -Force
    #Return ExecutionPolicy to previous state
    Set-ExecutionPolicy -ExecutionPolicy $executionpolicy -force
 
````

### From Gallery (Online environment)

And this is simplest

````PowerShell
Install-Module PrivateCloud.DiagnosticInfo
 
````

![](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/Screenshots/ImportModuleGallery.png)

## Collect data from cluster

````PowerShell
New-Item -Name SDDCDiagTemp -Path d:\ -ItemType Directory -Force
Get-SddcDiagnosticInfo -ClusterName S2D-Cluster -WriteToPath d:\SDDCDiagTemp
 
````

As you can see, script will also do validation of current cluster state

![](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/Screenshots/CollectData.png)

As you can see, all data are being written to SDDCDiagTemp folder

![](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/Screenshots/CollectDataFolder.png)

After script will finish, it will create ZIP in your users directory

![](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/Screenshots/CollectDataResult.png)

Let's generate a report into a text file

````PowerShell
#find the latest diagnostic zip in UserProfile
    $DiagZip=(get-childitem $env:USERPROFILE | where Name -like HealthTest*.zip)
    $LatestDiagPath=($DiagZip | sort lastwritetime | select -First 1).FullName
#expand to temp directory
    New-Item -Name SDDCDiagTemp -Path d:\ -ItemType Directory -Force
    Expand-Archive -Path $LatestDiagPath -DestinationPath D:\SDDCDiagTemp -Force
#generate report and save to text file
    $report=Show-SddcDiagnosticReport -Path D:\SDDCDiagTemp
    $report | out-file d:\SDDCReport.txt
    
````

That's it!

[SampleReport](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/SDDCReport.txt)

[SampleZIP](/Scenarios/S2D%20Tools/Get-SDDCDiagnosticInfo/HealthTest-S2D-Cluster-20180522-1546.ZIP)