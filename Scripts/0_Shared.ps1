#region Output logging
function WriteInfo($message) {
    Write-Host $message
}

function WriteInfoHighlighted($message) {
Write-Host $message -ForegroundColor Cyan
}

function WriteSuccess($message) {
Write-Host $message -ForegroundColor Green
}

function WriteError($message) {
Write-Host $message -ForegroundColor Red
}

function WriteErrorAndExit($message) {
    Write-Host $message -ForegroundColor Red
    Write-Host "Press enter to continue ..."
    Stop-Transcript
    Read-Host | Out-Null
    Exit
}
#endregion

#region Telemetry
Function Merge-Hashtables {
    $Output = @{}
    ForEach ($Hashtable in ($Input + $Args)) {
        If ($Hashtable -is [Hashtable]) {
            ForEach ($Key in $Hashtable.Keys) {$Output.$Key = $Hashtable.$Key}
        }
    }
    $Output
}
function Get-StringHash {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory = $true)]
        [string]$String,
        $Hash = "SHA1"
    )
    
    process {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $algorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Hash)
        $StringBuilder = New-Object System.Text.StringBuilder 
      
        $algorithm.ComputeHash($bytes) | 
        ForEach-Object { 
            $null = $StringBuilder.Append($_.ToString("x2")) 
        } 
      
        $StringBuilder.ToString() 
    }
}
function New-TelemetryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,

        $Properties,
        $Metrics,
        $NickName
    )

    process {
        if(-not $TelemetryInstrumentationKey) {
            WriteInfo "Instrumentation key is required in order to send telemetry data."
            return
        }
        
        $r = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $build = "$($r.CurrentMajorVersionNumber).$($r.CurrentMinorVersionNumber).$($r.CurrentBuildNumber).$($r.UBR)"
        $osVersion = "$($r.ProductName) ($build)"
        $hw = Get-CimInstance -ClassName Win32_ComputerSystem
        $computerName = $env:computername | Get-StringHash

        if(-not $NickName) {
            $NickName = "?"
        }

        $extraProperties = @{
            PowerShellEdition = $PSVersionTable.PSEdition
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            OsBuild = $r.CurrentBuildNumber
            Nick = $NickName
        }

        $payload = @{
            name = 'Microsoft.ApplicationInsights.Event' 
            time = $([System.dateTime]::UtcNow.ToString('o')) 
            iKey = $TelemetryInstrumentationKey
            tags = @{ 
                "ai.application.ver" = $wslabVersion
                "ai.cloud.roleInstance" = Split-Path -Path $PSCommandPath -Leaf
                'ai.internal.sdkVersion' = 'wslab-telemetry:1.0.0'
                'ai.session.id' = $TelemetrySessionId
                "ai.device.id" = $computerName 
                "ai.device.os" = $r.ProductName
                'ai.device.osVersion' = $osVersion
                'ai.device.locale' = (Get-WinsystemLocale).Name
                'ai.device.oemName' = $hw.Manufacturer
                'ai.device.model' = $hw.Model
            }
            data = @{
                baseType = 'EventData' 
                baseData = @{
                    ver = 2 
                    name = $Event
                    properties = ($Properties, $extraProperties | Merge-Hashtables)
                    measurements = $Metrics
                }
            }
        }
    
        $payload
    }
}

function Send-TelemetryObject {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    process {
        $json = "{0}" -f (($Data) | ConvertTo-Json -Depth 10 -Compress)
        try {
            Invoke-RestMethod -Uri 'https://dc.services.visualstudio.com/v2/track' -Method Post -UseBasicParsing -Body $json -TimeoutSec 20
        } catch { 
            WriteInfo "`tSending telemetry failed with an error: $($_.Exception.Message)"
        }
    }
}

function Send-TelemetryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,

        $Properties,
        $Metrics,
        $NickName
    )

    process {
        $telemetryEvent = New-TelemetryEvent -Event $Event -Properties $Properties -Metrics $Metrics -NickName $NickName
        Send-TelemetryObject -Data $telemetryEvent
    }
}

function Send-TelemetryEvents {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events
    )

    process {
        Send-TelemetryObject -Data $Events
    }
}

# Instance values
$ScriptRoot = $PSScriptRoot
$wslabVersion = "dev"
$TelemetryInstrumentationKey = "9ebf64de-01f8-4f60-9942-079262e3f6e0"
$TelemetrySessionId = $ScriptRoot + $env:COMPUTERNAME | Get-StringHash
#endregion
