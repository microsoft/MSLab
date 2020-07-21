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

function Get-VolumePhysicalDisk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume
    )

    process {
        if(-not $Volume.EndsWith(":")) {
            $Volume += ":"
        }

        $physicalDisks = Get-cimInstance "win32_diskdrive"
        foreach($disk in $physicalDisks) {
            $partitions = Get-cimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($disk.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
            foreach($partition in $partitions) {
                $partitionVolumes = Get-cimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($partition.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"
                foreach($partitionVolume in $partitionVolumes) {
                    if($partitionVolume.Name -eq $Volume) {
                        $physicalDisk = Get-PhysicalDisk -DeviceNumber $disk.Index
                        return $physicalDisk
                    }
                }
            }
        }
    }
}

function Get-TelemetryLevel {
    param(
        [switch]$OptOut
    )
    process {
        $acceptedTelemetryLevels = "None", "Basic", "Full"

        # LabConfig value has a priority
        if($LabConfig.TelemetryLevel -and $LabConfig.TelemetryLevel -in $acceptedTelemetryLevels) {
            return $LabConfig.TelemetryLevel
        }

        # Environment variable as a fallback
        if($env:WSLAB_TELEMETRY_LEVEL -and $env:WSLAB_TELEMETRY_LEVEL -in $acceptedTelemetryLevels) {
            return $env:WSLAB_TELEMETRY_LEVEL
        }

        # If nothing is explicitely configured and OptOut flag enabled, explicitely disable telemetry
        if($OptOut) {
            return "None"
        }

        # as a last option return nothing to allow asking the user
    }
}

function Get-TelemetryLevelSource {
    param(
        [switch]$OptOut
    )
    process {
        $acceptedTelemetryLevels = "None", "Basic", "Full"

        # LabConfig value has a priority
        if($LabConfig.TelemetryLevel -and $LabConfig.TelemetryLevel -in $acceptedTelemetryLevels) {
            return "LabConfig"
        }

        # Environment variable as a fallback
        if($env:WSLAB_TELEMETRY_LEVEL -and $env:WSLAB_TELEMETRY_LEVEL -in $acceptedTelemetryLevels) {
            return "Environment"
        }
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
        
        $level = Get-TelemetryLevel
        $levelSource = Get-TelemetryLevelSource

        $r = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $build = "$($r.CurrentMajorVersionNumber).$($r.CurrentMinorVersionNumber).$($r.CurrentBuildNumber).$($r.UBR)"
        $osVersion = "$($r.ProductName) ($build)"
        $hw = Get-CimInstance -ClassName Win32_ComputerSystem
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerNameHash = $env:computername | Get-StringHash

        if(-not $NickName) {
            $NickName = "?"
        }

        $osType = switch ($os.ProductType) {
            1 { "Workstation" }
            default { "Server" }
        }

        $extraMetrics = @{}
        $extraProperties = @{
            'telemetry.level' = $level
            'telemetry.levelSource' = $levelSource
            'telemetry.nick' = $NickName
            'powershell.edition' = $PSVersionTable.PSEdition
            'powershell.version' = $PSVersionTable.PSVersion.ToString()
            'os.type' = $osType
        }
        if($level -eq "Full") {
            # OS
            $extraProperties.'os.build' = $r.CurrentBuildNumber

            # RAM
            $extraMetrics.'memory.total' = [Math]::Round(($hw.TotalPhysicalMemory)/1024KB, 0)
            
            # CPU
            $extraMetrics.'cpu.logical.count' = $hw.NumberOfLogicalProcessors
            $extraMetrics.'cpu.sockets.count' = $hw.NumberOfProcessors

            # Disk
            $driveLetter = $PSScriptRoot -Split ":" | Select-Object -First 1
            $volume = Get-Volume -DriveLetter $driveLetter
            $disk = Get-VolumePhysicalDisk -Volume $driveLetter
            $extraMetrics.'volume.size' = [Math]::Round($volume.Size / 1024MB)
            $extraProperties.'volume.fs' = $volume.FileSystemType
            $extraProperties.'disk.type' = $disk.MediaType
            $extraProperties.'disk.busType' = $disk.BusType
            $extraProperties.'disk.model' = $disk.FriendlyName
        }

        $payload = @{
            name = "Microsoft.ApplicationInsights.Event"
            time = $([System.dateTime]::UtcNow.ToString("o")) 
            iKey = $TelemetryInstrumentationKey
            tags = @{ 
                "ai.application.ver" = $wslabVersion
                "ai.cloud.roleInstance" = Split-Path -Path $PSCommandPath -Leaf
                "ai.internal.sdkVersion" = 'wslab-telemetry:1.0.0'
                "ai.session.id" = $TelemetrySessionId
                "ai.device.locale" = (Get-WinsystemLocale).Name
                "ai.device.id" = $computerNameHash 
                "ai.device.os" = ""
                "ai.device.osVersion" = ""
                "ai.device.oemName" = ""
                "ai.device.model" = ""
            }
            data = @{
                baseType = "EventData"
                baseData = @{
                    ver = 2 
                    name = $Event
                    properties = ($Properties, $extraProperties | Merge-Hashtables)
                    measurements = ($Metrics, $extraMetrics | Merge-Hashtables)
                }
            }
        }

        if($level -eq "Full") {
            $payload.tags.'ai.device.os' = $r.ProductName
            $payload.tags.'ai.device.osVersion' = $osVersion
            $payload.tags.'ai.device.oemName' = $hw.Manufacturer
            $payload.tags.'ai.device.model' = $hw.Model
            if($hw.Manufacturer -eq "Lenovo") { # Lenovo sets common name of the model to SystemFamily property
                $payload.tags.'ai.device.model' = $hw.SystemFamily
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

function Read-TelemetryLevel {
    process {
        # Ask user for consent
        WriteInfoHighlighted "`nWould you be OK with providing a telemetry information about your WSLab usage?"
        WriteInfo "More details about content of the telemetry messages can be found at https://aka.ms/wslab/telemetry"
        WriteInfo "Tip: You can also configure telemetry settings explicitly in LabConfig.ps1 file and suppress this prompt completely."
        WriteInfoHighlighted "`n  Please select a telemetry level:"
        WriteInfo "    [N] None  -- No information will be sent"
        WriteInfo "    [B] Basic -- Lab info will be sent (e.g. script execution time, number of VMs)"
        WriteInfo "    [F] Full  -- More details about the host machine and deployed VMs (e.g. guest OS)"
        
        do {
            $response = Read-Host -Prompt "Telemetry level [B]"
        }
        while ($response -notin ("N", "[N]", "None", "B", "[B]", "Basic", "F", "[F]", "Full", ""))

        $telemetryLevel = $null
        switch($response) {
            { $_ -in "N", "[N]", "None" } {
                $telemetryLevel = 'None'
                WriteInfo "`nNo telemetry information will be send"
            }
            { $_ -in "B", "[B]", "Basic", "" } {
                $telemetryLevel = 'Basic'
                WriteInfo "`nTelemetry has been set to Basic level, thank you for your valuable feedback."
            }
            { $_ -in "F", "[F]", "Full" } {
                $telemetryLevel = 'Full'
                WriteInfo "`nTelemetry has been set to Full level, thank you for your valuable feedback."
            }
        }

        $telemetryLevel
    }
}

# Instance values
$ScriptRoot = $PSScriptRoot
$wslabVersion = "dev"
$TelemetryEnabledLevels = "Basic", "Full"
$TelemetryInstrumentationKey = "9ebf64de-01f8-4f60-9942-079262e3f6e0"
$TelemetrySessionId = $ScriptRoot + $env:COMPUTERNAME + ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid) | Get-StringHash
#endregion
