Configuration Config {
    Node localhost
    {
        WindowsFeature HyperV
        {
            Name = "Hyper-V"
            Ensure = "Present"
            IncludeAllSubFeature =  $true
        }
        Script CreateFolder
        {
            SetScript = "New-Item -Type Directory -Name ws2016lab -Path d:"
            TestScript = "Test-Path -Path d:\ws2016lab"
            GetScript = "@{Ensure = if (Test-Path -Path d:\ws2016lab) {'Present'} else {'Absent'}}"
        }
        Script DownloadScripts
        {
            SetScript = "Invoke-WebRequest -UseBasicParsing -Uri https://github.com/Microsoft/ws2016lab/blob/master/scripts.zip?raw=true -OutFile d:\scripts.zip"
            TestScript = "Test-Path -Path d:\scripts.zip"
            GetScript = "@{Ensure = if (Test-Path -Path d:\scripts.zip) {'Present'} else {'Absent'}}"
        }
        Script UnzipScripts
        {
            SetScript = "Expand-Archive d:\scripts.zip -DestinationPath d:\ws2016lab"
            DependsOn = "[Script]DownloadScripts"
        }
        
        LocalConfigurationManager 
        {
            RebootNodeIfNeeded = $true
        }
    }
}





