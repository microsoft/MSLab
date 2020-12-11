# Azure Image Builder

This scenario is just a walk trough on how to create Windows Virtual desktop image using Azure Image Builder

## LabConfig (optional)

You can run this scenario from anywhere, so WSLab is optional. It's just useful to have it as you can have vanilla system where you can run script from. In this case, simply run scenario from DC

```powershell
$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!' ; <#Prefix = 'WSLab-'#> ; DCEdition='4'; Internet=$true ; TelemetryLevel='Full' ; TelemetryNickname='' ; AdditionalNetworksConfig=@(); VMs=@()}
 
```

## The Lab

### Region Prereqs

This regin just installs Az modules that will be required in scenario, will log you into azure and will register providers.

### Region Create Role Identity and Role Definition for Azure Image Builder

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge01.png)

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge02.png)

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge03.png)

### Region Create Shared Image Gallery and Gallery definition

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge04.png)

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge05.png)

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge06.png)

### Region Build the Image

![](/Scenarios/Azure%20Image%20Builder/Screenshots/PowerShell01.png)

Build in progress (temporary VM is created)

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge07.png)

And there are 3 statuses you can observe in PowerShell

![](/Scenarios/Azure%20Image%20Builder/Screenshots/PowerShell02.png)

Once completed, image is available in Shared Gallery

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge08.png)

![](/Scenarios/Azure%20Image%20Builder/Screenshots/Edge09.png)