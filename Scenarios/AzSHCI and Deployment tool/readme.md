Following lab is based on new Azure Stack HCI deployment tool: https://learn.microsoft.com/en-us/azure-stack/hci/deploy/deployment-tool-powershell

Notes: 
* You can also notice in Labconfig, that nodes are not domain joined
* if you want step-by-step doc, you can use https://geos.to/AzSLabs
* Make sure Each node C: drive has more than 60GB free space. Telemetry agent would fail install. New createparentdisk will create 127GB disk