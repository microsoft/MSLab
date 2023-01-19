Following lab is based on new Azure Stack HCI deployment tool: https://learn.microsoft.com/en-us/azure-stack/hci/deploy/deployment-tool-powershell

Notes: 
* Deployment tool uses "D" drive, so each azure stack hci node requires it. In Labconfig it will add tools.vhdx
* ToolsVHD was 30GB, new mslab 2_CreateParentDisks.ps1 script will create 300GB ToolsVHD. If you have older vhd, just expand it (hyper-v tools, and then expand partition inside)
* You can also notice in Labconfig, that nodes are not domain joined
* if you want step-by-step doc, you can use https://geos.to/AzSLabs