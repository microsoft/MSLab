Notes: 
* Deployment tool uses "D" drive, so each azure stack hci node requires it. In Labconfig it will add tools.vhdx
* ToolsVHD was 30GB, new mslab 2_CreateParentDisks.ps1 script will create 300GB ToolsVHD. If you have older vhd, just expand it (hyper-v tools, and then expand partition inside)
* You can also notice in Labconfig, that nodes are not domain joined and there is a custom script to make tools disk online (default SAN policy on servers is to not mount disks)
* if you want step-by-step doc, you can use https://geos.to/AzSLabs