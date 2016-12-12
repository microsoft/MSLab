#Test if its run by Admin and run it elevated

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

##########################################################################################
#   Functions
##########################################################################################

function WriteInfo($message)
{
    Write-Host $message
}

function WriteInfoHighlighted($message)
{
    Write-Host $message -ForegroundColor Cyan
}

function WriteSuccess($message)
{
    Write-Host $message -ForegroundColor Green
}

function WriteError($message)
{
    Write-Host $message -ForegroundColor Red
}

function WriteErrorAndExit($message)
{
	Write-Host $message -ForegroundColor Red
	Write-Host "Press any key to continue ..."
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
	Exit
}

##########################################################################################
#   Cleanup
##########################################################################################

#load LabConfig
. "$PSScriptRoot\LabConfig.ps1"
$prefix=$LabConfig.Prefix

if (!$prefix){
    WriteErrorAndExit "Prefix is empty. Exiting"
}

$VMs=get-vm -Name $prefix* | where Name -ne "$($prefix)DC" -ErrorAction SilentlyContinue
$vSwitch=Get-VMSwitch "$($labconfig.prefix)$($LabConfig.SwitchName)" -ErrorAction SilentlyContinue
$DC=get-vm "$($prefix)DC" -ErrorAction SilentlyContinue

If ($VMs){
    WriteInfoHighlighted "VMs:"
    Write-Output $VMs.Name
}

if ($vSwitch){
WriteInfoHighlighted "vSwitch:"
Write-Output $vSwitch.name
}

if ($DC){
    WriteInfoHighlighted "DC:"
    Write-Output $DC.Name
}

#just one more space
WriteInfo ""

# This is only needed if you kill deployment script in middle when it mounts VHD into mountdir. 
if ((Get-ChildItem -Path $PSScriptRoot\temp\mountdir -ErrorAction SilentlyContinue)){
    &"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\temp\mountdir /discard
}

if (($vSwitch) -or ($VMs) -or ($DC)){
    $answer=read-host "This script will remove all VMs or (and) switches starting with $prefix (all above) Are you sure? (type  Y )"
    if ($answer -eq "Y"){
        if ($DC){
            WriteInfo "Turning off $($DC.Name)"
            $DC | Stop-VM -TurnOff -Force -WarningAction SilentlyContinue
            WriteInfo "Restoring snapshot on $($DC.Name)"
            $DC | Restore-VMsnapshot -Name Initial -Confirm:$False -ErrorAction SilentlyContinue
            Start-Sleep 2
            WriteInfo "Removing snapshot from $($DC.Name)"
            $DC | Remove-VMsnapshot -name Initial -Confirm:$False -ErrorAction SilentlyContinue
            WriteInfo "Removing DC $($DC.Name)"
            $DC | Remove-VM -Force
        }
        if ($VMs){
            foreach ($VM in $VMs){
            WriteInfo "Removing VMs $($VM.Name)"
            $VM | Stop-VM -TurnOff -Force -WarningAction SilentlyContinue
            $VM | Remove-VM -Force
            }
        }

        if (($vSwitch)){
            WriteInfo "Removing vSwitch $($vSwitch.SwitchName)"
            $vSwitch | Remove-VMSwitch -Force
        }
        
        #Cleanup folders
        "$PSScriptRoot\LAB\VMs","$PSScriptRoot\temp" | ForEach-Object {
            if ((Get-Item -Path $_ -ErrorAction SilentlyContinue)){
                WriteInfo "Removing folder $_"
                remove-item $_ -Confirm:$False -Recurse
            }    
        }
        
        #Unzipping configuration files as VM was removed few lines ago-and it deletes vm configuration... 
        $zipfile= "$PSScriptRoot\LAB\DC\Virtual Machines.zip"
        $zipoutput="$PSScriptRoot\LAB\DC\"

        Expand-Archive -Path $zipfile -DestinationPath $zipoutput

        WriteSuccess "Job Done! Press any key to close window ..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
    }else {
        WriteErrorAndExit "You did not type Y"
    }
}else{
    WriteErrorAndExit "No VMs and Switches with prefix $prefix detected. Exitting"
}