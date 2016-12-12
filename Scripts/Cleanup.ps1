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
    $VMS | ForEach-Object {
        WriteInfo "`t $($_.Name)"
    }
}

if ($vSwitch){
    WriteInfoHighlighted "vSwitch:"
    WriteInfo "`t $($vSwitch.name)"
}

if ($DC){
    WriteInfoHighlighted "DC:"
    WriteInfo "`t $($DC.Name)"
}

#just one more space
WriteInfo ""

# This is only needed if you kill deployment script in middle when it mounts VHD into mountdir. 
if ((Get-ChildItem -Path $PSScriptRoot\temp\mountdir -ErrorAction SilentlyContinue)){
    &"$PSScriptRoot\Tools\dism\dism" /Unmount-Image /MountDir:$PSScriptRoot\temp\mountdir /discard
}

if (($vSwitch) -or ($VMs) -or ($DC)){
    WriteInfoHighlighted "This script will remove all items listed above. Do you want to remove it?"
    if ((read-host "(type Y or N)") -eq "Y"){
        WriteSuccess "You typed Y .. Cleaning lab"
        if ($DC){
            WriteInfoHighlighted "Removing DC $($DC.Name)"
            WriteInfo "`t Turning off $($DC.Name)"
            $DC | Stop-VM -TurnOff -Force -WarningAction SilentlyContinue
            WriteInfo "`t Restoring snapshot on $($DC.Name)"
            $DC | Restore-VMsnapshot -Name Initial -Confirm:$False -ErrorAction SilentlyContinue
            Start-Sleep 2
            WriteInfo "`t Removing snapshot from $($DC.Name)"
            $DC | Remove-VMsnapshot -name Initial -Confirm:$False -ErrorAction SilentlyContinue
            WriteInfo "`t Removing DC $($DC.Name)"
            $DC | Remove-VM -Force
        }
        if ($VMs){
            WriteInfoHighlighted "Removing VMs"
            foreach ($VM in $VMs){
            WriteInfo "`t Removing VM $($VM.Name)"
            $VM | Stop-VM -TurnOff -Force -WarningAction SilentlyContinue
            $VM | Remove-VM -Force
            }
        }

        if (($vSwitch)){
            WriteInfoHighlighted "Removing vSwitch $($vSwitch.Name)"
            $vSwitch | Remove-VMSwitch -Force
        }
        
        #Cleanup folders       
        if ((test-path "$PSScriptRoot\LAB\VMs") -or (test-path "$PSScriptRoot\temp") ){
            WriteInfoHighlighted "Cleaning folders"
            "$PSScriptRoot\LAB\VMs","$PSScriptRoot\temp" | ForEach-Object {
                if ((test-path -Path $_)){
                    WriteInfo "`t Removing folder $_"
                    remove-item $_ -Confirm:$False -Recurse
                }    
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