# Installs / refreshes the windowless 10-minute accel pass as a scheduled task.
#
# Writing the hosts file normally needs administrator rights. This machine works
# today only because the hosts FILE carries an explicit write grant
# (icacls shows "Everyone:(F)"); the containing directory is still not writable.
# A task that "runs fine" but cannot write hosts would silently never accelerate
# anything, so this script preflights writability instead of assuming it.
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfg = Get-Content (Join-Path $dir 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$min = [int]$cfg.interval_minutes
$name = [string]$cfg.task_name
$hostsPath = [string]$cfg.hosts_path

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$canWrite = $false
try {
  $fs = [System.IO.File]::Open($hostsPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  $fs.Close()
  $canWrite = $true
} catch { $canWrite = $false }

if ($canWrite) {
  $runLevel = 'Limited'
  Write-Output ('hosts writable as current user: yes -> task runs at Limited, no elevation needed')
} elseif ($isAdmin) {
  $runLevel = 'Highest'
  Write-Output ('hosts writable as current user: no -> task runs at Highest (elevated at run time)')
} else {
  throw ('hosts is not writable by ' + $env:USERNAME + ' and this shell is not elevated. ' +
    'Either re-run this script from an elevated PowerShell, or grant a narrow write ACE first:' + "`n" +
    '  icacls "' + $hostsPath + '" /grant "' + $env:USERNAME + ':(M)"' + "`n" +
    'Without one of these the task would run every ' + $min + ' minutes and never change anything.')
}

$act = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('"' + (Join-Path $dir 'run-hidden.vbs') + '"') -WorkingDirectory $dir
$trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $min) -RepetitionDuration (New-TimeSpan -Days 3000)
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
$set.ExecutionTimeLimit = 'PT30M'
$prn = New-ScheduledTaskPrincipal -UserId ($env:USERDOMAIN + '\' + $env:USERNAME) -LogonType Interactive -RunLevel $runLevel

Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Register-ScheduledTask -TaskName $name -Action $act -Trigger $trg -Settings $set -Principal $prn -Description ('accel adaptive hosts, every ' + $min + ' minutes') | Out-Null

$t = Get-ScheduledTask -TaskName $name
$i = Get-ScheduledTaskInfo -TaskName $name
Write-Output ('task=' + $t.TaskName + ' state=' + $t.State + ' runlevel=' + $t.Principal.RunLevel + ' interval=' + $min + 'min nextrun=' + $i.NextRunTime)
