# Installs / refreshes the windowless 10-minute accel pass as a scheduled task.
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfg = Get-Content (Join-Path $dir 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$min = [int]$cfg.interval_minutes
$name = [string]$cfg.task_name

$act = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('"' + (Join-Path $dir 'run-hidden.vbs') + '"') -WorkingDirectory $dir
$trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $min) -RepetitionDuration (New-TimeSpan -Days 3000)
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
$set.ExecutionTimeLimit = 'PT30M'

Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Register-ScheduledTask -TaskName $name -Action $act -Trigger $trg -Settings $set -Description ('accel adaptive hosts, every ' + $min + ' minutes') | Out-Null

$t = Get-ScheduledTask -TaskName $name
$i = Get-ScheduledTaskInfo -TaskName $name
Write-Output ('task=' + $t.TaskName + ' state=' + $t.State + ' interval=' + $min + 'min nextrun=' + $i.NextRunTime)
