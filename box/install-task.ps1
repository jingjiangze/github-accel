# box/install-task.ps1 -- installs the windowless box accel-probe task (ASCII only).
#
# One ssh call, run from a machine that can reach the box:
#   ssh wbssh 'powershell -NoProfile -NonInteractive -Command -' < box/install-task.ps1
#
# Task AccelProbe: BootTrigger + a PT30M repetition watchdog, S4U + HighestAvailable,
# action runs `powershell -WindowStyle Hidden`. The real cadence is the 6h Start-Sleep
# inside run-probe.ps1; the repetition only restarts the loop if it ever died.
#
# Why full XML + schtasks /Create instead of Register-ScheduledTask: this box is
# PS 5.1 / ScheduledTasks 1.0 -- New-ScheduledTaskTrigger has no -RepetitionInterval,
# -Daily's .Repetition is $null, CIM assignment works only sometimes, and
# Register-ScheduledTask -Xml rejects the exported XML. All four dead ends were
# measured on this box; the XML route is the only one that works.
#
# ASCII only: PS 5.1 reads .ps1 as ANSI without a BOM, so non-ASCII would be mangled
# when this file is piped over ssh.

$ErrorActionPreference = 'Continue'

$Task   = 'AccelProbe'
$Script = 'D:\accel\repo\box\run-probe.ps1'
$XmlPath = Join-Path $env:TEMP 'accel-probe-task.xml'

if (-not (Test-Path $Script)) { Write-Output ('COOKIE missing-launcher ' + $Script); exit 1 }

$Ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $Ps)) { $Ps = 'powershell.exe' }

# $env:USERNAME is empty inside the ssh stdin pipe, so take the identity instead.
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-not $User) { $User = $env:COMPUTERNAME + '\Administrator' }
Write-Output ('principal=' + $User)

# Kill any previous launcher loop before re-creating the task: the loop reads its interval
# at start, so an old instance would keep the old cadence. Match BOTH 'accel' and
# 'run-probe.ps1' -- D:\web\spbox\run-probe.ps1 is a different script with the same name.
$killed = 0
foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue)) {
  $cl = [string]$p.CommandLine
  if ($cl -like '*accel*' -and $cl -like '*run-probe.ps1*') {
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    $killed++
  }
}
Write-Output ('killed-stale=' + $killed)

$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$User</Author>
    <Description>Accel box probe: measure GitHub accelerator entries on the box line, publish to manifest-box (6h, windowless)</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT30M</Interval>
        <Duration>P3650D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$User</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT5M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$Ps</Command>
      <Arguments>-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$Script"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Set-Content -Path $XmlPath -Value $xml -Encoding Unicode

& schtasks /Create /TN $Task /XML $XmlPath /F 2>&1 | Out-String | Write-Output
Write-Output ('create-exit=' + $LASTEXITCODE)

& schtasks /Run /TN $Task 2>&1 | Out-String | Write-Output
Write-Output ('run-exit=' + $LASTEXITCODE)
