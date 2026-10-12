# repair-hosts.ps1 -- emergency repair: restore the hosts file from the latest backup.
# Use only when C:\Windows\System32\drivers\etc\hosts is MISSING or corrupted;
# normal rounds are handled by accel.mjs itself.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File repair-hosts.ps1 [-Force]
# Requires silent elevation (ConsentPromptBehaviorAdmin=0 on this machine).
# ASCII-only on purpose: PowerShell 5.1 reads BOM-less files as the ANSI codepage.
param([switch]$Force)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = Join-Path $here 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ('repair-' + (Get-Date -Format 'yyyy-MM-dd-HHmmss') + '.log')
function W($m) { Add-Content -LiteralPath $log -Value ((Get-Date -Format s) + ' ' + $m) }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  W 'outer: relaunching elevated'
  # NOTE: do NOT add -WindowStyle Hidden; quote the script path explicitly (space in path).
  $pl = @('-NoProfile','-ExecutionPolicy','Bypass','-File', ('"' + $PSCommandPath + '"'))
  if ($Force) { $pl += '-Force' }
  $p = Start-Process powershell -Verb RunAs -PassThru -Wait -ArgumentList $pl
  W ('outer: exit=' + $p.ExitCode)
  exit $p.ExitCode
}

$dst = 'C:\Windows\System32\drivers\etc\hosts'
if ((Test-Path -LiteralPath $dst) -and -not $Force) {
  W 'hosts exists; nothing to do (use -Force to overwrite)'
  exit 0
}
$bakDir = Join-Path $here 'backups'
$src = $null
if (Test-Path -LiteralPath $bakDir) {
  $cand = Get-ChildItem -LiteralPath $bakDir -Filter 'hosts-*' | Sort-Object Name -Descending | Select-Object -First 1
  if ($cand) { $src = $cand.FullName }
}
if (-not $src) {
  W 'no backup found; refusing to invent a hosts file (manual repair required)'
  exit 3
}
if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Force }
Copy-Item -LiteralPath $src -Destination $dst
$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
icacls $dst /grant ('*' + $sid + ':(M)') | Out-Null
ipconfig /flushdns | Out-Null
W ('RESTORED from ' + $src)
exit 0
