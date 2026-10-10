# box/run-probe.ps1 -- box-side accel probe launcher (windowless; ASCII only on purpose).
#
# Runs on the remote box (Windows, `ssh wbssh`). It pulls this repo, measures the GitHub
# accelerator entries from the box's own line, and publishes the result to the
# `manifest-box` branch. The scheduled task (see install-task.ps1) keeps this process
# alive; the cadence is $Every below.
#
# Why the box: the GitHub Actions runner measures from a datacenter and cannot rank for a
# Chinese line. The box sits on China Unicom and is always on, so its numbers are the ones
# that look like the user's. The runner stays as a second vantage point (existence only).
#
# ASCII only: PowerShell 5.1 reads .ps1 as ANSI unless there is a BOM, so non-ASCII
# comments would be mangled on the box. Keep every string literal ASCII.
#
# The box pulls the script from the repo, so editing box/run-probe.ps1 here is enough --
# no need to copy files onto the box by hand (that was an explicit user correction).

$ErrorActionPreference = 'Continue'

$Root   = 'D:\accel'
$Repo   = Join-Path $Root 'repo'
$Pub    = Join-Path $Root 'publish'
$LogDir = Join-Path $Root 'logs'
$Key    = Join-Path $Root '.ssh\box_deploy'
$Known  = Join-Path $Root '.ssh\known_hosts'
$Branch = 'manifest-box'
$Every  = 21600   # 6 hours => four times a day

$Node = 'C:\Program Files\nodejs\node.exe'
if (-not (Test-Path $Node)) { $Node = 'node' }

# The key is only needed to push; fetching the repo is a public read.
$env:GIT_SSH_COMMAND = 'ssh -i "' + $Key + '" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="' + $Known + '"'

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log([string]$m) {
  Add-Content -Path (Join-Path $LogDir 'probe.log') -Value ('{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8
}

Write-Log ('start every=' + $Every + ' repo=' + $Repo + ' node=' + $Node)

while ($true) {
  try {
    # 1. pull the latest script + config (so a fix here reaches the box with no ssh work)
    if (Test-Path (Join-Path $Repo '.git')) {
      $pull = (& git -C $Repo pull --ff-only 2>&1 | Out-String).Trim()
      Write-Log ('pull: ' + $pull)
    } else {
      $clone = (& git clone https://github.com/jingjiangze/github-accel.git $Repo 2>&1 | Out-String).Trim()
      Write-Log ('clone: ' + $clone)
      & git -C $Repo remote set-url --push origin git@github.com:jingjiangze/github-accel.git
    }

    # 2. measure (manifest.mjs already: content-level check + bandwidth sample, nothing written to disk)
    # ACCEL_VANTAGE names this vantage point so gh.mjs can tell the box's manifest from the runner's.
    $env:ACCEL_VANTAGE = 'box-shandong'
    $out = Join-Path $Repo 'dist\proxies.json'
    $measureLog = Join-Path $LogDir ('measure-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
    Push-Location $Repo
    & $Node manifest.mjs --out $out *> $measureLog
    $code = $LASTEXITCODE
    Pop-Location
    Write-Log ('measure exit=' + $code)
    if ($code -ne 0 -or -not (Test-Path $out)) {
      # manifest.mjs exits non-zero when nothing is live; do NOT publish an empty manifest
      # over the last good one.
      Write-Log 'skip publish (no live entry or script error)'
      Start-Sleep -Seconds $Every
      continue
    }

    # 3. publish: one-commit branch + force push, same shape as the Actions workflow
    Remove-Item $Pub -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $Pub | Out-Null
    Copy-Item $out (Join-Path $Pub 'proxies.json')
    & git -C $Pub init -q
    & git -C $Pub checkout -q -b $Branch
    & git -C $Pub add proxies.json
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    & git -C $Pub -c user.name=box-probe -c user.email=box-probe@users.noreply.github.com commit -q -m ('manifest: ' + $stamp)
    & git -C $Pub remote add origin git@github.com:jingjiangze/github-accel.git
    $push = (& git -C $Pub push -q -f origin $Branch 2>&1 | Out-String).Trim()
    Write-Log ('publish exit=' + $LASTEXITCODE + ' ' + $push)
  } catch {
    Write-Log ('error: ' + $_.Exception.Message)
  }
  Start-Sleep -Seconds $Every
}
