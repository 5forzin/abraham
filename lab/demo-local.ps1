# demo-local.ps1 - full local demo: teamserver + implant + TUI, nothing leaves the machine.
#
# Everything binds to loopback only. Fresh throwaway state in %TEMP%,
# the lab implant beacons against the local teamserver every 5 s, and
# the TUI opens in THIS window - when you quit the TUI the server and
# the implant are stopped and the demo folder is left behind for
# post-mortem (logs + audit trail under %TEMP%\abraham-demo).
#
# Usage (from the repo root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File lab\demo-local.ps1
#
# Optional switches:
#   -Evasion "ekko"       pass an evasion spec to the implant (default none)
#   -SleepSecs 5          beacon interval
#   -NoImplant            server + TUI only (no demo session)

param(
    [string]$Evasion = "",
    [int]$SleepSecs = 5,
    [switch]$NoImplant
)

# NOTE: no $ErrorActionPreference='Stop' — cargo writes progress to stderr
# and PS 5.1 turns native stderr into terminating errors under 'Stop'.
# Failures are caught via $LASTEXITCODE after each build instead.
$repo = Split-Path -Parent $PSScriptRoot   # repo root = parent of lab\
$demo = Join-Path $env:TEMP 'abraham-demo'

Write-Host "== building (release)..." -ForegroundColor Cyan
Push-Location $repo
cargo build --release -p abraham-server -p abraham-tui 2>&1 | Select-Object -Last 1 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "server/tui build failed" }
if (-not $NoImplant) {
    cargo build --release -p abraham-implant --features lab-args,lab-log 2>&1 | Select-Object -Last 1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "implant build failed" }
}
Pop-Location

Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $demo | Out-Null

Write-Host "== starting teamserver (127.0.0.1:8443, mgmt 127.0.0.1:9200)..." -ForegroundColor Cyan
$server = Start-Process -FilePath (Join-Path $repo 'target\release\abraham-server.exe') `
    -ArgumentList "--listen 127.0.0.1:8443 --mgmt 127.0.0.1:9200 --state `"$demo\sessions.json`" --audit `"$demo\audit.jsonl`"" `
    -WorkingDirectory $demo -WindowStyle Minimized -PassThru `
    -RedirectStandardOutput "$demo\server.log" -RedirectStandardError "$demo\server.err.log"

try {
    $pubFile = Join-Path $demo 'server.pub'
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-Path $pubFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path $pubFile)) { throw "teamserver did not come up (see $demo\server.err.log)" }
    $pub = (Get-Content $pubFile -Raw).Trim()

    $implant = $null
    if (-not $NoImplant) {
        $evasionNote = if ($Evasion -ne "") { ", evasion $Evasion" } else { "" }
        Write-Host "== starting lab implant (sleep ${SleepSecs}s$evasionNote)..." -ForegroundColor Cyan
        $implantArgs = "--server 127.0.0.1:8443 --key $pub --sleep $SleepSecs --jitter 0.2"
        if ($Evasion -ne "") { $implantArgs += " --evasion $Evasion" }
        $implant = Start-Process -FilePath (Join-Path $repo 'target\release\abraham-implant.exe') `
            -ArgumentList $implantArgs `
            -WorkingDirectory $demo -WindowStyle Minimized -PassThru `
            -RedirectStandardError "$demo\implant.log" -RedirectStandardOutput "$demo\implant.out.log"
        Start-Sleep -Seconds 3
    }

    Write-Host ""
    Write-Host "== opening the TUI - quit with q / Ctrl-C; server and implant stop on exit." -ForegroundColor Green
    Write-Host ""
    & (Join-Path $repo 'target\release\abraham-tui.exe') '127.0.0.1:9200'
}
finally {
    Write-Host ""
    Write-Host "== cleaning up..." -ForegroundColor Cyan
    if ($implant -and -not $implant.HasExited) { Stop-Process -Id $implant.Id -Force -ErrorAction SilentlyContinue }
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "stopped. logs and audit trail kept in $demo"
}
