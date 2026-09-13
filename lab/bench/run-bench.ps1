# run-bench.ps1 - host-side orchestrator for the evasion bench.
#
# Builds the lab binaries (server + implant with lab-args/lab-log so the
# CLI surface exists), stages bench.ps1 / drscan.ps1 / pe-sieve64.exe /
# velociraptor.exe into the guest, runs each scenario via vmrun, zips the
# results inside the guest and pulls them back to lab/bench/results/.
#
# Run from the host:
#   powershell -File lab\bench\run-bench.ps1 -ScenarioNames plain,ekko,ekko-ppid
#
# Scenario name -> implant --evasion value mapping is fixed below; add
# entries there when new scenarios appear (hwbp, sleep2, ...).

param(
    [string[]]$ScenarioNames = @('plain', 'ekko', 'ekko-ppid'),
    [int]$Cycles = 20,
    [string]$Repo = "C:\Users\antho\Desktop\Workstation\projects\abraham",
    [string]$Vmx = "C:\Users\antho\Documents\Virtual Machines\Windows 11\Windows 11 x64.vmx",
    [string]$Vp = "sfor!@24",
    [string]$Gu = "lab",
    [string]$Gp = "P@ssw0rd!"
)

# NOTE: no $ErrorActionPreference='Stop' here — cargo writes progress to
# stderr, and PS 5.1 turns native stderr into terminating errors under
# 'Stop'. Failures are caught via $LASTEXITCODE after each step instead.
$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$scenarioMap = @{
    'plain'     = ''
    'ekko'      = 'ekko'
    'ekko-ppid' = 'ekko,ppid'
    'hwbp'      = 'ekko,hwbp'
    'sleep2'    = 'ekko,sleep2'
    'full'      = 'ekko,ppid,hwbp,sleep2'
}

function Guest([string]$interpreter, [string]$script) {
    & $vmrun -vp $Vp -gu $Gu -gp $Gp runScriptInGuest $Vmx $interpreter $script 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { Write-Warning "guest script exited ${LASTEXITCODE}: $script" }
}

# runProgramInGuest with separated arguments — the only invocation shape
# that passes through bash/PowerShell hosts without path mangling.
$guestPs = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
function GuestProg([string[]]$argv) {
    & $vmrun -vp $Vp -gu $Gu -gp $Gp runProgramInGuest $Vmx @argv 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { Write-Warning "guest program exited ${LASTEXITCODE}: $($argv -join ' ')" }
}

# --- 1. build ---------------------------------------------------------------
Push-Location $Repo
cargo build --release -p abraham-server 2>&1 | Select-Object -Last 2 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "server build failed" }
cargo build --release -p abraham-implant --features lab-args,lab-log 2>&1 | Select-Object -Last 2 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "implant build failed" }
Pop-Location

# --- 2. stage into the guest -------------------------------------------------
GuestProg @($guestPs, '-NoProfile', '-Command', 'New-Item -ItemType Directory -Force -Path C:\bench\tools | Out-Null')
$staged = @(
    @{ local = "$Repo\target\release\abraham-server.exe";  remote = 'C:\bench\tools\abraham-server.exe' },
    @{ local = "$Repo\target\release\abraham-implant.exe"; remote = 'C:\bench\tools\abraham-implant.exe' },
    @{ local = "$Repo\lab\bench\bench.ps1";                remote = 'C:\bench\bench.ps1' },
    @{ local = "$Repo\lab\bench\drscan.ps1";               remote = 'C:\bench\drscan.ps1' },
    @{ local = "$Repo\lab\bench\tools\pe-sieve64.exe";     remote = 'C:\bench\tools\pe-sieve64.exe' },
    @{ local = "$Repo\tools\psboot.cs";                   remote = 'C:\bench\tools\psboot.cs' }
)
foreach ($f in $staged) {
    & $vmrun -vp $Vp -gu $Gu -gp $Gp copyFileFromHostToGuest $Vmx $f.local $f.remote 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "copy failed: $($f.local)" }
}

# --- 3. scenarios -------------------------------------------------------------
$resultsDir = "$Repo\lab\bench\results"
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

foreach ($name in $ScenarioNames) {
    if (-not $scenarioMap.ContainsKey($name)) { throw "unknown scenario '$name' (add it to `$scenarioMap)" }
    $evasion = $scenarioMap[$name]
    Write-Host "=== scenario $name (evasion: '$evasion') ===" -ForegroundColor Cyan
    # Empty -Evasion values get dropped by vmrun argument marshalling, so
    # the bench is invoked through -Command with explicit quoting; the same
    # command captures the guest-side console for post-mortem.
    $benchCmd = "& 'C:\bench\bench.ps1' -Name '$name' -Evasion '$evasion' -Cycles $Cycles *>&1 | Out-File 'C:\bench\last-bench.log' -Encoding utf8"
    GuestProg @($guestPs, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $benchCmd)
    GuestProg @($guestPs, '-NoProfile', '-Command', "Compress-Archive -Path C:\bench\results\$name\* -DestinationPath C:\bench\results\$name.zip -Force")
    & $vmrun -vp $Vp -gu $Gu -gp $Gp copyFileFromGuestToHost $Vmx "C:\bench\results\$name.zip" "$resultsDir\$name.zip" 2>&1 | Write-Host
    & $vmrun -vp $Vp -gu $Gu -gp $Gp copyFileFromGuestToHost $Vmx "C:\bench\last-bench.log" "$resultsDir\$name.bench.log" 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not pull results for $name" }
}

Write-Host "done. results in $resultsDir" -ForegroundColor Green
