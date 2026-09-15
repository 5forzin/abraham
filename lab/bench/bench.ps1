# bench.ps1 - one evasion scenario, all sensors, one directory.
#
# Runs INSIDE the lab guest (elevated). Boots a throwaway teamserver on
# loopback, starts the lab implant with the scenario's evasion flags,
# drives an identical task workload through the management channel
# (module ps, module netstat, psrun, execasm with patch), samples the
# debug registers while the implant lives, scans memory mid-run with
# pe-sieve, and harvests every sensor into <outdir>:
#
#   summary.json     - counters (sysmon per EID, defender, ETW, DR, pe-sieve)
#   drscan.jsonl     - per-thread CONTEXT debug-register samples
#   sysmon-matched.jsonl / sysmon-total.json
#   etw.json         - Get-WinEvent over the traced .etl
#   pesieve\         - pe-sieve report + dumped modules
#   implant.log      - lab-log stderr of the implant
#   server.log       - teamserver stdout
#   audit.jsonl      - server audit trail
#
# Usage:
#   powershell -File bench.ps1 -Name ekko -Evasion "ekko" -Cycles 20
#   powershell -File bench.ps1 -Name plain -Evasion ""

param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Evasion = "",
    [int]$Cycles = 20,
    [int]$SleepSecs = 2,
    [string]$BenchDir = "C:\bench",
    [string]$ToolsDir = "C:\bench\tools"
)

$ErrorActionPreference = 'Continue'
$Out = Join-Path $BenchDir "results\$Name"
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Log([string]$msg) {
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg)
}

# --- mgmt helper: one JSON line in, one JSON line out -----------------------
function Mgmt([string]$json) {
    $client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 9200)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.WriteLine($json)
    $task = $reader.ReadLineAsync()
    if (-not $task.Wait(5000)) { $client.Close(); return $null }
    $line = $task.Result
    $client.Close()
    try { return $line | ConvertFrom-Json } catch { return $line }
}

# --- prep: tiny .NET assembly for execasm -----------------------------------
$asmPath = Join-Path $BenchDir 'benchasm.dll'
# Always regenerate: a cached assembly from an older bench source (e.g.
# the void-Go signature before the int-Go fix) silently breaks execasm.
if (Test-Path $asmPath) { Remove-Item -Force $asmPath }
if (-not (Test-Path $asmPath)) {
    $csPath = Join-Path $BenchDir 'benchasm.cs'
    @'
using System;
public static class Prog {
    // ExecuteInDefaultAppDomain requires: public static int <Method>(string)
    public static int Go(string a) {
        Console.WriteLine("bench-assembly-ok " + a);
        return 0;
    }
}
'@ | Set-Content -Path $csPath -Encoding ASCII
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /target:library /out:$asmPath $csPath 2>&1 | Out-Null
    Log ("benchasm: " + (Test-Path $asmPath))
}

# --- 1. teamserver (loopback, throwaway state) ------------------------------
# psrun's bootstrap compiles tools/psboot.cs from the server binary's
# build-time CARGO_MANIFEST_DIR (absolute path compiled in on the build
# host), so the guest recreates that exact path. Lab hack — the server
# falling back to <cwd>/tools/psboot.cs is the proper fix (follow-up).
$manifestTools = 'C:\Users\antho\Desktop\Workstation\projects\abraham\tools'
New-Item -ItemType Directory -Force -Path $manifestTools | Out-Null
Copy-Item (Join-Path $ToolsDir 'psboot.cs') (Join-Path $manifestTools 'psboot.cs') -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $Out 'tools') | Out-Null
Copy-Item (Join-Path $ToolsDir 'psboot.cs') (Join-Path $Out 'tools\psboot.cs') -Force -ErrorAction SilentlyContinue
$serverExe = Join-Path $ToolsDir 'abraham-server.exe'
$server = Start-Process -FilePath $serverExe `
    -ArgumentList "--listen 127.0.0.1:8443 --mgmt 127.0.0.1:9200 --state `"$Out\sessions.json`" --audit `"$Out\audit.jsonl`"" `
    -WorkingDirectory $Out -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput "$Out\server.log" -RedirectStandardError "$Out\server.err.log"

$pubFile = Join-Path $Out 'server.pub'
$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Path $pubFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
if (-not (Test-Path $pubFile)) { throw "teamserver did not write server.pub" }
$pubKey = (Get-Content $pubFile -Raw).Trim()
Log "teamserver pid $($server.Id), key $($pubKey.Substring(0,16))..."

# --- 2. ETW trace (DotNETRuntime: managed execution telemetry) --------------
$etlPath = Join-Path $Out 'bench.etl'
$traceOk = $true
# Clean up any residual collector set first: if a previous run's delete
# failed (large .etl flush), the next create silently fails with
# "already exists" and every later scenario loses the sensor.
logman stop abraham-bench 2>&1 | Out-Null
logman delete abraham-bench 2>&1 | Out-Null
# Provider must be NAMED — by GUID the flags silently fail and the trace
# stays empty (verified in guest). Keywords: Loader|JIT|Exception|Threading
# (0xC030), level informational: enough to prove CLR-hosting telemetry
# flows without the ~140k-event flood of keywords=all.
logman create trace abraham-bench -ow -o "$etlPath" -p "Microsoft-Windows-DotNETRuntime" 0xC030 0x4 -nb 16 256 -f bincirc -max 64 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $traceOk = $false; Log "logman create failed (admin?)" }
if ($traceOk) { logman start abraham-bench 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { $traceOk = $false } }

# --- 3. implant --------------------------------------------------------------
$t0 = Get-Date
$implantExe = Join-Path $ToolsDir 'abraham-implant.exe'
$implantArgs = "--server 127.0.0.1:8443 --key $pubKey --sleep $SleepSecs --jitter 0.1"
if ($Evasion -ne "") { $implantArgs += " --evasion $Evasion" }
$implant = Start-Process -FilePath $implantExe -ArgumentList $implantArgs `
    -WorkingDirectory $Out -WindowStyle Hidden -PassThru `
    -RedirectStandardError "$Out\implant.log" -RedirectStandardOutput "$Out\implant.out.log"
Log "implant pid $($implant.Id) args: $implantArgs"

# --- 4. drscan + guardscan samplers in the background ------------------------
$drOut = Join-Path $Out 'drscan.jsonl'
$drLoops = [Math]::Max(4, [int]($Cycles * $SleepSecs / 2))
Start-Process -FilePath "powershell" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$BenchDir\drscan.ps1`" -TargetPid $($implant.Id) -Loop $drLoops -IntervalSec 2" `
    -WindowStyle Hidden -RedirectStandardOutput $drOut | Out-Null
# ABR-T041 sensor: PAGE_GUARD on image pages of the implant process.
$gsOut = Join-Path $Out 'guardscan.jsonl'
Start-Process -FilePath "powershell" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& { 1..$drLoops | ForEach-Object { powershell -NoProfile -File `"$BenchDir\guardscan.ps1`" -TargetPid $($implant.Id) | Out-File -Append -Encoding ascii '$gsOut'; Start-Sleep 2 } }`"" `
    -WindowStyle Hidden | Out-Null

# --- 5. wait for the session to register ------------------------------------
$sessionId = $null
$deadline = (Get-Date).AddSeconds(40)
while (-not $sessionId -and (Get-Date) -lt $deadline) {
    $s = Mgmt '{"cmd":"sessions"}'
    if ($s -and $s.sessions -and $s.sessions.Count -gt 0) {
        $sessionId = $s.sessions[0].id
        # keep polling until the live pid matches this implant (old state is
        # fresh per-run, but sessions may briefly list stale entries)
        if ($s.sessions[0].pid -ne $implant.Id) { $sessionId = $null }
    }
    if (-not $sessionId) { Start-Sleep -Milliseconds 500 }
}
if (-not $sessionId) { Log "WARN: session never registered; continuing to harvest anyway" } else { Log "session id $sessionId" }

# --- 6. workload (identical across scenarios) --------------------------------
if ($sessionId) {
    $r1 = Mgmt ('{"cmd":"module","session":' + $sessionId + ',"name":"ps"}')
    Log ("task module-ps: " + ($r1 | ConvertTo-Json -Compress))
    Start-Sleep -Seconds 3
    $r2 = Mgmt ('{"cmd":"module","session":' + $sessionId + ',"name":"netstat"}')
    Log ("task module-netstat: " + ($r2 | ConvertTo-Json -Compress))
    Start-Sleep -Seconds 3
    $r3 = Mgmt ('{"cmd":"psrun","session":' + $sessionId + ',"script":"Get-Process -Name powershell | Select-Object -First 3 | Format-Table | Out-String"}')
    Log ("task psrun: " + ($r3 | ConvertTo-Json -Compress))
    Start-Sleep -Seconds 5
    $r4 = Mgmt ('{"cmd":"execasm","session":' + $sessionId + ',"source":"' + ($asmPath -replace '\\','\\') + '","type":"Prog","method":"Go","argument":"bench","patch":true}')
    Log ("task execasm: " + ($r4 | ConvertTo-Json -Compress))
    Start-Sleep -Seconds 5
}

# --- 7. mid-run memory scan (pe-sieve) --------------------------------------
# VQL first, while the implant is alive: pslist() of a dead pid is empty.
$vqlText = $null
$vr = Join-Path $ToolsDir 'velociraptor.exe'
if (Test-Path $vr) {
    try { $vqlText = (& $vr query "SELECT Pid, Name, Exe FROM pslist() WHERE Pid = $($implant.Id)" --format json 2>$null) -join ' ' } catch { $vqlText = $null }
}
$totalSecs = $Cycles * $SleepSecs
$midDelay = [int]($totalSecs * 0.6)
Log "midpoint scan in $midDelay s"
Start-Sleep -Seconds $midDelay
if (-not $implant.HasExited) {
    $pesieveDir = Join-Path $Out 'pesieve'
    New-Item -ItemType Directory -Force -Path $pesieveDir | Out-Null
    $pe = Start-Process -FilePath (Join-Path $ToolsDir 'pe-sieve64.exe') `
        -ArgumentList "/pid $($implant.Id) /dir `"$pesieveDir`" /quiet" -WindowStyle Hidden -PassThru -Wait `
        -RedirectStandardOutput "$Out\pesieve-stdout.txt" -RedirectStandardError "$Out\pesieve-stderr.txt"
    Log ("pe-sieve exit " + $pe.ExitCode)
}

# --- 8. let the remaining cycles elapse, then stop --------------------------
$left = $totalSecs - $midDelay + 3
if ($left -gt 0) { Start-Sleep -Seconds $left }
if (-not $implant.HasExited) { Stop-Process -Id $implant.Id -Force -ErrorAction SilentlyContinue }
$t1 = Get-Date
Log "implant stopped; harvesting"

# --- 9. harvest --------------------------------------------------------------
$summary = [ordered]@{
    name       = $Name
    evasion    = $Evasion
    implant_pid  = $implant.Id
    cycles     = $Cycles
    window     = @{ start = $t0.ToUniversalTime().ToString('o'); end = $t1.ToUniversalTime().ToString('o') }
}

# 9a. Sysmon: per-EID totals in window + events attributable to the implant pid.
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $t0; EndTime = $t1 } -ErrorAction Stop
} catch { $events = @() }
$pidStr = [string]$implant.Id
$totalByEid = @{}
$matchedByEid = @{}
$matchedLines = @()
foreach ($e in $events) {
    $eid = [string]$e.Id
    $totalByEid[$eid] = 1 + [int]($totalByEid[$eid])
    $xml = $null
    try { $xml = [xml]$e.ToXml() } catch { continue }
    $hit = $false
    foreach ($d in $xml.Event.EventData.Data) {
        if ($d.Name -match '^(ProcessId|SourceProcessId|TargetProcessId|SourceThreadId)$' -and $d.'#text' -eq $pidStr) { $hit = $true; break }
        if ($d.Name -eq 'Image' -and $d.'#text' -like "*abraham-implant*") { $hit = $true; break }
    }
    if ($hit) {
        $matchedByEid[$eid] = 1 + [int]($matchedByEid[$eid])
        $matchedLines += @{ time = $e.TimeCreated.ToUniversalTime().ToString('o'); eid = $eid }
    }
}
$summary.sysmon_total_by_eid = $totalByEid
$summary.sysmon_implant_by_eid = $matchedByEid
$matchedLines | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content (Join-Path $Out 'sysmon-matched.jsonl')

# 9b. Defender.
try {
    $dets = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.DetectionTime -ge $t0 })
    $summary.defender_detections = $dets.Count
    $dets | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 } | Set-Content (Join-Path $Out 'defender.jsonl')
} catch { $summary.defender_detections = "query failed: $($_.Exception.Message)" }

# 9c. ETW trace. logman appends a sequence suffix to the output name
#     (bench_000001.etl), so resolve whatever landed in the directory.
if ($traceOk) {
    logman stop abraham-bench 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    logman delete abraham-bench 2>&1 | Out-Null
    $etlFile = Get-ChildItem $Out -Filter '*.etl' | Sort-Object LastWriteTime | Select-Object -First 1
    try {
        if (-not $etlFile) { throw "no .etl produced" }
        # The trace is system-wide: DotNETRuntime events from every .NET
        # process on the VM land here. Split into total vs implant-pid.
        $etw = @(Get-WinEvent -Path $etlFile.FullName -Oldest -ErrorAction Stop)
        $byProvider = @{}
        $implantEtw = 0
        foreach ($e in $etw) {
            $p = [string]$e.ProviderName
            if (-not $p -or $p -eq '') { $p = [string]$e.ProviderId }
            $byProvider[$p] = 1 + [int]($byProvider[$p])
            if ($e.ProcessId -eq $implant.Id) { $implantEtw++ }
        }
        $summary.etw_events = $etw.Count
        $summary.etw_implant_events = $implantEtw
        $summary.etw_by_provider = $byProvider
    } catch { $summary.etw_events = "read failed: $($_.Exception.Message)" }
}

# 9d. debug registers.
try {
    $dr = @(Get-Content $drOut -ErrorAction Stop)
    $nonZero = @($dr | Where-Object { $_ -match '"dr[0-3]":\s*"0x[0-9a-f]*[1-9a-f]' })
    $summary.drscan_samples = $dr.Count
    $summary.drscan_nonzero = $nonZero.Count
    $nonZero | Set-Content (Join-Path $Out 'drscan-hits.jsonl')
} catch { $summary.drscan_samples = 0 }

# 9d-2. guardscan hits (ABR-T041 sensor).
try {
    $gs = @(Get-Content $gsOut -ErrorAction Stop)
    $gsHits = @($gs | Where-Object { $_ -match 'GUARD-ON-IMAGE' })
    $summary.guardscan_samples = $gs.Count
    $summary.guardscan_hits = $gsHits.Count
    $gsHits | Set-Content (Join-Path $Out 'guardscan-hits.jsonl')
} catch { $summary.guardscan_hits = 0 }

# 9e. pe-sieve: /quiet writes the human summary to stdout; the exit code
#     is "1 = something dumped", which is a finding, not an error.
$peOut = Join-Path $Out 'pesieve-stdout.txt'
if (Test-Path $peOut) {
    $peText = Get-Content $peOut -Raw
    $peNum = { param($label) if ($peText -match ($label + ':\s+(\d+)')) { [int]$Matches[1] } else { 0 } }
    $summary.pesieve = @{
        scanned   = & $peNum 'Total scanned'
        replaced  = & $peNum 'Replaced'
        hooked    = & $peNum 'Hooked'
        unmatched = & $peNum 'Unmatched'
        implanted = & $peNum 'Implanted'
    }
} else { $summary.pesieve = "no output captured" }

# 9f. Velociraptor VQL (captured mid-run above).
if ($vqlText) { $summary.vql_pslist = $vqlText } else { $summary.vql_pslist = 'skipped' }

# 9g. audit trail size (tasking actually delivered).
if (Test-Path "$Out\audit.jsonl") {
    $summary.audit_lines = (Get-Content "$Out\audit.jsonl" | Measure-Object -Line).Lines
}

$summary | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Out 'summary.json')
Log "done: $Out"

# stop the throwaway teamserver
if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
