# ABR-T030 — Host persistence toolkit: detection guidance

Status: `experimental`.

Scope: the PERSIST task — install/remove/list of boot/logon survival
mechanisms, executed in-process on the session thread: registry Run
keys (HKCU + HKLM), the per-user Startup folder and an auto-start SCM
service. The persisted binary is a copy of the implant
(%APPDATA%\<name>.exe) unless the operator staged one. The scheduled
task (ITaskService COM) and WMI event-subscription COM vectors are
documented follow-ups.

## Technique summary

- `run-key` / `run-key-hklm`: `RegCreateKeyExW` +
  `RegSetValueExW(REG_SZ)` on `Software\Microsoft\Windows\
  CurrentVersion\Run` — value data `"C:\...\name.exe" [args]`.
- `startup`: copy of the implant into
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`.
- `service`: `CreateServiceW` (WIN32_OWN_PROCESS, AUTO_START,
  ERROR_IGNORE) with the implant copy as BinaryPathName; deliberately
  NOT started at install (a running copy is a second beacon) — it
  survives reboots.
- `list` reads back the live state of every mechanism by name; `remove`
  uninstalls by name (RegDeleteValueW / file delete / stop+DeleteService).

## What telemetry remains

| Signal | Where | Notes |
|---|---|---|
| Run-key write | Sysmon EID 12/13 (registry set), registry auditing | the classic T1547.001 sigma families fire unchanged — this is by design the most detectable vector |
| Startup-folder binary drop | Sysmon EID 11 in the Startup path | content inspection of the dropped image matches the implant (hash) |
| Service creation | Sysmon EID 7045 (service installed), Security EID 4697 | BinaryPathName points at %APPDATA% — the "user-writable service binary" sigma family fires |
| The %APPDATA% implant copy itself | EID 11 + hash replication | persists AFTER removal of the running implant — sweep for it |

## What does NOT fire (validated in design)

- No schtasks.exe/REG.EXE/powershell.exe child at any point —
  process-tree detections for those tools stay silent.
- The service vector does not start the binary at install time, so
  there is no immediate second process; the artifact waits for a boot.

## Sigma

Existing community rules apply directly and are the intended outcome:
run-key set by a non-installer process (T1547.001), service install
with user-profile BinaryPathName (T1543.003), file create in the
Startup folder (T1547).

## Purple-team usage

The point of this technique in the registry is that detection coverage
here is MATURE — run each install, confirm which of the three
(sigma/Sysmon) rules fire on the lab VM, exercise `remove`, and
document the %APPDATA% copy sweep as the host-cleanup step of the
after-action. The COM follow-ups (schtasks, WMI sub) then contrast:
T1053.005/T1546.003 coverage against in-process COM callers is the
next gap to measure.
