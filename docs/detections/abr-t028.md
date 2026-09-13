# ABR-T028 — In-process filesystem modules: detection guidance

Status: `experimental`.

Scope: the mkdir/rm/mv/cp module additions (and the underlying
in-process file discipline of the module system, ABR-T011) — routine
file management without spawning `cmd.exe`/`powershell.exe` children.

## Technique summary

Four std::fs-backed module ops executed on the implant's session
thread: `mkdir <path>` (recursive), `rm <path>` (file or tree),
`mv <src> <dst>` (rename), `cp <src> <dst>` (file copy). No new
processes, no shells; the file APIs resolve through the normal Win32
layer.

## What telemetry remains

| Signal | Where | Notes |
|---|---|---|
| File operations on monitored paths | Sysmon EID 1 n/a; EID 11 (FileCreate) covers creates/renames in configured scopes | the acting process is the implant image itself — attribution is direct when the implant is known |
| Deletion of staging artifacts | Sysmon EID 23 / EID 11 with deletes, forensic timelines | `rm` of uploader staging (`%TEMP%`) after upload/run is a classic C2 pattern |
| Legacy driver artifacts | n/a | no kernel involvement |

## What does NOT fire (validated in design)

- Process-creation telemetry (Sysmon EID 1) — there is no child
  process; the whole point vs `shell cmd /c del ...`.
- PowerShell script-block logging — no powershell.exe involved.

## Sigma

Standard "suspicious file deletion in temp by an unusual process"
rules apply with the implant image as the actor; no new rule shape is
needed. Guidance: alert on any non-system process whose ONLY file
activity is create-then-delete in user temp directories.

## Purple-team usage

Run `cp` of a canary file and `rm` of it while Sysmon EID 11/23 record;
confirm the events attribute to the implant process directly (no
conhost/cmd chain), then use that as the detection anchor for the
whole module family.
