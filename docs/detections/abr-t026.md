# ABR-T026 — In-process PowerShell execution: detection guidance

## Technique summary

The `POWERSHELL` task (`task_type 0x0A`) runs a .ps1 script inside the
implant's own CLR instance — no `powershell.exe`, no child process, no
console host. The teamserver compiles `tools/psboot.cs` once with the
in-box `csc.exe` (no references beyond mscorlib; the bootstrap loads
`System.Management.Automation` from the GAC at runtime) and ships the
4.6 KB bootstrap with the task. The implant patches AMSI and ETW for
its process first (ABR-T024), hosts the CLR if it is not up yet
(ABR-T025 chain; `Start()` on an already-running runtime answers
`S_FALSE` — accepted), runs `Boot.Run("<outpath>\n<script>")`, reads
the captured output back as the task result and deletes it. This is
the AMSI bypass that actually bites for red-team work: the script
never enters a fresh `powershell.exe` whose own AMSI would be intact.

## What the technique defeats

- **AMSI**: `AmsiScanBuffer` is patched in the only process that would
  ever scan the script — the hosting implant. No content inspection.
- **Script-block and module logging** (EID 4104/4103): these ride
  `EtwEventWrite` in-process, which ABR-T024 has stubbed. A
  transcription GPO writes files, but the engine events are gone.
- **Process creation telemetry**: there is no `powershell.exe` child —
  EID 1, EID 7 for powershell.exe, console-host events: all dark.

## What remains (detection side)

1. **Assembly loads (EID 7)**: `clr.dll`/`clrjit.dll` and
   `System.Management.Automation.dll` loading into a process that is
   not a known .NET host is the classic in-process-PowerShell
   analytic. Sigma rule below keys on the SMA load.
2. **Memory scanning**: the script text lives in the managed heap
   while it runs; a .NET-aware scanner (and any full-process dump)
   recovers it verbatim.
3. **The bootstrap disk flash**: same as ABR-T025 — a random-named
   temp `.dll` the CLR pins; EID 11 with the residue persisting.
4. **Absence as an analytic**: a host with PowerShell logging policy
   enforced that stops producing 4104 while other PowerShell activity
   indicators continue is itself a hunt lead (works only if the blue
   team monitors for the gap — document it in the SOC runbook).
5. **Kernel ETW (TI provider)** survives the user-mode patch — see
   abr-t024.md; allocations and thread activity of the CLR remain
   visible there.

## Sigma

`detections/sigma/abr-t026_sma_loaded_by_non_powershell.yml` — Sysmon
EID 7: `System.Management.Automation.dll` image load where the loading
process is not `powershell.exe`/`pwsh.exe`/a known .NET service.
Level: medium (tune per estate).

## Notes

- Second and later tasks in the same session reuse the running CLR
  (`Start()` → `S_FALSE`); bootstrap temp file follows the ABR-T025
  residue rules (delete / delete-on-close / reported path).
- **Assembly staleness (empirical)**: the default AppDomain identifies
  the loaded bootstrap by its simple name — once a Boot assembly is
  loaded in a process, later tasks with an UPDATED bootstrap still
  resolve to the first-loaded version until the process restarts.
  Found live: after recompiling psboot.cs, the old code kept executing
  until the implant was relaunched. Operational rule: rotate the
  bootstrap together with the implant build, or version the assembly
  name when iterating on it.
- `Constrained Language Mode` applies inside the runspace — operators
  account for it exactly as they would in `powershell.exe`.
