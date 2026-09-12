# ABR-T011 — Detection guidance: in-process task modules (no child processes)

Status: `experimental` (Phase 2, host-validated on Windows 11 build 26200 on
2026-09-11; VM e2e validated same day — module tasks executed
in-process on the lab implant, see
`docs/lab/2026-09-11-stack-memory-observation.md` Part 7).

Scope: routine post-exploitation collection runs as built-in modules
inside the implant process — `ps` (process enumeration via
`NtQuerySystemInformation(SystemProcessInformation)`), `ls`, `cat`
(capped file read) and `whoami` (environment block only). The NT-based
module dispatches through the indirect-syscall layer, so the collection
syscall itself runs with the ABR-T010 synthetic call stack. The point of
the technique is what does NOT happen: no `cmd.exe`/`conhost.exe` child
processes, no new threads, no console hosts — the classic
process-creation telemetry (Sysmon EID 1, ABR-T002's Sigma) never fires
for module tasks.

## What telemetry remains

The technique removes process creation, not the underlying operations:

1. **The collection syscalls still reach the kernel.** `ps` issues a
   real `NtQuerySystemInformation` (visible to kernel ETW and any
   filter-driver telemetry); `ls`/`cat` read directories and files
   through the ordinary Win32-to-NT path (std library), producing
   `NtCreateFile`/`NtQueryDirectoryFile` traffic attributable to the
   implant process.
2. **Results leave over the C2 channel** — the polling cadence and
   transfer sizes remain observable at the network layer regardless of
   how the data was collected.
3. **Memory forensics are unaffected** — the module code is ordinary
   implant `.text`; the ABR-T008/T010 region indicators still apply
   while evasion is armed.

## Detection ideas

1. **Absence-based hunting is a correlation game.** An implant that
   switches from shell tasks to module tasks disappears from
   process-creation telemetry. Hunt the combination instead: a beaconing
   process whose network cadence continues while process activity drops
   to zero, with steady file-read traffic — the operation is clearly
   alive but never spawns. Behavioral analytics that model "remote
   access without execution artifacts" catch this shape.
2. **Flag the collection syscalls of unsigned processes.**
   `NtQuerySystemInformation(SystemProcessInformation)` from a process
   with no security-product/module context is ordinary for task
   managers, unusual for headless beacons. Kernel ETW + signature
   context (unsigned image) is a workable analytic.
3. **Cross-check claimed stacks (ABR-T010 interplay).** The `ps` module
   runs on the synthetic stack; the chain claims a thread-thunk origin
   for a syscall that a real `BaseThreadInitThunk` frame would
   essentially never make directly. Detection idea 6 of
   `abr-t010.md` (correlate the claimed chain with the operation)
   applies verbatim to module traffic.
4. **Result-shape signatures.** The TSV output format is fixed; if an
   exfiltrated result leaks (exercise, proxy, hunt), the
   `pid\tppid\tthreads\thandles\tname` header is an implementation
   artifact of this exact module set.

## What this technique does NOT remove

Nothing about the implant's presence: image on disk, module list,
beaconing network flows, and the ABR-T006/T008/T010 memory indicators.
It narrows the operational footprint to in-process activity — the
detections that still land are the behavioral and memory-side ones
above.

## References

- `NtQuerySystemInformation` / SYSTEM_PROCESS_INFORMATION:
  https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
- Process-creation telemetry baseline this technique avoids:
  `detections/sigma/abr-t002_cmd.yml` and `docs/detections/abr-t002.md`
