# ABR-T016 — DKOM process hiding via kernel write primitive: detection guidance

| Field | Value |
|---|---|
| Registry | `ABR-T016` |
| Component | `implant::vdm` (`hide` / `unhide`) |
| MITRE ATT&CK | T1564.008 (Hide Artifacts: Rootkit), T1014 |
| Prereq | ABR-T014 (kernel R/W primitive live) |
| Sigma | n/a — no native event exists; behavioral diffing (below) |
| Phase | 3 (BYOVD chain, stage 3.4) |

## What the technique does

With the kernel R/W primitive live, the implant discovers every
GLOBAL process list inside the System EPROCESS by structural signature
(circular walk passing its own PID, list length matching the live
process count from SystemProcessInformation), unlinks its own EPROCESS
from each, and can relink later — the relink is refused unless the
saved neighbors still point at each other. Offsets are discovered at
runtime (build 26200: ActiveProcessLinks +0x418; a second global list
at +0x498).

## The 2026 reality — and why it helps defenders

On Windows 11 24H2+ the classic unlink does NOT hide a process from
`tasklist` / `NtQuerySystemInformation` anymore: PSI enumerates via
`PspAllProcess`, whose links are not the EPROCESS-relative lists a
data-plane primitive can structurally validate (lab-verified
2026-09-11: implant unlinked from the discovered lists remained
visible to tasklist). Full modern hiding needs symbol-aware access to
the PspAllProcess head — a materially higher bar than the 2010s DKOM.

## Detection ideas, in priority order

1. **Enumeration-source diff (the gift of the new reality):** compare
   processes seen via PspAllProcess-based APIs against a kernel-side
   walk of ActiveProcessLinks (EDR kernel callback or driver-assisted
   audit). A process present in one and absent from the other IS DKOM —
   either direction. This turns the attacker's list manipulation into a
   high-fidelity boolean.
2. **Detect the prerequisite** (ABR-T013/T014 telemetry: EID 7045
   staging + EID 6 hash match). A host where a known-vulnerable driver
   loaded should be triaged regardless of what followed.
3. **Session-survival anomaly**: an established C2-style connection
   (long-lived TCP from a user-session process) whose owning PID stops
   appearing in process inventory while the socket keeps exchanging
   data — correlation between netflow and process inventory catches
   exactly the hidden-but-alive state DKOM creates.
4. **Kernel-list integrity callbacks**: EDRs with kernel presence can
   checksum the list topology periodically; any silent re-link without
   a matching process-exit event is tampering.

## Lab validation

Round-trip validated 2026-09-11 (`docs/lab/2026-09-11-byovd-phase3.md`
Part 7): unlink verified by neighbor read-backs, relink verified the
same way and by tasklist re-showing the pid; the modern tasklist
limitation documented above. One bugcheck taught the non-global-list
discriminator (0x139 arg3 — Part 6).
