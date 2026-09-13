# ABR-T022 — In-process shellcode execution: detection guidance

## Technique summary

The `EXEC` task (`task_type 0x08`) copies an operator-supplied
position-independent blob into a fresh private allocation through the
indirect-syscall layer (`NtAllocateVirtualMemory` RW → copy →
`NtProtectVirtualMemory` RX), calls it as a function on the implant's
session thread, and frees the region (`NtFreeVirtualMemory`). No child
process, no new thread, no `CreateRemoteThread`, no named objects: the
classic user-mode injection tripwires (Sysmon EID 8 ThreadCreate,
EID 10 ProcessAccess with WRITE rights into a foreign process) never
fire, because nothing crosses a process boundary.

## What telemetry remains

1. **Kernel ETW (Threat-Intelligence provider).** Sensors subscribed to
   the kernel memory ETW channel observe the full lifecycle:
   `VirtualAllocate`/`VirtualAllocEx` with RW, followed by
   `VirtualProtect` to RX on the same region, executed by a process
   whose image path never appears as the module for that region.
   The RW→RX flip without loader involvement (no image load event, no
   `MapViewOfSection`) is the strongest signal — benign software almost
   always gets executable memory through the loader or JIT frameworks
   with known signatures.
2. **Region anatomy after the flip.** While the stage runs, the region
   is `MEM_PRIVATE`, `PAGE_EXECUTE_READ`, allocation-base == region-base
   (single allocation), and unbacked by any file. pe-sieve/Moneta
   style scanners flag exactly this shape. The region is freed when the
   stage returns, so scanning wins only while the stage is resident —
   which favors stages that return quickly (stagers) and punishes
   long-runners, inverting the operator's usual tradeoff.
3. **Timing correlation.** The allocation exists only between the
   TASK_POLL that carried the EXEC task and the RESULT that follows. A
   sensor that watches poll cadence can bracket the window precisely;
   on-scanned hosts with periodic memory sweeps the hit probability is
   the sweep period divided by the stage duration.

## What does NOT fire (validated in design)

- Sysmon EID 8 (ThreadCreate): the call runs on the session thread.
- Sysmon EID 10 (ProcessAccess): no cross-process operation.
- Sysmon EID 7 (ImageLoad): no module is loaded.
- AMSI: the blob is native code, never inspected by AMSI.

## Sigma

No reliable Sigma-compatible logsource exists for the kernel
memory-channel events across vendors; the actionable detection is the
ETW TI-provider correlation above. When the stage performs its own
follow-on actions (shell spawning, file writes), the corresponding
per-technique Sigma rules apply on those events.

## Purple-team usage

Queue `exec <session> <local-file>` from the TUI with a proof stage
(`mov eax, 0x1337; ret` — six bytes) and expect
`exec: 6B ret=0x1337` in the result. Host-validated 2026-09-12
(session 2, task 7).
