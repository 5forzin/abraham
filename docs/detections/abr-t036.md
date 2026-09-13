# ABR-T036 — AMSI/ETW suppression via hardware breakpoints

Technique: `implant/src/evasion/hwbp.rs` (registry `ABR-T036`).
The patch-free successor of ABR-T024: instead of rewriting the prologues
of `amsi.dll!AmsiScanBuffer` and `ntdll!EtwEventWrite`, execution
breakpoints (DR0/DR1, DR7 = L0|L1) are armed on both exports and a
first-in-chain vectored exception handler retires every resulting
single-step exception with the "clean" return value (`Rax = 0`,
`AMSI_RESULT_CLEAN` through the 6th argument slot, resume at the
function's first `ret`). No byte of a signed module changes.

## Primary IOC — debug-register state

The artifact this technique cannot avoid is the breakpoint state
itself, readable by any thread-context query an EDR or anti-cheat
already performs:

| Register | Value | Meaning |
|---|---|---|
| DR0 | `ntdll!EtwEventWrite` | execute breakpoint, 1 byte |
| DR1 | `amsi.dll!AmsiScanBuffer` | execute breakpoint, 1 byte |
| DR7 | `0x3` (L0\|L1, RW=execute, LEN=1) | both locally enabled |

A scan that flags any of the following is catching this technique:

1. `GetThreadContext(CONTEXT_DEBUG_REGISTERS)` on any thread of any
   process where DR0–DR3 are non-zero and resolve inside `nttdll` or
   `amsi.dll` exports. Legitimate user-mode DR usage is dominated by
   debuggers (rare on servers) and some anti-cheat agents — everything
   else deserves the question "why is this thread breakpointing an
   instrumentation export?".
2. The `lab/bench/drscan.ps1` probe implements exactly this check
   against a live pid and emits JSONL suitable for replay; it is the
   sensor the evasion bench uses for this column.
3. `AddVectoredExceptionHandler` registrations are enumerable by
   hunting the ntdll vectored-handler list; a handler whose code page
   is RX, carries synthetic unwind metadata (see ABR-T008), and
   compares RIP against those two exports is conclusive — though
   reading another process's handler list requires the same
   thread-context-class access as (1).

## What does NOT fire (the honest gap)

- **Hash-based tamper detection is blind here — by design.** pe-sieve
  `hooked`/`replaced` counts drop to zero because module bytes are
  pristine. This is the exact trade against ABR-T024: the byte patch
  lights up memory scanners, the breakpoint variant lights up
  thread-context scanners. Defenses need the DR check to see this.
- Sysmon records nothing: no process, file or network event exists for
  a debug-register write, and swallowed single-step exceptions never
  surface as crash telemetry.
- Kernel-mode ETW (Threat-Intelligence provider) does not observe
  user debug-register state either.

## Structural mitigation — measured, not theorized

On Windows 11 26200 with **any hypervisor owning the debug registers**,
user-mode DR writes are silently discarded:

- Host with VBS/Credential Guard running (`VirtualizationBasedSecurityStatus
  = 2`, service 2): `SetThreadContext` returns success, the readback
  reads DR0 = 0, the breakpoints never trigger. Verified through four
  write vectors — kernel32 self-set, full-context get→modify→set,
  raw `NtSetContextThread` via the indirect-syscall layer, and the
  suspend/set/resume helper — all identical.
- Lab VM with `HypervisorPresent = true` and VBS **off**: same
  discard. The enlightenments alone are enough on this build.

The implant treats a zero readback as "cannot arm" and falls back to
the ABR-T024 byte patch, so coverage degrades to T024's detection
surface (memory scanners) rather than to nothing. For defenders this
means: **on the VBS fleet, ABR-T036 is dead on arrival and the byte
patch is what you will see; on non-virtualized hosts, the DR0 IOC is
the tell.** Turning VBS on is a genuine, measurable kill-switch for
this technique class.

## Validation evidence

- `evasion::hwbp::tests::handler_retires_synthetic_contexts` drives the
  assembled handler directly with a synthetic `EXCEPTION_POINTERS` /
  `CONTEXT` (the exact state the kernel delivers on a DR single-step)
  and asserts the retirement semantics for the ETW target, the AMSI
  target (including `AMSI_RESULT_CLEAN` through `[Rsp+0x28]`) and the
  pass-through path for non-targets. Runs on any host, VBS or not.
- `etw_write_is_retired_clean` / `amsi_scan_reports_clean` perform the
  real retired calls when the debug registers stick; on hosts where the
  readback gate reports the VBS discard they print the evidence line
  and pass by skip.
- Lab journal: `docs/lab/2026-09-13-red-focus-run.md`, Part 2.

## Hunting one-liners

```powershell
# drscan against a suspect pid (same check an EDR performs)
powershell -File lab\bench\drscan.ps1 -TargetPid <pid> -Once
```

Sigma cannot express thread-context reads; any DR-based detection must
live in the sensor (EDR, Velociraptor artifact) rather than in event
log rules — the rule-shaped artifacts for this technique are the
guidance above plus the bench probe.
