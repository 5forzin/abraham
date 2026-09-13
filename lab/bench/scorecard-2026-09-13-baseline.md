# Evasion bench scorecard — baseline (2026-09-13)

State of the tree at `9af8f73` (post C2-maturity run, CI green), before
any red-focus changes. Three scenarios, identical workload (module ps,
module netstat, psrun, execasm), 20 cycles × 2 s sleep, lab VM
(Windows 11 26200, elevated, Sysmon 15.22 SwiftOnSecurity, Defender
real-time on). Sensor stack: Sysmon, ETW DotNETRuntime (Loader|JIT|
Exception|Threading, informational), Defender, drscan (debug registers),
pe-sieve 0.4.1.1 mid-run, Velociraptor 0.77.2 pslist.

| Sensor | plain | ekko | ekko-ppid |
|---|---|---|---|
| Sysmon implant events (EID 1 + 11) | 1 + 3 | 1 + 3 | 1 + 3 |
| Defender detections (window) | 0 | 0 | 0 |
| ETW DotNETRuntime — implant pid | 0 | 0 | 0 |
| ETW DotNETRuntime — system-wide | 1276 | 1339 | 1325 |
| drscan: threads with Dr0–Dr3 set | 0 | 0 | 0 |
| pe-sieve modules hooked | **3** | **4** | **5** |
| pe-sieve replaced / implanted / unmatched | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| Velociraptor pslist sees implant | yes | yes | yes |
| Tasks delivered (audit trail) | 4/4 | 4/4 | 4/4 |

## Findings

1. **T024's permanent patch is the loudest artifact the bench sees.**
   pe-sieve reports 3–5 *hooked* modules (amsi.dll / ntdll byte patches)
   in every scenario — the patch is not gated by `--evasion`; it rides
   the CLR tasks (psrun patches unconditionally, execasm by `patch`
   default). This is the number the T036 hardware-breakpoint variant
   must drive to zero.
2. **The implant's user-mode ETW is already silent** — zero
   DotNETRuntime events attributable to the implant pid in all
   scenarios, because `EtwEventWrite` is patched before the CLR engine
   starts logging. The system-wide counts are other .NET processes
   (csc bootstrap compile, bench tooling); they confirm the sensor
   works and provide the control population.
3. **Defender (stock, real-time) sees nothing** in any scenario —
   consistent with the BYOVD-phase lab results; the bench's detection
   pressure comes from the memory/host sensors, not signatures.
4. **drscan reads 0 everywhere** — no debug-register usage exists yet
   (expected: no hardware breakpoints in the current tree). This is the
   column that will change when T036 lands.
5. Sysmon output is minimal and identical across scenarios (creation +
   file writes of the throwaway state); the SwiftOnSecurity config
   filters loopback, so no EID 3 for the loopback teamserver (documented
   in the bench README).
6. ekko/ekko-ppid add +1/+2 "hooked" vs plain — hypothesis: scan timing
   relative to the patch window, not an ekko effect (ekko does not touch
   module bytes); to be re-checked on the post-change run.

## What this baseline sets up

The before/after contract for the red-focus run: T036 (hwbp) must keep
ETW/AMSI silent (row 3 stays 0) while moving pe-sieve hooked to 0 and
accepting the new drscan signal (row 5 becomes non-zero — its own
detection doc). Sleep 2.0 and stomp hardening will be judged against
these same rows plus the mid-run memory-scan deltas.
