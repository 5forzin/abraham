# Evasion bench scorecard — post red-focus run (2026-09-13)

After: T036 (hwbp, opt-in), Sleep 2.0 (T006 upgrade), stomp hardening
(T012 upgrade), profile UA pool/headers — commits through the red-focus
run. Same workload, same sensors, same lab VM as the baseline
(`scorecard-2026-09-13-baseline.md`, tree at `b3055df`). A fourth
scenario (`hwbp`) exercises the opt-in flag.

| Sensor | plain | ekko | ekko-ppid | hwbp (opt-in) |
|---|---|---|---|---|
| Tasks succeeded | 4/4 | 4/4 | 4/4 | psrun rc=2, execasm failed |
| Defender detections | 0 | 0 | 0 | 0 |
| ETW DotNETRuntime — implant pid | 0 | 0 | 0 | **28** (leak, see below) |
| drscan: threads with DR set | 0 | 0 | 0 | 0 |
| pe-sieve hooked modules | 3 | 5 | 5 | 0 (unpatched) |
| pe-sieve replaced / implanted | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

## Before/after against the baseline

- **Functional parity restored by default**: after the mid-run CLR
  regression (see Part 5 of the journal) the default path is bit-for-bit
  the baseline behavior — every scenario delivers all four tasks,
  implant-attributable ETW stays at zero, Defender stays at zero.
- **pe-sieve hooked 3→3/5**: the T024 patch is what memory scanners see,
  same as baseline (the hwbp opt-in that would zero it is the scenario
  that misbehaves — below). The ekko scenarios show 5 hooked modules
  (baseline showed 4-5 in the same noise band; the delta is scan-timing
  relative to the patch window, not a new artifact — hypothesis from the
  baseline scorecard, still standing).
- **Sleep 2.0 leaves no bench-visible trace** — which is the point: the
  stack/heap cipher widens what a *mid-sleep memory capture* sees as
  ciphertext, not what event-based sensors record. Its proof lives in
  `sleep2_scrambles_live_stack_and_restores` (external reader sees the
  marker scramble mid-sleep and restore bit-for-bit) and in the closed
  detection gap (abr-t006 idea 6).
- **The opt-in `hwbp` scenario documents its own failure honestly**: on
  the virtualized lab the readback passed once (unpatch ran — hence
  hooked=0), but the breakpoints never actually fired: 28 CLR events
  leaked through the now-unpatched ETW and the managed tasks broke with
  a TargetInvocationException. Every isolated test — debug and release,
  host and guest — passes; only the full async implant on the
  virtualized guest breaks. That is why the flag is opt-in and the
  guidance says: hosts measured to honor debug-register writes only.

## Reading of the whole run

The bench earned its keep twice over: it caught the CLR regression the
isolated tests could not see (and drove the commit-bisection that
pinned it on the hwbp arm path), and it turned the "VBS blocks debug
registers" lab note into a measured, reproducible kill-switch with an
honest operational boundary for the technique that survives it.
