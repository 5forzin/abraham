# Evasion bench

The measurement instrument for the red side of the purple equation: run the
implant under a fixed workload against a sensor stack on the lab VM and
count what each sensor sees, scenario by scenario. Used to produce the
before/after scorecards that gate evasion work (`scorecard-*.md`).

## Sensors

| Sensor | What it measures | How |
|---|---|---|
| Sysmon 15.22 (SwiftOnSecurity config) | Process/file telemetry of the implant | evtx query filtered by pid + window |
| ETW `Microsoft-Windows-DotNETRuntime` | Managed-execution telemetry (CLR hosting, execute-assembly) | `logman` trace, keywords=all |
| Defender (real-time, tamper-protected) | Signature detections | `Get-MpThreatDetection` in window |
| drscan.ps1 | Debug-register hooking (hardware breakpoints) — what an EDR's `GetThreadContext` check sees | thread CONTEXT sampling while implant lives |
| pe-sieve 0.4.1.1 | In-memory module tampering: hooked/replaced/unmatched modules | mid-run scan of the live pid |
| Velociraptor 0.77.2 (standalone VQL) | Process view consistency (pslist) | local query during the run |

Out of scope by construction: kernel Threat-Intelligence ETW (needs a
real EDR driver) — documented as a permanent gap in the detection docs.

## Layout

- `run-bench.ps1` — host orchestrator: builds lab binaries, stages the
  guest, runs scenarios, pulls zipped results back into `results/`.
- `bench.ps1` — guest side: throwaway teamserver on loopback, implant with
  the scenario's `--evasion`, identical workload for every scenario
  (module ps, module netstat, psrun, execasm), sensor harvest,
  `summary.json`.
- `drscan.ps1` — per-thread debug-register probe (the abr-t036 IOC check).
- `diag.ps1` — guest environment sanity check (elevation, Sysmon, csc).
- `tools/` — pinned sensor binaries (gitignored; see versions above).

## Running

From the repo root on the host (VMware lab VM must be running):

```console
powershell -Command "& 'lab/bench/run-bench.ps1' -ScenarioNames @('plain','ekko','ekko-ppid') -Cycles 20"
```

Scenario names map to `--evasion` values inside `run-bench.ps1`
(`$scenarioMap`); add entries there when new evasion modes land
(hwbp, sleep2, ...).

## Known caveats

- The SwiftOnSecurity config filters loopback connections, so Sysmon EID 3
  never appears for the loopback teamserver — network telemetry is covered
  by the live-host validation instead.
- `psrun`'s bootstrap compiles `tools/psboot.cs` from the server binary's
  build-time `CARGO_MANIFEST_DIR`; the bench recreates that exact path on
  the guest (lab hack — a cwd fallback in `ps_bootstrap()` is the proper
  fix, tracked as follow-up).
- pe-sieve exit code 2 can appear even with a complete scan summary; the
  parsed counters, not the exit code, are the signal.
- Sysmon counts both total events in the window and events attributable to
  the implant pid (matching ProcessId fields or Image path).
