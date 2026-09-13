# Red-focus run — closing the evasion gaps (2026-09-13)

Follow-up to the C2-maturity run (same date, earlier). Scope agreed with
the operator: attack the four "mais ou menos" points from the external
assessment — AMSI/ETW suppression without patching, stack/heap coverage
during sleep, deterministic stomping targets, and the missing *measurement*
of evasion itself — with the repo rule intact: every offensive change
ships with its coupled detection artifact.

Out of scope (deliberately): lateral movement (future AD lab), and the
TLS-fingerprint item — retired as already solved (Schannel migration of
2026-09-12; `abr-t001.md` treats rustls-JA3 as legacy).

## Part 1 — The sensor bench

`lab/bench/` is the instrument: a fixed workload (module ps, module
netstat, psrun, execasm) against a loopback teamserver on the lab VM,
under a six-sensor stack — Sysmon 15.22 (SwiftOnSecurity), ETW
`Microsoft-Windows-DotNETRuntime`, Defender real-time, `drscan.ps1`
(per-thread debug-register probe), pe-sieve 0.4.1.1 (mid-run memory
scan), Velociraptor 0.77.2 (standalone VQL pslist).

Tooling notes (all bit us, all fixed in-script):

- vmrun from Git Bash mangles `/c`-style args and drops empty
  parameters; the only reliable invocation shape is
  `runProgramInGuest` with separated args and full interpreter paths,
  and scripts always travel as files (`-File`), never inline.
- `powershell -File` binds extra scenario names as positional
  parameters — the orchestrator is invoked through `-Command` with an
  explicit array.
- logman silently ignores keyword flags when the provider is given by
  GUID; the DotNETRuntime trace only flows when the provider is named.
  A residual "Stopped" collector set (delete failure on a large .etl)
  makes every later `create` fail — cleaned up before each run.
- `psrun`'s bootstrap compiles `tools/psboot.cs` from the server
  binary's build-time CARGO_MANIFEST_DIR; the bench recreates that
  path on the guest. Proper fix (cwd fallback) tracked as follow-up.
- The mgmt protocol wants `"session": <id>`, not `"id"`.

Baseline captured (`lab/bench/scorecard-2026-09-13-baseline.md`), the
headline: **the implant's user-mode ETW is already silent (0 CLR events
attributable to its pid in every scenario) and the price is on the
memory scan — pe-sieve sees 3–5 hooked modules from the T024 byte
patches.** Defender stays at zero throughout. drscan reads zero (no
hardware breakpoints exist yet). That table is the before/after contract
for everything that follows.

## Part 2 — T036: AMSI/ETW via hardware breakpoints

(pending)
