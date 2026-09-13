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

Implemented the patch-free successor of T024: DR0/DR1 execution
breakpoints on `AmsiScanBuffer`/`EtwEventWrite`, retired by a
hand-assembled VEH handler living on the external code page (stomped
DLL preferred, unwind metadata registered). `clr.rs` prefers hwbp and
falls back to the byte patch automatically.

Three bugs the validation caught (all in the hand-assembled handler,
all invisible to "it compiles"):

1. **ModRM reg field**: `4D 39 1B` decodes `cmp [r11], r11` — the
   handler compared Rip against the *address of the params block*
   instead of against r10. Both compares fixed to reg=010 (`0x13`,
   `0x53`); the layout test now pins those bytes.
2. **Epilogue order**: the AMSI path falls through into whichever
   block sits next — `.pass` was first, so every retirement returned
   CONTINUE_SEARCH after doing all the work. `.done` moved before
   `.pass`, and the `jmp` rel32 had to be recalculated (a stale 0x46
   landed mid-instruction and produced a literal SIGILL — the first
   crash caught by the synthetic test).
3. **Self SetThreadContext is undefined on a running thread**: arming
   moved to a helper thread (suspend → SetThreadContext with debug
   flags → readback → resume) that exists only for the call, keeping
   the single-thread execution model intact.

**The finding that matters: Windows 11 26200 discards user-mode debug
register writes whenever a hypervisor owns them.** Measured on two
environments — the operator host (VBS/Credential Guard running) and
the lab VM (HypervisorPresent with VBS off) — through four write
vectors (kernel32 self, full-context, raw NtSetContextThread via the
indirect-syscall layer, suspend/set/resume helper): every write
reports success, the readback reads zero, breakpoints never fire.
`ensure_armed` gates on the readback and falls back to the T024 patch,
so coverage degrades to the patch's detection surface rather than to
nothing. For the blue side this is a measured kill-switch: the DR0 IOC
(`lab/bench/drscan.ps1`) is the tell on non-virtualized hosts; on the
VBS fleet the technique is structurally dead. All of it documented in
`docs/detections/abr-t036.md`.

The handler itself is validated everywhere by
`handler_retires_synthetic_contexts`: it drives the assembled bytes
with a synthetic EXCEPTION_POINTERS/CONTEXT — the exact kernel
delivery state for a DR single-step — and asserts the ETW retirement,
the AMSI retirement (including AMSI_RESULT_CLEAN through
`[Rsp+0x28]`) and the pass-through. That test is what exposed bugs 1
and 2; the DR-gated integration tests only run where debug registers
stick.

Also this phase: the `clipboard_returns_something` test became a
diagnostic (the lab host's clipboard is chronically held open —
observed failing for every process including standalone PowerShell;
VMware clipboard arbitration with a running guest is the prime
suspect).
