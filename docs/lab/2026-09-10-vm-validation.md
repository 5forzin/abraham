# Purple lab validation — 2026-09-10

First end-to-end validation of the Phase 1 core (encrypted C2 channel, remote
shell, file transfer, jittered polling) against live Sysmon telemetry in a
Windows 11 VM. All four Phase 1 techniques were flipped to `experimental` in
`registry/techniques.yaml` based on the evidence below.

## Environment

| Component | Detail |
|---|---|
| Teamserver | `abraham-server` 0.1.0 on the operator host, C2 `0.0.0.0:8443`, mgmt `127.0.0.1:9200`, Ed25519 identity `ae5ac1c402eb43b2ce38d61646e5e50dd3ee42ef894659734d4c1ee78d82086a` |
| Target VM | Windows 11 x64 build 10.0.26200.0, hostname `ABRAHAM`, VMware NAT (`192.168.162.128` → host `192.168.162.1`) |
| Implant | `abraham-implant` 0.1.0, session 1, user `Abraham\lab`, pid 2232, `--sleep 3 --jitter 0.25`, binary at `C:\Users\antho\Desktop\abraham-implant.exe` |
| Telemetry | Sysmon 15.22 (SwiftOnSecurity `sysmonconfig-export`) |
| Capture | 73 events from `Microsoft-Windows-Sysmon/Operational`, full XML export (kept in `lab/captures/`, gitignored) |

Deployment used VMware guest operations (local lab account); the implant was
launched as a non-interactive child of `vmtoolsd.exe`, which is itself a
telemetry-relevant delivery pattern (see ABR-T002 results).

## Executed activity

1. Implant registered and established the encrypted session (ABR-T001).
2. Three shell tasks via mgmt: `whoami`, `whoami /priv`, `net user` (ABR-T002).
3. Upload of a 1,029,120-byte executable to
   `C:\Users\lab\Desktop\abraham-uploaded.exe`; download of an 81-byte file to
   `loot/session-1/task-5.bin` (ABR-T003).
4. All tasks served across polling cycles at sleep 3 s / jitter 0.25 (ABR-T004).

## Detection outcomes

Sigma rule logic was evaluated verbatim (`endswith`/`contains`/condition
semantics) against the captured event stream by `lab/validate_capture.py`.

| Technique | Detection | Outcome | Key records |
|---|---|---|---|
| ABR-T002 | Sigma `3f9a6c1e-8b2d-4e7f-9c4a-1d6e5b8f2a01` (cmd.exe with unusual parent) | **MATCH — 4 events** | rec 34/36/38: `cmd.exe` spawned by `abraham-implant.exe`; rec 51: `cmd.exe` spawned by `vmtoolsd.exe` (vix script — deployment artifact, consistent with the rule's documented FP surface) |
| ABR-T003 | Sigma `8c2f9d3a-1b4e-4f6a-9c7d-2e8b5a3f1c02` (executable written to user path) | **MATCH — 14 events** | rec 41: `abraham-implant.exe` writes `C:\Users\lab\Desktop\abraham-uploaded.exe`; remaining 13 are lab tooling (.ps1 copies by `vmtoolsd.exe`, PowerShell script-policy probe files) — matches the rule's `low` severity and documented false positives |
| ABR-T001 | Guidance (`docs/detections/abr-t001.md`) | Validated at host layer | rec 14 (Sysmon EID 3): `192.168.162.128:61000 → 192.168.162.1:8443` by `abraham-implant.exe` |
| ABR-T004 | Guidance (`docs/detections/abr-t004.md`) | Validated | 5 tasks served across jittered cycles; Sysmon deduplicates identical TCP connections, so a single EID 3 represents the polling flow — periodicity evidence comes from task service times |

ABR-T001 note: validated over the current raw TCP transport; the outer HTTPS
egress wrapper (malleable profiles) is the remaining Phase 1 item and will be
re-validated against proxy-visible telemetry when implemented.

## Findings

- **Windows 11 build 26200 removed `wevtutil export-log`** (`Command e is not
  supported`) and `EventLogSession.ExportLog` fails with "The parameter is
  incorrect". Collection must use `Get-WinEvent`/`To-Xml` (or API-based
  tooling). DFIR collection scripts that shell out to `wevtutil e` break on
  24H2+ — worth a note in future detection guidance.
- Implant spawned by `vmtoolsd.exe` (VMware guest operations) is a distinctive
  process-creation pattern; the ABR-T002 rule caught it without modification.

## Addendum: outer HTTPS re-validation (same day)

After implementing the outer HTTPS layer (rustls TLS + HTTP/1.1 envelope,
malleable profiles, certificate pinning — `docs/protocol.md` v0.2), the same
techniques were re-executed from the VM over the new transport:

- Implant deployed with `--tls-pin` (sha256 of the self-signed server
  certificate); wrong pins are rejected at TLS level (validated locally).
- ABR-T002: MATCH — `cmd.exe` spawned by `abraham-implant.exe` (EID 1).
- ABR-T003: MATCH — fresh creation of `C:\Users\lab\Desktop\abraham-uploaded.exe`
  (2,599,936 bytes, 44 chunks in one HTTP body) logged as EID 11 with
  `RuleName: EXE`; **overwriting the pre-existing file produced no EID 11**,
  a coverage gap now noted in the Sigma rule.
- ABR-T001/T004: EID 3 network events from the implant to the teamserver
  (single long-lived TLS connection per session; the rejected raw-TCP
  reconnect attempts of the previous build are also visible as periodic
  EID 3 with no TLS). Schannel ETW stays silent for the implant process
  (rustls in-process) — see the updated `docs/detections/abr-t001.md`.
- Evidence: `lab/captures/abraham-vm_sysmon-https_2026-09-10.xml`.

## Addendum 2: Phase 2 evasion validation (2026-09-11)

First Phase 2 increment: indirect syscalls (ABR-T005), waitable-timer sleep
obfuscation (ABR-T006) and PPID-spoofed child spawning (ABR-T007), all
flag-gated behind `--evasion ekko,ppid` (default off — baseline telemetry
stays comparable).

### ABR-T005 — indirect syscalls (T1106)

- SSN resolution (Hell's Gate + adjacent-stub recovery) validated on
  build 26200; the dispatcher was proven byte-equivalent to calling the
  ntdll export directly (`NtYieldExecution` returns the same NTSTATUS on
  both paths; `NtAllocateVirtualMemory` allocates identically).
- Shadow-space subtlety documented in code: syscall stack arguments live at
  `[rsp+0x28]`/`[rsp+0x30]` (past the return address and 32 bytes of
  Win64 shadow space), not at `[rsp+8]`.
- The hand-rolled export walk matches `GetProcAddress` for every resolved
  symbol, including api-set forwarders (which required following the
  forwarder chain to kernelbase — resolving the api-set name itself
  returns the forwarding module again).

### ABR-T006 — sleep obfuscation (T1027 / T1497.003)

- Five waitable-timer APCs flip the executable section RW, RC4-encrypt it
  via `SystemFunction032`, decrypt and restore RX across the sleep window.
  Validated by an external scanner process (`ReadProcessMemory`): the probe
  observes scrambled bytes mid-sleep and the section hashes identical
  before/after (`ekko_encrypts_during_sleep_and_restores`).
- Implementation notes: timer-queue callbacks (`CreateTimerQueueTimer`) run
  on worker threads — unusable for this technique since the encrypting
  callbacks must fire on the sleeping thread itself; waitable-timer APCs
  are the correct primitive. The argument thunk and its argument blocks
  must live on separate pages (`NtProtectVirtualMemory` is page-granular).
- Stack erasure below RSP stops one page above the TEB StackLimit
  (`gs:[0x10]`): the lowest committed page is the guard page, and writing
  through it grows the stack and chases the limit down the reservation.
- Sysmon produces **no events** for the whole cycle — honest absence,
  matching the guidance (ETW-TI / memory-scanner coverage required).
- VM long-run note: with `--evasion ekko` the implant registered, kept
  polling across many encrypted cycles (last_seen advancing for ~40s ≈ a
  dozen cycles) and executed shell tasks mid-cadence, then died silently
  (native exit, no panic) after roughly 15–20 cycles in the vmtoolsd
  service context. The single-cycle release-mode proof is solid on the
  host; the periodic re-arm of the waitable timers is the prime suspect —
  tracked as follow-up work before relying on ekko for long sessions.
  (Resolution 2026-09-11: the death no longer reproduces on the current
  binary — 300 staged cycles pass in this VM in 49.4 s. By timeline the
  likely cause was the arena-tail staging regression (stack locals
  clobbered mid-wait in optimized builds), fixed and test-pinned the
  same day; the timer re-arm hypothesis is downgraded. See
  `2026-09-11-stack-memory-observation.md` Part 6.)

### ABR-T007 — PPID spoofing (T1134.004): blocked on 25H2

Validated with three independent implementations (Rust implant, C#/PowerShell
control, Python/ctypes control) on two build-26200 machines:

1. Cross-process parent attributes fail at `CreateProcessW` with
   `ERROR_INVALID_PARAMETER` in every tested context (interactive and
   service; `PROCESS_CREATE_PROCESS` through `PROCESS_ALL_ACCESS` handles;
   SAC on and off; Defender realtime on — an attempted disable was blocked
   by tamper protection, so Defender remains an unexcluded variable).
   Self-parent succeeds from an interactive session.
2. `BLOCK_NON_MICROSOFT_BINARIES` mitigation attributes are rejected for
   ordinary (unsigned) callers regardless of parentage — the signature
   policy requires the special signer EKU.
3. The implant therefore attempts the spoof and falls back to a plain
   spawn, prefixing the task result with `[abraham] ppid spoof unavailable
   (...)` — operator-visible and hunter-friendly.
4. Detection impact: the companion Sigma (`abr-t007_cmd_via_explorer.yml`)
   cannot fire on 25H2 (nothing to match); on builds where spoofing works
   it matches the exact shape the technique produces. Failed-attempt
   telemetry (GLE 87 on attribute-list creates) is the high-signal 25H2
   indicator — see `docs/detections/abr-t007.md`.

### VM side notes

- SAC was disabled on the lab VM during the experiment (registry +
  reboot) — irreversible for that install; it is a dedicated lab machine.
- `wevtutil export-log` removal on build 26200 re-confirmed while pulling
  events (Get-WinEvent ToXml used instead).

## Addendum 3 — Morgana-derived hardening (ABR-T008/T009), 2026-09-11

Two capabilities adapted from the author's Morgana prototype landed after
the Phase 2 increment, host-validated on Windows 11 build 26200 (same build
as the VM); VM e2e validated 2026-09-11 in
`docs/lab/2026-09-11-stack-memory-observation.md` Part 6).

### ABR-T008 — dynamic unwind metadata for unbacked code

- The Ekko trampoline and wait loop now carry RUNTIME_FUNCTION/UNWIND_INFO
  registered via `RtlAddFunctionTable`, so stack walks traverse those
  frames like JIT code. (Correction, 2026-09-11: before registration the
  walk does not *abort* — a frame without RUNTIME_FUNCTION is treated as
  a leaf, return address assumed at [rsp], and the walk continues onto
  garbage. Leaf semantics, legitimate-NULL lookups and the kernel32 thunk
  nuance are pinned empirically in
  `docs/lab/2026-09-11-stack-memory-observation.md`.)
- Two x64 ABI facts were re-derived empirically and are recorded in
  `docs/detections/abr-t008.md`: UNWIND_INFO must live INSIDE the
  registered region (UnwindData RVAs resolve against the ImageBase
  argument), and the unwind-code array is stored in REVERSE prolog order
  (verified against kernel32's own .xdata on build 26200).
- Proof of correctness is semantic, not just structural:
  `RtlVirtualUnwind` on crafted contexts reads the return address from the
  right slot and restores rbx/rsi/rdi/r12 for the wait loop's program —
  debug and release.

### ABR-T009 — pristine SSN fallback from \KnownDlls\ntdll.dll

- When Hell's/Halo's Gate finds no clean local stub, `resolve()` now reads
  untouched stubs from a read-only `\KnownDlls\ntdll.dll` view built via
  indirect `NtOpenSection`/`NtMapViewOfSection` (new ten-argument
  dispatcher). No disk read.
- Build 26200 finding: the mapping returns `STATUS_IMAGE_NOT_AT_BASE`
  (0x40000003) because the process already maps ntdll at the preferred
  base — consumers must use the NT_SUCCESS convention, not equality with
  STATUS_SUCCESS.
- Host validation: view is the same image as local ntdll (export
  directory extent identical); SSNs match local resolution on a clean host
  for five syscalls including the bootstrap pair; the pristine gadget
  executes end-to-end through the indirect dispatcher.

### Regression coverage added

- `ekko_cycle_roundtrip_on_private_buffer` runs a full APC cycle against a
  private buffer (parallel-safe, non-ignored, runs in every profile). This
  closes the gap found during this increment: an earlier edit had reverted
  the arena-tail staging (key/USTRINGs/protect_old back on the stack) and
  the existing suite — RC4 roundtrip on stack locals plus an ignored full
  test — could not catch it. The restored staging plus this test pin the
  invariant.
