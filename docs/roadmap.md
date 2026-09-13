# Abraham — Roadmap

Current phase: **3 — BYOVD** (Phase 2 core landed 2026-09-11; leftovers
parked in the deferred list inside Phase 2).

## Phase 0 — Foundation

Goal: make the repository citable, governable and CI-validated before any
offensive capability exists.

- [x] Repository layout (monorepo)
- [x] README with dual-use positioning, usage policy and disclaimer
- [x] MIT license
- [x] Technique registry schema + initial Phase 1 techniques
- [x] Wire protocol specification (docs/protocol.md)
- [x] Initial Sigma rules + detection guidance
- [x] CI validating registry integrity and Sigma rules
- [x] Purple lab bootstrap: Sysmon config + capture procedure (lab/)

**Exit criteria:** green CI, registry validates, every Phase 1 technique has a
detection artifact (even if `planned`).

## Phase 1 — Core C2 (MVP)

Goal: a stable, encrypted, boring C2. No evasion beyond the E2E session.

- [x] Cargo workspace with `common`, `implant`, `server`, `tui` crates
- [x] Protocol v0.1 implementation (handshake, framing, tasking, batches)
- [x] Teamserver with c2 + mgmt listeners and Ed25519 identity persistence
- [x] Implant: REGISTER, TASK_POLL, SHELL, UPLOAD, DOWNLOAD, SLEEP, EXIT
- [x] TUI: session list, task submission, result view
- [x] Malleable profile support (sleep/jitter, URIs, user agents, HTTPS outer)
- [x] Unit tests for handshake, framing and message roundtrips
- [x] End-to-end smoke test (register/shell/upload/download/exit)
- [x] Purple lab: execute each Phase 1 technique, capture Sysmon/ETW
      telemetry, validate detections, store evidence
      (see `docs/lab/2026-09-10-vm-validation.md`)

**Exit criteria:** all ABR-T001..T004 marked `experimental` in the registry
with validated detections.

## Phase 2 — Evasion, incrementally

Goal: every classic evasion technique, each landing with its detection.

- [x] Direct/indirect syscalls for NT API usage
- [x] Sleep obfuscation (in-memory encryption while dormant)
- [x] Module system — built-in in-process task modules, no child
      processes (ABR-T011; host-validated 2026-09-11)
- [x] Phantom DLL stomping for the ekko code home (ABR-T012;
      host-validated 2026-09-11 — MEM_IMAGE home, phantom view)
- [x] PPID spoofing, spawn protection (blocked on 25H2 in lab contexts — findings in docs/detections/abr-t007.md)
- [x] Dynamic unwind metadata for unbacked code (ABR-T008, concept from
      the Morgana prototype; VM-validated 2026-09-11)
- [x] Pristine SSN fallback from `\KnownDlls\ntdll.dll` (ABR-T009, concept
      from the Morgana prototype; VM-validated 2026-09-11)
- [x] Stack/memory attribution captures with legit controls + host ekko
      long-run (900 cycles) — corrected premises recorded in
      `docs/lab/2026-09-11-stack-memory-observation.md`
- [x] Stack/return-address spoofing (ABR-T010 — Morgana-derived
      HSP-aware synthetic chain built from live unwind metadata;
      host + VM walker captures 2026-09-11)

**Status:** core complete 2026-09-11. The remainder is parked so work can
move on to Phase 3; evidence and details live in
`docs/lab/2026-09-11-stack-memory-observation.md` (Parts 9–10).

Deferred (parked 2026-09-11 — pick up when the implant track reopens):

- [ ] Adversarial validation pass in the VM: run the modern implant
      (T011+T012 active) against Sysmon + ETW + Defender and grade the
      detection hypotheses in `docs/detections/abr-t006.md`..`abr-t012.md`
      — the "good against a real sensor" bar
- [ ] T013 — spoofed dormant parking: the movabs pivot to the staged
      park chain dies fast (0xC0000005 that never reaches the
      calibrated VEH); blocked, next steps recorded in lab report
      Part 9. Stays out of the registry until re-enabled and
      lab-validated
- [ ] T010 detection idea 6 (claimed-chain vs operation-origin
      correlation) tested against a real analytic — folds into the
      validation pass above
- [ ] ETW/AMSI research notes with detection counterparts

## Phase 3 — BYOVD end-to-end (implant-driven kernel staging)

Goal: the implant stages its own ring-0 component end-to-end, KdMapper
style — drop and start a signed-but-vulnerable driver (true BYOVD), use
its primitives to manually map our unsigned kernel module, and run
ring-0 capabilities from that phantom module. Every stage lands with
its detection counterpart. The implant never depends on ring 0: a
capability gate probes fitness first and degrades gracefully to the
ring-3-only mode Abraham already is.

Standing rule (amended 2026-09-11; core unchanged): **no vulnerable
driver binaries in this repository.** The exploit client, the mapper
and our own payload module (not a vulnerable driver) live in the repo;
the vulnerable `.sys` is operator-supplied at runtime through C2
tasking (e.g. fetched from LOLDrivers by the operator, never committed).

### 3.0 — Lab fitness (decide before any code)

- [x] VM state on build 26200: Memory Integrity / Vulnerable Driver
      Blocklist status — **HVCI fully off; blocklist registry `=1` but
      unenforced without it** (a Desktop-loaded signed driver produced
      no CodeIntegrity telemetry). Both outcomes are now evidence, not
      hypotheses (`docs/lab/2026-09-11-byovd-phase3.md` Part 1)
- [x] Pick the vulnerable driver: shortlist RTCore64.sys > iqvw64e.sys
      > WinIo-family; client interface stays pluggable (operator
      decision, binaries never committed)
- [x] Safety snapshot taken before kernel work — pending: `vmrun
      snapshot` on this encrypted VM rejects the host password
      (`listSnapshots` accepts it); must be resolved or taken manually
      before stage 3.3

### 3.1 — Loader mechanics (benign; no vulnerable driver involved)

- [x] Implant driver tasking: drop / service create / start / device
      open / stop / delete, exercised against benign signed drivers
      copied from System32; full lifecycle telemetry captured —
      EID 7045 on every install (Sigma rule condition verbatim),
      EID 11 binding the staged file to the implant, load confirmed
      RUNNING in the kernel; findings: kernel image dedupe (183),
      non-stoppable stand-ins pin the staged file (lab report Part 2)

### 3.2 — Vulnerable-driver client

- [x] Protocol client for the chosen driver yielding kernel read/write
      primitives: RTCore64 client (CVE-2019-16098 family) live —
      probe leaked ntoskrnl base and read its MZ header through the
      driver (`docs/lab/2026-09-11-byovd-phase3.md` Part 3, ABR-T014);
      client surface pluggable, write primitives reserved for the
      mapper
- [x] Operator-supplied driver staging via C2 upload (same-path
      staging); unload + service cleanup after use — full
      stop/deregister/file-delete validated live

### 3.3 — Kernel mapper

- [x] v1 (kernel-write proof): SYSTEM token swap — validated live
      2026-09-11 (ABR-T015, `driver elevate`): swap landed, read back
      correctly, session survived the round-trip. Three bugchecks on the
      way produced the load-bearing patterns: per-hop kernel-address
      shape validation, runtime structural offset discovery (links
      +0x418 vs the stale table's 0x1D8; token confirmed by SYSTEM
      AuthenticationId), and staged read-only dry-runs (`driver probe`
      depth 1-3). Lab report Parts 4-5; VM snapshot `pre-byovd-phase3`
      taken manually (vmrun cannot snapshot this encrypted VM)
- [x] v1b — mapped as a boundary, not a feature: RX image pages
      refuse writes (0xBE twice, including the driver's header-RWX INIT
      which is read-only at runtime), no physical path on this variant,
      no call primitive → data-plane code exec is unreachable with
      RTCore64. The HalDispatchTable stub design is preserved in the
      lab report (Part 6) for a code-capable driver (iqvw64e shortlist)
- [x] v2 — REPLACED by the KDMapper path and PROVEN live 2026-09-12
      (ABR-T018, `driver map`, lab Part 11): with the Microsoft
      Vulnerable Driver Blocklist disabled (and nothing else — the
      offline guest's revocation state does not block it), the signed
      Intel iqvw64e.sys loads through the SCM and the full manual
      mapper runs on top: `ExAllocatePoolWithTag` via the NtAddAtom
      trampoline, DIR64 relocations, imports against the live export
      tables, readback-verified copy, real `DriverEntry` call. Two
      consecutive proofs stamped `0x610defaced` at the same pool
      address, zero new minidumps, clean teardown, and the loader's
      real EID 7045 validated the Sigma counterpart. The old
      RTCore64+WinIo dual-driver exec (`driver call`) stays fail-closed
      (Parts 10-12 + post-mortem; ABR-T017 intentionally without
      `lab_validated`) — the mapper path never walks page tables, which
      retires the entire 0x1A class. `lab/captures/t018/` holds the
      artifacts; builtin proof payload unit-executed in a usermode RWX
      view including a volatile-trashing callee

### 3.4 — Ring-0 payload module

- [x] Evasiveness pass (2026-09-12, lab Part 12): client-agnostic
      RwClient (iqvw64e preferred) under every DKOM/discovery
      technique; **modhide/modshow PROVEN** (PsLoadedModuleList
      192→191, own SystemModuleInformation cross-view blind, device
      live, guarded restore); **protect on/off PROVEN twice**
      (EPROCESS.Protection at the API-anchored +0x5fa — admin
      Stop-Process/taskkill both Access denied, byte restored);
      serviceless loader (DeleteService-marks nuance documented).
      ABR-T019/T020 `lab_validated`. Negative finding baked into the
      design: on 26200 psi does not enumerate EPROCESS lists, so
      process DKOM cannot hide from Get-Process — `hide` now fails
      closed with full diagnostics (its kernel-side walk-oracle and
      ~1s psi-oracle/rollback live-proven crash-free after the
      0x139-arg3 audited-list incident produced a dump).
- [x] Our own `.sys` — WITHOUT the WDK (2026-09-12, lab Part 13):
      `payloads/abraham-km` is freestanding Rust with ZERO PE imports,
      linked by rust-lld as a native driver (`tools/build_payload.sh`,
      no MSVC env, no elevation); kernel functions arrive through the
      mapper-injected fn table. Covert channel over a shared pool
      block (no device/IRP/handles): `chan hb/ping/protect/unprotect/
      stop` PROVEN live — 2s-tick heartbeat, command round-trips, and
      kernel-side SELF-HEALING anti-kill (admin kills DENIED twice 10s
      apart with re-apply between; `unprotect` restored control; an
      orphaned payload even blocked my own deployments until a VM
      reset). ABR-T021 `lab_validated`. WDK remains on the table for
      WDM-API-heavy payloads, but the fn-table pattern makes it
      optional.
- [ ] WDK chain (optional now): richer WDM surface, tests-signed
- [ ] Covert implant↔kernel channel (private device with a
      nondescript name, or a shared page)
- [x] Process hiding (DKOM unlink + guarded relink, ABR-T016) —
      round-trip validated; the 2026 reality (PSI via PspAllProcess)
      documented: classic DKOM no longer hides from tasklist, and the
      enumeration-source diff it enables is the paired detection
- [ ] Self-protection (ObRegisterCallbacks), EDR kernel-callback
      tampering — blocked on the code-exec boundary (need the
      call-capable driver); token escalation already lives in
      ABR-T015

### 3.5 — Capability gate (graceful degradation)

- [x] Capability gate shipped as `driver gate`: cheapest-first survey
      (device, kernel read, restored RW-write proof, exec-capability
      audit) returning a tier verdict — live tier-2 answer captured in
      the lab report (Part 7); no-half-states and the watchdog remain
      design notes for the full DRIVER_STAGE composite
- [ ] Remaining for the full gate: pre-load fitness (WinVerifyTrust on
      the staged binary, CI-state read) and the dead-channel watchdog

### 3.6 — End-to-end tasking

- [x] The DRIVER task family IS the tasking: load / unload / probe
      (staged dry-runs) / elevate / gate / hide / unhide, all wired
      through protocol, server, TUI and the mgmt helper; a one-shot
      DRIVER_STAGE composite and malleable knobs remain polish

### 3.7 — Detection pack (coupled to each stage, not an afterthought)

- [x] Sigma: EID 7045 staging rule (ABR-T013) + EID 6 RTCore64 rule
      (ABR-T014) — the EID 6 rule hash leg validated against a live
      event after enabling Sysmon's image-load switch (lab Part 7;
      CodeIntegrity 3033/3077 remain structurally absent on this
      HVCI-off host — that absence is itself documented telemetry
      truth)
- [x] Guidance docs: DKOM via enumeration-source diff (ABR-T016),
      callback/phantom hunting notes parked with the exec-dependent
      capabilities

### 3.8 — VM validation & evidence

- [x] Per-stage captures through 2026-09-11 (lab report Parts 1-7):
      staging lifecycle, kernel read/write primitives, token swap,
      DKOM round-trip, capability gate, EID 6 telemetry; registry
      ABR-T013..T016 all lab_validated with paired detections

## Phase 3.9 — Implant hardening & utility (review pass, 2026-09-12)

Full-project review findings executed in priority order; every change
ships with its paired detection or guidance.

- [x] A1+A2 compiled-in operational configuration (ABRAHAM_EMBED,
      build-random XOR, volatile decode — the LTO constant-fold of the
      plaintext was found and killed empirically) + artifact hygiene:
      lab-args/lab-log features, strip+panic-abort+lto, /DEBUG:NONE
      (strip alone leaves the RSDS on MSVC), path remaps, HKDF/domain
      string renames, reconnect backoff, fail-closed server default.
      Static audit: zero project/flag/PDB/builder strings; CI gates it
      (ABR-T023)
- [x] Real registration data: ppid via ProcessBasicInformation, token
      integrity SID, RtlGetVersion build (was: 0/1/"Windows_NT")
- [x] ps detail pass (image path + command line per pid through
      spoofed NT queries), netstat (TCP/UDP owner tables), env module
- [x] EXEC task: in-process shellcode, RW->RX->call->free on the
      session thread, no child/thread/cross-handle (ABR-T022, host
      proof `exec: 6B ret=0x1337`)
- [x] secure_clear of commands/args/payloads/downloads + embedded
      config buffer; residual-surface section added to
      docs/detections/abr-t006.md (session keys remain the blue-side
      win — documented)
- [x] Execute-assembly (ABR-T025): bare CLR hosting in-process, all
      COM entry points through the manual resolver, vtable layouts
      pinned to the mingw-w64/wine headers and a live unit proof that
      compiles its own assembly with the in-box csc.exe; residue
      handling reported honestly (CLR pins the temp file — EID 11 is
      the anchor and the artifact persists)
- [x] AMSI/ETW in-process patching (ABR-T024): AmsiScanBuffer ->
      E_INVALIDARG stub, EtwEventWrite -> xor eax/eax;ret, volatile
      writes with readback, restore of page protections, idempotent
- [x] netstat IPv6 owner tables (TCP6/UDP6 rows, RFC 5952 formatter)
- [x] In-process PowerShell (ABR-T026): bootstrap compiled server-side
      from tools/psboot.cs (exact-signature reflection, manual overload
      selection), AMSI/ETW patched first, CLR reused across tasks
      (Start S_FALSE accepted), captured output returned as the result
- [x] In-process PowerShell (ABR-T026) — final piece of the AMSI
      story: scripts never enter a fresh powershell.exe; see Part 10
- [x] In-memory native PE execution (ABR-T027): user-mode manual
      mapper + RtlCreateUserThread payload thread + ExitProcess-family
      redirect to ExitThread; no_std proof payloads compiled by the
      tests with rustc; CRT/TLS limitation recorded honestly
- [x] Redirector deployment pattern: --plain-c2 server mode +
      deploy/redirector (nginx real-TLS front; kills the rustls-JA3 vs
      Chrome-UA contradiction and the self-signed leaf IOC)
- [x] LAB: live VM pass for T022/T023 — session 3 (Abraham\lab,
      integrity=high real, build 26200) with ekko armed: ps detail
      pass, netstat, env and `exec: 6B ret=0x1337` all green;
      lab-build command line captured as the T023 sigma's positive
      control (docs/lab/2026-09-12-implant-hardening.md,
      lab/captures/t022-t023/)

## Phase 4 — Consolidation

- [x] Frame session tagging: cover-envelope `X-Session`/`X-Handshake`
      headers route every POST to its session, so server-side routing
      survives CDN origin-connection pooling (observed behind Cloudflare:
      foreign requests land on a live session's origin connection; a bad
      frame now costs the request, never the connection — see
      docs/lab/2026-09-12-implant-hardening.md Part 11, protocol.md §5.1)
- [x] Teamserver session persistence (`state/sessions.json`): a redeploy
      restart keeps sessions (ids, tokens, results); beacons RESUME into
      the same session id and drain tasks queued while offline (deploy
      restarts are routine now — `deploy/avln/push.sh` — so history must
      survive them)
- [ ] ATT&CK coverage matrix generated from the registry
- [ ] Lab automation: technique → telemetry → detection validation pipeline
- [ ] Detection pack release (Sigma + Sysmon config + queries)
- [ ] Lab hygiene: rotate VM guest/teamserver credentials

## Phase 5 — Launch

- [ ] Per-technique write-ups
- [ ] First tagged release
- [ ] Talk submissions (BSides, Hacker Conference BR)
