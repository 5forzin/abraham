# Operability + guard-page run (2026-09-14)

Two long research tracks, per the operator's goal: one on evasion
("extreme, hard-fucking-skill" general improvements), one on
operability (a useful first-landing flow: install the implant, walk it
to a resident state). Both validated empirically on the lab VM; repo
rules intact — every offensive technique ships with its coupled
detection doc, registry validated at 41 techniques.

## Track A — operability (T039 + T040)

The "what do I do first when a box beacons" flow, automated:

- **T039 onboarding playbooks** — a config rule (T037) may carry a
  `playbook: [specs]`. On `session_new` — and only there, never on
  resume — the server queues the steps with the first batch. Specs:
  `module survey`, `collect clipboard`, `sleep N`,
  `persist install <mech> <name>`, `relocate <dir> <name> [mech]
  [respawn]`. Version gates per step (relocate needs ≥ 0.2.2): a step
  the implant can't run is skipped with an audit line, not an error.
  Spec syntax is validated at `cfg add` time against a "9.9.9"
  implant, so a typo can't ride silently.
- **T040 relocate self-install** — task `0x10` makes the implant copy
  its own image to `<dir>\<name>` (hidden+system attributes), install
  a persistence mechanism pointing at the copy, and respawn itself
  from the new image with the session token carried in the
  environment (`ABRAHAM_RESUME`/`ABRAHAM_OLD_PATH`,
  `CREATE_NO_WINDOW`, argv forwarded). The new image resumes the SAME
  session (server token map — audited as `session_resume`), and
  deletes the original stage after the first successful link. Net
  effect: drop-on-Desktop → resident in `ProgramData` in one operator
  action, session history intact.

Validated by `lab/opsflow-test.ps1` (ALL GREEN) and then again as
Phase B of the final battery.

**Defender measured the chain**: on the first validation run (no
exclusions) Defender behavioral detection quarantined the resident
file, process and run-key ~11 s after relocate — the binary itself was
not signature-detected; the *combination* tripped it. That is the
coupled-detector evidence recorded in `abr-t040.md`; the lab now runs
with the relocation paths excluded so the rest of the battery can
exercise the mechanics.

## Track B — guard-page interposition (T041)

AMSI/ETW neutralization that leaves every byte of ntdll and amsi.dll
pristine: the pages of `EtwEventWrite`/`AmsiScanBuffer` get
`PAGE_GUARD` OR-ed into their original protection; a VEH handler
(living on the stomped external page) retires the faults — target
functions return success without executing (AMSI_RESULT written via
arg 6), page-mates single-step out of the page, foreign guard faults
pass through. pe-sieve and module hashing see nothing.

The two bugs worth remembering (both found by synthetic-context tests
and live probes, both fixed):

1. **Re-arm must be a raw syscall.** `VirtualProtect` from inside the
   handler recursed: kernelbase!VirtualProtect itself emits ETW, faulted
   on the guarded page, and the nested handler died on a corrupted
   stack. The handler now re-arms via `NtProtectVirtualMemory` with the
   SSN from the direct-syscall resolver — no user-mode callee in the
   path. (Also: `mov r10d, -1` zero-extends; the handle needs
   `mov r10, -1` sign-extended.)
2. **x64 arg 6 lives at `[entry_rsp+0x30]`, not `+0x28]`** — the home
   space shifts the spill by one slot versus the call site. The probe
   wrote through arg 5 (null) and AMSI reported clean while the result
   word stayed -1. The same latent bug existed in T036's HWBP handler
   and was fixed there too (it had never fired: DR7 never arms under
   VBS).

Measured, honestly:

- Host (VBS): arm / probe / disarm all green; the guard bit is
  observable with VirtualQuery and persists (guardscan hunt).
- VM: CLR tasks (psrun, execasm) run green under guard; pe-sieve
  reports ntdll+amsi pristine (the last IOC from the previous
  scorecard, gone). Cost: ~95 DotNETRuntime events per steady-state
  minute still attributable to the pid — dismissed-window races under
  the CLR's multithreaded logging storm (the patch approach is
  hermetic but byte-visible; the guard is pristine but leaks a
  little). Full numbers in `abr-t041.md`.
- The blue-side artifact: guardscan (`VirtualQueryEx` hunting
  PAGE_GUARD on MEM_IMAGE — nothing legitimate guards ntdll .text).

## The final complete battery (`lab/fulltest.ps1`)

Everything the build can do, one session, one pass: server + onboarding
rule → stage with `ekko,guard` → playbook (whoami, clipboard,
relocate) → resident checks (hidden+system, run-key, stage deleted,
single session) → 9 modules → FS cycle → shell → collects → transfers
with SHA-256 end-to-end (asset = remote file = loot) → exec/bof/runpe
→ CLR under guard (notes must say `amsi=guard`, managed probe must
return 42) → T038 wmi persist cycle → sleep → exit → audit sanity.

The battery itself needed fixes the runs exposed — the instrument has
to be trustworthy or the verdict is noise:

- the SHA-256 check hashed a stale Desktop path instead of the
  uploaded remote file and the looted copy (transfers were fine all
  along — verified by hand: asset, remote and loot hashes identical);
- the `ps` module takes ~30 s on the VM under the sensor stack
  (Sysmon + Defender), and tasks execute serially in the beacon loop,
  so the first two modules blew a 17 s result window — the sweep now
  gets 90 s;
- an `Add-Type` wrapper-type mistake made `Wake-Display` throw
  statement-terminating, which fell through try/finally into a
  **false "ALL GREEN" at 24 checks**. The P/Invoke is now a plain
  self-contained type, and the verdict refuses to print green under 30
  checks ("ABORTED EARLY") so a partial run can never masquerade.

The screenshot investigation — the one check that refused to pass —
turned into the run's best finding. The module is GDI
(`GetDC(0)`/BitBlt): it captures the desktop of the CALLER's session.
Everything the lab harness launches rides vmrun guest operations,
which live in session 0 — no interactive desktop, BitBlt fails, on
every run, no matter the monitor power state (the "locked display"
theory died when a live look at the console showed an unlocked
desktop). Proof of the real path: an `/IT` scheduled task launched
the same stage in the interactive console session (the context a T040
run-key resident gets at logon) and the capture produced a real
2.35 MB PNG, magic verified. The battery now checks BOTH lanes:
session-0 must fail cleanly, and when the console belongs to the
guest-ops user, an interactive mini-stage must produce a real PNG.
(Two protocol facts learned on the way: task ids are global across
sessions — never assume task 1 for a new session — and the T037
onboarding rule correctly adopts ANY matching new session, playbook
and all, including a battery's mini-stage.)

Final result: **38/38 ALL GREEN** (run 7, 2026-09-14).

## Deploy

`deploy/contabo/push.sh` shipped the final state to the Contabo
origin: source synced, server rebuilt on the VPS, identity kept
(bundle no-op — server.key present), avln-server restarted. Health:
mgmt responds with the preserved session history (26 stale sessions
from earlier eras), strict-TLS loopback fetch of the staged implant
hash-matches the local build, and the full Caddy chain (CF edge →
origin) serves the identical stage. Exactly one "bad frames: crypto
operation failed" line at the restart instant — an implant mid-frame
during the cutover — zero after. Embed decision: `evasion: ""` stands
(ekko/hwbp/guard stay operator opt-in flags).

## Workspace state

Implant 94 passed / 18 ignored; common 19; server 13; clippy clean;
fmt applied; `tools/validate_registry.py`: 41 techniques. All
uncommitted pending the operator's explicit go (repo rule).

## Follow-ups (non-blocking, recorded)

- Ekko sleep "executable section changed" failures: pre-existing,
  environmental, same count in the committed run of 2026-09-13.
- Download of a nonexistent file loses its error result (old hole).
- Guard dismissal races under CLR logging storms (the ~95-event leak):
  candidate fix is a wider dismissed-window on page-mate TF exits —
  deliberately not chased; the trade is documented and the detector
  (guardscan) catches the mechanism either way.
- `module ps` latency (~30 s) under a full sensor stack is honest
  telemetry cost, not a defect — drivers must budget for it.
- The lab VM console is now logged in as `lab` (was `antho`) — that
  is what makes the interactive screenshot lane of the battery run.
