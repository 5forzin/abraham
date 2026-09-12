# Lab report — stack & memory attribution (ABR-T008/T009) + ekko long-run

Date: 2026-09-11
Environment: dev host, Windows 11 25H2 (build 26200), non-admin shell.

Everything below was produced by committed, repeatable harnesses — each
capture cites the test that generates it, so the evidence is re-runnable
with `cargo test`. No EDR and no Defender scan were in the loop: nothing
here is a confirmed detection. Conclusions are kept in three strictly
separate classes throughout: **functional correctness** (the primitives
behave as described), **available telemetry** (what a given query
returns), and **detection** (hypotheses keyed on the two former classes —
none confirmed). VM end-to-end re-runs remain pending; the lab VM runs
the same build.

## Why this report exists

The static review of the ABR-T008/T009 increment found three premises in
our own documentation stated stronger than the evidence:

1. "A stack walk aborts on frames without RUNTIME_FUNCTION."
2. Detection ideas implying `RtlLookupFunctionEntry` returning NULL is
   itself an anomaly.
3. A memory-scan idea implying the `\KnownDlls\ntdll.dll` object name is
   what region queries surface.

All three are corrected below — each pinned by an executable test, with
legitimate-software controls.

## Part 1 — what a walker really does with unbacked frames (ABR-T008)

Conclusion class: functional correctness of the walker primitives
(user-mode `RtlLookupFunctionEntry` / `RtlVirtualUnwind` — the same
primitives user-mode EDR stack sampling builds on).

| Case | Capture | Harness |
| --- | --- | --- |
| Unbacked frame, NO table (the pre-T008 condition) | lookup returns NULL; `RtlVirtualUnwind` treats the frame as a LEAF: rip := [rsp], rsp += 8 — the walk CONTINUES onto whatever the routine parked at [rsp] | `evasion::unwind::tests::frame_without_runtime_function_walks_as_leaf` |
| Unbacked frame WITH the dynamic table | lookup resolves base + entry; full context restore (rbx/rsi/rdi/r12, rsp, return address read from the correct slot) | `unwind_program_replays_trampolines_alloc`, `unwind_program_restores_wait_loop_nonvolatiles` |
| Legit control: `ntdll!RtlAllocateHeap` | resolves to a bracketing RUNTIME_FUNCTION with ntdll as ImageBase | `image_backed_frame_resolves_bracketing_entry` |
| Counter-control: kernel32 exports (`VirtualProtect`, `Sleep`, `LoadLibraryA`, `GetProcAddress`, `CreateFileW`, `WriteFile`, `GetModuleHandleW`) | lookup returns NULL LEGITIMATELY — they are `jmp [rip+disp32]` thunks into KernelBase (`48 ff 25 …` / `ff 25 …`); a thunk never pushes a frame, so it carries no RUNTIME_FUNCTION (jmp bytes verified in the harness when the lookup is NULL) | same test |

Corrections to the record:

- **"The walk aborts" was wrong.** The walk does not abort; it applies
  leaf semantics and keeps walking. For the Ekko trampoline — a non-leaf
  — [rsp] at capture time parks the RC4/USTRING staging block, so a
  pre-T008 walk replayed implant-controlled data as a fake call chain.
  Detectors waiting for "unwind failed" telemetry wait for something
  that does not happen.
- **"Lookup NULL = anomaly" would false-positive on Microsoft's own
  kernel32 thunk section** (see counter-control above). The anomaly is
  the frame's region type — a return address inside MEM_PRIVATE
  executable memory — not the lookup result.

## Part 2 — what region queries attribute to the pristine view (ABR-T009)

Conclusion class: available telemetry (what each query returns; no
consumer was watching at capture time).

Harness: `evasion::syscalls::tests::knowndlls_view_attribution` (queries
issued through the implant's own indirect-syscall layer).

| Query | Pristine `\KnownDlls\ntdll.dll` view | Local ntdll (control) |
| --- | --- | --- |
| `MemoryBasicInformation` | State = MEM_COMMIT, Type = MEM_IMAGE, AllocationBase = view base (its own allocation) | image-backed, allocation = module base |
| `MemorySectionName` | `\Device\HarddiskVolume3\Windows\System32\ntdll.dll` — the backing FILE path; the object-manager name `\KnownDlls\ntdll.dll` is NEVER surfaced | identical string (same backing file) |
| PEB module list (`K32EnumProcessModules`) | ABSENT | present |

Corrections to the record:

- **Region telemetry does not carry the `\KnownDlls\` name at all.** The
  earlier "UTF-16 `\KnownDlls\ntdll.dll` memory scan" detection idea is
  downgraded in `docs/detections/abr-t009.md` to a transient
  staging-buffer artifact (the OBJECT_ATTRIBUTES name buffer freed after
  the open — the bytes persist until heap reuse). No VAD-side detection
  should expect that string.
- The durable memory-side identity is the **duplicate**: two image-backed
  allocations reporting the same section file name, the second with its
  own AllocationBase and absent from the PEB module list. All three
  properties are asserted in the harness.

## Part 3 — ekko integrated long-run (host)

Conclusion class: functional correctness + stability on the host. The VM
long-run failure (silent death after ~15–20 cycles, reported in
`2026-09-10-vm-validation.md`) remains an open VM-only follow-up — this
host run exercises the same machinery far past that point but under host
scheduling.

| Run | Result |
| --- | --- |
| `ekko_long_run_private_buffer` debug ×1 | 300/300 cycles, bit-for-bit integrity checked after EVERY cycle, 51.07 s |
| `ekko_long_run_private_buffer` release ×2 | 300/300 each, integrity OK, 51.29 s and 51.28 s |
| `ekko_encrypts_during_sleep_and_restores` release ×2 (serial) | external `ReadProcessMemory` probe observed the encrypted window both times; image restored bit-for-bit (2.26 s each) |

Observations:

- **The ~171 ms/cycle cost of a 10 ms sleep is by design, not a stall.**
  The APC chain stages five timers with 50 ms gaps
  (`STAGE_GAP_MS = 50`; last due = delay + 3 × gap = 160 ms) plus
  waitable-timer quantum slippage. Debug and release are within 0.5 % of
  each other — independent confirmation that the cost is wait-side, not
  compute-side.
- 900 staged cycles across profiles with zero hangs, zero errors, zero
  integrity losses. Every cycle re-arms the waitable timers — the
  suspected VM failure mode — so the re-arm logic itself is exercised
  well past the VM's observed failure point.
- Consumption: no growth observable at this scale (per-cycle integrity
  hashing is deterministic; the arenas are pre-allocated once per
  EkkoSleep instance).

## Part 4 — T010 synthetic-chain captures (call-stack spoofing)

Conclusion class: functional correctness (the spoof works and the walk is
misdirected as designed) + available telemetry (what the walker can and
cannot attribute). No sensor observed it; detection hypotheses keyed on
these captures live in `docs/detections/abr-t010.md`.

Harness: the `evasion::stack` tests. The dispatcher
(`stack::indirect_spoof6`) pivots rsp to a synthetic stack, jumps to the
ntdll `syscall; ret` gadget, and returns through an ntdll `jmp rbx`
gadget; the synthetic frames are placed by walking-math computed from the
anchors' real UNWIND_INFO at runtime.

| Capture | Result | Harness |
| --- | --- | --- |
| Walker replay over the synthetic stack at syscall time (rip = syscall gadget, rsp = synthetic buffer) | every frame attributes to ntdll or kernel32 (Zw stub → ntdll leaf trampoline → `kernel32!BaseThreadInitThunk`); ZERO frames attribute to this image; clean termination on the zero sentinel | `walker_sees_only_system_frames_on_spoofed_stack` |
| Legit control: the SAME walker over a REAL thread of this process (RtlCaptureContext) | inner frames attribute to this image, chain bottoms out at the canonical kernel32/ntll anchors — the exact contrast the spoof removes | `real_thread_control_exposes_own_image_and_canonical_bottom` |
| Spoofed dispatch execution | `NtYieldExecution` via the pivot path returns SUCCESS/NO_YIELD_PERFORMED — the ret→`jmp rbx`→label return lands cleanly | `spoofed_syscall_executes` |
| Ten-argument layout (the KnownDlls bootstrap shape) | a big-frame ntdll anchor (frame adjust 0x50..0x78, first match in export-table order) clears slots 5..10; the walker replay attributes every frame to ntdll/kernel32; the REAL `\KnownDlls\ntdll.dll` mapping now runs end-to-end through the spoofed ten-argument dispatcher (`knowndlls_view_attribution`) | `walker_sees_only_system_frames_on_spoofed10_stack`, `spoofed10_dispatcher_executes` |
| Kernel-read argument slots | template keeps slots 5/6 ([rsp+0x28]/[rsp+0x30]) free of frames; live a5/a6 masquerade as the anchor frame's saved state | `template_keeps_argument_zone_clear` |
| HSP probe | user shadow stack policy = Some(false) on this host → spoof path ACTIVE; full suite (27 tests, ekko included) runs through it | `hsp_probe_definite` + suite |
| Frame arithmetic | `frame_adjust` on the registered scratch table returns (0x28, 23) and (0x48, 9) — matches the T008 semantic tests' stack math | `frame_adjust_matches_registered_programs` |

Build-26200 findings (details in `docs/detections/abr-t010.md`):

- **Mitigation policy indices matter**: `ProcessUserShadowStackPolicy`
  is 15; index 18 is `ProcessSEHOPolicy`, which reads ENABLED by default
  on this host. The first probe implementation keyed on SEHO and would
  have silently disabled the technique on every 25H2 box.
- **Every `jmp rbx` candidate in ntdll lives in a tiny leaf** (frame
  adjust 0) — an initial design requiring a large qualifying frame found
  zero gadgets. Leaf trampolines are the norm, and they are sufficient:
  only slots 5/6 are kernel-read.
- **`RtlUserThreadStart`'s unwind program is unparsable on this build**
  (opcodes outside the provable set), so the chain anchors on
  `BaseThreadInitThunk` (adjust 40) alone and terminates early — turned
  into detection idea 1 (early-terminating chains).

## Part 5 — Dormant-window attribution (async execution)

Conclusion class: available telemetry — what an observer can attribute
while the thread is inside the ekko cycle. Harness:
`evasion::sleep::tests::ekko_dormant_window_stack_attribution` — an
observer thread suspends the sleeper mid-cycle, confirms the target
buffer is in its RC4-encrypted window (hash diverges from plaintext),
captures the context with `GetThreadContext`, and replays the same
walker primitives a sensor uses.

Capture (build 26200, one representative run):

- rip inside ntdll's wait stub (blocked in the alertable wait).
- Walk: **ntdll** (wait stub) → **kernelbase** (`WaitForSingleObjectEx`
  implementation) → **the T008-registered private RX code page** (the
  hand-assembled wait loop frame) → **11 frames of the owning image**
  (the Rust sleep machinery) → **kernel32** (`BaseThreadInitThunk`) →
  **ntdll** (`RtlUserThreadStart`) — canonical bottom.

The finding, both sides of it:

- For defenders: encryption hides memory CONTENT, not stack ATTRIBUTION.
  A suspend-and-walk over dormant threads sees a private executable
  region mid-chain and the owning image behind it — a concrete shape
  (detection idea 6 in `docs/detections/abr-t006.md`).
- For the offense: the dormancy window is exactly where ABR-T010 does
  NOT help — the pivot exists only for the duration of a dispatched
  syscall. The sleeper's parked stack is genuine, and T008 makes its
  unbacked frame legible (by design — the alternative was a leaf-derail).
  Closing that gap is future work in the T010 lineage (spoofed wait /
  ROP-thread parking), not a property of the current implementation.

## Part 6 — VM end-to-end re-run (2026-09-11)

The lab VM (Windows 11 Pro, build 26200, VM "ABRAHAM", user `Abraham\lab`)
was driven through two independent channels: the current release test
binary was uploaded to `C:\Users\Public\ab_vm_tests.exe` through the
C2 itself (session 7/8, baseline implant; batches ran via shell tasks
with output redirected to files pulled back through the download
channel, `loot/session-*`), and the long-run re-check ran synchronously
through `vmrun` (VMware Tools) after the C2-channel launch attempt
failed in a way that mimicked the failure under test (see below).

| Batch | Result |
| --- | --- |
| Full `evasion::` suite, serial (T008/T009/T010 + ekko + controls) | **30/30 passed in 2.90 s** — identical outcome to the host run, including the HSP probe (`Some(false)`, host parity), the KnownDlls bootstrap mapping through the spoofed ten-argument dispatcher, and the dormant-window capture (same shape: ntdll wait → kernelbase → private code page → owning-image frames → canonical anchors) |
| Full-image ekko (`ekko_encrypts_during_sleep_and_restores`, external probe) | **passed in 2.27 s** — the `ReadProcessMemory` probe observed the encrypted window inside the VM and the image was restored bit-for-bit |
| 300-cycle long-run (`ekko_long_run_private_buffer`) | **passed: 300/300 cycles in 49.40 s** (host: ~51 s) — run synchronously through `vmrun`/VMware Tools after the C2-channel launch attempt failed (below) |

### The VM "silent death" no longer reproduces — and a retracted false positive

The long-run was first launched through the C2 channel with
`start "" /b cmd /c run_longrun.cmd`. The result looked exactly like the
2026-09-10 silent-death report: the implant session's `last_seen` froze
for 45 minutes, no task ever completed, the queued tasks behind never
ran. That conclusion was WRONG, and the correction is recorded here
because the mistake is instructive:

- Post-mortem via `vmrun` (VMware Tools channel, independent of the C2):
  `vm_longrun.txt` **did not exist** — the `.cmd` never executed at all.
  Two orphaned `cmd.exe` processes from the launch chain (verified in
  the Services session, same as the implant) held the shell task's
  stdout pipe open, and the implant's single-threaded task loop blocked
  reading it. Killing the orphans by PID revived the session instantly
  (`last_seen` resumed).
- The same batch then ran directly via `vmrun`: **300/300 cycles green
  in 49.40 s**, no hang.
- Conclusion: the wedge was an artifact of the launch method (pipe
  inheritance through `start /b`), not of the ekko machinery.

With 300 cycles now passing in the VM on the current binary, the
2026-09-10 silent death (~15–20 cycles, waitable-timer re-arm as the
then-prime suspect) **no longer reproduces**. The most likely actual
root cause, by timeline: that observation predates the arena-tail
staging fix — the regression that moved the ekko argument staging back
to stack locals, which optimized builds clobber mid-wait (restored
2026-09-11 and pinned since by
`ekko_cycle_roundtrip_on_private_buffer`). The timer re-arm hypothesis
is downgraded; keep the historical report as-is, without its follow-up
weight.

Lab procedure lessons (both now recorded):

1. Detached runs launched through the implant's shell MUST NOT inherit
   the implant's stdout pipe (schedule via `schtasks` or an intermediate
   that closes the handle). A blocked pipe freezes the whole session —
   single-threaded task loop.
2. Single-channel evidence is not ground truth. A false "repro" was
  minutes away from being recorded as fact: it survived six minutes of
  one-channel polling and only fell apart when the independent `vmrun`
  path falsified it. Cross-channel verification before writing a
  failure conclusion is now lab procedure.

## Part 7 — ABR-T011 module e2e and the tokio × ekko race (2026-09-11)

The first live run of the module-capable implant in the VM (deployed via
`vmrun`, registered as a fresh session) validated two things at once.

**Module e2e (evasion off):** `ps`, `whoami`, `ls`, `cat` tasks queued
through the restarted teamserver executed in-process on the VM implant in
a single poll batch, zero child processes — `ps` returned the full real
process table through the spoofed `NtQuerySystemInformation` dispatch,
`ls` listed the target directory, `cat` returned file contents.

**A real crash, found and fixed.** The first ekko-armed deployment died
with STATUS_ACCESS_VIOLATION (0xC0000005, guest exit code -1073741819)
within roughly a dozen sleep cycles — the same footprint as the
2026-09-10 "silent death". Root cause this time was identifiable because
the crash was early and loud: shell/download tasks used
`tokio::process`/`tokio::fs`, which hop to the runtime's BACKGROUND
thread pool — violating the single-thread invariant ekko depends on (the
session thread encrypts the whole image while pool threads may still be
executing implant code). The fix executes shell and file tasks with
blocking `std::process`/`std::fs` on the session thread itself — which
already blocks inside `evasion.sleep()`, so nothing changes
operationally. The fixed build then survived ~3 minutes (~35 cycles)
of ekko sleep WITH shell and module tasks firing every cycle,
`last_seen` advancing throughout.

Lab notes: the teamserver was restarted on the new protocol build with
its persisted identity and TLS certificate — same pin, so the baseline
implant reconnected transparently. And the crash is a lab finding in its
own right for the defense side: **AV crashes of long-lived beacons
mid-cadence are themselves a detection signal** (Defender's crash
reporting, WER telemetry).

## Part 8 — ABR-T012 phantom stomping (2026-09-11)

The ekko code home moved from `MEM_PRIVATE` into a phantom-mapped signed
DLL's `.text` (host + VM validated):

- Host: 41/41 release serial including the full-image ekko and the
  300-cycle long-run, all executing from the carved page.
- VM (Defender realtime present): 32/32 suite green including both
  stomping tests (MEM_IMAGE type, `colorui.dll` section name, absent
  from the module list), plus full-image ekko (2.28 s) and the long-run
  (300 cycles, 49.62 s) from the stomped home.
- Build-26200 findings recorded in `docs/detections/abr-t012.md`:
  `NtCreateSection` takes the file handle LAST (NT order, unlike the
  Win32 wrapper); SEC_IMAGE views deliver `.text` pages with the PE's RX
  protection regardless of a `PAGE_READWRITE` mapping request — the
  loader's own COW dance (flip RW → write → flip RX) is required, with
  the transitions observed live (0x20 → 0x8 → 0x4 → 0x20); and because
  the phantom view never entered the loader, no `.pdata` of its own is
  registered — the ABR-T008 dynamic table is the sole unwind authority
  for the carved range, no conflicts.

## Part 9 — ABR-T013 dormant parking: work in progress (2026-09-11)

The dormant-window stack parking (Part 5's offense-side gap) is designed
and half-integrated, currently DISABLED pending a mystery worth
recording:

- **Design**: a second wait-loop variant whose prolog matches the plain
  loop exactly (same ABR-T008 metadata), pivoting rsp to a pre-staged
  copy of the ABR-T010 anchor chain before every alertable wait — the
  continuation lives in rbx, the return rides the T010 `jmp rbx`
  trampoline, so a suspended dormant thread replays a system-only chain
  with zero implant frames. HSP-gated via `stack::chain()` like T010.
- **Verified working**: the chain staging, the setup-time movabs
  immediate patch (byte-wise — immediates are unaligned), the full byte
  layout on the stomped page (dumped at runtime and checked
  instruction-by-instruction), and register-only pivots.
- **The blocker**: executing the blob with the stack pointer moved to
  the parked chain kills the process with exit code 0xC0000005 — but
  **the fault never reaches a vectored exception handler** (the handler
  is proven working via calibration), and no instruction between pivot
  and restore touches the stack. This is a fast-kill, not a dispatched
  exception, with the bytes on the page verified correct.
- **Next steps** (next session): reproduce in a minimal standalone
  binary outside the cargo-test harness; attach cdb/WinDbg if available;
  audit for a `NtTerminateProcess` caller via process ETW. The variant
  ships disabled (`spoofed_park = false`) — the plain loop remains the
  default and the full suite is green.

## Part 10 — what remains open

- The ekko long-run now passes in the VM (300 cycles, 49.4 s); the
  2026-09-10 silent death no longer reproduces and its timer re-arm
  suspect is downgraded in favor of the since-fixed arena-tail staging
  regression (Part 6). If a long-session death ever reappears, re-run
  the long-run batch via `vmrun` FIRST — single-channel evidence is not
  ground truth.
- T010 does not cover the dormant window itself — the sleeper's parked
  stack is genuine (Part 5); a spoofed wait / ROP-thread parking is the
  natural continuation of that lineage.
- The synthetic chain's plausibility is structural, not semantic —
  detection idea 6 in `abr-t010.md` (correlating the claimed chain with
  the operation's origin) is untested against a real analytic.
- No sensor (EDR/Defender) observed any capture above; every detection
  idea in `docs/detections/abr-t008.md`..`abr-t010.md` remains a
  hypothesis keyed on the corrected premises until a validation pass
  with a real consumer (Sysmon/ETW capture or EDR lab) says otherwise.
