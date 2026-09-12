# ABR-T010 — Detection guidance: call-stack/return-address spoofing

Status: `experimental` (Phase 2, host-validated on Windows 11 build 26200 on
2026-09-11; walker-replay captures in
`docs/lab/2026-09-11-stack-memory-observation.md` Parts 4 and 6; VM e2e
validated 2026-09-11).

Scope: a plain indirect dispatch leaks frame 1 of every telemetry stack
walk — the `syscall; ret` gadget's unwinder pops [rsp], the return address
into the implant's dispatcher. The implant now pivots rsp to a synthetic
stack for the duration of each dispatched syscall (currently
`NtAllocateVirtualMemory`/`NtProtectVirtualMemory` via `dispatch6` and
the `\KnownDlls\ntdll.dll` bootstrap pair — `NtOpenSection`/
`NtMapViewOfSection`/`NtClose` — via `dispatch6`/`dispatch10`, with
graceful fallback to the plain indirect dispatchers): the value at [rsp]
at syscall time is a real ntdll address (a `jmp rbx` gadget used as the
execution return), and the frames below it are return addresses into
`kernel32!BaseThreadInitThunk` (and, where the build's unwind data
allows, `ntdll!RtlUserThreadStart`) placed at exactly the offsets a
walker computes from those functions' REAL unwind programs. Frame sizes
are derived at runtime by parsing each anchor's UNWIND_INFO — the chain
is built from the running system's own metadata, not hardcoded offsets.
Concept adapted from the Morgana prototype (HSP-aware design); the frame
math, gadget selection and measurement harness are Abraham-specific.

## Implementation findings (2026-09-11, build 26200)

1. **Synthetic frames only need to dodge the kernel-read argument
   slots.** The kernel reads stack-passed syscall arguments at
   [rsp+0x28]/[rsp+0x30] (slots 5/6) at syscall time; every other slot is
   invisible to it. A `jmp rbx` gadget inside a tiny leaf (frame adjust 0)
   puts the first synthetic frame in the shadow space — and the walker
   never reads "saved register" slots for their value, only does rsp
   arithmetic, so the live argument bytes masquerade as a frame's locals.
   The chain-build constraint reduces to: no return-address slot may land
   in {5, 6}.
2. **`jmp rbx` trampolines exist but live in small thunks.** All
   candidates on build 26200 have frame adjust 0 — an initial design
   requiring a large qualifying frame found nothing. Leaf trampolines are
   not just acceptable; they are the norm.
3. **`RtlUserThreadStart`'s unwind program is not always parsable.** On
   build 26200 it uses opcodes outside the provable set (frame pointers /
   saved-register classes), so the chain anchors on
   `kernel32!BaseThreadInitThunk` (adjust 40) and treats
   `RtlUserThreadStart` as best-effort. Consequence documented below as a
   detection idea: the synthetic chain TERMINATES EARLY where real
   threads bottom out at the ntdll anchor.
4. **Ten-argument layouts need a big-frame anchor.** With a7..a10
   occupying slots 7..10, a leaf trampoline plus `BaseThreadInitThunk`
   would place the next return address exactly at slot 7 — inside the
   kernel-read zone. The builder scans ntdll's export table in ordinal
   order at runtime and takes the FIRST function whose frame adjust falls
   in [0x50, 0x78]: its return address lands at slots 12..15, clearing
   the whole argument zone while still fitting the thread-thunk anchor
   and sentinel. Deterministic per build; the qualifying function is an
   ordinary ntdll internal, semantically arbitrary — exactly the
   structural-not-semantic plausibility limitation of idea 6.
5. **The HSP probe must use policy index 15** —
   `ProcessUserShadowStackPolicy`. Index 18 is `ProcessSEHOPolicy`, which
   reads as enabled by default on this 25H2 host; the first probe
   implementation keyed on SEHO and silently disabled the technique. Both
   values are now recorded by the harness; on this host the shadow stack
   policy is Some(false), so the spoof path is active.
6. The measurement harness walks the synthetic stack with the same
   primitives a sensor uses (`RtlLookupFunctionEntry` +
   `RtlVirtualUnwind`): every frame attributes to ntdll or kernel32, none
   to the implant image, while the control walk of a real thread of the
   same process shows its own image in inner frames — the exact contrast
   the spoof removes (lab report Part 5).

## Detection ideas

1. **Early-terminating chains.** Real user threads bottom out at
   `ntdll!RtlUserThreadStart` (then `BaseThreadInitThunk` in reverse). A
   syscall-time chain that ends at `BaseThreadInitThunk` with a zero/void
   beyond it — or terminates anywhere non-canonical — is synthetic or
   corrupted. ETW stack events and sampled stacks can be validated
   against the canonical bottom shape.
2. **Constant-chain signature.** The synthetic layout is computed once
   per process: every spoofed call presents the BYTE-IDENTICAL stack
   bytes (same return addresses, same slot offsets). Real call chains
   vary per call site. Aggregating stack hashes per (process, syscall)
   yields a cluster of size one for spoofed dispatches.
3. **Return-address-into-gadget correlation.** Frame 1 is a real ntdll
   address chosen because its bytes are `FF E3` (`jmp rbx`) — a byte
   pattern that is essentially never a legitimate call target. Sensors
   that capture return addresses can byte-check the first few frames for
   register-indirect jump opcodes (`FF /4`) at the exact target offset.
4. **Argument/frame slot aliasing.** The live a5/a6 argument values sit
   inside a frame the walker replays as saved state. Telemetry that
   captures both the stack bytes AND the syscall arguments (ETW can)
   can flag events where an argument value appears at a slot the
   attributed frame treats as saved nonvolatile/local — impossible in a
   genuine call chain.
5. **Shadow stacks as structural mitigation.** Enforcing the user-mode
   shadow stack (CET) policy — via mitigation policy, IFEO or
   image-level `/CETCOMPAT` — breaks ret-based returns off the synthetic
   stack outright. The implant probes the policy and degrades to the
   plain dispatcher (visible as the ABR-T005 behavior); defenders should
   treat "spoofing stopped" telemetry as the win, and instrument the
   policy query itself (`GetProcessMitigationPolicy`) from rare
   processes as a weak leading indicator.
6. **Cross-check with the operation's origin.** The stack claims the
   syscall came from the thread thunk; the operation (e.g., an RX
   allocation of the same size the implant uses) has no corresponding
   source frame anywhere in the process. Correlating stack claims with
   the target of the syscall is the Elastic-style attribution analysis
   this technique is designed to evade — and precisely the analytic that
   catches chains which are legible but semantically impossible.

## What this technique does NOT defeat

The pivot exists only for the duration of the dispatched syscall; every
Rust-side frame above it is genuine and the implant image remains in the
module list. Full-stack telemetry (walking beyond the syscall window),
memory scanning, and the ABR-T008/T009 region indicators are unaffected.
It composes with, and requires, the earlier work: the synthetic frames
resolve only because real unwind metadata exists for the anchors.

## References

- Silent Moonwalk (Deep Instinct) — the stack-spoofing research lineage:
  https://github.com/deepinstinct/SilentMoonwalk
- Elastic Security Labs — stack-based detection research framing idea 6:
  https://www.elastic.co/security-labs
- x64 unwind codes and RUNTIME_FUNCTION:
  https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
- `GetProcessMitigationPolicy` / user-mode shadow stacks:
  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy
