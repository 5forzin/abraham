# ABR-T041 — Guard-page AMSI/ETW interposition: detection notes

Technique: the 4 KB pages of `ntdll!EtwEventWrite` and
`amsi.dll!AmsiScanBuffer` are re-protected `orig | PAGE_GUARD`; a
hand-assembled VEH on an external page retires execution faults at the
two functions (ETW → STATUS_SUCCESS drop, AMSI → S_OK +
AMSI_RESULT_CLEAN), redirects Rip to an out-of-page `ret`, and re-arms
both guards via raw `NtProtectVirtualMemory` syscalls. Zero bytes of
any signed module change; no debug registers exist to be owned by a
hypervisor (the kill-switch that ended ABR-T036 on VBS fleets).

## The primary IOC: PAGE_GUARD on image pages

Nothing legitimate guards a module's `.text`. The sanctioned uses of
`PAGE_GUARD` are stack-growth pages (`MEM_PRIVATE`, at the stack
region's edge) and application-managed private buffers — never
`MEM_IMAGE` pages inside ntdll or amsi.dll. A `VirtualQuery`/
`NtQueryVirtualMemory` walk reporting `Protect & PAGE_GUARD` on a
`MEM_IMAGE` page is a high-fidelity, near-zero-false-positive signal.

Hunt shipped: `lab/bench/guardscan.ps1` (per-process VirtualQueryEx
walk; guards on image pages only). An EDR telemetry path would be an
ETW/kernel callback on protection changes filtering
`PAGE_GUARD|MEM_IMAGE` — the kernel-side event exists regardless of
user-mode ETW suppression.

## Secondary signals

- **Exception-rate anomaly**: while managed code runs, every ETW emit
  and every page-mate call on the two guarded pages raises exceptions
  (guard + trap-flag chains for page-mates). Per-instruction TF
  stepping of page-mate functions multiplies the exception count —
  visible as context-switch/exception overhead, and on ETW-for-exceptions
  telemetry if such a provider is enabled.
- **VEH registration**: the handler is a vectored exception handler on
  an image-backed external page (stomped-DLL home, ABR-T012) — the
  RtlAddVectoredExceptionHandler call and the phantom module are
  covered by the T012 tripwire docs (unlinked/phantom module hunts).
- **The syscall re-arm itself**: `NtProtectVirtualMemory` on
  ntdll/amsi .text pages, called from an address outside any loaded
  module's export surface (kernel callbacks / ETW kernel providers see
  the protect request origin).

## What stays quiet (honest)

- pe-sieve-class memory scanning sees pristine module bytes — that is
  the point (the baseline's "hooked 3-5 modules" goes to 0 on this
  path).
- The retirement semantics are indistinguishable from the T024 patch
  at the API level (same return values) — only the mechanism differs.
- During a page-mate trap-flag chain (microseconds) the guard is
  dismissed; a target call racing into that window executes for real —
  a coverage gap, not a detection one.

## Measured

**Windows 11 26200 VBS host (2026-09-15)**: both pages armed and
query-verified guard-flagged; `EtwEventWrite(0,0,0)` retired with 0
(the real function rejects the null registration handle);
`AmsiScanBuffer` retired with S_OK and AMSI_RESULT_CLEAN through the
6th argument; disarm restored the real functions. On the host the
guard bit PERSISTS and the guardscan hunt sees it.

**Virtualized lab (VMware, same build)** — the honest split:

- Functional: the arm-time probe retires live (ensure_armed's probe
  is the same direct call); psrun and execasm complete under the
  guard; pe-sieve reports **ntdll and amsi pristine** (the plain
  default path shows both as `hooked` — the byte-patch IOC this
  technique exists to remove).
- Steady-state leak: DotNETRuntime events attributed to the implant
  pid — **0 with the T024 patch vs 95 with the guard** (of ~6000
  provider events). The multithreaded CLR ETW storm keeps hitting
  dismissed-window races (a page-mate fault on another thread
  dismisses the one-shot guard; a concurrent target call in that
  window executes for real), and after the storm the settled page
  state is unguarded (external VirtualQueryEx sees no guard bit).
  The re-arm syscalls themselves return STATUS_SUCCESS (traced in
  the task note as `rearm=0x0/0x0`).
- Net reading: the guard trades a small, measurable telemetry leak
  for a pristine memory image — the inverse of the T024 patch's
  trade. The leak itself is a detection: DotNETRuntime events from a
  process whose image is not a .NET binary.

Bugs the live validation caught (worth recording for the blue side):
the re-arm must be a raw syscall (kernelbase's `VirtualProtect`
emits ETW itself and recursed the handler to stack death — an
attacker using the API here dies loudly), and the AMSI 6th-argument
offset is `[Rsp+0x30]`, not `+0x28` (arg5's home slot) — a bug
ABR-T036 shipped silently because its DR breakpoints never arm on
VBS builds to exercise it.

Related: abr-t036.md (the DR-based variant and its VBS kill-switch),
abr-t024.md (byte patches this replaces), abr-t012.md (the stomped
home the handler lives in).
