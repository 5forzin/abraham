# ABR-T008 — Detection guidance: dynamic unwind metadata for unbacked code

Status: `experimental` (Phase 2, host-validated on Windows 11 build 26200 on
2026-09-11; attribution captures in
`docs/lab/2026-09-11-stack-memory-observation.md`; VM e2e validated
2026-09-11 — same report, Part 6).

Scope: the Ekko argument trampoline and its wait loop are hand-assembled
routines on a private RX page. Before this technique, any stack walk that
hit those frames failed to resolve a RUNTIME_FUNCTION for their addresses.
That does not abort the walk: per Microsoft's x64 model a frame without
unwind data is treated as a LEAF — the return address is assumed at [rsp]
and rsp advances one slot — so a non-leaf routine's parked locals (for the
trampoline, its RC4/USTRING staging) get replayed as return addresses and
the walk continues onto garbage. That misattribution, not an unwind
failure, is the "unbacked executable memory" tell (leaf semantics pinned
empirically on build 26200 — see the lab report above). The implant now
encodes UNWIND_INFO programs that mirror the routines' real stack effects
(verified semantically with `RtlVirtualUnwind`) and registers them through
`RtlAddFunctionTable`, making walkers traverse the frames exactly like
legitimate JIT-emitted code — the same mechanism CLR, V8 and Delphi
runtimes use. Concept adapted from the Morgana prototype.

## Implementation findings worth knowing (2026-09-11)

1. **UNWIND_INFO for a registered table must live inside the registered
   region.** `RUNTIME_FUNCTION` RVAs — including the `UnwindData` pointer —
   resolve against the `ImageBase` argument of `RtlAddFunctionTable`.
   Metadata written to a separate allocation makes `RtlVirtualUnwind`
   read zeros and silently treat the frame as a leaf function. Abraham
   embeds the blobs at a fixed offset of the code page (like .pdata/.xdata
   inside a PE).
2. **The unwind-code array is stored in REVERSE prolog order** — slot 0
   describes the LAST prolog instruction and the unwinder replays the array
   front-to-back. Confirmed empirically against kernel32's own .xdata
   (build 26200) and by observing `RtlVirtualUnwind` pops. Tools that
   hand-craft unwind data in "natural" order misrestore nonvolatile
   registers.
3. **`RtlAddFunctionTable` copies the 12-byte entries** into ntdll's
   inverted function table; `RtlLookupFunctionEntry` returns pointers into
   that private copy, while UNWIND_INFO bytes are read live from the
   registered region for the table's lifetime.
4. Registration is self-checked: if a lookup for the first routine does not
   resolve to the code page base, initialization fails loudly instead of
   shipping metadata that misdirects walkers.
5. **Legitimate NULL lookups exist — do not key on lookup failure.** On
   build 26200, kernel32's exports (`VirtualProtect`, `Sleep`,
   `LoadLibraryA`, `GetProcAddress`, ...) are `jmp [rip+disp32]` thunks
   into KernelBase (`48 ff 25 ...` / `ff 25 ...`). A thunk never pushes a
   frame, so it legitimately carries no RUNTIME_FUNCTION:
   `RtlLookupFunctionEntry` returns NULL for addresses inside a
   Microsoft-signed module. A detector treating "NULL lookup for a module
   address" as anomalous false-positives on kernel32 wholesale. The
   anomaly is the frame's REGION TYPE (return address inside MEM_PRIVATE
   executable memory), not the lookup result — pinned in
   `image_backed_frame_resolves_bracketing_entry`.

## Detection ideas

1. **Enumerate dynamic function tables and audit their bases.** ntdll tracks
   dynamic tables in an internal inverted function table. Defender tooling
   (EDR sensors, memory-scanning campaigns à la pe-sieve/MonetaBay) can walk
   `LdrpInvertedFunctionTable` and flag any entry whose ImageBase lies in a
   `MEM_PRIVATE` region. Legitimate entries overwhelmingly belong to JIT
   runtimes — corroborate with loaded modules (`clr.dll`, `jscript.dll`,
   V8/Electron, Delphi RTL) and the process image; a dynamic table in a
   process hosting none of those is high-signal.
2. **Instrument the registration API.** `kernel32!RtlAddFunctionTable` is a
   rarely-hooked export; a user-mode hook or Detour on it yields direct
   telemetry (base + count) at registration time. Base outside any mapped
   image → alert.
3. **The walk completing is not the region hiding.** Registration defeats
   "unwind failed / stack-telemetry anomaly" detections — which were
   already the wrong premise, since unbacked frames walk as leaves rather
   than failing — but every frame address still points into the private
   RX page. Two complementary signals: (a) stack-based detections should
   hunt for *frames resolving into unbacked memory* on successfully
   walked stacks — the addresses remain visible in ETW stack events and
   sampled stacks; (b) the PRE-registration signature is a leaf-derail —
   a "return address" read from [rsp] of a non-leaf routine, typically
   landing in stack/heap data or non-executable memory, which surfaces as
   frames the walker cannot attribute to any module at all.
4. **Memory-scan signature.** The metadata and the code it describes share
   one private page: a scan for RUNTIME_FUNCTION triplets whose
   `UnwindData` RVA lands inside the same `MEM_PRIVATE` region as its
   begin/end captures the layout (true for JIT too — see idea 1's module
   correlation for triage).

## What this technique does NOT defeat

Unwind registration makes walks *legible*; it does not relocate any frame.
Return-address spoofing (candidate future ABR-T010, Morgana's stack
spoofing) is the counterpart that moves frames — detection engineering for
stack telemetry should treat the two independently.

## References

- x64 exception handling and unwind codes:
  https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
- `RtlAddFunctionTable` / `RtlLookupFunctionEntry` / `RtlVirtualUnwind`:
  https://learn.microsoft.com/en-us/windows/win32/api/winnt/
- pe-sieve (hasherezade) — scanning for unbacked executable memory:
  https://github.com/hasherezade/pe-sieve
- Silent Moonwalk — stack spoofing research framing the next stage:
  https://github.com/deepinstinct/SilentMoonwalk
