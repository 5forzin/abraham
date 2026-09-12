# ABR-T009 — Detection guidance: pristine syscall numbers from KnownDlls

Status: `experimental` (Phase 2, host-validated on Windows 11 build 26200 on
2026-09-11; VM e2e validated 2026-09-11 — see
`docs/lab/2026-09-11-stack-memory-observation.md` Part 6).

Scope: when a target's local ntdll stubs are hooked so heavily that even
Halo's Gate finds no clean neighbour, the implant opens
`\KnownDlls\ntdll.dll` (NtOpenSection, SECTION_MAP_READ) and maps a
read-only view (NtMapViewOfSection, ViewUnmap) — both through the existing
indirect-syscall dispatcher. Untouched stub bytes (SSN immediates and a
`syscall; ret` gadget) are then read from the view the object manager
already shares system-wide: no disk read, no loader, no GetProcAddress. The
view is mapped once and kept for the process lifetime. Concept adapted from
the Morgana prototype.

## Bootstrap design and its residual risk

The two syscalls that build the pristine view are themselves resolved from
the local (possibly hooked) ntdll — an unavoidable circularity in this
class of technique. The design accepts it explicitly: `NtOpenSection` and
`NtMapViewOfSection` are not on the hot paths EDRs instrument, and once the
view exists every locally resolved SSN, including the bootstrap pair, can
be revalidated against pristine bytes. A defender who hooks exactly those
two stubs denies the bootstrap — cheap and effective tripwire coverage.

## Implementation findings (2026-09-11, build 26200)

1. The mapping succeeds with `STATUS_IMAGE_NOT_AT_BASE` (0x40000003), an
   informational status: the process already maps ntdll at its preferred
   base, so the second view lands elsewhere (kernel-relocated). Consumers
   must use the `NT_SUCCESS` convention (severity bit clear), not equality
   with `STATUS_SUCCESS` — a strict check throws away a working view.
2. On a clean host, SSNs derived from the view match local Hell's Gate
   resolution exactly (verified for NtAllocateVirtualMemory,
   NtProtectVirtualMemory, NtYieldExecution, NtOpenSection,
   NtMapViewOfSection), and the view's stub gadget page is executable —
   image-section views inherit PE page protections, so the fallback
   executes entirely inside ntdll bytes.
3. The fallback gadget's return address lands in the *view*, a second
   image-backed mapping of ntdll — distinct from the process's ntdll
   module range. Module-enumeration-based "return address inside ntdll"
   checks miss it; memory-type checks (image-backed) pass it. Detection
   idea 3 below turns that same fact into a signal.
4. **Region queries surface the backing FILE, never the object name**
   (pinned on build 26200, see
   `evasion::syscalls::tests::knowndlls_view_attribution`):
   `NtQueryVirtualMemory(MemorySectionName)` on the view reports
   `\Device\HarddiskVolume...\Windows\System32\ntdll.dll` — the same
   string as the local ntdll — so no `\KnownDlls\` string exists in the
   target's VAD telemetry. The view's memory-side identity is the
   DUPLICATE: a second MEM_IMAGE allocation of the same file, with
   AllocationBase equal to its own base, absent from the PEB module list.

## Detection ideas

1. **User-mode hooks on the bootstrap pair.** EDR hook engines that
   instrument `NtOpenSection`/`NtMapViewOfSection` see the
   `\KnownDlls\ntdll.dll` OBJECT_ATTRIBUTES directly — an exceptionally
   rare pattern for ordinary software. Object-manager callbacks do NOT
   cover section objects, so user-mode instrumentation is the practical
   telemetry point.
2. **Memory-scan for the staged object path.** The UTF-16
   `\KnownDlls\ntdll.dll` buffer that stages the OBJECT_ATTRIBUTES is a
   transient artifact in private RW memory (YARA memory-scan rule; the
   freed bytes persist until heap reuse); the same string is left behind
   by most unhooking tooling. Caveat per finding 4: this is a
   staging-buffer artifact only — region queries never carry the name, so
   do not build VAD-side detections expecting a `\KnownDlls\` string.
3. **Duplicate image-backed ntdll views.** Memory forensics (Volatility 3
   VAD analysis) and EDR memory campaigns can flag any process whose VAD
   tree contains more than one image-backed view of ntdll.dll — same
   section file name, a second allocation whose AllocationBase is its own
   base, not present in the PEB module list (all three properties pinned
   on build 26200). Legitimate software essentially never maps ntdll a
   second time; this catches the technique regardless of which syscalls
   built the view.
4. **Defensive mirror (the purple pairing).** The identical primitive run
   by defenders — diffing a process's ntdll .text against the KnownDlls
   copy — is a hook-detection/integrity check (used by self-healing EDRs
   and scanners like pe-sieve). One mapping API, both directions; detection
   content should cover both uses.

## References

- KnownDlls and the object manager namespace:
  https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
- NtMapViewOfSection / STATUS_IMAGE_NOT_AT_BASE:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwmapviewofsection
- pe-sieve — .text integrity comparison against on-disk/shared images:
  https://github.com/hasherezade/pe-sieve
