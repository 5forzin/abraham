# ABR-T012 — Detection guidance: phantom DLL stomping for the code home

Status: `experimental` (Phase 2, host-validated on Windows 11 build 26200 on
2026-09-11; lab report `docs/lab/2026-09-11-stack-memory-observation.md`).

Scope: the hand-assembled ekko routines (ABR-T006's thunk and wait loop,
plus their ABR-T008 unwind metadata) used to live on a `MEM_PRIVATE`
executable page — the classic unbacked-memory tripwire that pe-sieve,
MonetaBay and every memory-scanning campaign flag. The implant now maps
a legitimately signed, mundane DLL from System32 (`colorui.dll`, falling
back to `dbgcore.dll`) as an image section through direct syscalls —
`NtOpenFile` → `NtCreateSection(SEC_IMAGE)` → `NtMapViewOfSection` —
without the loader: no PEB module-list entry, no Image Load (Sysmon EID
7) event. It carves the code home out of the DLL's `.text` (flipping the
span RW/COW to write, RX to execute, like the loader applying
relocations). The ekko code then executes from a `MEM_IMAGE` region
whose section name is a real Microsoft DLL path; each consumer carves
its own page from a process-lifetime view.

## Implementation findings (2026-09-11, build 26200)

1. **`NtCreateSection` puts the FILE HANDLE LAST** —
   `(handle*, access, objattrs, MaximumSize*, PageProtection,
   AllocationAttributes, FileHandle)` — the reverse of the Win32
   `CreateFileMapping` wrapper's habit of taking the file first. Getting
   this wrong yields STATUS_SECTION_TOO_BIG-class failures from the
   garbage MaximumSize.
2. **SEC_IMAGE views ignore the mapping protection for their pages.**
   Requesting `PAGE_READWRITE` on the view still delivers `.text` pages
   with the PE's own `PAGE_EXECUTE_READ` — writing faults. The working
   sequence is the loader's own dance: flip the span to RW with
   `NtProtectVirtualMemory` (the pages become copy-on-write,
   `PAGE_WRITECOPY` observed live), write, flip RX. Verified by MBI
   checkpoints: 0x20 → (flip) → 0x8 → (write) → 0x4 → (flip) → 0x20.
3. **The phantom view carries no function tables.** Because the view
   never entered the loader, nothing registered its `.pdata` — the
   ABR-T008 dynamic table registered over the carved page is the only
   unwind authority for the range (no conflicts, unlike stomping a
   LOADED module, whose own .pdata would fight the dynamic table).

## Detection ideas

1. **Phantom-image analytics (the primary signal).** An image-backed
   mapping whose base is absent from the PEB module list is a phantom —
   pe-sieve's phantom-module mode and Volatility VAD-vs-pslist cross-
   checks catch exactly this shape. Same detection family as the ABR-T009
   KnownDlls view; a single hunt covers both.
2. **Image/disk integrity mismatch.** The carved pages diverge from the
   on-disk DLL (and mid-ekko-sleep the whole span is RC4 noise).
   Scanners that hash-mapped images against disk catch the tampering —
   including transients if sampled during dormancy.
3. **The syscall sequence itself.** `NtCreateSection(SEC_IMAGE)` on a
   System32 DLL from an unsigned process that never loads it through
   the loader is a rare kernel-telemetry shape; user-mode hooks or ETW
   on `NtCreateSection`/`NtOpenFile` of known sacrificial DLLs is cheap
   tripwire coverage (same pattern as the ABR-T009 bootstrap-pair
   tripwire).
4. **Copy-on-write bursts inside foreign .text.** The COW flips and
   re-flips (`PAGE_WRITECOPY` observed) on pages of an image the process
   never called are anomalous protection telemetry; EDRs tracking
   protection transitions on image-backed pages see the dance.
5. **Sacrificial-DLL census.** Hunt processes mapping more than one view
   of the same System32 DLL, or views of DLLs with zero loaded-module
   references — the candidate list in any given toolkit is small and
   public (`colorui.dll`, `dbgcore.dll`, ...), making the file path
   itself a workable indicator.

## What this technique does NOT remove

The implant's own image remains in the module list, on disk and
unsigned; the network cadence is untouched; and the phantom-view shape
(item 1) is now a KNOWN pattern this repo itself documented for T009 —
a defender deploying the phantom hunt closes both techniques at once.
It removes the loudest memory-forensics signal (`MEM_PRIVATE`
executable code) and nothing else.

## References

- pe-sieve (phantom modules, image-hash mismatch):
  https://github.com/hasherezade/pe-sieve
- NtCreateSection / SEC_IMAGE:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ztcreatesection
- Copy-on-write protection transitions in image views:
  https://learn.microsoft.com/en-us/windows/win32/memory/protection
