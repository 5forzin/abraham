# ABR-T017 post-mortem: reproducible 0x1A/0x61941 in the WinIo physical path

Date: 2026-09-12  
Environment: VMware Workstation, Windows 11 build 26200.9445 (25H2)  
Status: **ABR-T017 not validated; live CALL paths disabled**

## Executive summary

Four controlled runs ended in the same bugcheck: three full
`driver call` runs and one `driver call-preflight` run that contained no
physical write, dispatch-table change or kernel trigger. Every recovered
Kernel-Power 41 event reported `0x1A` with parameter 1 `0x61941`. Microsoft
defines that subcode as **paging hierarchy corrupted**.

The fourth run changes the diagnosis materially. The stub write,
`HalDispatchTable` patch and `NtQueryIntervalProfile` trigger are no longer
required to reproduce the failure. The common failing region is earlier:
the WinIo physical map/read/unmap loop used to discover and walk the System
CR3. Part 10's large-page bug was real and its fix should remain, but it was
not the demonstrated root cause of these crashes.

The project now fails closed. If the iqvw64e/Nal branch is unavailable,
`driver call` returns a descriptive error instead of entering the
RTCore64+WinIo fallback. `driver call-preflight` is also blocked before its
first physical IOCTL.

## Evidence

| Run | Path | Last recovered event 41 (UTC) | Result |
|---|---|---:|---|
| 1 | full CALL, task 11 | 2026-09-12 04:59:46 | `0x1A / 0x61941` |
| 2 | hardened full CALL, task 16 | 2026-09-12 05:15:03 | `0x1A / 0x61941` |
| 3 | hardened full CALL, task 21 | 2026-09-12 05:20:21 | `0x1A / 0x61941` |
| 4 | read-only CALL preflight, task 5 | 2026-09-12 05:34:10 | `0x1A / 0x61941` |

All four EFI-carried records had parameters 2-4 equal to zero and
`BugcheckInfoFromEFI=true`. No new WER 1001 record or minidump was created,
so there is no faulting stack or virtual address from parameter 2. The raw
captures are retained under `lab/captures/`:

- `abraham-vm-postexec-2026-09-12.txt`
- `abraham-vm-postexec-second-0x1a-2026-09-12.txt`
- `abraham-vm-postexec-third-0x1a-2026-09-12.txt`
- `cleanup-byovd-2026-09-12.txt` (fourth event plus cleanup receipt)

The exact drivers used were captured before cleanup:

| Driver | Size | SHA-256 | Signature |
|---|---:|---|---|
| RTCore64 | 14,024 | `01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD` | valid, Micro-Star International |
| winio64.sys | 17,080 | `E1980C6592E6D2D92C1A65ACAD8F1071B6A404097BB6FCCE494F3C8AC31385CF` | valid, Exacq Technologies |

The WinIo hash is independently catalogued as a 2014 vulnerable sample by
[LOLDrivers](https://www.loldrivers.io/drivers/94eb0694-29ba-4f8e-b763-86c6371db6cc/).

## What is established

1. Driver staging is not the crash point. Both kernel services reached
   `STARTED`, and the VM remained healthy until the task entered the
   physical-memory path.
2. A physical write is not necessary. Run 4 used only map/read/unmap and
   still produced the same stop code.
3. The dispatch slot, stub execution and restore logic are not necessary
   to explain the observed 0x1A. They remain separate safety problems that
   must be corrected before any future CALL attempt.
4. The failure is deterministic enough to treat as a software/ABI problem,
   not as an unexplained one-off VM failure.
5. The current evidence does **not** distinguish map from unmap or identify
   the exact PFN/VA. EFI preserved the stop tuple but Windows did not write a
   new dump.

## Most likely fault boundary

`discover_cr3` scans candidate KPROCESS fields, treats aligned values as
potential CR3s, and repeatedly calls `WinIo64::read_phys64`. Each read maps
one physical page with IOCTL `0x80102040`, dereferences eight bytes in user
mode, then unmaps with `0x80102044`. The read-only preflight died inside
this region before it could return its first report.

Two explanations currently lead; neither should be promoted to root cause
without a kernel stack:

### 1. Exact-driver ABI mismatch

The client uses the classic five-`u64`/40-byte WinIo request layout, based
on the public
[memflow-winio implementation](https://github.com/a2x/memflow-winio/blob/master/src/lib.rs).
That is evidence for one WinIo lineage, not proof for this exact Exacq
binary. Device name and IOCTL numbers are not a sufficient ABI signature:
multiple WinIo-family builds reuse them while changing buffer validation,
map semantics and unlock requirements. Sending a structurally wrong
METHOD_BUFFERED request can corrupt driver stack or bookkeeping even when
the user-mode operation is conceptually read-only.

### 2. Mapping ordinary/page-table RAM through an I/O mapping interface

The CR3 walk intentionally maps PFNs that back page-table pages. Microsoft
documents that `MmMapIoSpace` is for locked pages or genuine I/O space and
warns against mapping ordinary unlocked RAM because its ownership or
attributes can change ([Microsoft Learn](https://learn.microsoft.com/en-gb/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmapiospace)).
Modern Windows also contains checks around sensitive PFNs; independent
reverse engineering describes the `MiShowBadMapper` guard when page-table
or other protected RAM is mapped through this class of primitive
([research note](https://cschwarz1.github.io/posts/0x05/)). This fits the
location and the paging-related stop code, but is still an inference until
WinDbg captures the faulting stack.

The official bugcheck reference confirms only the observed meaning:
`0x1A/0x61941` is a corrupted paging hierarchy
([Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1a--memory-management)).

## Defects that must be corrected

### P0 -- before any more live physical IOCTLs

1. **Reverse the pinned Exacq driver, not a family name.** Verify the exact
   input/output lengths, field offsets, map mechanism, cache type, unlock
   handshake and unmap contract for SHA-256 `E198...85CF`. Add an ABI test
   fixture derived from that binary's dispatch routine. Do not infer
   compatibility from `\\.\WinIo` or the IOCTL constants.
2. **Capture a real kernel dump/stack.** Configure a kernel debugger or a
   full dump that survives this EFI crash. Split diagnostics so one boot
   performs at most one map or one unmap. Record and flush the stage,
   physical address, request length and returned fields before the next
   operation.
3. **Do not use the live vulnerable driver to validate page-table math.**
   Validate translations against WinDbg, a VM memory snapshot, or
   hypervisor introspection first. Only a driver-specific, known-safe PFN
   should ever reach the live mapper.
4. **Keep both C2 actions fail-closed.** Re-enabling requires the ABI proof
   and a dump-backed explanation for run 4, not merely another guard.

### P1 -- physical client hardening

1. Make each mapping an RAII object whose `Drop` performs exactly one
   checked unmap. Today `unmap_physical` discards the IOCTL result, so map
   accounting failures are invisible.
2. Validate returned byte count, base address, section handle and referenced
   object before dereferencing the mapping; reject partial/unchanged output.
3. Enumerate valid physical memory ranges and reject candidate frames
   outside them. Do not treat every aligned, sub-52-bit KPROCESS value as a
   safe physical address.
4. Require a unique CR3 candidate that matches several independent,
   non-zero VAs across different modules. A zero cave must never serve as
   identity evidence.
5. Keep the page-window guards added in this post-mortem: no physical read
   or write may cross the one frame actually mapped.

### P2 -- before restoring the full CALL proof

1. Replace the two-transfer `RtCore64::write64` dispatch-pointer patch.
   Two 32-bit stores expose a torn 64-bit function pointer. Permit a single
   low-DWORD update only when old and new pointers have the same high DWORD,
   or abandon this dispatch vector.
2. Stop treating discardable INIT tail padding as owned executable memory.
   Prove the section is resident, non-discarded and not shared/reused, or use
   a purpose-built benign research driver with an explicit test buffer.
3. Separate physical-write, slot-patch, trigger and restore into individually
   observable gates. Every mutation needs immediate readback and a recovery
   path that does not depend on the implant surviving.
4. Reassess the research objective: a custom instrumented test driver can
   demonstrate the call/telemetry boundary without relying on an ambiguous
   third-party mapper ABI.

## Cleanup state

At `2026-09-12T05:36:43Z`, both services were stopped and successfully
deleted. The staged and Desktop copies of RTCore64, WinIo64, the implant and
the launch/post-mortem helpers were removed. The System log and host-side
captures were deliberately preserved. The VM was then shut down cleanly.

The lab credentials appeared in the operator transcript and should be
rotated before the next experiment.
