# ABR-T027 — In-memory native PE execution: detection guidance

## Technique summary

The `RUNPE` task (`task_type 0x0B`) maps an operator-supplied native
x64 PE (console `.exe` or `.dll`) inside the implant through a
user-mode manual mapper: sections copied to a fresh RW allocation,
DIR64 relocations applied (a moved image with an empty reloc directory
is legal — modern tiny PEs are RIP-relative throughout and the IAT is
resolved at load time), imports resolved against live modules through
the manual export resolver, then the whole image flips RX. The entry
point runs on a dedicated thread created with
`RtlCreateUserThread` and is waited on synchronously by the session
thread (the ekko single-thread invariant holds — no sleep window can
open while the payload runs).

**Host protection**: the import resolver redirects `ExitProcess`,
`TerminateProcess`, `RtlExitUserProcess`, `exit`, `_exit` and `_Exit`
to a 12-byte stub (`movabs rax, <real ExitThread>; jmp rax`) that ends
the payload's thread with the exit code preserved — a console EXE
cannot take the implant down with it. Transport: 48 KB inline in the
task frame; larger PEs travel by `upload` and run from their staged
path, which is deleted the moment the image is mapped (execution is
always from memory).

## Documented limitations (found empirically, kept honest)

- **CRT/TLS payloads crash**: an EXE built with the Rust `std`
  (thread-local storage) faults in its CRT init — without the loader,
  the payload's TLS directory is never materialized into the TEB. The
  proof payloads are `no_std` by design; for CRT/TLS-heavy targets use
  ABR-T022 (`exec`) / ABR-T025 (`execasm`) / T026 (`psrun`), or a
  sacrificial-process flow (out of scope, and loud by definition).
- An entry's plain **return value does not become the thread exit
  code** on NT — well-formed payloads exit explicitly (the proofs call
  `ExitProcess`/`ExitThread` with the magic code).
- The payload sees the REAL PEB: command-line introspection observes
  the implant's arguments, not the payload's. TLS callbacks are not
  invoked. Import-by-ordinal aborts (fail-closed, same rule as the
  kernel mapper).

## Detection anchors

1. **Region anatomy**: a `MEM_PRIVATE` RX region of
   allocation-base == region-base, unbacked by any file, containing a
   full PE with a valid (non-zero) preferred image base — pe-sieve /
   Moneta flag exactly this shape while the payload runs.
2. **The import-resolver footprint**: the manual export walk performs
   `LoadLibraryA` for every module the payload imports — Sysmon EID 7
   image loads appearing in a burst without loader-initiated context
   (no matching EID 1 / no assembly loads) is a strong correlate.
3. **RtlCreateUserThread** usage from user mode is rare in benign
   software; ETW TI-provider thread-create events attribute it.
4. **Frame transport**: inline PEs ride the task frame — the C2
   traffic-shape analytics of ABR-T001 apply unchanged.
5. Nothing here fires on Sysmon EID 8 as a cross-process injection —
   there is none; the thread lives inside the implant.
