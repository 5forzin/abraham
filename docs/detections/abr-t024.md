# ABR-T024 — In-process AMSI/ETW patching: detection guidance

## Technique summary

Before executing attacker-controlled managed code, the implant
neutralizes the two instrumentation layers present in every Windows 11
process, **for its own process only**:

- `amsi.dll!AmsiScanBuffer` → `mov eax, 0x80070057 ; ret`
  (E_INVALIDARG): every AMSI scan reports an invalid argument and
  succeeds.
- `ntdll!EtwEventWrite` → `xor eax, eax ; ret`: event writes report
  success and vanish.

The patches flip the target page RW through the indirect-syscall layer
(`NtProtectVirtualMemory`), write via volatile stores, read back
byte-exact and restore the original protection. `amsi.dll` is loaded on
demand through the manual export resolver — no IAT entry, no
`LoadLibrary` telemetry in the import table. Both patchers are
idempotent.

## Detection

1. **AMSI diagnostic log.** With `HKLM\SOFTWARE\Microsoft\Windows
   \CurrentVersion\WINEVT\Channels\Microsoft-Windows-Antimalware-Scan
   -Interface/AMSI/Debug` enabled (or the ETW provider
   `2E5D9B47-426F-4175-8F00-0D8A1D81D3F5` traced), a patched process
   stops producing scan events while continuing to spawn/execute
   managed content — absence-of-expected-scan is the analytic.
2. **Page-protection churn on module code.** Kernel-memory ETW
   (Threat-Intelligence provider) sees `VirtualProtect` RW→RX on an
   address inside `amsi.dll`/`ntdll.dll` `.text` — code pages of
   signed modules are never legitimately re-protected by user mode
   outside the loader.
3. **Memory scanning.** Hash the first bytes of `AmsiScanBuffer` and
   `EtwEventWrite` from the on-disk DLLs and compare against live
   process memory (pe-sieve style module-hash checks): a mismatch on
   either export is a direct hit with essentially no false positives —
   the bytes differ only when someone patched them.
4. **EDR callback-equivalent checks.** Endpoint agents that re-scan
   their own hooks/exports periodically catch the regression when the
   patch lands (the write itself is a one-shot, not continuous).

## Notes

- Patching `EtwEventWrite` silences classic ETW providers routed
  through it for this process (including, on this build, Sysmon's
  in-process event submission if the agent hooks there) — but NOT
  kernel-side ETW (e.g. the syscall-level TI provider), which never
  enters user mode. Defense in depth must live below the patch.
- The patch survives for the process lifetime; there is no restore.
