# ABR-T019 — Module DKOM (PsLoadedModuleList) + serviceless loader

Offensive: `implant/src/vdm.rs` (`modhide`/`modshow`, RwClient) +
`implant/src/driver.rs` (serviceless load). The driver-stage evasiveness
pair: the SCM load deregisters its service and deletes the staged file
right after the start, and the loader module's
`KLDR_DATA_TABLE_ENTRY` is unlinked from `nt!PsLoadedModuleList`, so
driver enumeration built on that list goes blind while the image stays
mapped and the device keeps answering.

## Signals

1. **EID 7045 is irreducible.** The service install event fires before
   anything is removed (covered by the ABR-T013/T018 Sigma rules —
   name/path/hash matches). Correlate it forward: a 7045 for a kernel
   driver followed by the service NOT existing anymore (`sc query`
   empty, no Services registry key) is itself the serviceless-load
   signature — alert on install-without-persistence.
2. **Cross-view module diff (the modhide killer).** Compare
   `NtQuerySystemInformation(SystemModuleInformation)` against views
   that do not walk PsLoadedModuleList:
   `\Driver` object namespace (`ObReferenceObjectByName`-based
   enumeration, object manager snapshots), open device objects
   (`\\.\Nal` answering IOCTLs while absent from the module list),
   `MmUnloadedDrivers` (stays consistent — the module was never
   legitimately unloaded), and kernel pool scans for the image's
   header in NonPagedPool. A device that answers but a module that
   cannot be enumerated = DKOM until proven otherwise.
3. **Image-load telemetry ordering.** CodeIntegrity EID 3007/3033
   (image load) for `iqvw64e.sys` with a subsequent query gap in
   module enumeration feeds behavioral detection.
4. **Boot hygiene.** Everything here dies at reboot: a driver that
   was live and answering before reboot and is entirely absent after
   (no service, no file, no event) indicates a memory-only driver
   stage — audit for the missing persistence.

## Hardening

- Vulnerable Driver Blocklist ON (the loader never survives that wall —
  see ABR-T018 lab evidence).
- WDAC enforce-mode policies reject the signed-but-vulnerable image
  regardless of SCM state.
- EDR baselines should snapshot the module list at boot and diff
  against device-object inventories continuously.
