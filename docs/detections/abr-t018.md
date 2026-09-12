# ABR-T018 — KDMapper-style unsigned-driver mapping via iqvw64e

Offensive: `implant/src/mapper.rs` (manual mapper) + the iqvw64e client
in `implant/src/vdm.rs`. With the Intel "Nal" driver (iqvw64e.sys)
loaded, an unsigned driver PE is allocated into NonPagedPool through a
real `ExAllocatePoolWithTag` call, staged (sections, DIR64
relocations, imports resolved against the live kernel export tables)
in implant memory alone, copied in with readback verification, and its
`DriverEntry` invoked through the NtAddAtom trampoline — all restored
before the action returns. No payload service, no payload file, no
signature event for the mapped image: the only system-visible stage is
the iqvw64e loader itself.

## Why detection anchors on the loader

The mapped payload never touches the SCM, the filesystem, or
CodeIntegrity — there is no EID 7045/6 for it. Everything an operator
can observe happens when iqvw64e is staged and loaded, and (on
default-armed Windows 11 24H2+) when the Microsoft Vulnerable Driver
Blocklist rejects it.

## Signals

1. **Service install (Sysmon EID 7045 / SCM)** — service `iqvw64e`
   (or any name) with `ImagePath` outside `System32\drivers`. Covered
   by ABR-T013's generic rule and by
   `detections/sigma/abr-t018_iqvw64e_kdmapper_driver_load.yml`.
2. **Driver load (Sysmon EID 6)** — `ImageLoaded` ends with
   `\iqvw64e.sys` or its SHA256 matches the LOLDrivers entry
   (`4429f32d…` in the lab sample). Renaming the file does not evade
   the hash match.
3. **Blocklist rejection (CodeIntegrity)** — on stock 24H2 the load
   fails `0x800B010C` with CodeIntegrity events (3023/3077/3089
   family); this is the *defensive win* and was lab-reproduced
   (Parts 8–9 of `docs/lab/2026-09-11-byovd-phase3.md`).
4. **Blocklist disabled (configuration telemetry)** — mapping only
   succeeds after `VulnerableDriverBlocklistEnable=0` under
   `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config` (or the Windows
   Security UI toggle). Monitor that value and the corresponding
   registry-audit event; it is the single switch this whole technique
   depends on in the lab.
5. **Behavioral residual** — a transient hook over `nt!NtAddAtom`
   (movabs/jmp stub, 12 bytes) exists only during each kernel call;
   PatchGuard may crash the box on an unlucky sample. There is no
   steady-state artifact inside the payload image (pool-resident, no
   image entry in the loader list) — pool scanners that walk
   `PoolTag 'EtwB'`-style allocations and driver-object-less executable
   pool are the advanced countermeasure.

## Hardening

- Keep the Vulnerable Driver Blocklist ON (it is the empirical
  difference between "load fails 0x800B010C" and "full kernel exec").
- Microsoft driver block list + WDAC policy in enforce mode.
- Alert on `CI\Config` value changes and on EID 7045 installs of
  kernel-driver services in user-writable paths (ABR-T013 rule).
