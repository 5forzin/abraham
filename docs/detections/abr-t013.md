# ABR-T013 — Kernel-driver staging lifecycle via the SCM: detection guidance

| Field | Value |
|---|---|
| Registry | `ABR-T013` |
| Component | `implant::driver` |
| MITRE ATT&CK | T1543.003 (Windows Service), T1068 (Exploitation for Privilege Escalation) |
| Sigma | [`detections/sigma/abr-t013_driver_service_imagepath_outside_system32.yml`](../../detections/sigma/abr-t013_driver_service_imagepath_outside_system32.yml) |
| Phase | 3 (BYOVD chain, stage 3.1) |

## What the technique does

The implant copies a driver file to a staging path (in the lab: a copy of
the signed, benign `null.sys`), registers a demand-start **kernel
service** on it through `OpenSCManagerW` → `CreateServiceW`
(`Type = SERVICE_KERNEL_DRIVER`, `Start = SERVICE_DEMAND_START`,
`ImagePath = \??\<drop path>`), starts it with `StartServiceW`, and —
on unload — stops/deregisters the service and deletes the file. All
entry points resolve through the manual export walk (no
`GetProcAddress`), and the file copy uses blocking `std::fs` on the
session thread.

This is the mechanics-only stage of the BYOVD chain: no vulnerable
driver is involved yet. KdMapper-style tooling performs exactly this
sequence right before opening the vulnerable driver's device.

## Telemetry the sequence cannot avoid

1. **Service install — Sysmon EID 7045 / Security 4697.** A kernel-driver
   service whose `ImagePath` lives outside `%SystemRoot%\System32\drivers`
   is the highest-value single signal; legitimate installs stage under
   `System32\drivers` almost exclusively. The Sigma rule keys on this.
2. **Driver load — Sysmon EID 6 (DriverLoad)** for the staged file path,
   with signature details (Signer, is Osiris-signed, etc.) — a driver
   loaded from a user-writable path is anomalous on its own.
3. **Registry — `HKLM\SYSTEM\CurrentControlSet\Services\<name>`** with
   `Type=1` and an absolute `\??\` `ImagePath` (SYSMON DLL + registry
   auditing or any configuration-management delta will see it).
4. **File write of a `.sys` into a user-writable path** (Sysmon EID 11)
   preceding the service creation by milliseconds — the copy step of the
   staging.
5. **Rapid create→delete of the same service name** (probe-then-abort or
   KdMapper-style footprint hygiene: unload + deregister + file delete
   right after mapping). Short-lived driver services are rare in
   legitimate software and make a compact behavioral rule.

## Detection ideas, in priority order

1. **The shipped Sigma rule** (EID 7045, kernel type, ImagePath outside
   System32\drivers) — high signal, near-zero false positives.
2. **EID 6 with `ImageLoaded` outside System32\drivers** — catches the
   load even when the service was created by other means (e.g.
   `NtLoadDriver` directly, which is the stage 3.2 variant and skips
   EID 7045 entirely but still fires EID 6).
3. **Correlation rule:** `EID 11 (.sys written, user-writable path)` →
   `EID 7045 (kernel service, same path)` → `EID 6 (same path)` within
   a short window is the full staging fingerprint regardless of who
   performs it.
4. **Load-block telemetry as an affirmative signal:** on hosts where the
   Vulnerable Driver Blocklist *is* enforced (HVCI on), a blocked load
   surfaces as Microsoft-Windows-CodeIntegrity event **3033** with the
   driver's SHA256 — mapping that hash against the LOLDrivers dataset
   turns a failed attack into high-fidelity detection. In the Abraham
   lab (build 26200, HVCI off) enforcement is not expected — see
   `docs/lab/2026-09-11-byovd-phase3.md` Part 1.
5. **Driver-service enumeration from a user-session process**
   (`OpenSCManagerW` from an unelevated-context binary) is normal for
   admin tooling but anomalous for the process lineage that also wrote
   the `.sys` file — pair with idea 3.

## Lab validation

Validated 2026-09-11 in the VM lab, end-to-end through the C2 (evidence
in `docs/lab/2026-09-11-byovd-phase3.md` Part 2):

- Full load and unload lifecycles against signed stand-ins
  (`null.sys`, `acpitime.sys` copies).
- **EID 7045 fired on every install** with `Service Type: kernel mode
  driver` and an ImagePath outside System32\drivers — the shipped Sigma
  rule's condition, confirmed verbatim in the guest.
- **Sysmon EID 11** bound the staged `.sys` write to the implant
  process image.
- **EID 6 did not appear — lab config artifact**: this VM's Sysmon
  config has image loading disabled (no EID 6 at all in 24 h). Re-test
  with image loading enabled during stage 3.7.
- **No CodeIntegrity events** for a Desktop-loaded signed driver on
  this HVCI-off host: the Vulnerable Driver Blocklist registry value
  alone enforces nothing without Memory Integrity — detections built
  solely on 3033/3077 would have missed this load entirely.

## References

- LOLDrivers project — <https://www.loldrivers.io/>
- Microsoft recommended driver block rules —
  <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>
- KdMapper (reference implementation of the broader chain) —
  <https://github.com/TheCruZ/kdmapper>
