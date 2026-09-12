# ABR-T014 — Kernel read/write primitives via operator-supplied vulnerable driver: detection guidance

| Field | Value |
|---|---|
| Registry | `ABR-T014` |
| Component | `implant::vdm` |
| MITRE ATT&CK | T1068 (Exploitation for Privilege Escalation) |
| Sigma | [`detections/sigma/abr-t014_rtcore64_driver_load.yml`](../../detections/sigma/abr-t014_rtcore64_driver_load.yml) |
| Prereq | ABR-T013 (staging lifecycle) |
| Phase | 3 (BYOVD chain, stage 3.2) |

## What the technique does

After the operator stages a vulnerable signed driver over C2 upload and
loads it through the ABR-T013 SCM lifecycle, the implant opens the
driver's device and speaks its protocol to obtain arbitrary **kernel
virtual** read/write. The shipped client targets RTCore64 (MSI
Afterburner / MSI Center, CVE-2019-16098 family): device `\\.\RTCore64`,
one 48-byte METHOD_BUFFERED struct for both directions, IOCTLs
`0x80002048` (read) / `0x8000204C` (write), widths 1/2/4 bytes. The
`probe` action proves the primitive end-to-end by leaking the ntoskrnl
base (`NtQuerySystemInformation(SystemModuleInformation)` through the
spoofed indirect-syscall layer) and reading its `MZ` header through the
driver. No vulnerable driver binary ever lives in this repository —
that is the standing repo rule.

## Lab validation (2026-09-11, build 26200.9445)

Full chain through the C2 (`docs/lab/2026-09-11-byovd-phase3.md`
Part 3): upload (14024 bytes) → same-path staging load → service
`rtcore-probe` RUNNING → probe returned
`ntoskrnl @ 0xfffff80289800000; kernel read ok: 0x5a4d (MZ verified)` →
unload stopped the driver, deregistered the service and deleted the
file. Signature on the staged binary: **Valid** (MICRO-STAR
INTERNATIONAL). Three defensive findings:

1. **Zero CodeIntegrity telemetry.** The Vulnerable Driver Blocklist
   value was `1`, but with HVCI off (this host) nothing was enforced —
   no 3022/3033/3077 events for a LOLDrivers-listed driver loaded from
   a user Temp directory. Detections that assume the blocklist will
   fire are wrong on every non-HVCI host.
2. **Zero Defender detections.** Stock Defender real-time protection
   did not flag the upload, the drop, the service install or the load
   of the known-vulnerable hash. Signature-less hunting (hash feeds,
   behavioral rules) is what stands between this chain and silence.
3. **The load itself was only visible where Sysmon was configured to
   see it.** The lab's Sysmon originally had the image-load switch off
   (a sensor-configuration gap, not a detection gap); after
   `Sysmon64 -c <config> -l` the EID 6 event carried the exact SHA256
   the shipped rule matches, with `Signature: MICRO-STAR INTERNATIONAL
   CO., LTD., SignatureStatus: Valid` (lab report Part 7). The **EID
   7045 service install** also fired from the start and is caught by
   the ABR-T013 rule — staging remains the reliable default-telemetry
   signal on hosts without load logging.

## Detection ideas, in priority order

1. **Shipped Sigma rule** — EID 6 match by image name OR SHA256 (the
   hash leg survives binary renames; extend to the full LOLDrivers
   hash set in production).
2. **EID 7045 staging rule (ABR-T013)** — fired in the lab for this
   exact run; the most broadly available signal since it needs only the
   System log.
3. **Device-open analytics**: a handle to `\\.\RTCore64` from a process
   that is not MSI-signed vendor software. Requires ETW/ObjectAccess
   auditing — rare in default configs, high fidelity where present.
4. **Rapid load→unload→delete of a kernel service** (this chain's
   footprint hygiene) — behavioral correlation over EID 7045/704x +
   file-delete telemetry inside a short window.
5. **Blocklist enforcement as a defensive uplift recommendation**: the
   countermeasure with real teeth on this build is enabling Memory
   Integrity (HVCI), which turns the inert registry value into
   enforcement — and tampering with CI config to prevent that is
   itself detectable.

## References

- LOLDrivers entry (hashes, samples): loldrivers.io/drivers/e32bc3da…
- Original research: CVE-2019-16098 PoC; idafchev, *Exploring the
  Windows kernel using vulnerable drivers*; grisuno, CVE-2022-22077
  framework (protocol cross-checks).
