# ABR-T017 — Kernel function calls via call-capable driver (iqvw64e client): detection guidance

| Field | Value |
|---|---|
| Registry | `ABR-T017` |
| Component | `implant::vdm` (`Iqvw64e`, `WinIo64`, `driver call`, `driver call-preflight`) |
| MITRE ATT&CK | T1068 (Exploitation for Privilege Escalation), T1055-ish kernel manipulation |
| Sigma | [`detections/sigma/abr-t017_revoked_driver_load_attempt.yml`](../../detections/sigma/abr-t017_revoked_driver_load_attempt.yml) |
| Phase | 3 (BYOVD chain, the code-exec-capable branch) |

## What the technique does

The iqvw64e client (the KdMapper engine, protocol ported from the
reference implementation) gives the implant everything RTCore64
cannot: arbitrary kernel/user virtual memcpy, VA→PA translation,
MmMapIoSpace-based writes that bypass page protections (RX pages
included), and a true **kernel CALL primitive** — a
`movabs rax, target; jmp rax` stub over `nt!NtAddAtom` entered via the
usermode `NtAddAtom` syscall, with the original bytes restored. The
`driver call` action proves it live: `ExAllocatePoolWithTag` → RW
round-trip on the returned pool → `ExFreePool`.

## The 2026 reality (lab-proven on build 26200)

The driver is on Microsoft's **revoked-driver list**: every load
attempt returns 0x800B010C and emits CodeIntegrity **3023 + 3077 +
3089**, and the revocation is enforced independently of HVCI, of
test-signing, and of OS-side tampering with the trust lists (they
regenerate on reboot; the policy is also EFI-backed). Three unblock
avenues were tried and all failed cleanly (lab report Part 8). On
current builds the KdMapper lineage is dead as a load vector; the
client remains for hosts where the list is absent.

## Detection ideas, in priority order

1. **Shipped Sigma rule — EID 3023 (revoked driver load attempt).**
   Zero-false-positive by construction: only revoked drivers produce
   it, on every host, HVCI or not. The single highest-value CI signal
   in this phase's lab work.
2. **Cluster rule 3023 → tamper follow-on**: a 3023 followed within
   minutes by hosts-file edits blocking CRL/OCSP endpoints, renames in
   `System32\CodeIntegrity\`, or `bcdedit /set testsigning` is the
   attacker escalating against the block — each follow-on is itself a
   rule (file integrity on the CodeIntegrity directory, Sysmon EID 11
   + registry EID 13).
3. **Nal device telemetry**: a handle to `\\.\Nal` from any
   non-Intel-signed process (ObjectAccess auditing where present).
4. **The paired asymmetric insight**: still-signed vulnerable drivers
   (RTCore64 class) produce ZERO CodeIntegrity events on non-HVCI
   hosts — detections must not assume CI telemetry exists. Correlate
   EID 6 (load) with hash feeds on every host, and treat 3023 as the
   bonus signal that revoked-driver attackers hand you for free.

## Lab validation

Not validated. The iqvw64e branch is blocked by revocation (Part 8).
The RTCore64+WinIo fallback did execute far enough to crash the guest:
three full runs and one read-only preflight reproduced MEMORY_MANAGEMENT
0x1A/0x61941. Because the preflight contained no write or trigger, the
fault boundary is now WinIo physical map/read/unmap or CR3 discovery
(Parts 10-12 and the dedicated post-mortem). Both dual-driver actions
fail closed. ABR-T017 deliberately has no `lab_validated` field until
the cause is dump-backed and a full restore round-trip survives.
