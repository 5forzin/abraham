# ABR-T020 — EPROCESS.Protection spoof (protected-process anti-kill)

Offensive: `implant/src/vdm.rs` (`protect on|off`). Copies the SYSTEM
process's `EPROCESS.Protection` byte onto the implant so termination
from every unprotected context (admin taskkill, PowerShell
Stop-Process, most EDR kill-switches) returns ACCESS DENIED while the
process keeps running. The offset is confirmed at runtime against
System and winlogon before any write; the write is a verified
read-modify-write; `protect off` restores the saved byte.

## Signals

1. **Protection changes are never legitimate post-creation.** A
   process whose Protection byte changes after creation (ETW
   process-audit or periodic EPROCESS snapshots) is spoofed by
   definition — Windows never promotes a normal process to protected.
2. **Kill-denial anomalies.** taskkill/Stop-Process returning ACCESS
   DENIED for a process that is not on the protected list
   (`Get-Process ... .ProtectionLevel` cross-check, PPL-aware tools)
   is the behavioral tell: correlate failed-termination audits with
   the process's signaled protection level.
3. **Inconsistent views.** The spoof is data-only: the process token
   still carries its original signer/signature levels. Any view that
   joins EPROCESS.Protection with token SignatureLevel /
   SectionSignatureLevel will disagree for a spoofed process — the
   mismatch is the detection.
4. **Process hide interplay.** When stacked with ABR-T016 (process
   DKOM), the process disappears from listings entirely; monitoring
   should anchor on stable kernel objects (threads, handles, network
   sockets) rather than process enumeration.

## Hardening

- Vulnerable Driver Blocklist ON removes the write primitive entirely
  (see ABR-T018 lab evidence).
- Detect the write primitive's loader (EID 7045/iqvw64e) — every
  technique in this family depends on it.
- Anti-tamper drivers validate EPROCESS fields against the
  object-manager-signed process list periodically.
