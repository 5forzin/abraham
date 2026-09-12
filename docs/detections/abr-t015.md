# ABR-T015 — EPROCESS token swap via kernel write primitive: detection guidance

| Field | Value |
|---|---|
| Registry | `ABR-T015` |
| Component | `implant::vdm` (`elevate`) |
| MITRE ATT&CK | T1134.002 (Access Token Manipulation: Create Process with Token)? — closest mapping is token theft/impersonation via kernel write; also T1068 |
| Prereq | ABR-T014 (kernel R/W primitive live) |
| Sigma | none possible on default telemetry — guidance only (see below) |
| Phase | 3 (BYOVD chain, stage 3.3 v1) |

## What the technique does

With the ABR-T014 kernel read/write primitive live, the implant
resolves `PsInitialSystemProcess` by walking ntoskrnl's in-memory
export table through the driver, walks `ActiveProcessLinks` to its own
EPROCESS (validating `System` PID == 4 and its own PID on the way),
then swaps its EPROCESS token slot for the System token
(EX_FAST_REF-preserving copy), proves SYSTEM in-process, and restores
the original token. Offsets pinned for build 26200 (25H2):
Token=0x248, Links=0x1D8, PID=0x1D0.

## Why there is no Sigma rule

Token-slot manipulation in EPROCESS produces **no native event**: no
handle operation, no process creation, no registry/file telemetry. The
process keeps its original image, parent and command line while its
access checks silently run as SYSTEM. This is precisely why BYOVD
token theft is a favorite — and why detection has to be indirect.

## Detection ideas, in priority order

1. **Detect the prerequisite, not the swap.** The whole chain is
   visible in ABR-T013/T014 telemetry (EID 7045 staging, EID 6 hash
   match). A host where a known-vulnerable driver loaded should be
   treated as compromised regardless of what followed — the swap
   itself will never page anyone.
2. **Token enumeration sweeps.** Periodic `NtQueryInformationProcess`
   sweeps comparing each process's token owner against expectation
   (e.g., tools like SATI): an unprivileged image running with a
   SYSTEM-owned primary token is the anomaly. EDRs with kernel
   callbacks can do this on token-modification windows; stock Windows
   cannot.
3. **Audit-by-canary**: canary SAM/SYSTEM-only resources with
   full auditing — an open from a non-SYSTEM-image process with a
   SYSTEM token shows as (Image != SYSTEM context, Access granted)
   in Object Access events 4656/4663 with a mismatched Subject.
   Requires SACL tuning, high fidelity once set.
4. **Behavioral aftermath**: SYSTEM-tokened user-session processes
   touching LSASS-adjacent hives or creating services in quick
   succession after a driver-load event — the correlation rule
   "driver load (T014) → privileged anomaly within T+5m" is the
   realistic detection.

## Lab status

Validated 2026-09-11 after three bugchecks taught the stage its
methodology (lab report Part 5): the token swap wrote, read back
correctly, and the session survived the full swap/proof/restore cycle.
Offsets are discovered at runtime (links +0x418 on this UBR — public
tables said 0x1D8 and were wrong; token +0x248, confirmed by the
SYSTEM AuthenticationId signature). Defensive-era note from the same
work: 24H2+ pool tag obfuscation breaks tag-based token signatures.

## References

- HackTricks, *Arbitrary kernel R/W → token theft*
- Vergilius Project `_EPROCESS` layouts
- I3r1h0n/eprocess_offsets (build-offset table)
