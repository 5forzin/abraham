# ABR-T040 — Self-install relocation: detection notes

Technique: a running implant copies its own image to a durable location
(default operator choice: a `ProgramData` subdirectory), marks the copy
hidden+system, optionally installs a persistence mechanism pointing at
the copy, then respawns from the copy — passing the session token and
the old path through the environment — and exits. The respawned beacon
deletes the staging binary after its first successful link.

## Host telemetry (Sysmon default config)

This chain is LOUD on purpose-of-design — it combines the classic
dropper artifacts, and each stage has a default-Sysmon event:

1. **EID 11 (FileCreate)** — an executable written into `ProgramData`,
   `%APPDATA%` or another user-writable non-temp path, immediately
   followed by:
2. **EID 11/SetFileAttributes equivalent** — the new file flips to
   hidden+system. Sysmon does not log attribute changes directly, but
   the *directory listing asymmetry* (file present in EID 11, absent
   from a non-hidden enumeration) is a hunt.
3. **EID 1 (ProcessCreate)** — parent = the staging binary (wherever it
   was dropped), child = `C:\ProgramData\...\Sysnet.exe`. **Same
   SHA256 hash for parent and child** — the single hardest IOC in the
   chain; self-copy respawn is virtually unique in legitimate software.
4. **EID 13 (RegistryEvent SetValue)** if a `run-key` mechanism was
   armed — value under `...\CurrentVersion\Run` pointing at the
   ProgramData copy (abr-t030.md coverage).
5. **EID 11 again** — the staging binary deleted seconds later, from a
   DIFFERENT process (the resident copy), with the deleter being the
   child of the deleted file's creator. Process-tree + file-lifecycle
   correlation catches this trivially.

Environment hand-off (`ABRAHAM_RESUME`, `ABRAHAM_OLDPATH`) is NOT
logged by default Sysmon configs (no environment capture in EID 1) —
but any EDR that records process environment sees two non-standard
variables on a ProgramData binary, which is close to a signature.

## Hunts

1. **Self-hash spawn**: `ProcessCreate` where `SHA256(parent) ==
   SHA256(Image)` — high-fidelity, near-zero false positives.
2. **Hidden executable in user-writable dirs**: file created in
   `ProgramData\*` with `.exe` extension that does not appear in a
   follow-up visible enumeration of the same directory.
3. **Create-spawn-delete triangle**: EID 11 (create) → EID 1 (spawn
   from it) → EID 11 (delete of the parent image) within one window,
   where the deleting process's parent is the deleted file's creator.
4. Run-key/service/Startup-folder writes pointing at paths outside
   `Program Files` (abr-t030 hunts, applied to the relocated path).

## Measured in the lab (2026-09-15, VM session, Defender real-time on)

The unexcluded first run of the full chain (ProgramData copy, hidden+
system, HKCU run-key, respawn) was caught by Defender behavioral
**11 seconds after the respawn**, with the detection resources naming
all three artifacts at once: the file (`C:\ProgramData\Sysnet\
Sysnet.exe`), the process (`pid`, `ProcessStart`) and the run key
(`HKCU\...\Run\Sysnet`) — followed by automatic remediation of file and
registry value. The binary itself was NOT signature-detected (the same
image ran undetected from the Desktop all along); it was the
**combination** that tripped the ML. Implication for the operator: a
relocate WITH persistence into ProgramData is a race against
behavioral AV measured in seconds, not a silence guarantee — which is
exactly the trade this document describes. The detection doc's hunts
above cover what a Defender-less (or excluded) host still exposes.

## Gaps (honest)

- `respawn: false` relocation (copy + persist only, no spawn) removes
  IOC 3 and 5 — the operator trades continuity for silence. What
  remains: the hidden copy (IOC 2) and whatever persistence was armed.
- A relocation into a path that already blends (`ProgramData` with a
  vendor-like name) survives casual review; the self-hash and hidden
  hunts are the answer, not path reputation.
- The staging-binary delete fails silently if the old process is still
  alive (race) — the stage then survives as evidence, which is a
  detection GAIN; noted for completeness.

Related: abr-t030.md (mechanism coverage), abr-t039.md (playbooks that
trigger relocation automatically), abr-t038.md (WMI persistence that
may be combined with a relocated copy).
