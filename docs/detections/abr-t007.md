# ABR-T007 — Detection guidance: PPID spoofing on child spawns

Status: `experimental` (Phase 2 lab validation 2026-09-11; see the Windows 11
25H2 findings below).

Scope: shell tasks are spawned through `CreateProcessW` with an explicit
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing at the session's
`explorer.exe`, plus a restricted handle-inheritance list, so the child's
reported lineage bypasses naive parent/child allowlists (the ABR-T002 rule
filters `explorer.exe` as an interactive parent).

## Sigma companion

`detections/sigma/abr-t007_cmd_via_explorer.yml` — `cmd.exe` carrying `/C`
with `explorer.exe` recorded as parent. Users launching `.bat` files by
double-click produce the same shape; corroborate with ancestry, token and
signer telemetry as the rule notes say.

## Windows 11 25H2 (build 26200) lab findings — 2026-09-11

Validated with three independent implementations (Rust, C#/PowerShell,
Python/ctypes) on two machines (host and lab VM, both build 26200):

1. **Cross-process parent attributes fail at `CreateProcessW` with
   `ERROR_INVALID_PARAMETER` (GLE 87)** in every context tested: interactive
   session and service context, parent handles opened with
   `PROCESS_CREATE_PROCESS` or `PROCESS_ALL_ACCESS`, SAC enabled or disabled.
   A *self* parent succeeds from an interactive session. The kernel rejects
   the cross-process token-derivation path on this build in our contexts —
   treat PPID spoofing as unreliable on 25H2 until proven otherwise, and
   re-validate on each target build.
2. **The binary-signature mitigation
   (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES`) is
   only settable by callers signed with the signature-policy EKU** (Microsoft
   and select EDR vendors). Ordinary processes get the same GLE 87 — with or
   without a parent attribute. Offensive tooling advertising "block non-MS
   DLLs" on children is overstating what an unsigned implant can request.
3. The implant degrades gracefully: when the spoof is rejected it falls back
   to a plain spawn and prefixes the task result with
   `[abraham] ppid spoof unavailable (...)` so operators and defenders can see
   which path executed.

## Detection ideas beyond the Sigma

1. **Process-creation failure telemetry**: EDRs that log failed
   `NtCreateUserProcess` calls with `STATUS_INVALID_PARAMETER` involving
   attribute lists have a high-signal 25H2 indicator of PPID-spoofing
   *attempts* — the failure itself is the detection.
2. **Parent/token mismatch heuristics**: classic analytics (Elastic
   DET0489-style) still apply on builds where spoofing succeeds.
3. **Result-content tripwires**: blue-team can hunt the fallback prefix in
   exfiltrated task outputs during exercises — an artifact of this exact
   implementation.
