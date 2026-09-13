# ABR-T029 — In-process survey modules: detection guidance

Status: `experimental`.

Scope: the arp/route/domain/disks/services module additions and the
user column added to `ps` — host and network inventory gathered
entirely in-process, without `arp.exe`, `route.exe`, `systeminfo` or
SCM shells.

## Technique summary

- `arp` — `GetIpNetTable` (iphlpapi, resolved on demand): TSV of
  interface, address, MAC, entry type.
- `route` — `GetIpForwardTable`: TSV of destination, mask, next hop,
  metric, interface.
- `domain` — `NetGetJoinInformation` + `DsGetDcNameW` +
  `GetComputerNameExW` + logon-server env: join state, DC/forest/site
  names, DNS identity. The AD-reconnaissance basics short of LDAP.
- `disks` — `GetLogicalDriveStringsW` + `GetDiskFreeSpaceExW` +
  `GetVolumeInformationW`.
- `services` — `EnumServicesStatusExW` through the SCM (pattern of
  ABR-T013): name, state, PID, display name.
- `ps` gains a best-effort owner column: process token
  (`NtOpenProcessToken` on the already-open QUERY_LIMITED handle) →
  `LookupAccountSidW`.

All API pointers resolve through the manual export walker; the NT-side
calls ride the indirect-syscall layer.

## What telemetry remains

| Signal | Where | Notes |
|---|---|---|
| SCM enumeration from a user process | ETW `Microsoft-Windows-Security-Auditing` (SCM auditing), service control point telemetry | `OpenSCManagerW(ENUMERATE_SERVICE)` by a non-service process is the strongest host signal here |
| DC discovery | DC security eventlog (directory-service logon attempts from the implant host), `DsGetDcNameW` is a plain LDAP-less locator call | weak on its own; joins a pattern of recon calls |
| NetBIOS/domain locator traffic | wire (port 389/135-less locator is local; DsGetDcName may hit DNS SRV queries) | DNS SRV `_ldap._tcp.dc._msdcs` queries from a non-domain-member context are interesting |
| Process/token queries per PID | kernel ETW callback coverage (EDR), `NtQueryInformationProcess`/token frequency | the per-PID pass is O(processes) token opens — behavioral spike |

## What does NOT fire (validated in design)

- Process creation for `arp.exe`/`route.exe`/`systeminfo`/`sc.exe` —
  none are spawned; the classic "network discovery via CLI tools"
  Sigma families stay silent.
- PowerShell module/script-block logging — no powershell.exe.

## Sigma

Guidance: `arp.exe`, `route.exe`, `systeminfo.exe` detection rules
exist precisely because those tools are loud; this technique's gap is
that nothing equivalent fires in-process. The compensating detection
is the SCM-enumeration signal above and, fleet-wide, the ABSENCE of
discovery binaries alongside evidence of discovery-sized data leaving
the host (beacon result chunks after `module` tasks — cross-reference
the teamserver audit log in an exercise).

## Purple-team usage

Map each module's output to what the equivalent CLI would have
emitted, then diff the telemetry: the exercise report shows exactly
which Sigma families (T1016/T1018/T1007 CLI rules) lose coverage
against in-process collection — the concrete argument for
EDR behavioral sensors over process-tree rules.
