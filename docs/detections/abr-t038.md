# ABR-T038 — WMI event-subscription persistence: detection guidance

Persistence without autoruns artifacts: an hourly `Win32_LocalTime`
`__EventFilter`, a `CommandLineEventConsumer` (executable = the implant
copy in `%APPDATA%`) and the binding live in the WMI repository
(`root\subscription`). Created through the implant's **in-process**
PowerShell runspace (ABR-T026, AMSI/ETW patched) — no `wmic.exe`, no
`powershell.exe`, no service install, no registry write at creation.

## Install-time IOCs

| Signal | Where | Reliability |
| --- | --- | --- |
| Sysmon EID 19 (`WmiFilterEvent`), 20 (`WmiConsumerEvent`), 21 (`WmiBindingEvent`) | Sysmon, **only if the config includes the WMI event section** | high when configured; **most deployed configs omit it** |
| `WmiPrvSE.exe` connecting to the repository from the implant host | Microsoft-Windows-WMI-Activity/Operational (5857/5858 range) | low: noisy log, rarely shipped to SIEMs |
| Nothing in `Run` keys, Startup folder, services | — | the gap: registry diffing and Autoruns' default view see **nothing** |

The honest headline: against a stock Sysmon configuration install-time
is invisible. This is the exact gap the technique buys; hunting is the
only reliable counter at rest.

## At-rest hunting (the real defense)

Periodic sweep of the subscription namespace — any result that is not
a known-legitimate subscription (rare outside DCs/SCCM) is a hit:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Select Name, Query
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Select Name, ExecutablePath, CommandLineTemplate
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

Autoruns shows the same under its WMI tab (hidden by default). The
objects carry the operator-chosen name (`<name>-flt`, `<name>-cmd`) —
do not rely on the name; rely on the classes' population.

## Fire-time IOCs (hourly, and at each fire)

- **Process creation with parent `WmiPrvSE.exe`** (Sysmon EID 1) — the
  strongest generic IOC; any process-tree-aware EDR trips on an
  unsigned binary spawned by WmiPrvSE outside a legit admin context.
- The spawned binary is the implant copy in `%APPDATA%` — file hash
  correlation closes the loop with the staged sample.
- One beacon connection shortly after each hour boundary — cadence
  artifact for netflow periodicity analysis.

## Gaps documented

- Default Sysmon configs without the WMI section: no install-time event.
- The WMI-Activity operational log is high-volume and low-signal.
- Once the implant is running, its C2 blend (ABR-T001/T035) applies —
  this technique's residual risk concentrates entirely at fire-time
  parent-child anomaly and at-rest hunts.

## Operator trade-off

Run-key (ABR-T030) survives reboots loudly; WMI survives hourly with a
max one-hour gap after login/boot, silently at rest, loudly at each
fire (parent `WmiPrvSE.exe`). Combined use is a detection exercise for
both IOCs; solo use trades autoruns visibility for parent-process
visibility.
