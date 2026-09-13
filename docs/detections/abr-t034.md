# ABR-T034 — COFF object loader (BOF convention): detection guidance

Status: `experimental`.

Scope: the EXECBOF task — an operator-supplied x64 COFF object (.obj)
linked in memory and executed in-process: sections laid out by the
loader (COFF objects are unlinked; every header VA is zero),
relocated (ADDR64/ADDR32/ADDR32NB/REL32, unaligned-safe writes),
externals resolved against a minimal Beacon API (BeaconOutput, the
BeaconData* parser family, GetCurrentProcess/Thread) and then the
loaded-module export walker; far REL32 targets get in-image
`movabs rax; jmp rax` trampolines (a private allocation sits terabytes
from ntdll — the raw disp cannot reach). The whole image flips RX via
the indirect-syscall layer and `go(args, argslen)` runs on the session
thread. Arguments follow the CS convention
([u32 total][i32 type][payload]*, packed server-side).

## What telemetry remains

| Signal | Where | Notes |
|---|---|---|
| Unbacked RX private region + later RX→RW transitions | ETW/EDR memory sensors, Sysmon-style allocation telemetry | same shape as ABR-T022 (in-process shellcode) — the module-stomping home (T012) is the mitigating context for the implant's own code, but the BOF image is a fresh private allocation |
| The BOF's own behavior | whatever the object does | the loader is a container; detection coverage for a given BOF is the coverage for that BOF's technique |
| BeaconOutput traffic | task result chunk sizes | operationally visible, not host telemetry |

## What does NOT fire (validated in design)

- No file write: the object travels in the task frame, links and runs
  entirely in memory (contrast tools dropping .obj + loader to disk).
- No child process, no powershell.
- No import-table additions to the implant image: every external is
  resolved through the existing manual export walker.

## Sigma

Loader-shape guidance (EDR sensor, not native log): a private RW
allocation that receives non-image bytes, transitions RX, and executes
an entry by indirect call from a process whose image never loaded a
module containing those bytes. Signature-wise the BOF COFF header
(`machine 0x8664`, optional-header size 0) briefly exists in the
cleartext copy buffer.

## Purple-team usage

Pair each community BOF run with its own technique's detection
expectations (the loader adds none of its own beyond the allocation
shape); cross-reference teamserver audit `task_delivered kind=bof`
timestamps with host telemetry to attribute which sensor saw which
BOF action.
