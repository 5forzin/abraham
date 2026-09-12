# ABR-T005 — Detection guidance: indirect native API system calls

Status: `experimental` (Phase 2 lab validation 2026-09-11; see `docs/lab/2026-09-10-vm-validation.md` addendum).

Scope: the implant resolves system service numbers from the loaded `ntdll.dll`
at runtime (including adjacent-stub recovery when an export is hooked) and
calls a `syscall; ret` gadget inside `ntdll.dll`. The kernel therefore sees a
system call originating in `ntdll`, while the normal exported `Nt*` entry point
and any user-mode hook on it are bypassed.

## Telemetry sources

| Source | Event / field | Notes |
|---|---|---|
| EDR kernel sensor | System call plus full user-mode call stack | Primary source. Preserve frames below the `ntdll` gadget; checking only the instruction pointer at the kernel transition is insufficient for an indirect syscall. |
| ETW Threat Intelligence / equivalent EDR memory telemetry | Virtual-memory allocation and protection events, source process, target process and stack | Detects the operations performed through the syscall layer rather than the dispatch mechanism itself. Access to the protected Threat Intelligence provider normally requires an authorized security product. |
| Sysmon | EID 1 (Process Create), EID 10 (Process Access) and behavior-specific events | Useful for downstream effects. Sysmon does not identify whether an NT operation reached the kernel through an exported stub, a direct syscall or an indirect gadget. |
| Memory and module inspection | Address-to-module mapping for call targets and stack frames | Establish whether execution entered the middle of an `ntdll` syscall stub and whether the preceding frame belongs to an unexpected image. |

## Detection ideas

1. **Unwind beyond the kernel-transition address**: flag system calls whose
   transition instruction is inside `ntdll` but whose call path enters the
   middle of a syscall stub without traversing the corresponding exported
   `Nt*` entry point. Require a full stack or branch trace; the top address
   alone looks legitimate by design.
2. **Correlate sensitive NT operations**: alert on uncommon processes issuing
   sequences such as allocate writable memory followed by an executable
   protection change, cross-process memory access or thread creation. Treat
   this as behavioral coverage, because the same sequence can use ordinary
   APIs and legitimate JIT runtimes can produce similar events.
3. **Compare call-site provenance with a baseline**: for high-value processes,
   baseline the modules and exported stubs that normally initiate sensitive
   system calls. A caller in an unsigned or newly loaded image that repeatedly
   targets interior `syscall; ret` addresses is higher signal than one event.
4. **Use branch tracing for focused hunts**: hardware-assisted branch traces
   can expose the transfer from implant code directly into the interior of an
   `ntdll` stub. This is expensive telemetry and is better suited to a lab or
   short investigation window than continuous fleet-wide collection.

## Coverage limitations

- Static import inspection is not coverage for ABR-T005 because the syscall
  numbers and gadget addresses are resolved at runtime.
- Integrity checks of `ntdll` can remain clean: this implementation reads its
  stubs and reuses an existing gadget; it does not need to patch the module.
- A rule that only checks whether the kernel transition originated inside
  `ntdll` will miss this implementation. Detection needs deeper call-path
  context or a behavioral analytic for the syscall's effect.

## Validation plan (Phase 2 lab run)

1. Execute the same allocate/protect operation once through the normal
   exported API and once through ABR-T005.
2. Capture kernel/EDR stack telemetry and record the transition address, the
   resolved `ntdll` export range and the preceding image frame for both runs.
3. Confirm that the indirect run reaches an interior `syscall; ret` gadget and
   bypasses the exported `Nt*` entry while the normal control does not.
4. Exercise one downstream behavior visible to Sysmon and document that its
   event describes the effect but cannot distinguish the dispatch path.
5. Store the trace and address mapping under `lab/captures/` before promoting
   this guidance and ABR-T005 to `experimental`.
