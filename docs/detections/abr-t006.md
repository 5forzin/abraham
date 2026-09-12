# ABR-T006 — Detection guidance: Ekko-style sleep obfuscation

Status: `experimental` (Phase 2 lab validation 2026-09-11; see `docs/lab/2026-09-10-vm-validation.md` addendum).

Scope: on the implant's current thread, five waitable-timer APC completion
routines change the image's executable section from RX to RW, encrypt it with
RC4 through `SystemFunction032`, wait for the configured sleep interval,
decrypt it, restore RX protection and signal the wake event. The encrypted
window exists only while the thread is in an alertable wait.

## Telemetry sources

| Source | Event / field | Notes |
|---|---|---|
| ETW Threat Intelligence / equivalent EDR memory telemetry | Image-backed protection changes, base address, size and call stack | Primary signal: a loaded PE executable section transitions RX → RW → RX around a dormant interval. Rules that look only for RWX miss this sequence. |
| EDR API and thread telemetry | `SetWaitableTimer`, alertable waits, timer completion routines and APC call stacks | Correlate timer APC dispatch with memory-protection and cryptographic activity on the same thread. Sysmon does not record APC delivery. |
| Memory scanner or process snapshot | In-memory section bytes, page protection and mapped-image metadata | A sample taken during sleep can show an executable image section whose bytes no longer match the backing file and whose entropy has increased. |
| Sysmon | Process, image-load and network events | Provides surrounding process context, but has no native event for page-protection changes, alertable waits or transient in-memory encryption. |

## Detection ideas

1. **Image-section protection cycle**: detect an image-backed executable
   section changing RX → RW and later RW → RX in the same process. Score the
   sequence higher when the base and size are identical and the interval
   matches a recurring sleep cadence.
2. **Transient image-integrity mismatch**: sample the process during a dormant
   interval and compare its executable section with the mapped image on disk.
   A high-entropy mismatch that returns to the original hash after wake is a
   strong sleep-masking signal.
3. **Timer APC plus memory mutation**: correlate several timer completion
   routines dispatched on one alertable thread with a protection change,
   writes across the process's own executable section and an event signal.
   Repeated completion addresses in a small executable thunk strengthen the
   analytic.
4. **Cryptography applied to executable pages**: where API tracing is
   available, flag `SystemFunction032` operating on a buffer that overlaps a
   loaded image's executable section. Dynamic export resolution means the API
   may be absent from the process import table.
5. **Sleep-state contradiction**: alert when a thread appears dormant in an
   alertable wait while its process image is temporarily writable and fails an
   in-memory integrity check. Correlation reduces false positives from normal
   hot patching and JIT compilation.
6. **Dormant-window stack attribution** (pinned 2026-09-11, build 26200 —
   `evasion::sleep::tests::ekko_dormant_window_stack_attribution`): while the
   target bytes are unreadable (RC4 window verified live), suspending the
   sleeping thread and walking its context yields a fully legible chain —
   ntdll wait stub → kernelbase `WaitForSingleObjectEx` → the hand-assembled
   wait loop on a MEM_PRIVATE RX page (legible precisely because of ABR-T008)
   → a dozen frames of the owning image → the canonical thread anchors.
   Encryption hides memory CONTENT, not stack ATTRIBUTION: suspend-and-walk
   analytics that hunt for sleeping threads whose stacks transit a private
   executable region — or whose dormant wait returns into an image that is
   simultaneously failing integrity — have a concrete, reproducible shape.

## Coverage limitations

- The encrypted window is bounded by the sleep interval, so periodic scanners
  can miss short sleeps. Event-based protection telemetry is more reliable.
- The implementation uses RW rather than RWX while encrypting. Analytics that
  require simultaneous write and execute permissions will not match.
- API-name and import-table rules are weak coverage because the implementation
  resolves `SetWaitableTimer`, `VirtualProtect` and `SystemFunction032`
  dynamically.
- Packers, hot patching, profilers and security products can legitimately
  modify image-backed code. Require the full recurring sequence and process
  context before escalating.

## Validation plan (Phase 2 lab run)

1. Run the implant with one executing thread and a long enough sleep interval
   to sample before encryption, during dormancy and after wake.
2. Record the executable-section hash and page protection at all three points;
   verify that the dormant hash differs and that the original hash and RX
   protection return after wake.
3. Capture timer/APC and memory-protection telemetry with stacks, then confirm
   the five completion stages occur on the same alertable thread in order.
4. Validate an analytic for the RX → RW → RX cycle and document whether the
   memory-integrity and `SystemFunction032` correlations are available from the
   selected lab sensor.
5. Store the trace and memory-probe evidence under `lab/captures/` before
   promoting this guidance and ABR-T006 to `experimental`.
