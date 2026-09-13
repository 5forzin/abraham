# ABR-T006 — Detection guidance: Ekko-style sleep obfuscation

Status: `experimental` (Phase 2 lab validation 2026-09-11; see `docs/lab/2026-09-10-vm-validation.md` addendum).

Scope: on the implant's current thread, waitable-timer APC completion
routines change the image's executable section from RX to RW, encrypt it with
RC4 through `SystemFunction032`, wait for the configured sleep interval,
decrypt it, restore RX protection and signal the wake event. The encrypted
window exists only while the thread is in an alertable wait.

Sleep 2.0 (2026-09-13) extends the same cycle to the LIVE part of the stack
and to registered sensitive heap buffers (embedded configuration text,
session cookie, the AES key schedules of the session object): a prefill APC
derives the upper bound of the stack that is inert during the wait
(everything above the kernel APC dispatcher's frames), an RC4 pair scrambles
that window for the sleep interval, and the heap regions are ciphered
synchronously around the timer arming. A memory view of the dormant thread is
now high-entropy in the image, the caller-stack frames AND the sensitive
heap — a suspend-and-dump during sleep no longer yields session keys.

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
6. **Dormant-window stack attribution** (pinned 2026-09-11, build 26200;
   MITIGATED 2026-09-13 by Sleep 2.0): the original observation was that
   while the image bytes were unreadable, suspending the sleeping thread and
   walking its context yielded a fully legible chain down into the owning
   image — "encryption hides memory CONTENT, not stack ATTRIBUTION". Sleep
   2.0 encrypts the caller frames themselves, so a mid-sleep walk now sees
   ciphertext above the APC dispatcher and terminates in garbage — the
   attribution signal moved from "legible chain into a failing image" to the
   NEW shape below.
6a. **Stack entropy above an alertable wait** (new with Sleep 2.0): sample
   the caller frames of a dormant thread (anything above the kernel APC
   dispatcher depth): plaintext return addresses into loaded modules are
   normal; a large contiguous window of high-entropy bytes in an otherwise
   normal stack — aligned to the top of the committed region — is the
   ciphered-frames signature. The old analytic inverted: hunters should now
   look for walks that BREAK above a private-region wait loop, not ones that
   succeed.
6b. **Sensitive-heap entropy**: the registered buffers (configuration text,
   session objects) read as high-entropy during the sleep window and return
   to structured plaintext after wake; a scanner sampling the same heap
   addresses across the cadence sees entropy pulse in phase with the beacon
   sleep. Narrow regions that keep flipping between structured and
   high-entropy states on a fixed period are the tell.

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

## Residual plaintext surface during the encrypted window (2026-09-12)

Ekko encrypts the executable section only. A memory image taken while
the beacon sleeps still contains, in plaintext:

- the session keys (`Session` holds both AES-256-GCM cipher keys in the
  async task state on the heap) — they are long-lived by design and
  never encrypted;
- `.data`/`.bss`, both real stacks (ekko erases only the dead area
  below RSP before sleeping), and any heap buffers not yet collected —
  task command strings, module output, downloaded data;
- the decoded embedded configuration early in process life, and the
  malleable profile for the whole process lifetime.

Mitigations shipped (2026-09-12 hardening pass): task frames, shell
commands, module arguments, shellcode payloads, download buffers and
upload buffers are zeroed through `secure_clear` (volatile writes) as
soon as the session thread is done with them, and the embedded
configuration buffer is zeroed right after decode. This narrows the
window for task-content recovery to the duration of the task itself.

Defender guidance: a dump taken mid-sleep still yields the session
keys — the reliable blue-side play. Decrypting captured traffic with
recovered keys plus extracting the profile (URIs, UA, timing) works
even against a fully armed implant; scanning for task remnants only
works for tasks in flight at dump time. Conversely, hunting for the
*encrypted* window itself (RX pages whose hash flips on a 5+ second
cadence) remains the primary detection of the technique rather than of
its residue.
