# ABR-T031 — Collection: screenshot, clipboard, keylogging: detection guidance

Status: `experimental`.

Scope: the COLLECT task — virtual-screen capture (PNG via WIC, BMP
fallback), clipboard text and keystroke capture, in-process on the
session thread.

## Technique summary

- **screenshot**: GetSystemMetrics(virtual screen) → GetDC/
  CreateCompatibleDC/BitBlt/GetDIBits into a top-down BGRA buffer;
  PNG through WIC resolved as raw COM vtables on demand
  (factory/stream/encoder/frame), automatic BMP fallback on any WIC
  failure. The image rides the standard chunked-result path.
- **clipboard**: OpenClipboard/GetClipboardData(CF_UNICODETEXT) at
  request time — a point-in-time read, no monitor.
- **keylog**: GetAsyncKeyState sampled for all 256 VKs at EVERY beacon
  wake-up, buffered (32 KB cap) and returned+cleared by the `keylog`
  action. Deliberately NO dedicated thread: ekko sleep obfuscation
  encrypts the implant image while the session thread sleeps, and a
  second thread executing implant code inside that window would fault.
  Coverage therefore equals the beacon cadence — the documented
  limitation; the follow-up is a dynamically-allocated
  syscalls-only polling stub outside the image.

## What telemetry remains

| Signal | Where | Notes |
|---|---|---|
| Screen/GDI access by a non-interactive process | soft — GDI capture from a service session fails outright; from a user session nothing logs BitBlt | the classic T1113 gap: no native event says "something read the screen" |
| Clipboard open | no native audit on OpenClipboard | T1115 is behaviorally detected (clipboard utilities), not natively logged |
| GetAsyncKeyState polling | no native event | keyloggers are caught by AV/EDR heuristics on hooking or driver use — GetAsyncKeyState sampling is the stealth variant by design |
| Result exfiltration | beacon result chunks (audit log `task_result` on the teamserver side) | the network side sees only the enlarged POST |

## What does NOT fire (validated in design)

- No SetWindowsHookEx — no hook DLL, no injected callback, none of the
  classic keylogger IOC families.
- No child processes — nothing for process-tree rules.
- PNG encoding happens in-process via WIC; no file written to disk
  (contrast with tools that save a temp screenshot file — EID 11).

## Sigma

No native-log rule is possible for the capture itself; compensating
guidance: EDR sensors that hook BitBlt/GetDIBits and GetAsyncKeyState
from non-UI processes, and DLP-style screen-read detection. For the
exercise report, pair the teamserver audit `task_delivered
(kind=collect)` timestamps with host telemetry absence to document the
coverage gap precisely.

## Purple-team usage

Take a screenshot mid-exercise, exfiltrate, and show which (if any)
sensor flagged it — then the same for clipboard and a keylog dump
while typing canary text into notepad. The report documents the real
T1113/T1115/T1056.001 coverage posture of the lab stack.

Measured in the lab (2026-09-14, `lab/fulltest.ps1` lane C4):

- An implant dropped through guest-automation (session 0, no
  interactive desktop) fails the capture cleanly with
  `BitBlt/GetDIBits failed` — the module reports the environment,
  nothing crashes, no partial leak.
- The same binary launched in the interactive console session (an
  `/IT` scheduled task, i.e. the context a T040 run-key resident gets
  at logon) captures and exfiltrates a real PNG (2.35 MB for the
  1920×1080 lab desktop, PNG magic verified in loot).
- Detection takeaway for the blue side: the interesting event is a
  NON-UI process in a USER session touching GDI screen capture — a
  service-session process simply cannot, which is itself a useful
  triage signal (which context a suspicious process lives in).
