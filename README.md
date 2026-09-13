# Abraham

**A command-and-control framework that refuses to ship an offensive technique without its detection.**

[![CI](https://github.com/5forzin/abraham/actions/workflows/ci.yml/badge.svg)](https://github.com/5forzin/abraham/actions/workflows/ci.yml)

## What this is

Abraham is a purple-team C2 research framework for Windows. Implant,
teamserver, TUI, a kernel demonstrator, an operator web view — and, riding
along with every single offensive technique, the artifact that catches it:
a Sigma rule or a detection-guidance document, validated against live
telemetry on an instrumented lab VM before the technique is allowed into
the registry. Thirty-six techniques are in there right now, from indirect
syscalls with stack spoofing to LSASS dumps taken from kernel address
space. The registry validator enforces the pairing in CI, so a technique
without a detection doesn't get merged, doesn't get built, doesn't get to
pretend.

That's the whole idea. Everything else is implementation.

## The house rule

No detection, no merge. Not "detection later", not "detection in the next
sprint". Same commit, same author, same blame line. It has a surprisingly
calming effect on how you design things — when you know the rule for
catching your trick has to sit next to the trick, you start writing
different tricks.

The loop every capability goes through, no shortcuts:

```
   idea
    |
    v
 registry entry (ABR-T0xx)  -->  detection artifact (Sigma / guidance)
    |                                      |
    v                                      v
 implementation                        written honestly
 (what it does NOT trigger, included)
    |                                      |
    +----------------+--------------------+
                     v
           judged in the lab:
     telemetry captured, rule fired,
       evidence archived under lab/
                     |
                     v
           merged -- or thrown out
```

The "what it does NOT trigger" part matters as much as the rest. A
detection doc that only lists wins is marketing.

## The map

| Path | What lives there |
|---|---|
| `common/` | The protocol, framing and crypto both sides agree on. Boring on purpose. |
| `implant/` | The part that lives in someone else's process. Syscalls resolved by walking exports, sleep obfuscation that encrypts the live stack too, a hand-assembled VEH handler, a COFF loader. `mapper.rs` is the deep end. |
| `server/`, `tui/` | Teamserver and operator console. Sessions, task queue, audit trail, mgmt auth. |
| `web/` | Three.js operator view — read-only session telemetry, no tasking route. Loopback only; the management token never leaves the gateway process. |
| `payloads/abraham-km/` | Freestanding Rust, zero imports, no std — kernel functions are handed to it at runtime by the mapper. About 30KB and does nothing but keep time. |
| `detections/`, `tools/` | Where every claim gets cross-examined. Sigma rules, the registry validator, the evasion bench. |
| `docs/`, `lab/` | The lab journals. Failures included — especially the failures. |

## Field notes

Things the lab taught us the hard way, kept here so nobody has to relearn
them:

1. **DKOM process hiding has a build number.** On 26200,
   `SystemProcessInformation` doesn't walk the lists everyone's
   hide-technique unlinks from. The unlink still defeats classic
   list-walkers, but "invisible" it is not. The framework fails closed and
   says so instead of shipping the demo-friendly version of the truth.
   (`docs/lab/2026-09-11-byovd-phase3.md`)

2. **A revoked certificate is a vibe, not a wall.** On an offline host,
   revocation checks fail open. The vulnerable-driver blocklist is the
   last line, which is why the detections in this family anchor on the one
   event that can't be lied about: the driver install itself.

3. **What usermode grants, usermode revokes.** A protected process that
   gets its shield stripped stays stripped — unless something resident
   reapplies it every two seconds. Two lab deployments died proving the
   first half of that sentence before the timer came along.

4. **VBS quietly kills hardware-breakpoint hooking.** On Windows 11 with a
   hypervisor owning the debug registers, `SetThreadContext` writes to
   DR0 report success and then vanish. Four write vectors, two
   environments, same result (`docs/detections/abr-t036.md`). The technique
   stays in the tree, opt-in, with the kill-switch documented.

## The bench

`lab/bench/` runs the implant through a fixed workload under six sensors —
Sysmon, ETW, Defender, a per-thread debug-register probe, pe-sieve and
Velociraptor — and commits the scorecards. Baseline first, then after
every evasion change. It looks like overkill until the day it catches a
regression that every unit test, every isolated test and both build
profiles missed: the day the CLR refused to start on any thread that had
touched debug registers, and only the full implant on the real VM knew.
That day is written up in the journal like it deserves.

If you take one piece of this repo to copy, take the bench. Measure
before, measure after, commit both numbers.

## Building it

```console
$ cargo build --release
$ cargo test --workspace
$ python tools/validate_registry.py
$ ./tools/build_payload.sh       # the kernel demonstrator; no WDK required
$ python tools/vm_mgmt.py        # operator console, against your own lab
```

All of it green, every commit. The lab journals under `docs/lab/` walk
through the full validation passes, captures included.

## License, and what this is not

MIT.

It is not a weapon, and it contains none. The only driver binary in this
tree is the ~30KB demonstrator above, whose entire personality is keeping
time and insisting on being left alone. No vulnerable drivers live here,
no exploits, no stolen anything. The dangerous artifacts some techniques
reference are supplied by the operator, inside their own laboratory,
under their own rules — which is also the only place this framework is
meant to run.

---

*Everything here was tested on machines I own, against sensors I
configured, and written down even when it made the author look careless.
That's the whole trick.*
