# Abraham

### *A Critique of Pure Kernel Reason*

[![CI](https://github.com/5forzin/abraham/actions/workflows/ci.yml/badge.svg)](https://github.com/5forzin/abraham/actions/workflows/ci.yml)

> I have been asked — not infrequently, and invariably by persons ill-prepared
> to profit from the answer — why one would construct such a system at all. I
> reply that reason has this peculiar fate: it is burdened with questions
> which it cannot dismiss, because they are posed by the very architecture it
> interrogates, but which it also cannot answer until it has interrogated its
> own privilege. This work performs that interrogation. On a machine. In
> kernel space. Where, as I alone have had the patience to demonstrate,
> nobody is watching the watchmen.

---

## Prolegomena to Any Future Kernel Metaphysics

Abraham is a research framework in which the power to subvert a Windows
system and the power to detect that subversion are not two projects, nor
even two faculties of one project, but **one and the same act of
legislation**. Every technique in this repository — all twenty-one, each
validated in a live laboratory and not one merely reasoned about at a desk —
is admitted only together with its counter-sign: a Sigma rule, a guidance,
an exhibit, filed under `detections/` and `registry/techniques.yaml`. The
offensive and the defensive are given as a synthetic unity a priori. Those
who ship one without the other have not yet attained the standpoint of
science, whatever their stars may flatter them into believing.

## The Categorical Imperative of Detection

> *Act only according to that maxim of subversion which you can at the same
> time will to be detectable as a universal law.*

This is not ethics grafted onto engineering; it is the condition of
possibility of the engineering itself. A capability whose detection I could
not will is a capability about which I could know nothing — and I do not
traffic in things I cannot know. Hence each registry entry cites its
evidence (`lab/captures/`), its MITRE form, and the exact event identifiers
by which it shall be judged. The reader will forgive my thoroughness; it is
the only luxury I permit myself.

## The Circle of Understanding

Every capability traverses the same circle — none enters the archive by a
shortcut:

```
   capability is conceived
              |
              v
   technique entry ABR-T0xx   (registry/techniques.yaml)
        |               |
        v               v
 implementation     detection (Sigma / guidance)
        |               |
        +-------+-------+
                v
      judged in the laboratory:
      telemetry captured, rule fired,
      exhibit archived (lab/captures/)
                |
                v
        admitted — or annihilated
```

## Transcendental Analytic: the Faculties

| Faculty | Path | Function in the system of reason |
|---|---|---|
| The Schema | `common/` | The categories (protocol, framing) under which all experience herein is possible |
| The Executive Faculty | `implant/` | Acts in a territory not its own; `mapper.rs` is its most audacious moment |
| The Unity of Apperception | `server/`, `tui/` | The "I think" that must accompany every session |
| The Thing-in-Itself | `payloads/abraham-km/` | Freestanding Rust, zero imports, given its kernel functions by an act of the mapper — a modest proof that the noumenon can be mapped |
| The Tribunal | `detections/`, `tools/` | Where every claim above is cross-examined |
| The Archive of Experience | `docs/`, `lab/` | Thirteen parts of experimental record, failures included — for I conceal nothing so reliably as I conceal nothing |

## The Antinomies of Pure Evasion

Reason falls into antinomy when it extends principles beyond experience. I
have collected the genuine ones and settled them empirically
(`docs/lab/2026-09-11-byovd-phase3.md`, Parts 4–13):

1. **First Antinomy (of Process Concealment).**
   *Thesis:* a process unlinked from the kernel's object lists cannot be
   enumerated. *Antithesis:* on build 26200, `SystemProcessInformation`
   does not enumerate through those lists at all. — Resolution: the
   technique stands against list-walkers; the framework now refuses,
   fail-closed and with full diagnostics, to pretend otherwise. Lesser
   minds would have shipped the bug as a feature.

2. **Second Antinomy (of the Loader).**
   *Thesis:* a revoked certificate must forbid the driver. *Antithesis:* on
   an offline host revocation fails open, and only the blocklist avails. —
   Hence this family of detections anchors on the one irreducible event:
   the installation itself.

3. **Third Antinomy (of Self-Protection).**
   *Thesis:* what usermode grants, usermode may revoke. *Antithesis:* a
   resident payload re-applying its protection on a two-second timer
   survives the revocation — as two of my own deployments learned, to their
   cost, before I deigned to intervene.

## Practical Reason: Building

```console
$ cargo build --release
$ cargo test --workspace
$ python tools/validate_registry.py
$ ./tools/build_payload.sh       # the thing-in-itself; no WDK required
$ python tools/vm_mgmt.py        # operator console, against your own laboratory
```

All checks are expected green. If they are not, the defect is in your
environment, not in the system — though I concede, as a matter of pure
courtesy, that one might verify.

## Kingdom of Ends

MIT-licensed. Use it as an end — the hardening of the very systems it
interrogates — never merely as a means. That is not sentiment; it is the
imperative again, and it is universal.

---

*It remains to be said what this repository is not: it is not a weapon, and
it contains none — no driver binaries but its own thirty-kilobyte
demonstrator, which does nothing but keep time and insist, gently, on being
left alone. The dangerous artifacts are supplied by the operator, within
their own laboratory, under their own law. As, indeed, must we all.*

*— the author, who has merely done for the kernel what the kernel lacked
the candor to do for itself.*
