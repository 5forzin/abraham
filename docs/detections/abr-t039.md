# ABR-T039 — Onboarding playbooks: detection notes

Technique: the teamserver queues a rule-matched chain of first-action
tasks the moment a NEW implant session registers, so the first poll
carries survey/collect/persist work without an operator typing any of
it. Server-side automation only — the implant executes ordinary tasks.

## What a defender sees

The playbook has **no host-side artifact of its own**: every step lands
as its constituent technique's telemetry (module executions are
in-process reads, collects are screen/clipboard/keylog access,
relocation is ABR-T040's file/process chain). Detect the steps through
their own docs:

- survey/ps modules → in-process handle and memory telemetry
  (abr-t011), none of it process-spawn based
- `collect screenshot` → user32 calls from a non-interactive context
  (abr-t031)
- `relocate ...` → abr-t040.md, the strongest signal in the chain
- `persist install` → abr-t030.md / abr-t038.md coverage

## The wire shape (network-side)

The one artifact T039 itself adds is behavioral on the C2 channel:

- **First-poll response burst**: a session that registered seconds ago
  receives N task frames in a single response — a response body
  measurably larger than the steady-state 204/body-less idle, and
  larger than a typical single-task exchange. With tasking-on-check-in
  C2s this is normal for ANY operator-driven burst, so alone it is weak
  — the discriminator is the *timing*: burst arrives at the first or
  second poll after the REGISTER, i.e. correlated with session birth,
  at machine speed, seconds after first contact.
- **Result back-flow symmetry**: N task frames out, N results back in a
  tight cadence, then silence/204s — an automation fingerprint (humans
  type commands with irregular gaps; playbooks fire the whole chain and
  wait).

## Hunts

1. Netflow/HTTP analytics: for each newly observed beacon source,
   compare first-3-poll response sizes against the session's steady
   state; a ≥5× spike at birth followed by near-empty polls is playbook
   or pre-staged tasking.
2. Correlate the burst window with the result uploads (chunked frames
   for screenshot/file loot arrive seconds later) — the *content* of
   the burst identifies the playbook's steps.

## Gaps (honest)

- Over a fronting proxy with consistent request sizes (padding,
  cover-traffic profiles), the burst is indistinguishable from an
  operator working fast.
- A playbook of pure in-process modules produces no host telemetry at
  all; the chain is only visible on the wire.

Related: abr-t037.md (rule table and its behavioral notes — T039 rides
the same matcher), abr-t040.md (the relocation step).
