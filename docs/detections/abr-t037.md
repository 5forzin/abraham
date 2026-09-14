# ABR-T037 — Server-driven configuration over the beacon channel

Technique: `server/src/main.rs` (rule table, resolution, delivery),
`implant/src/main.rs` (`apply_config`), protocol kind `0x10` (registry
`ABR-T037`).

The teamserver holds an operator-managed rule table (persisted beside
the session state as `config-rules.json`). Each rule matches an
implant's registration attributes — domain, hostname prefix, username,
and the client's real IPv4 netblock (the `CF-Connecting-IP` /
`X-Forwarded-For` address; the connection peer is the edge) — and
resolves to a configuration update: beacon `sleep_secs`/`jitter`, URI
pool and User-Agent pool. The first matching rule wins. Updates ride
the sealed frame channel inside the REGISTER response (the implant's
very first exchange) and inside the first poll after the operator
changes the resolution; delivery is gated to implants ≥ 0.2.1, whose
decoder knows kind `0x10`. Kill date and activation gates are
deliberately not server-configurable.

## What this buys the operator

Per-context timing without touching each implant: drop the poll
interval to seconds on the one machine being worked (match by hostname
prefix), keep every other host at the slow embed cadence, revert by
editing the rule — the next poll picks it up. Task `SLEEP` remains the
instant, single-session override.

## Detection

The channel is the beacon itself, so the IOC is behavioral, not
signature-shaped:

1. **Beacon cadence shift (primary).** A host whose periodic HTTPS
   POSTs to the same destination suddenly change interval — 10 s → 1 s,
   or back — is the definitive signal. Periodicity analysis over
   NetFlow/Zeek connection logs (per-source destination regularity,
   interval variance before/after) catches it; signature products do
   not. A cadence that changes step-wise more than once is stronger
   still: legitimate update agents drift, they do not switch regimes on
   a schedule an operator controls.
2. **Register/poll response size anomaly.** The sealed frame inside a
   REGISTER response makes that response body materially larger than
   the usual empty ack; a proxy or IDS that profiles response sizes per
   path sees a one-frame spike at register time and at each rule
   change. Steady state is indistinguishable from before (idle 204s
   unchanged).
3. **Rule-table management on the mgmt channel.** The operator's
   `cfg add/remove` is an audited local action (`config_rule_changed`)
   — detectable only with access to the teamserver or its audit trail,
   which is to say: this is the artifact the incident responder wants
   after compromise, not a network signal.

## What does NOT fire (the honest gap)

- No new process, file, registry key or network destination exists —
  the config rides frames the channel already carries.
- Sysmon records nothing: no EID 1/3/7/10 is attributable to a config
  update.
- Steady-state traffic is byte-indistinguishable from the pre-T037
  beacon (identical cadence, identical 204 idle responses) until the
  operator actually changes a rule.
- The shorter the operator sets the interval, the EASIER signal 1
  becomes: responsiveness is purchased with statistical visibility.
  That trade is the point of documenting it here.

## Mitigations worth noting

- Egress netflow periodicity baselining (the counter to signal 1) is
  cheap and catches the whole beacon family, not just this feature.
- Pinning allowed update/telemetry destinations per host makes the
  "legitimate-looking CDN path" less legitimate.
- On the defense side of THIS repo: the bench's ETW column and the
  cadence math from `scorecard-*-baseline.md` give the blue team the
  same measurement instrument.
