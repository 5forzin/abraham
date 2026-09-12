# ABR-T004 — Detection guidance: jittered task polling (beaconing)

Status: `experimental` (validated in the purple lab on 2026-09-10, see
`docs/lab/2026-09-10-vm-validation.md`).

Scope: the implant polls the teamserver with a configurable sleep interval
plus random jitter (see malleable profile in `docs/protocol.md`). Jitter
defeats naive "identical delta" detection, so the analytics below model it
explicitly.

## Telemetry sources

- Proxy / firewall logs with per-flow timestamps (primary).
- Zeek `conn.log` (connection-level periodicity).
- Sysmon EID 3 for host-based correlation (same source process contacting the
  same destination repeatedly).

## Detection ideas

1. **Interval regularity with tolerance**: over a sliding window of N
   connections from one (source, destination) pair, compute the coefficient of
   variation of inter-arrival deltas. Jittered beacons stay within a tight
   band (e.g. CV < 0.5) while human browsing does not.
2. **Low-and-slow filters**: flag pairs with connection counts inside a band
   (e.g. 20–500/day) — above scanning behavior, below interactive use.
3. **Hypothesis-test beaconing**: the wavelet/variance approach described in
   "Finding Beacons in the Dark" (2018) models noisy periodicity directly and
   handles jitter.
4. **Empty-body check-ins**: TASK_POLL requests with near-constant small
   request size and 2xx responses of varying length.

## Validation plan (Phase 1 lab run)

- Run the implant with sleep 30s / jitter 25% and with sleep 300s / jitter 40%.
- Export Zeek `conn.log`; compute CV of deltas for both profiles.
- Document the detection threshold that separates both profiles from a
  baseline browsing capture, store evidence in `lab/captures/`, and promote
  the analytic (as pseudo-Sigma network rules or a Velociraptor artifact) to
  `experimental`.
