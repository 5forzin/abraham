# ABR-T035 — Malleable transport hardening: detection guidance

Status: `experimental`.

Scope: the 0.2.0 transport changes — session token moved from the
`X-Session` header to a profile-named session cookie, idle TASK_POLLs
answered with body-less `HTTP 204`, compiled-in kill date, environment
gates (activation delay + blocked-process dormancy) and multi-front
failover. Together these remove several long-standing "this is a C2"
wire signatures. This page documents what that removal costs the
defender and what the residual signals are.

## Technique summary

- **Cookie demux**: `Cookie: sid=<decimal u64>` replaces `X-Session`
  (header still accepted for pre-0.2.0 builds). Same routing, same
  crypto — the token only selects keys.
- **204 idle polls**: an empty poll is answered `204 No Content` with
  no body — no sealed BATCH_END blob. The steady "small binary POST
  answered by small binary 200" signature disappears; idle beacons now
  look like a client whose API answers "nothing new".
- **Kill date**: `kill_date` (unix seconds) in the embedded config;
  past it the process exits silently at the next loop check.
- **Environment gates**: random pre-contact activation delay
  (`initial_delay_max_secs`) and dormancy while any
  `blocked_processes` entry runs (name-only
  `NtQuerySystemInformation` polls, no per-process queries).
- **Front failover**: after 3 consecutive transport failures the
  implant rotates to the next entry in `servers` (session token
  preserved; the teamserver resumes the session).

## What telemetry remains

| Signal | Where | Notes |
|---|---|---|
| Numeric-only cookie value on POST flows | SSL-inspection proxy / CDN logs | real session ids are not bare decimal u64s; value is constant per implant process (see ABR-T001 idea 7) |
| POST → 204 cadence | proxy/CDN access logs, Zeek http.log | near-100% 204 ratio at a fixed-ish interval on one URI set is a beacon pattern; legit polling APIs rarely idle-monotone like this |
| Rotation to the backup front | proxy/Zeek, SNI change | after 3 failures the same process starts contacting the next domain with the SAME cookie value — correlation across fronts |
| Pre-contact delay | host timelines | process start → first outbound TLS no longer immediate; the gap defeats the trivial "start = beacon" correlation but is itself a soft signal when measured fleet-wide |
| Dormancy polling | ETW/Sysmon | a dormant implant re-queries the process list every backoff window without spawning children or opening sockets |

## What does NOT fire (validated in design)

- Content inspection of idle polls: no body, no constant-size binary
  blob (the sealed BATCH_END is gone).
- Custom-header rules (X-Session): the header is no longer sent by
  0.2.0+ builds.
- "Immediate beacon on process start" rules: the activation delay
  breaks the correlation by design.

## Sigma

Access-log shaped (proxy/CDN), guidance only:

```yaml
title: High-ratio 204 answers to a numeric cookie POST flow
logsource:
    category: proxy
detection:
    selection:
        http.method: POST
        sc-status: 204
        cookie|re: 'sid=\d{5,20}$'
    condition: selection | count() by src_ip, cookie > 20 in 10m
```

## Purple-team usage

Drive an idle session for an hour (sleep 10, no tasks) and validate
the 204-cadence rule against the proxy/CDN logs; then queue one task
and confirm the single 200-with-body exchange inside the 204 field.
Cross-reference the teamserver `state/audit.jsonl`
(`task_delivered` timestamps) with the log lines to prove which HTTP
exchange carried which technique — the after-action mapping. Seize the
teamserver state file in the exercise and pivot on the cookie token as
an IOC.
