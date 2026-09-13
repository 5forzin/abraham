# ABR-T001 — Detection guidance: encrypted C2 channel over HTTPS

Status: `experimental` (validated in the purple lab on 2026-09-10, see
`docs/lab/2026-09-10-vm-validation.md`; TLS-stack section updated
2026-09-12 after the implant moved to the OS TLS stack — see
`docs/lab/2026-09-12-implant-hardening.md` Part 11).

Scope: the implant's outer HTTPS transport (X25519/AES-256-GCM inner
session, see `docs/protocol.md`). The inner session is invisible to network
monitors by design — detection focuses on the outer flow.

## Telemetry sources

| Source | Event / field | Notes |
|---|---|---|
| Sysmon | EID 3 (Network Connection) | process → destination IP/port correlation (validated, see below) |
| ETW | `Microsoft-Windows-Schannel` | the implant now negotiates TLS through Schannel (SSPI), so handshake/error events for a **non-browser process** become visible — see detection idea 6 |
| Proxy | HTTP access logs | user agent, URI patterns, timing — requires TLS interception; otherwise only connection metadata is visible |
| Zeek | `ssl.log`, `http.log` | JA3/JA4 fingerprints, certificate details, SNI. Direct-IP lab builds send an IP as SNI; domain builds (e.g. avln behind Cloudflare) present the C2 domain, and the JA3/JA4 is **Schannel's** — indistinguishable from ordinary Windows HTTPS on the wire |

## TLS stack note (two eras)

- **Before 2026-09-12** the implant carried rustls/ring in-process:
  Schannel telemetry stayed silent while TLS flowed — a non-browser
  process emitting TLS with zero Schannel activity was itself the
  anomaly, and the rustls JA3/JA4 stood out from browser baselines.
- **From 2026-09-12** the implant uses the OS stack (Schannel on
  Windows) specifically to defeat middleboxes that hold non-browser
  ClientHellos (measured against Fortinet DPI: rustls took ~16 min to
  pass; Schannel connects in seconds). Wire fingerprints and Schannel
  activity are now identical to legitimate Windows traffic — the
  TLS-layer signals below no longer fire for the current build. They
  remain valid against the older artifacts and any custom-stack
  rebuild.

## Detection ideas

1. **TLS fingerprinting (legacy builds)**: a Rust TLS stack (rustls)
   produces a distinct JA3/JA4 signature from browser baselines. Alert
   on non-browser JA4s that also appear in low-volume, recurring flows.
2. **Certificate anomalies**: self-signed or recently-issued certificates on
   destinations contacted by non-browser processes.
3. **Sinkhole/generic names**: listener infrastructure frequently presents
   generic RDNS; combine with rarity scoring of the destination ASN.
   Domain-fronted deployments (CDN edge in front of the origin) hide the
   origin ASN — pivot to per-process flow baselines instead.
4. **Volume asymmetry**: C2 check-ins produce many short sessions with
   near-constant request sizes; flag flows where std-dev of request size is
   unusually low over a rolling window. Validated against the 2026-09-10
   capture; still true behind a CDN edge (only the destination IP changes
   to the edge).
5. **IP-as-SNI (lab builds)**: direct-IP configurations connect with an IP
   as server_name (no hostname). TLS flows to port 443/8443 with IP SNI
   from a non-browser process are high-signal.
6. **Schannel ownership (current builds)**: Schannel now executes the
   handshake for the implant process. Correlate
   `Microsoft-Windows-Schannel` operational events (handshake failures,
   fatal alerts — including the CDN-edge 400/reset retries) with Sysmon
   EID 3 for the same PID: a non-browser, non-service process with a
   steady Schannel session cadence to one destination is the residual
   host-side signal once the wire looks native.
7. **Demux tag correlation (network side, 2026-09-12; updated for the
   cookie era 2026-09-12/T035)**: every protocol POST carries the
   session token in the clear at the outer-TLS layer (protocol.md
   §5.1). Any middlebox that terminates TLS — the CDN edge always does;
   enterprise SSL-inspection proxies would — sees a stable
   per-implant-process token that joins the beacon's requests across
   connection churn and IP rotation. Until 0.1.x this rode in the
   `X-Session` header (recurring custom header with a decimal u64
   value); since 0.2.0 it rides in the profile-named session cookie
   (`Cookie: sid=<token>` by default). The alert shape moves to:
   a session cookie whose value is a bare decimal number (real web
   session ids are not), constant across requests, on keep-alive POST
   flows from one source that answer mostly `204`. The token is still
   an IOC-grade pivot — it appears verbatim in the teamserver's
   `state/sessions.json` when seized.

## Lab validation (2026-09-10, outer HTTPS)

Implant against the teamserver in the VM lab, Sysmon 15.22 recording:

- **Sysmon EID 3 fires** for every connection attempt from
  `abraham-implant.exe` to the teamserver IP:port — including the rejected
  pre-TLS connections of an old raw-TCP build, which shows up as the same
  process contacting the same destination repeatedly (idea 4's periodicity
  without any payload insight). Re-confirmed 2026-09-12 from the work
  network through the Cloudflare edge (destination = edge IP).
- **Schannel stays silent for the legacy rustls build** while TLS traffic
  flows (in-process stack) — the anomaly that motivated idea 6's inverse.
- URI/User-Agent/Server-header shaping is invisible to passive network
  observers by design; only TLS-intercepting proxies can evaluate the
  malleable metadata.
- Evidence: `lab/captures/abraham-vm_sysmon-https_2026-09-10.xml` and
  `docs/lab/2026-09-10-vm-validation.md`.

## UA pool and extra headers (2026-09-13)

Profiles can now carry a User-Agent pool and literal extra headers.
Detection nuance: a per-session stable UA is what real browsers do, so a
fleet of implants each holding a DIFFERENT consistent UA is harder to
correlate by UA alone — pivot instead on the behavioral pair (same
cookie name + same URI set + same cadence across IPs). The extra
headers are verbatim: a header set that never varies byte-for-byte
across thousands of requests is fingerprintable the same way — treat a
static header ORDER + static casing as the long-term correlation key,
since browsers reorder and re-case with updates.
