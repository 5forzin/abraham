# ABR-T001 — Detection guidance: encrypted C2 channel over HTTPS

Status: `experimental` (validated in the purple lab on 2026-09-10, see
`docs/lab/2026-09-10-vm-validation.md`).

Scope: the implant's outer HTTPS transport (X25519/AES-256-GCM inner
session, see `docs/protocol.md`). The inner session is invisible to network
monitors by design — detection focuses on the outer flow.

## Telemetry sources

| Source | Event / field | Notes |
|---|---|---|
| Sysmon | EID 3 (Network Connection) | process → destination IP/port correlation (validated, see below) |
| ETW | `Microsoft-Windows-Schannel`, `Microsoft-Windows-WinHTTP` | only applies to implants using OS TLS stacks — abraham v0.1.0+ uses rustls/ring in-process, so Schannel telemetry stays **silent**; a non-browser process emitting TLS with zero Schannel activity is itself an anomaly worth alerting on |
| Proxy | HTTP access logs | user agent, URI patterns, timing — requires TLS interception; otherwise only connection metadata is visible |
| Zeek | `ssl.log`, `http.log` | JA3/JA4 fingerprints, certificate details, SNI (abraham sends the destination IP, not a hostname, as SNI/server_name) |

## Detection ideas

1. **TLS fingerprinting**: a Rust TLS stack (rustls) produces a distinct
   JA3/JA4 signature from browser baselines. Alert on non-browser JA4s that
   also appear in low-volume, recurring flows.
2. **Certificate anomalies**: self-signed or recently-issued certificates on
   destinations contacted by non-browser processes.
3. **Sinkhole/generic names**: listener infrastructure frequently presents
   generic RDNS; combine with rarity scoring of the destination ASN.
4. **Volume asymmetry**: C2 check-ins produce many short sessions with
   near-constant request sizes; flag flows where std-dev of request size is
   unusually low over a rolling window.
5. **IP-as-SNI**: abraham's rustls client connects by IP (server_name is an
   IP address, no hostname). TLS flows to port 443/8443 with IP SNI from a
   non-browser process are high-signal.

## Lab validation (2026-09-10, outer HTTPS)

Implant (rustls TLS + HTTP envelope) against the teamserver in the VM lab,
Sysmon 15.22 recording:

- **Sysmon EID 3 fires** for every connection attempt from
  `abraham-implant.exe` to the teamserver IP:port — including the rejected
  pre-TLS connections of an old raw-TCP build, which shows up as the same
  process contacting the same destination repeatedly (idea 4's periodicity
  without any payload insight).
- **Schannel stays silent** for the implant process while TLS traffic flows
  (rustls in-process), confirming the anomaly in the telemetry table.
- URI/User-Agent/Server-header shaping is invisible to passive network
  observers by design; only TLS-intercepting proxies can evaluate the
  malleable metadata.
- Evidence: `lab/captures/abraham-vm_sysmon-https_2026-09-10.xml` and
  `docs/lab/2026-09-10-vm-validation.md`.
