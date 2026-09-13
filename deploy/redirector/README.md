# Redirector deployment

The default lab topology (implant → rustls teamserver directly) has two
network-level tells that no amount of implant hardening removes:

1. **TLS fingerprint mismatch.** The beacon speaks rustls/ring with a
   stable JA3/JA4 that is not any browser's, while the malleable
   profile advertises a Chrome User-Agent. Network analyzers that
   correlate the two flag the pair.
2. **Self-signed certificate.** The generated teamserver certificate is
   an immediate indicator on any TLS-visibility sensor.

The fix is architectural, which is why it ships as a deployment pattern
(ABR-T023) rather than implant code: terminate real TLS at a fronting
redirector and let the teamserver speak plain HTTP behind it.

```
implant ──TLS (real cert, nginx fingerprint)──▶ redirector :443
                                                   │ plain HTTP
                                                   ▼
                                         teamserver :9443 --plain-c2
```

## Setup

1. VPS with a domain (or org PKI cert); issue a real certificate.
2. Install the front: `nginx-abraham.conf` (adjust `server_name`,
   cert paths; proxy target is the local teamserver port).
3. Run the teamserver with `--plain-c2`:

   ```
   abraham-server --listen 127.0.0.1:9443 --mgmt 127.0.0.1:9200 --plain-c2
   ```

   `--plain-c2` accepts the beacon's HTTP envelope without TLS. This is
   safe **only** because the inner protocol is authenticated and
   encrypted end-to-end (Ed25519-signed X25519 handshake → per-frame
   AES-256-GCM; `docs/protocol.md` §4) — the outer TLS was never a
   security boundary, and the implant's `--tls-pin`/embedded pin now
   pins the redirector's real leaf certificate.

4. Embed `c2.example.com:443` in the operational build via
   `ABRAHAM_EMBED` (see `docs/usage.md`).

## Properties

- Outer fingerprint: nginx/OpenSSL behind a real certificate — the
  UA-vs-JA3 contradiction disappears.
- Redirector compromise exposes only ciphertext frames.
- Non-profile URIs 404 as an ordinary web property; host additional
  vhosts for cover.
- Takedown isolation: the teamserver address never appears in implant
  config if you front with a CDN/domain that can be rotated.
