# Abraham Wire Protocol — v0.2 (draft)

Status: **draft**, Phase 1 implementation. This document is the normative
specification for communication between the implant (`implant/`) and the
teamserver (`server/`).

## 1. Overview

The protocol is layered:

```
+---------------------------------------------+
| TLS 1.2/1.3 session (OS stack: Schannel on  |  outer confidentiality
| Windows via native-tls; rustls on the       |
| teamserver listener)                        |
+---------------------------------------------+
| HTTP/1.1 envelope (keep-alive POSTs)        |  malleable cover traffic
+---------------------------------------------+
| Abraham wire protocol (encrypted frames)    |  this spec
+---------------------------------------------+
| Tasking messages (REGISTER, TASK, RESULT..) |  Section 6
+---------------------------------------------+
```

The c2 listener is HTTPS: every implant message is the body of an HTTP/1.1
`POST` to a profile-configured URI (Section 8) with a profile User-Agent,
inside a long-lived TLS connection. The inner layer is an end-to-end
encrypted session between the implant and the teamserver, so middleboxes
only ever observe TLS, HTTP metadata and timing — never tasking content.

Outer TLS properties (Phase 1):

- The teamserver presents a self-signed certificate (generated on first
  run, persisted as PEM next to the identity key) and prints its
  `sha256(cert DER)` pin at startup.
- The implant accepts any certificate by default: authenticity is enforced
  by the inner Ed25519-pinned handshake, so a TLS MITM can observe but not
  forge or alter tasking. `--tls-pin <sha256-hex>` optionally pins the
  certificate for full outer-layer MITM resistance.

## 2. Threat model

- Network observers see only the outer transport and the malleable profile.
- The teamserver authenticates itself with an Ed25519 signature over the
  handshake (key pinned into the implant at build time).
- The implant is an anonymous client; operator-side identification happens
  after REGISTER via session metadata.
- Forward secrecy: session keys are re-derived on every handshake; sessions
  additionally re-key after `REKEY_INTERVAL` application messages
  (default 2^16).

## 3. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Key agreement | X25519 (ECDHE) |
| Server authentication | Ed25519 (pinned public key) |
| Key derivation | HKDF-SHA256 |
| Symmetric encryption | AES-256-GCM |
| Nonce construction | 96-bit: 32-bit direction (0 = client→server) \|\| 32-bit reserved zeros \|\| 32-bit counter, big-endian |
| Hashing | SHA-256 |

Rationale: widely available in Rust (`RustCrypto` / `ring`), no exotic
dependencies, conservative choices.

## 4. Session handshake

The handshake rides in the first two HTTP exchanges on a connection. The
first POST body is the raw 64-byte `ClientHello`; the response body is the
raw 128-byte `ServerHello`. A body length mismatch is a protocol error and
the connection is dropped with HTTP 400.

```
Implant                                    Teamserver
   |                                          |
   | -- POST (body: X25519 pubkey_I ||        |
   |          nonce_I) ---------------------> |
   |                                          |
   | <-- 200 (body: X25519 pubkey_S ||        |
   |           nonce_S || Ed25519_sig(...))   |
   |                                          |
   | both sides:                               |
   |   shared = X25519(priv, peer_pub)         |
   |   keys    = HKDF-SHA256(shared,          |
   |             nonce_I || nonce_S,           |
   |             "c2-hkdf-v1", 64 bytes)       |
   |   key_tx/key_rx split per direction       |
   |                                          |
   | -- POST (REGISTER frame) --------------> |
   | <-- 200 (empty body) ------------------- |
```

The first framed message after the handshake MUST be `REGISTER`. A teamserver
that receives any other message first closes the session.

## 5. Framing and the HTTP envelope

All multi-byte integers are big-endian. Frame layout:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------+---------+-----------+-----------------+
| magic "AB"    | version | msgtype | length    | counter         |
| (2 bytes)     | (1)     | (1)     | (2, u16)  | (4, u32)        |
+---------------+---------+---------+-----------+-----------------+
| ciphertext (length bytes) ...                        | tag (16) |
+-----------------------------------------------------+----------+
```

- `version` is the wire protocol major version (`0x01`). Minor changes are
  additive fields inside encrypted payloads.
- `counter` is the per-direction message counter used in the GCM nonce. It
  MUST be strictly increasing; a regression indicates replay or tampering and
  the session MUST be dropped.
- The GCM tag is appended to the ciphertext; `length` covers only the
  ciphertext.
- Maximum frame size: 65 535 bytes (`length` is `u16`). Larger payloads are
  transferred as `CHUNK` messages of up to 60 000 bytes.
- The full frame header (magic, version, message type, length, counter) is
  authenticated as AES-GCM associated data.

HTTP envelope rules:

- One implant message (or a contiguous run of chunks) per `POST` body; one
  server response per request. Requests and responses always carry
  `Content-Length` (never chunked encoding).
- `TASK_POLL` responses batch zero or more sealed frames terminated by
  `BATCH_END` in a single response body. Chunked downloads from the implant
  may batch all chunks in one body; the server acknowledges the final chunk
  with a `RESULT` frame in that response's body.
- URIs not in the profile yield HTTP 404; non-POST methods yield 405; a
  body over 8 MiB yields 413. Frames that fail authentication yield HTTP
  400 for that request — the connection itself survives, because other
  sessions may be riding it (see connection pooling below).
- Counter progression is enforced per direction per session (not per HTTP
  request and not per TCP connection).

### 5.1 Session demux (connection pooling)

A fronting proxy (Cloudflare et al.) terminates the client TLS and pools
origin connections: requests from several implant transports can arrive
INTERLEAVED on one server-side TCP connection. The server therefore never
binds protocol state to the connection. Every implant POST tags itself
inside the cover envelope:

- `Cookie: <cookie_name>=<session_token>` — decimal u64 riding in the
  profile-named session cookie (`cookie_name`, default `sid`); routes
  the request to its session. Present on every protocol POST (handshake
  included). Since 0.2.0 this replaces the `X-Session` header on the
  wire; the header is still accepted (legacy builds).
- `X-Handshake: 1` — marks the POST body as a raw ClientHello.

**Idle polls are cheap on the wire (0.2.0+):** a TASK_POLL that
delivers nothing is answered `HTTP 204` with no body — no sealed
BATCH_END, so an idle beacon stops emitting a constant small binary
blob per poll. Implants report their build version at REGISTER; older
builds (pre-0.2.0) keep receiving the sealed empty batch with 200.

Server-side routing per POST: a handshake parks its derived keys under
the announced token (a "provisional"); the REGISTER that follows (same
token, possibly arriving on a different pooled connection) binds or
resumes the session and adopts those keys; every later request decrypts
under the current session keys regardless of which origin connection
delivered it. A request whose frames fail to decrypt costs itself
(HTTP 400) — never the connection or the session.

Routing by header grants nothing on its own: the token only selects
keys, and frames must still authenticate under them (AES-GCM, strictly
increasing counters). Headerless requests still work through a
connection-bound legacy path (one handshake + session per connection).

Defensive note: the demux headers are visible to any middlebox that
terminates the outer TLS (the CDN edge always does) — a per-host
correlation handle for beacon traffic, joining requests of one implant
process even as its origin connections churn.

## 6. Message types

| Type | Name | Direction | Purpose |
|---|---|---|---|
| `0x01` | `REGISTER` | implant → server | Session registration with host metadata |
| `0x02` | `TASK_POLL` | implant → server | Request pending tasks |
| `0x03` | `TASK` | server → implant | A task for the implant to execute |
| `0x04` | `RESULT` | implant → server | Result of an executed task |
| `0x05` | `CHUNK` | both | Chunked transfer of large results/payloads |
| `0x06` | `PING` | both | Liveness check |
| `0x07` | `PONG` | both | Liveness response |
| `0x08` | `SLEEP` | server → implant | Update poll interval and jitter |
| `0x09` | `ERROR` | both | Structured error (code + message) |
| `0x0A` | `BATCH_END` | server → implant | Terminates the batch returned for a `TASK_POLL` |

Task batching: the implant sends `TASK_POLL` and the teamserver responds with
zero or more `TASK`/`CHUNK` frames terminated by a single `BATCH_END`. The
implant then executes each task and streams `RESULT`/`CHUNK` frames back
before issuing the next poll.

### 6.1 REGISTER payload

| Field | Type | Notes |
|---|---|---|
| hostname | string (u16-len prefixed) | |
| username | string | |
| domain | string | may be empty |
| pid / ppid | u32 | |
| arch | u8 | `0=arm64`, `1=x64` |
| integrity_level | u8 | token SID RID via `NtQueryInformationToken`: `0=unknown`, `1=low`, `2=medium`, `3=high`, `4=system`, `5=protected` |
| os_build | string | e.g. `10.0.19045` |
| implant_version | string | semver |

### 6.2 TASK payload

| Field | Type | Notes |
|---|---|---|
| task_id | u32 | unique per session |
| task_type | u8 | see table below |
| args | blob | task-type specific |

Initial task types (Phase 1):

| task_type | Name | Notes |
|---|---|---|
| `0x01` | SHELL | Execute command line via `cmd.exe` (ABR-T002) |
| `0x02` | UPLOAD | Write blob to path (ABR-T003) |
| `0x03` | DOWNLOAD | Read file, reply in `CHUNK`s (ABR-T003) |
| `0x04` | EXIT | Terminate implant process |
| `0x05` | SLEEP | Local override of interval/jitter (ABR-T004) |

Phase 2 addition:

| task_type | Name | Notes |
|---|---|---|
| `0x06` | MODULE | Built-in in-process module, no child process (ABR-T011). Payload after the task id: `name` string, `args` string |

Phase 3 addition:

| task_type | Name | Notes |
|---|---|---|
| `0x07` | DRIVER | Kernel-driver staging lifecycle through the SCM (ABR-T013). Payload after the task id: `action` u8 (`0=load`, `1=unload`, `2=probe`, `3=elevate`, `4=gate`, `5=hide`, `6=unhide`, `7=call`, `8=call-preflight`, `9=map`, `0x0A=modhide`, `0x0B=modshow`, `0x0C=protect`, `0x0D=chan`), `service` string, `source` string, `drop_path` string. `load` copies `source` to `drop_path`, registers a demand-start kernel service on it and starts it; `unload` stops/deregisters the service and removes the staged file; `probe` (ABR-T014) opens every known vulnerable-driver device and proves arbitrary kernel read on the first that answers (no staging fields required) |

Phase 4 addition:

| task_type | Name | Notes |
|---|---|---|
| `0x08` | EXEC | In-process shellcode execution (ABR-T022). Payload after the task id: `data` blob (48 KB frame cap). The implant copies the blob to a private RW region via indirect syscalls, flips it RX, calls it as `fn(usize) -> usize` on the session thread and frees the region; the result reports `exec: <n>B ret=<hex>` |
| `0x09` | EXECASM | In-process .NET assembly execution via bare CLR hosting (ABR-T025), optionally preceded by AMSI/ETW patching (ABR-T024). Payload after the task id: `data` blob (48 KB cap), `type_name` string, `method_name` string, `argument` string, `patch` u8. Invokes the operator convention `public static int <method_name>(string)` and reports the managed exit code plus the temp-file residue disposition |
| `0x0A` | POWERSHELL | In-process PowerShell (ABR-T026): `script` string, `bootstrap` blob (compiled from tools/psboot.cs by the teamserver). AMSI/ETW patched first; the script's captured output is returned as the result |
| `0x0B` | RUNPE | In-memory native PE execution (ABR-T027): `data` blob (48 KB cap) or `path` string of an uploaded stage deleted after mapping. Reports the payload thread's exit code |
| `0x0C` | PERSIST | Host persistence (ABR-T030): `action` u8 (0=install, 1=remove, 2=list), `mechanism` string (run-key, run-key-hklm, startup, service), `name` string, `exe` string (empty = copy of the implant to %APPDATA%), `args` string |
| `0x0D` | COLLECT | Collection (ABR-T031): `action` u8 (0=screenshot PNG/BMP chunked, 1=clipboard text, 2=keylog dump+clear), `arg` string reserved |
| `0x0E` | CRED | Credential access (ABR-T032/T033): `action` u8 (0=LSASS user-mode dump, 1=LSASS kernel-attach dump), `arg` string reserved. Result is the `%TEMP%` dump path |

### 6.3 RESULT payload

| Field | Type | Notes |
|---|---|---|
| task_id | u32 | matches the TASK |
| status | u8 | `0=ok`, `1=error`, `2=partial` (chunked) |
| data | blob | stdout/stderr or task-specific output |

## 8. Malleable profile

Profiles are YAML consumed by the teamserver (`--profile`, default
`profiles/default.yaml`) and optionally by the implant (`--profile`, or
piecewise `--ua` / `--uri` / `--sleep` / `--jitter`). They control only the
**outer** layer — the inner protocol is constant:

```yaml
uris:                # implant picks one at random per request
  - /api/v1/telemetry
  - /cdn/update
user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
server_header: nginx # Server header on responses
cookie_name: sid     # session cookie the demux token rides in (0.2.0)
sleep_secs: 5        # default poll interval (overridable via SLEEP task)
jitter: 0.25         # +/- 25% randomization of sleep
```

The teamserver serves every tasking exchange on any listed URI with the
configured `Server` header; everything else 404s. Changing a profile on the
server applies to new connections; running implants pick up `sleep_secs` /
`jitter` only through the `SLEEP` task.

### 8.1 Embedded deployment configuration (T035)

Operational builds carry their configuration as one encrypted JSON blob
(`ABRAHAM_EMBED` at build time; see `implant/build.rs`). Schema:

```json
{
  "servers": ["c2.example.com:443", "backup.example.com:443"],
  "key": "<64-hex ed25519 public key>",
  "tls_pin": "",
  "evasion": "ekko",
  "profile": "sleep_secs: 10\njitter: 0.3\n",
  "kill_date": 1797036250,
  "gates": {"initial_delay_max_secs": 0, "blocked_processes": []}
}
```

- `servers` — fronts in priority order; after 3 consecutive transport
  failures the implant rotates to the next (same session token, so the
  teamserver resumes the session). `server` (string) is a legacy alias.
- `kill_date` — unix seconds; past it the implant exits silently
  (0 = never). A SUNBURST-style expiry: dead tooling must not beacon.
- `gates.initial_delay_max_secs` — random activation delay before first
  contact, breaking the process-start → immediate-beacon correlation.
- `gates.blocked_processes` — the implant stays dormant (no contact)
  while any listed process runs.

## 9. Error codes

| Code | Meaning |
|---|---|
| `0x01` | malformed frame |
| `0x02` | counter regression (possible replay) |
| `0x03` | authentication failure |
| `0x04` | unknown message type |
| `0x05` | task execution failure |
| `0x06` | protocol version mismatch |

## 10. Versioning

This specification follows the repository version. Breaking changes to the
wire format bump the `version` byte and require a matching registry entry
documenting both the change and its detection impact.
