# Lab report — implant hardening & utility pass (2026-09-12)

Full-project review executed in priority order. Host: VAQK (build
26200). VM: ABRAHAM (Windows 11 Pro, build 26200, Sysmon active).
Evidence: `lab/captures/t022-t023/`.

## Part 1 — Compiled-in configuration (ABR-T023, A1)

`ABRAHAM_EMBED=<json>` bakes server/key/tls-pin/evasion/profile into
the artifact under a build-random XOR keystream; the CLI parser and
stderr logging exist only behind `lab-args`/`lab-log`. Live proof on
the host: the embedded binary launched with **zero arguments**
(Win32_Process `CommandLine` empty) and registered as session 2.

**The const-fold incident.** The first audit of the embedded build
found the entire configuration in plaintext in `.rdata`. Root cause:
with LTO, the optimizer folded the `CONFIG_CIPHER ^ CONFIG_KEY` loop
(two const slices) into compile-time data and materialized the
plaintext as a constant — the keystream was encrypting the config straight
back into the artifact. Fix: decode through `read_volatile` on every
byte (and a volatile length probe), which the optimizer may not fold;
re-audit shows zero occurrences of any configuration value. Also
zeroed: the decode buffer after parsing.

## Part 2 — Artifact hygiene (ABR-T023, A2)

Release profile: `lto`, `codegen-units=1`, `strip="symbols"`,
`panic="abort"` + a silent panic hook; `-C link-arg=/DEBUG:NONE`
(`strip` alone leaves the RSDS/PDB record on MSVC);
`--remap-path-prefix` over the cargo home and workspace (builder
username gone); HKDF domain separator and rcgen CN renamed off the
project name; tokio `full` → `rt,net,time,io-util,macros` (2.79 MB →
1.98 MB). Final audit (CI-enforced since this pass): zero project-name,
binary-name, PDB, usage, CLI-flag, log-string, fallback-note,
builder-identity or cargo-path strings. Residual: 75 std
`/rustc/<hash>/` panic-location paths — documented, inherent to stable
rustc.

## Part 3 — Real registration data (B2)

`ppid` via `NtQueryInformationProcess(ProcessBasicInformation)` on the
indirect-syscall layer; integrity via
`NtQueryInformationToken(TokenIntegrityLevel)` — the first attempt
queried with an 8-byte buffer and failed `STATUS_BUFFER_TOO_SMALL`
(0xC0000023, needed 28: the SID rides inside the caller buffer) —
fixed with a 64-byte buffer and bounds-checked relative reads;
`os_build` via `RtlGetVersion`. Live: host session reports
`integrity=medium` (2), VM session (elevated guest) reports
`integrity=high` (3), both with real PPIDs and `10.0.26200`.

## Part 4 — Collection utility (B3)

`ps` gained a per-pid detail pass (`NtOpenProcess`
QUERY_LIMITED → `ProcessImageFileName` + `ProcessCommandLineInformation`
→ `NtClose`); protected processes degrade to `-` columns. VM output
carries NT-style paths (`\Device\HarddiskVolume3\...`) and command
lines. New modules: `netstat` (GetExtendedTcpTable/UdpTable OWNER_PID,
IPv4, network-order port/addr decode) and `env`. All green on both
hosts.

## Part 5 — In-process shellcode execution (ABR-T022, B1)

EXEC task: RW alloc → volatile copy → RX flip → call as
`fn(usize) -> usize` **on the session thread** → free. No child
process, no new thread, no cross-process handle — Sysmon EID 8/10
cannot fire by construction (detection story in
`docs/detections/abr-t022.md`: kernel-memory ETW RW→RX correlation and
private-RX region scanning). Live proof twice: host session
(`exec: 6B ret=0x1337`) and VM session **with ekko armed** — the
single-thread invariant held across the encrypted sleep windows that
bracket the poll carrying the task. Found-and-fixed during bring-up:
the first `secure_clear` call in the EXEC arm zeroed the result buffer
*before* sending (18 NUL bytes arrived instead of
`exec: 6B ret=0x1337`) — the arm now clears the payload, not the
result.

## Part 6 — Buffer hygiene + residual surface (A3)

`secure_clear` (volatile zeroing + compiler fence) now runs on task
frames after dispatch, shell commands and outputs, module args,
shellcode payloads, download/upload buffers and the embedded-config
decode buffer. The residual surface during the ekko window (session
keys in heap task state, `.data`, live stacks) is documented in
`docs/detections/abr-t006.md` with defender guidance: keys remain the
reliable blue-side recovery from a mid-sleep dump.

## Part 7 — Redirector pattern (A4)

`--plain-c2` server mode + `deploy/redirector/` (nginx terminating
real TLS). Resolves the rustls-JA3-vs-Chrome-UA contradiction and the
self-signed leaf IOC without implant changes — the inner Ed25519
session was always the security boundary. Not deployed live in this
pass (needs an external VPS); config and playbook committed.

## Part 8 — Reconnect hardening (A5)

Backoff doubles per consecutive failure (5 s → 300 s cap, 20% jitter),
resets once a session reaches the beacon loop. No default server: a
build with no embedded config and no flags exits instead of beaconing
to localhost.

## Part 9 — Execute-assembly, AMSI/ETW patching, IPv6 (T024/T025)

The COM discovery arc is the load-bearing part of this pass and is
recorded in `lab/captures/t022-t023/t024-t025-evidence.txt`: recalled
GUIDs answered E_NOINTERFACE on `GetRuntime`; the IID_IUnknown fallback
returned an object whose slot 10 was `IsLoadable`, not `GetInterface`
(access violation); the authoritative vtable orders and GUIDs came
from the mingw-w64 `mscoree.h` and wine `metahost.h` mirrors
(`ICLRRuntimeInfo::GetInterface` slot 9; `ICLRRuntimeHost` Start slot
3, `ExecuteInDefaultAppDomain` slot 11; CLSID/IID
`...7A5EBA6BDB02`), after which the chain returned hr=0 end-to-end.
Two syscall-signature slips on the way (NtOpenFile arg order,
NtSetInformationFile IoStatusBlock) were caught by the
delete-on-close unit test on an uncontended file.

Residue reality: the CLR maps the temp assembly without
FILE_SHARE_DELETE for the process lifetime — delete fails, POSIX
delete-on-close fails, so the task result reports the random-named
residue path verbatim. That is the honest trade: EID 11 is the
irreducible detection anchor and the persisted file is the operator's
own assembly, recoverable by the blue team.

Flaky-suite root cause: the proof assembly wrote to Console.Error,
which interacted intermittently with the test harness's captured
stderr pipe (CLR console init inside a capture-parented process);
removing the write made the serial release suite deterministic
(4/4 green after 2 crashes in 5 runs).

VM deployment footgun (recorded for future sessions): queueing EXECASM
against a stale implant binary (pre-0x09) makes `Message::decode`
reject the task kind, the `?` drops the session and the implant
reconnect-loops — the process stays alive, so it looks like a crash
but is a version skew. Symptom signature: session dies exactly on task
arrival, new session appears within one backoff interval.

VM live proof (session 4, integrity=high, ekko armed):
`execasm: 3584B hr=0x00000000 ret=0x1337 ... (amsi=patched,etw=patched)`
with the residue path reported and the beacon continuing.

netstat gained IPv6 owner tables (AF_INET6, TCP6 56B / UDP6 28B rows,
RFC 5952 formatter with unit tests); the guest's host-only network
exposed no v6 rows in the result preview, and the v6 query paths run
crash-free in the host suite.

## Part 10 — In-process PowerShell and native PE (T026/T027)

The user-facing gap this pass closed: the AMSI patch only ever
protected the implant's own process, so `shell` tasks through
`powershell.exe` still hit a pristine AMSI in the child; and there was
no way to run a native `.exe` at all.

**T026 (`psrun`)** runs .ps1 scripts inside the implant's CLR instance
through a bootstrap the teamserver compiles once with the in-box csc
(`tools/psboot.cs`, mscorlib-only references, SMA loaded from the GAC
at runtime). Host proof and VM live proof (ekko armed, elevated
guest): `ps: rc=0 (amsi=patched,etw=patched)` with the script output
captured (`ps-proof:4919` / `ps-vm:4919`). The reflection dance took
three iterations (binder ambiguity against the generic Create/Invoke
siblings — manual per-method overload selection is the stable answer);
.NET 4's GetMethod overloads did not help. **Assembly staleness
finding**: the default AppDomain pins the first-loaded Boot by simple
name, so a recompiled bootstrap keeps executing the old code until the
implant process restarts — live-debugged, documented, operational rule
recorded.

**T027 (`runpe`)** maps a native x64 PE in-memory (sections, DIR64
relocations, imports against live modules, whole image RX) and runs it
on a dedicated RtlCreateUserThread thread waited synchronously on the
session thread. The import resolver redirects
ExitProcess/TerminateProcess/RtlExitUserProcess/exit/_exit/_Exit to a
12-byte stub tail-jumping to the real ExitThread with the exit code in
RCX — a console EXE cannot take the implant down. Proofs (rustc-built
no_std payloads): exe via the redirect and dll via explicit ExitThread
both return 0x1337; VM live: `runpe: inline 3072B exit=0x1337` with
ekko armed. Engine lessons recorded in the evidence file: RVA!=file
offset walked through the section table, OldProtection must be a real
pointer, RtlCreateUserThread is not a syscall stub, GetExitCodeThread
before NtClose, an entry's plain return is not the thread exit code,
tiny rustc PEs are legitimately reloc-less, and CRT/TLS payloads fault
without the loader — honest limitation; std targets belong in
exec/execasm/psrun.

## Part 11 — Transport over a real CDN edge (avln, 2026-09-12 afternoon)

Environment: work network with Fortinet DPI (SSH 22 blocked, SSH@80
reset mid-kex), Cloudflare-proxied domain avln.nora.systems -> Azure
origin. The implant ran on the host itself; the teamserver on the VM.

Findings, in the order they bit:

1. **rustls ClientHello is fingerprint-held by the DPI.** Direct
   (DNS-only) the rustls handshake hangs forever while curl/openssl
   pass; behind the CF edge a rustls implant took ~16 minutes to get
   one handshake through. Fix: implant TLS switched to the OS stack
   (native-tls/Schannel on Windows) — ClientHello fingerprint equals
   ordinary Windows traffic; connects in seconds. Pin semantics moved
   to a post-handshake DER hash check (inner Ed25519 handshake remains
   the real authentication, so cover TLS accepts any cert by default).
2. **Half-open connections hang the beacon forever.** The edge drops
   connections silently; local writes drain into the socket buffer and
   the response read never returns (implant observed ESTABLISHED with
   zero sockets activity, tasking dead). Fix: every HTTP exchange is
   bounded by a 30s timeout -> transport error -> reconnect + resume.
3. **Session resume works across edge churn.** Same process token
   re-registers into the same server session (journal:
   `[~] session 2 resumed`); queue and results survive. Edge rejects
   ~1/3 of fresh POSTs with 400/0B before origin (no server log) —
   short backoff absorbs it.
4. **u16 frame length caps results at ~64 KiB.** A host `ps` (113 KB)
   killed the session ("frame exceeds maximum size"). Fix: results over
   48 KiB split into an inline preview (1.9 KB, UTF-8-boundary cut) plus
   the full payload via the existing chunk path -> server-side loot
   file `loot/session-N/task-M.bin` + StoredResult rows. Validated
   live: task 4 preview + 113727-byte loot row, zero transport errors.
5. **CF origin connection pooling violates "1 TCP = 1 crypto session".**
   Foreign requests occasionally arrive on a live session's origin
   connection ("bad frames: bad magic", "register: bad frames"). The
   connection ends but the session persists and resume heals it.
   Durable fix (roadmap Phase 4): tag every sealed frame with a session
   identifier so routing no longer depends on the TCP connection.

Live evidence: sessions 1-4 (VAQK\antho@VAQK), tasks `env` and `ps`
round-tripped through the edge, loot stored on the teamserver, journal
`15:16:03 [~] session 2 resumed from ...`.

## Disposition

| Review item | Status |
|---|---|
| A1 config out of the command line | live-proven (embedded session, empty cmdline) |
| A2 static strings/identity | live-proven (audit clean, CI-gated) |
| A3 heap hygiene | shipped + residual documented |
| A4 TLS mismatch | pattern shipped (redirector), deployment needs infra |
| A5 fixed retry/default server | shipped |
| B1 in-memory execution | live-proven twice (host + VM w/ ekko) |
| B2 real registration data | live-proven (medium/high/build/ppid) |
| B3 collection depth | live-proven (ps detail/netstat/env, IPv6 tables) |
| B1+ execute-assembly | live-proven host+VM (T024/T025) |
| AMSI/ETW patching | live-proven host+VM (T024) |
| In-process PowerShell | live-proven host+VM (T026) |
| Native PE in-memory | live-proven host+VM (T027) |

CI parity: fmt clean, clippy `-D warnings` clean, workspace 16+70,
release serial 81/81 (execasm, powershell, runpe exe+dll, amsi/etw
patches, ekko, spoof), registry 27 techniques, sigma 0 issues,
artifact audit clean.

## Part 12 — Session demux, persistence, one-command deploy (2026-09-12 evening)

Goal: stability as a property, not a workaround — kill the last known
transport fragility (CDN origin pooling) and make the deploy itself a
single command, so iteration stops being the risky part.

### What changed

1. **Per-request session demux** (`protocol.md` §5.1). Every implant
   POST now carries `X-Session: <token>`; the ClientHello POST also
   carries `X-Handshake: 1`. The teamserver keeps ALL session state
   (crypto keys, task queue, result history, chunk reassembly) in a
   registry keyed by token — connections are stateless pipes. A
   handshake parks its keys in a token-keyed provisional map (the
   REGISTER may land on ANY pooled origin connection); the register
   binds/resumes and adopts them; later requests decrypt under the
   session's current keys wherever they arrive. A frame that fails to
   open costs its request (HTTP 400) — never the connection, never the
   session. Headerless requests keep the legacy conn-bound path (old
   implants unchanged).
   - Routing by header grants nothing cryptographically: the token only
     selects keys; AES-GCM + strictly increasing counters still decide.
   - Regression test: two sessions interleaved on ONE server-side
     connection (the exact Cloudflare shape) — tasking lands per
     session, an unknown token gets a 400 and both sessions keep
     riding the same connection.
   - Found by that test's first failure: on RESUME the REGISTER is
     sealed with the NEW handshake keys, so routing must prefer the
     token's provisional over the live session's current keys
     (previously the register would hit the old keys -> crypto failure).
2. **Session persistence** (`state/sessions.json`, flag `--state`).
   The registry (ids, tokens, identity, last 200 results per session,
   counters) is snapshotted on register/result/loot and reloaded at
   startup. A redeploy restart no longer orphans history: the beacon
   re-registers with its token, resumes the SAME session id, and
   drains tasks queued while it had no transport (regression test:
   queue-offline-then-resume round-trip). Queued-but-undelivered tasks
   do not survive the restart itself (in-memory channel) — documented.
3. **One-command deploy** (`deploy/avln/push.sh`): builds the
   operational implant from the checked-in `deploy/avln/embed.json`,
   syncs the workspace, builds the server on the VM, swaps the stage,
   restarts the service and health-checks (mgmt sessions + public stage
   hash equals local). Helpers live in the repo now
   (`upload_chunked.py` chunked gzip+base64 Run Command upload,
   `mgmt.py` JSON-lines wrapper). With persistence, the restart in
   every deploy is non-disruptive by design.

### Blue-team notes (coupled)

- The `X-Session` header is a durable per-implant-process correlation
  handle for any middlebox that terminates the outer TLS (the CDN edge
  always does, enterprise SSL-inspection proxies would too): it joins
  the beacon's requests across origin-connection churn even when IPs
  and connections rotate. Added to protocol.md §5.1 as a defensive
  note.
- `state/sessions.json` on the teamserver is responder loot: identity,
  usernames, hostnames, result summaries — worth adding to the
  seizure playbook alongside `loot/` and `server.key`.

CI parity: fmt clean, clippy `-D warnings` clean, workspace tests
16+70+2 (new: header roundtrip in common, pooled-conn demux and
restart-resume in server).

### Live validation (avln, 2026-09-12 23:05 UTC-3)

Full chain observed over the real Cloudflare path with the staged
operational build (hash 0fa65025…):

```
[*] state: 1 session(s) restored from state/sessions.json   <- restart (deploy)
[!] session 1: bad frames: crypto operation failed          <- in-flight poll from
                                                               the dead transport:
                                                               400 costs the request
                                                               only
[~] session 1 resumed from 104.23.254.190:13728             <- 6s later, SAME id
```

Task round-trip after resume: `PERSIST-VALIDATED` delivered. Session
list never lost id 1 across the restart.

Deploy lesson (the failure that hid for one cycle): RunShellScript
executes via a bare dash with no `~/.cargo/bin` on PATH — the VM build
step silently died with `cargo: not found` and the service restart
happily restarted the OLD binary (stage was new, so the headerless
legacy path masked it). push.sh now resolves cargo explicitly, prints
`BUILD-STATUS:<n>` and fails the deploy on anything but 0; run-command
output goes through `--query value[0].message -o tsv` so markers are
checked against clean text, not JSON-escaped blobs. The tell that
exposed it: the OLD binary's duplicated `[+] session N` register line
(old double-print bug) and a missing `state/` directory.
